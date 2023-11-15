// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
#define _GNU_SOURCE 1
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <poll.h>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <libHX/ctype_helper.h>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <gromox/config_file.hpp>
#include <gromox/fileio.h>
#include <gromox/hook_common.h>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#if (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2090000fL) || \
    (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x1010000fL)
#	define OLD_SSL 1
#endif
using namespace std::string_literals;
using namespace gromox;

namespace {
struct rd_delete {
	void operator()(SSL *x) const { SSL_free(x); }
	void operator()(SSL_CTX *x) const { SSL_CTX_free(x); }
};

struct rd_connection {
	~rd_connection() {
		if (fd >= 0)
			close(fd);
	}
	int fd = -1;
	std::unique_ptr<SSL, rd_delete> tls;
};
}

static errno_t rd_starttls(rd_connection &&, const MESSAGE_CONTEXT *, std::string &);

static constexpr unsigned int network_timeout = 180;
static std::unique_ptr<SSL_CTX, rd_delete> g_tls_ctx;
static std::unique_ptr<std::mutex[]> g_tls_mutex_buf;
static std::string g_mx_host;
static uint16_t g_mx_port;
static bool g_enable_tls;
DECLARE_HOOK_API();

static constexpr cfg_directive remote_delivery_cfg_defaults[] = {
	{"mx_host", "::1"},
	{"mx_port", "25", 0, "1", "65535"},
	{"starttls_support", "on", CFG_BOOL},
	CFG_TABLE_END,
};

#ifdef OLD_SSL
static void rd_ssl_locking(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		g_tls_mutex_buf[n].lock();
	else
		g_tls_mutex_buf[n].unlock();
}

static void rd_ssl_id(CRYPTO_THREADID *id)
{
	CRYPTO_THREADID_set_numeric(id, static_cast<uintptr_t>(pthread_self()));
}
#endif

static int rd_run()
{
	SSL_library_init();
	SSL_load_error_strings();
#ifdef OLD_SSL
	try {
		g_tls_mutex_buf = std::make_unique<std::mutex[]>(CRYPTO_num_locks());
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "remote_delivery: failed TLS mutex setup");
		return -1;
	}
	CRYPTO_THREADID_set_callback(rd_ssl_id);
	CRYPTO_set_locking_callback(rd_ssl_locking);
#endif
	OpenSSL_add_all_algorithms();
	g_tls_ctx.reset(SSL_CTX_new(SSLv23_client_method()));
	if (g_tls_ctx == nullptr) {
		mlog(LV_ERR, "remote_delivery: failed TLS setup");
		return -1;
	}
	return 0;
}

static void rd_log(const CONTROL_INFO &eci, unsigned int level,
    const char *fmt, ...)
{
	std::string outbuf = "[remote_delivery]";
	auto ctrl = &eci;
	outbuf += " QID=" + std::to_string(ctrl->queue_ID) + " from=<"s +
	          ctrl->from + "> to=";

	bool second_rcpt = false;
	for (const auto &rcpt : ctrl->rcpt) {
		if (second_rcpt)
			outbuf += ',';
		second_rcpt = true;
		outbuf += '<';
		outbuf += rcpt;
		outbuf += '>';
	}
	outbuf += ": ";
	std::unique_ptr<char[], stdlib_delete> asbuf;
	va_list args;
	va_start(args, fmt);
	vasprintf(&unique_tie(asbuf), fmt, args);
	va_end(args);
	outbuf += asbuf.get();
	mlog(level, "remote_delivery: %s", outbuf.c_str());
}

static bool rd_send_cmd(const rd_connection &conn,
    const char *cmd, ssize_t clen = -1)
{
	if (clen == -1)
		clen = strlen(cmd);
	ssize_t w = conn.tls != nullptr ? SSL_write(conn.tls.get(), cmd, clen) :
	            write(conn.fd, cmd, clen);
	return w == clen;
}

static errno_t rd_get_response(const rd_connection &conn,
    std::string &response, char want_code = '2')
{
	size_t offset = 0;
	response.clear();
	response.resize(512);

	do {
		struct pollfd pfd = {conn.fd, POLLIN};
		if (poll(&pfd, 1, network_timeout * 1000) <= 0)
			return ETIMEDOUT;
		auto write_ptr = response.data() + offset;
		auto space = response.size() - offset;
		if (space < 256) {
			response.resize(response.capacity() * 2);
			space = response.size() - offset;
		}
		ssize_t have_read = conn.tls != nullptr ?
		                    SSL_read(conn.tls.get(), write_ptr, space) :
		                    read(conn.fd, write_ptr, space);
		if (have_read <= 0)
			return ETIMEDOUT;
		offset += static_cast<size_t>(have_read);
		if (have_read >= 1 && write_ptr[have_read-1] != '\n')
			/*
			 * Remainder of current line still to be read, and
			 * perhaps even more lines.
			 */
			continue;
		if (offset >= 4 && response[3] == ' ')
			/*
			 * First line (it is complete now) in the entire
			 * multigroup buffer is already the final line.
			 */
			break;
		/* Scan for the last line of a ML group */
		auto nl = response.c_str();
		while ((nl = strchr(nl, '\n')) != nullptr) {
			++nl;
			if (nl[0] != '\0' && nl[1] != '\0' &&
			    nl[2] != '\0' && nl[3] == ' ')
				break;
		}
		if (nl != nullptr && nl[0] != '\0' && nl[1] != '\0' &&
		    nl[2] != '\0' && nl[3] == ' ')
			break;
	} while (true);
	response[offset] = '\0';
	HX_chomp(response.data());
	response.resize(strlen(response.c_str()));
	if (!HX_isdigit(response[1]) || !HX_isdigit(response[2]))
		return EBADMSG;
	return want_code != 0 && response[0] == want_code ? 0 : EBADMSG;
}

static errno_t rd_hello(const rd_connection &conn, const MESSAGE_CONTEXT *ctx,
    std::string &response)
{
	char cmd[1024];
	auto len = gx_snprintf(cmd, std::size(cmd), "EHLO %s\r\n", get_host_ID());
	if (!rd_send_cmd(conn, cmd, len))
		return ETIMEDOUT;
	auto ret = rd_get_response(conn, response);
	if (ret == 0 || ret == ETIMEDOUT)
		return ret;
	/* retry with HELO */
	len = gx_snprintf(cmd, std::size(cmd), "HELO %s\r\n", get_host_ID());
	if (!rd_send_cmd(conn, cmd, len))
		return ETIMEDOUT;
	ret = rd_get_response(conn, response);
	if (ret == 0 || ret == ETIMEDOUT)
		return ret;
	response += " (after HELO)";
	return ret;
}

static errno_t rd_mailfrom(rd_connection &conn, const MESSAGE_CONTEXT *ctx,
    std::string &response)
{
	char cmd[UADDR_SIZE+24];
	auto f = strcmp(ctx->ctrl.from, ENVELOPE_FROM_NULL) != 0 ? ctx->ctrl.from : "";
	auto len = gx_snprintf(cmd, std::size(cmd), "MAIL FROM: <%s>\r\n", f);
	if (!rd_send_cmd(conn, cmd, len))
		return ETIMEDOUT;
	auto ret = rd_get_response(conn, response);
	if (ret == 0 || ret == ETIMEDOUT)
		return ret;
	response += " (after MAIL)";
	return ret;
}

static errno_t rd_rcptto(rd_connection &conn, const MESSAGE_CONTEXT *ctx,
    std::string &response)
{
	bool any_success = false;
	for (const auto &rcpt : ctx->ctrl.rcpt) {
		char cmd[1024];
		auto len = gx_snprintf(cmd, std::size(cmd), "RCPT TO: <%s>\r\n", rcpt.c_str());
		if (!rd_send_cmd(conn, cmd, len))
			return ETIMEDOUT;
		auto ret = rd_get_response(conn, response);
		if (ret == ETIMEDOUT)
			return ret;
		if (ret != 0) {
			response += " (after RCPT)";
			return ret;
		}
		any_success = true;
	}
	if (!any_success)
		return ENOENT;
	return 0;
}

static errno_t rd_data(rd_connection &&conn, const MESSAGE_CONTEXT *ctx, std::string &response)
{
	if (!rd_send_cmd(conn, "DATA\r\n", 6))
		return ETIMEDOUT;
	auto ret = rd_get_response(conn, response, '3');
	if (ret == ETIMEDOUT)
		return ret;
	if (ret != 0)
		return ret;
	auto tls_write = +[](void *obj, const void *buf, size_t z) -> ssize_t {
	                   	return SSL_write(static_cast<SSL *>(obj), buf, z);
	                 };
	bool did_data = conn.tls != nullptr ? ctx->mail.emit(tls_write, conn.tls.get()) :
	                ctx->mail.to_file(conn.fd);
	if (!did_data) {
		ret = rd_get_response(conn, response);
		if (ret == ETIMEDOUT)
			return ret;
		response += " (after DATA)";
		return ret;
	}
	if (!rd_send_cmd(conn, ".\r\n", 3))
		return ETIMEDOUT;
	ret = rd_get_response(conn, response);
	if (ret == ETIMEDOUT)
		return ret;
	if (ret != 0) {
		response += " (after DOT)";
		return ret;
	}
	mlog(LV_INFO, "remote_delivery: SMTP output to %s ok", g_mx_host.c_str());
	rd_send_cmd(conn, "QUIT\r\n", 6);
	return 0;
}

static errno_t rd_session_begin(rd_connection &&conn, const MESSAGE_CONTEXT *ctx,
    std::string &response)
{
	auto ret = rd_hello(conn, ctx, response);
	if (ret != 0)
		return ret;
	if (g_enable_tls && conn.tls == nullptr &&
	    (search_string(response.c_str(), "250-STARTTLS", response.size()) != nullptr ||
	    search_string(response.c_str(), "250 STARTTLS", response.size()) != nullptr))
		return rd_starttls(std::move(conn), ctx, response);
	ret = rd_mailfrom(conn, ctx, response);
	if (ret != 0)
		return ret;
	ret = rd_rcptto(conn, ctx, response);
	if (ret != 0)
		return ret;
	return rd_data(std::move(conn), ctx, response);
}

static errno_t rd_starttls(rd_connection &&conn, const MESSAGE_CONTEXT *ctx,
    std::string &response)
{
	if (!rd_send_cmd(conn, "STARTTLS\r\n", 10))
		return ETIMEDOUT;
	auto ret = rd_get_response(conn, response);
	if (ret == ETIMEDOUT)
		return ret;
	if (ret != 0) {
		response += " (after STARTTLS)";
		return EHOSTUNREACH;
	}
	conn.tls.reset(SSL_new(g_tls_ctx.get()));
	if (conn.tls == nullptr) {
		mlog(LV_ERR, "E-1553: Could not create local TLS context");
		return EHOSTUNREACH;
	}
	SSL_set_fd(conn.tls.get(), conn.fd);
	if (SSL_connect(conn.tls.get()) != 1) {
		mlog(LV_WARN, "W-1569: Could not TLS-connect to [%s]:%hu",
		        g_mx_host.c_str(), g_mx_port);
		return EHOSTUNREACH;
	}
	return rd_session_begin(std::move(conn), ctx, response);
}

static errno_t rd_send_mail(const MESSAGE_CONTEXT *ctx, std::string &response)
{
	rd_connection conn;
	conn.fd = HX_inet_connect(g_mx_host.c_str(), g_mx_port, 0);
	if (conn.fd < 0) {
		rd_log(ctx->ctrl, LV_ERR, "Could not connect to SMTP [%s]:%hu: %s",
			g_mx_host.c_str(), g_mx_port, strerror(-conn.fd));
		return EHOSTUNREACH;
	}
	auto ret = rd_get_response(conn, response);
	if (ret == 0)
		return rd_session_begin(std::move(conn), ctx, response);

	if (ret == ETIMEDOUT)
		return ret;
	rd_log(ctx->ctrl, LV_DEBUG, "SMTP said answered \"%s\" after connection", response.c_str());
	/* change reason to connection refused */
	if (ret == 0 || 1)
		ret = ECONNREFUSED;
	rd_send_cmd(conn, "QUIT\r\n", 6);
	return ret;
}

static hook_result remote_delivery_hook(MESSAGE_CONTEXT *ctx)
{
	std::string errstr;
	int ret;
	try {
		ret = rd_send_mail(ctx, errstr);
		if (ret == 0)
			return hook_result::stop;
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1552: ENOMEM");
		return hook_result::proc_error;
	}

	mlog(LV_ERR, "remote_delivery: Local code: %s (ret=%d). "
	        "SMTP reason string: %s. Recipient(s) affected:",
	        strerror(ret), ret, errstr.c_str());
	for (const auto &rcpt : ctx->ctrl.rcpt)
		mlog(LV_ERR, "remote_delivery:\t%s", rcpt.c_str());
	return hook_result::stop;
}

static BOOL remote_delivery_entry(int request, void **apidata)
{
	if (request == PLUGIN_FREE) {
		g_tls_ctx.reset();
		g_tls_mutex_buf.reset();
		return TRUE;
	}
	if (request != PLUGIN_INIT)
		return TRUE;

	LINK_HOOK_API(apidata);
	auto cfg_file = config_file_initd("remote_delivery.cfg", get_config_path(),
	                remote_delivery_cfg_defaults);
	if (cfg_file == nullptr) {
		mlog(LV_ERR, "remote_delivery: config_file_initd remote_delivery.cfg: %s",
			strerror(errno));
		return false;
	}
	g_mx_host = cfg_file->get_value("mx_host");
	g_mx_port = cfg_file->get_ll("mx_port");
	g_enable_tls = cfg_file->get_ll("starttls_support");
	if (rd_run() != 0) {
		mlog(LV_ERR, "remote_delivery: rd_run failed");
		return false;
	} else if (!register_remote(remote_delivery_hook)) {
		mlog(LV_ERR, "remote_delivery: register_remote failed");
		return false;
	}
	return TRUE;
}
HOOK_ENTRY(remote_delivery_entry);
