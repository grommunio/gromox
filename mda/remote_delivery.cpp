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
#include <libHX/string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <gromox/config_file.hpp>
#include <gromox/fileio.h>
#include <gromox/hook_common.h>
#include <gromox/mem_file.hpp>
#include <gromox/socket.h>
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
	void operator()(SSL *x) { SSL_free(x); }
	void operator()(SSL_CTX *x) { SSL_CTX_free(x); }
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

static int rd_starttls(rd_connection &&, MESSAGE_CONTEXT *, std::string &);

static constexpr unsigned int network_timeout = 180;
static std::unique_ptr<SSL_CTX, rd_delete> g_tls_ctx;
static std::unique_ptr<std::mutex[]> g_tls_mutex_buf;
static LIB_BUFFER g_files_allocator;
static std::string g_mx_host;
static uint16_t g_mx_port;
static bool g_enable_tls;
DECLARE_HOOK_API();

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
		printf("[remote_delivery]: failed TLS mutex setup\n");
		return -1;
	}
	CRYPTO_THREADID_set_callback(rd_ssl_id);
	CRYPTO_set_locking_callback(rd_ssl_locking);
#endif
	OpenSSL_add_all_algorithms();
	g_tls_ctx.reset(SSL_CTX_new(SSLv23_client_method()));
	if (g_tls_ctx == nullptr) {
		printf("[remote_delivery]: failed TLS setup\n");
		return -1;
	}
	return 0;
}

static void rd_log(const MESSAGE_CONTEXT *ctx, unsigned int level,
    const char *fmt, ...)
{
	std::string outbuf = "[remote_delivery]";
	auto ctrl = ctx->pcontrol;
	outbuf += " QID=" + std::to_string(ctrl->queue_ID) + " from=<"s +
	          ctrl->from + "> to=";

	char rcpt[UADDR_SIZE];
	bool second_rcpt = false;
	ctrl->f_rcpt_to.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (ctrl->f_rcpt_to.readline(rcpt, arsizeof(rcpt)) != MEM_END_OF_FILE) {
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
	fprintf(stderr, "[remote_delivery]: %s\n", outbuf.c_str());
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

static int rd_get_response(const rd_connection &conn,
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

static int rd_hello(const rd_connection &conn, MESSAGE_CONTEXT *ctx,
    std::string &response)
{
	char cmd[1024];
	auto len = gx_snprintf(cmd, arsizeof(cmd), "EHLO %s\r\n", get_host_ID());
	if (!rd_send_cmd(conn, cmd, len))
		return ETIMEDOUT;
	auto ret = rd_get_response(conn, response);
	if (ret == 0 || ret == ETIMEDOUT)
		return ret;
	/* retry with HELO */
	len = gx_snprintf(cmd, arsizeof(cmd), "HELO %s\r\n", get_host_ID());
	if (!rd_send_cmd(conn, cmd, len))
		return ETIMEDOUT;
	ret = rd_get_response(conn, response);
	if (ret == 0 || ret == ETIMEDOUT)
		return ret;
	response += " (after HELO)";
	return ret;
}

static int rd_mailfrom(rd_connection &conn, MESSAGE_CONTEXT *ctx,
    std::string &response)
{
	char cmd[UADDR_SIZE+24];
	auto len = strcmp(ctx->pcontrol->from, "none@none") == 0 ?
	           gx_snprintf(cmd, arsizeof(cmd), "MAIL FROM: <>\r\n") :
	           gx_snprintf(cmd, arsizeof(cmd), "MAIL FROM: <%s>\r\n", ctx->pcontrol->from);
	if (!rd_send_cmd(conn, cmd, len))
		return ETIMEDOUT;
	auto ret = rd_get_response(conn, response);
	if (ret == 0 || ret == ETIMEDOUT)
		return ret;
	response += " (after MAIL)";
	return ret;
}

static int rd_rcptto(rd_connection &conn, MESSAGE_CONTEXT *ctx,
    std::string &response)
{
	bool any_success = false;
	char rcpt[UADDR_SIZE];
	while (ctx->pcontrol->f_rcpt_to.readline(rcpt,
	       arsizeof(rcpt)) != MEM_END_OF_FILE) {
		char cmd[1024];
		auto len = gx_snprintf(cmd, arsizeof(cmd), "RCPT TO: <%s>\r\n", rcpt);
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

static int rd_data(rd_connection &&conn, MESSAGE_CONTEXT *ctx, std::string &response)
{
	if (!rd_send_cmd(conn, "DATA\r\n", 6))
		return ETIMEDOUT;
	auto ret = rd_get_response(conn, response, '3');
	if (ret == ETIMEDOUT)
		return ret;
	if (ret != 0)
		return ret;
	bool did_data = conn.tls != nullptr ? ctx->pmail->to_ssl(conn.tls.get()) :
	                ctx->pmail->to_file(conn.fd);
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
	fprintf(stderr, "[remote_delivery]: SMTP output to %s ok\n", g_mx_host.c_str());
	rd_send_cmd(conn, "QUIT\r\n", 6);
	return 0;
}

static int rd_session_begin(rd_connection &&conn, MESSAGE_CONTEXT *ctx,
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

static int rd_starttls(rd_connection &&conn, MESSAGE_CONTEXT *ctx,
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
		fprintf(stderr, "E-1553: Could not create local TLS context\n");
		return EHOSTUNREACH;
	}
	SSL_set_fd(conn.tls.get(), conn.fd);
	if (SSL_connect(conn.tls.get()) != 1) {
		fprintf(stderr, "W-1569: Could not TLS-connect to [%s]:%hu\n",
		        g_mx_host.c_str(), g_mx_port);
		return EHOSTUNREACH;
	}
	return rd_session_begin(std::move(conn), ctx, response);
}

static int rd_send_mail(MESSAGE_CONTEXT *ctx, std::string &response)
{
	ctx->pcontrol->f_rcpt_to.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	rd_connection conn;
	conn.fd = gx_inet_connect(g_mx_host.c_str(), g_mx_port, 0);
	if (conn.fd < 0) {
		rd_log(ctx, 8, "Could not connect to SMTP [%s]:%hu: %s",
			g_mx_host.c_str(), g_mx_port, strerror(-conn.fd));
		return EHOSTUNREACH;
	}
	auto ret = rd_get_response(conn, response);
	if (ret == 0)
		return rd_session_begin(std::move(conn), ctx, response);

	if (ret == ETIMEDOUT)
		return ret;
	rd_log(ctx, 8, "SMTP said answered \"%s\" after connection", response.c_str());
	/* change reason to connection refused */
	if (ret == 0 || 1)
		ret = ECONNREFUSED;
	rd_send_cmd(conn, "QUIT\r\n", 6);
	return ret;
}

static BOOL remote_delivery_hook(MESSAGE_CONTEXT *ctx)
{
	CONTROL_INFO l_ctrl = *ctx->pcontrol;
	MESSAGE_CONTEXT l_ctx;
	l_ctx.pcontrol = &l_ctrl;
	l_ctx.pmail    = ctx->pmail;

	std::string errstr;
	l_ctrl.f_rcpt_to.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	int ret;
	try {
		ret = rd_send_mail(ctx, errstr);
		if (ret == 0)
			return TRUE;
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1552: ENOMEM\n");
		return false;
	}

	char rcpt[UADDR_SIZE];
	fprintf(stderr, "[remote_delivery]: Local code: %s (ret=%d). "
	        "SMTP reason string: %s. Recipient(s) affected:\n",
	        strerror(ret), ret, errstr.c_str());
	l_ctrl.f_rcpt_to.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (l_ctrl.f_rcpt_to.readline(rcpt, arsizeof(rcpt)) != MEM_END_OF_FILE)
		fprintf(stderr, "[remote_delivery]:\t%s\n", rcpt);
	return TRUE;
}

static BOOL remote_delivery_entry(int request, void **apidata) try
{
	if (request == PLUGIN_FREE) {
		g_tls_ctx.reset();
		g_tls_mutex_buf.reset();
		return TRUE;
	}
	if (request != PLUGIN_INIT)
		return TRUE;

	LINK_HOOK_API(apidata);
	std::string plugname = get_plugin_name();
	auto pos = plugname.find('.');
	if (pos != plugname.npos)
		plugname.erase(pos);
	auto filename = plugname + ".cfg";
	auto cfg_file = config_file_initd(filename.c_str(), get_config_path());
	if (cfg_file == nullptr) {
		printf("[remote_delivery]: config_file_initd %s: %s\n",
		       filename.c_str(), strerror(errno));
		return false;
	}
	static constexpr cfg_directive remote_delivery_cfg_defaults[] = {
		{"mx_host", "::1"},
		{"mx_port", "25", 0, "1", "65535"},
		{"starttls_support", "on", CFG_BOOL},
		CFG_TABLE_END,
	};
	config_file_apply(*cfg_file, remote_delivery_cfg_defaults);
	g_files_allocator = LIB_BUFFER(FILE_ALLOC_SIZE, 256 * get_threads_num());
	g_mx_host = cfg_file->get_value("mx_host");
	g_mx_port = cfg_file->get_ll("mx_port");
	g_enable_tls = cfg_file->get_ll("starttls_support");
	if (rd_run() != 0) {
		printf("[remote_delivery]: rd_run failed\n");
		return false;
	} else if (!register_remote(remote_delivery_hook)) {
		printf("[remote_delivery]: register_remote failed\n");
		return false;
	}
	return TRUE;
} catch (const cfg_error &) {
	return false;
}
HOOK_ENTRY(remote_delivery_entry);
