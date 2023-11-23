// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2023 grommunio GmbH
// This file is part of Gromox.
/* http parser is a module, which first read data from socket, parses rpc over http and
   relay the stream to pdu processor. it also process other http request
 */ 
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <poll.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <fmt/core.h>
#ifdef HAVE_GSSAPI
#	include <gssapi/gssapi.h>
#endif
#include <sys/wait.h>
#include <libHX/io.h>
#include <libHX/misc.h>
#include <libHX/proc.h>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/clock.hpp>
#include <gromox/cryptoutil.hpp>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/fileio.h>
#include <gromox/hpm_common.h>
#include <gromox/http.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/scope.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "hpm_processor.h"
#include "http_parser.h"
#include "mod_cache.hpp"
#include "mod_fastcgi.h"
#include "mod_rewrite.h"
#include "pdu_ndr.h"
#include "resource.h"
#include "system_services.hpp"
#if (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2090000fL) || \
    (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x1010000fL)
#	define OLD_SSL 1
#endif
#define	MAX_RECLYING_REMAINING						0x4000000

#define OUT_CHANNEL_MAX_LENGTH						0x40000000
#define TOSEC(x) static_cast<long>(std::chrono::duration_cast<std::chrono::seconds>(x).count())

using namespace std::string_literals;
using namespace gromox;

namespace {
struct VIRTUAL_CONNECTION {
	VIRTUAL_CONNECTION() = default;
	~VIRTUAL_CONNECTION();
	NOMOVE(VIRTUAL_CONNECTION);

	std::atomic<int> reference{0};
	std::mutex lock;
	bool locked = false;
	std::unique_ptr<PDU_PROCESSOR> pprocessor;
	HTTP_CONTEXT *pcontext_in = nullptr, *pcontext_insucc = nullptr;
	HTTP_CONTEXT *pcontext_out = nullptr, *pcontext_outsucc = nullptr;
};
}

static constexpr time_duration OUT_CHANNEL_MAX_WAIT = std::chrono::seconds(10);
static std::unordered_map<std::string, VIRTUAL_CONNECTION> g_vconnection_hash;

namespace {
class VCONN_REF {
	public:
	VCONN_REF() = default;
	explicit VCONN_REF(VIRTUAL_CONNECTION *p, decltype(g_vconnection_hash)::iterator i) :
		pvconnection(p), m_hold(p->lock), m_iter(std::move(i)) {}
	~VCONN_REF() { put(); }
	NOMOVE(VCONN_REF);
	bool operator!=(std::nullptr_t) const { return pvconnection != nullptr; }
	bool operator==(std::nullptr_t) const { return pvconnection == nullptr; }
	void put();
	VIRTUAL_CONNECTION *operator->() { return pvconnection; }

	private:
	VIRTUAL_CONNECTION *pvconnection = nullptr;
	std::unique_lock<std::mutex> m_hold;
	decltype(g_vconnection_hash)::iterator m_iter;
};
}

alloc_limiter<stream_block> g_blocks_allocator{"g_blocks_allocator.d"};
static size_t g_context_num;
static gromox::atomic_bool g_async_stop;
static bool g_support_tls;
static SSL_CTX *g_ssl_ctx;
static int g_max_auth_times;
static int g_block_auth_fail;
static time_duration g_timeout;
unsigned int g_http_debug;
size_t g_rqbody_flush_size, g_rqbody_max_size;
bool g_http_php, g_enforce_auth;
static thread_local HTTP_CONTEXT *g_context_key;
static alloc_limiter<RPC_IN_CHANNEL> g_inchannel_allocator{"g_inchannel_allocator.d"};
static alloc_limiter<RPC_OUT_CHANNEL> g_outchannel_allocator{"g_outchannel_allocator.d"};
static std::unique_ptr<HTTP_CONTEXT[]> g_context_list;
static std::vector<SCHEDULE_CONTEXT *> g_context_list2;
static char g_certificate_path[256];
static char g_private_key_path[256];
static char g_certificate_passwd[1024];
static std::unique_ptr<std::mutex[]> g_ssl_mutex_buf;
static std::mutex g_vconnection_lock;

static void http_parser_context_clear(HTTP_CONTEXT *pcontext);

static void httpctx_report(const HTTP_CONTEXT &ctx, size_t i)
{
	auto &cn = ctx.connection;
	if (cn.sockd < 0)
		return;
	mlog(LV_INFO, "%-3zu  %-2d  [%s]:%hu->[%s]:%hu", i, cn.sockd,
	        cn.client_ip, cn.client_port, cn.server_ip, cn.server_port);
	const char *chtyp = "NONE";
	switch (ctx.channel_type) {
	case hchannel_type::none: chtyp = "NONE"; break;
	case hchannel_type::in:   chtyp = "IN";   break;
	case hchannel_type::out:  chtyp = "OUT";  break;
	default:                  chtyp = "?";    break;
	}
	mlog(LV_INFO, "   %4s  [%s]:%hu  %s",
		chtyp, ctx.host, ctx.port, ctx.username);
}

void http_report()
{
	/* There is no lock surrounding these structures, and they can be in an undefined state */
	mlog(LV_INFO, "HTTP Contexts:");
	mlog(LV_INFO, "Ctx  fd  src->host");
	mlog(LV_INFO, "   ChTy  RPCEndpoint, Username");
	mlog(LV_INFO, "-------------------------------------------------------------------------------");
	for (size_t i = 0; i < g_context_num; ++i)
		httpctx_report(g_context_list[i], i);
}

void http_parser_init(size_t context_num, time_duration timeout,
	int max_auth_times, int block_auth_fail, bool support_tls,
	const char *certificate_path, const char *cb_passwd,
	const char *key_path)
{
    g_context_num           = context_num;
    g_timeout               = timeout;
	g_max_auth_times        = max_auth_times;
	g_block_auth_fail       = block_auth_fail;
	g_support_tls = support_tls;
	g_async_stop = false;
	
	if (!support_tls)
		return;
	gx_strlcpy(g_certificate_path, certificate_path, std::size(g_certificate_path));
	if (cb_passwd != nullptr)
		gx_strlcpy(g_certificate_passwd, cb_passwd, std::size(g_certificate_passwd));
	else
		g_certificate_passwd[0] = '\0';
	gx_strlcpy(g_private_key_path, key_path, std::size(g_private_key_path));
}

#ifdef OLD_SSL
static void http_parser_ssl_locking(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		g_ssl_mutex_buf[n].lock();
	else
		g_ssl_mutex_buf[n].unlock();
}

static void http_parser_ssl_id(CRYPTO_THREADID* id)
{
	CRYPTO_THREADID_set_numeric(id, static_cast<uintptr_t>(pthread_self()));
}
#endif

VIRTUAL_CONNECTION::~VIRTUAL_CONNECTION()
{
	if (pprocessor != nullptr)
		pdu_processor_destroy(std::move(pprocessor));
}

/* 
 *    @return
 *         0    success
 *        <>0    fail    
 */
int http_parser_run()
{
	if (g_support_tls) {
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();
		g_ssl_ctx = SSL_CTX_new(SSLv23_server_method());
		if (NULL == g_ssl_ctx) {
			mlog(LV_ERR, "http_parser: failed to init TLS context");
			return -1;
		}
		if (*g_certificate_passwd != '\0')
			SSL_CTX_set_default_passwd_cb_userdata(
				g_ssl_ctx, g_certificate_passwd);
		if (SSL_CTX_use_certificate_chain_file(
			g_ssl_ctx, g_certificate_path) <= 0) {
			printf("[http_parser]: fail to use certificate file:");
			ERR_print_errors_fp(stdout);
			return -2;
		}
		if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx,
			g_private_key_path, SSL_FILETYPE_PEM) <= 0) {
			printf("[http_parser]: fail to use private key file:");
			ERR_print_errors_fp(stdout);
			return -3;
		}
		if (1 != SSL_CTX_check_private_key(g_ssl_ctx)) {
			printf("[http_parser]: private key does not match certificate:");
			ERR_print_errors_fp(stdout);
			return -4;
		}
		auto mp = g_config_file->get_value("tls_min_proto");
		if (mp != nullptr && tls_set_min_proto(g_ssl_ctx, mp) != 0) {
			mlog(LV_ERR, "http_parser: tls_min_proto value \"%s\" rejected", mp);
			return -4;
		}
		tls_set_renego(g_ssl_ctx);
		try {
			g_ssl_mutex_buf = std::make_unique<std::mutex[]>(CRYPTO_num_locks());
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "http_parser: failed to allocate TLS locking buffer");
			return -5;
		}
#ifdef OLD_SSL
		CRYPTO_THREADID_set_callback(http_parser_ssl_id);
		CRYPTO_set_locking_callback(http_parser_ssl_locking);
#endif
	}
	try {
		g_context_list = std::make_unique<HTTP_CONTEXT[]>(g_context_num);
		g_context_list2.resize(g_context_num);
		for (size_t i = 0; i < g_context_num; ++i) {
			g_context_list[i].context_id = i;
			g_context_list2[i] = &g_context_list[i];
		}
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "http_parser: failed to allocate HTTP contexts");
        return -8;
    }
	g_inchannel_allocator = alloc_limiter<RPC_IN_CHANNEL>(g_context_num,
	                        "http_inchannel_allocator",
	                        "http.cfg:context_num");
	g_outchannel_allocator = alloc_limiter<RPC_OUT_CHANNEL>(g_context_num,
	                         "http_outchannel_allocator",
	                         "http.cfg:context_num");
    return 0;
}

void http_parser_stop()
{
	g_context_list2.clear();
	g_context_list.reset();
	g_vconnection_hash.clear();
	if (g_support_tls && g_ssl_ctx != nullptr) {
		SSL_CTX_free(g_ssl_ctx);
		g_ssl_ctx = NULL;
	}
	if (g_support_tls && g_ssl_mutex_buf != nullptr) {
		CRYPTO_set_id_callback(NULL);
		CRYPTO_set_locking_callback(NULL);
		g_ssl_mutex_buf.reset();
	}
}

int http_parser_threads_event_proc(int action)
{
	return 0;
}

int http_parser_get_context_socket(const schedule_context *ctx)
{
	return static_cast<const http_context *>(ctx)->connection.sockd;
}

time_point http_parser_get_context_timestamp(const schedule_context *ctx)
{
	return static_cast<const http_context *>(ctx)->connection.last_timestamp;
}

static VCONN_REF http_parser_get_vconnection(const char *host,
    int port, const char *conn_cookie)
{
	char tmp_buff[384];
	VIRTUAL_CONNECTION *pvconnection = nullptr;
	
	snprintf(tmp_buff, std::size(tmp_buff), "%s:%d:%s", conn_cookie, port, host);
	HX_strlower(tmp_buff);
	std::unique_lock vhold(g_vconnection_lock);
	auto it = g_vconnection_hash.find(tmp_buff);
	if (it != g_vconnection_hash.end())
		pvconnection = &it->second;
	if (pvconnection != nullptr)
		pvconnection->reference ++;
	vhold.unlock();
	if (pvconnection == nullptr)
		return {};
	return VCONN_REF(pvconnection, it);
}

void VCONN_REF::put()
{
	if (pvconnection == nullptr)
		return;
	m_hold.unlock();
	std::unique_lock vc_hold(g_vconnection_lock);
	pvconnection->reference --;
	if (0 == pvconnection->reference &&
		NULL == pvconnection->pcontext_in &&
		NULL == pvconnection->pcontext_out) {
		auto nd = g_vconnection_hash.extract(m_iter);
		vc_hold.unlock();
		/* end locked region before running ~nd (~VCONN_REF, pdu_processor_destroy) */
	}
	pvconnection = nullptr;
}

static char *
http_parser_request_head(http_request::other_map &m, const char *k)
{
	auto i = m.find(k);
	return i != m.end() ? i->second.data() : nullptr;
}

/**
 * Trim data to the left of the current stream position. Semantically like {
 * memmove(&data[0], &data[current_pos], total_size - current_pos);
 * total_size -= current_pos; current_pos = 0; }
 */
static int http_parser_reconstruct_stream(STREAM &stream_src)
{
	int size1;
	int size1_used;
	STREAM stream_dst(&g_blocks_allocator);
	auto pstream_src = &stream_src, pstream_dst = &stream_dst;
	int size = STREAM_BLOCK_SIZE;
	auto pbuff = pstream_src->get_read_buf(reinterpret_cast<unsigned int *>(&size));
	if (NULL == pbuff) {
		stream_src = std::move(stream_dst);
		return 0;
	}
	size1 = STREAM_BLOCK_SIZE;
	auto pbuff1 = pstream_dst->get_write_buf(reinterpret_cast<unsigned int *>(&size1));
	/*
	 * do not need to check the pbuff pointer because it will
	 * never be NULL because of stream's characteristic
	 */
	size1_used = 0;
	do {
		if (size <= size1 - size1_used) {
			memcpy(pbuff1, pbuff, size);
			size1_used += size;
		} else {
			auto size_copied = size1 - size1_used;
			memcpy(static_cast<char *>(pbuff1) + size1_used, pbuff, size_copied);
			size1 = STREAM_BLOCK_SIZE;
			pstream_dst->fwd_write_ptr(STREAM_BLOCK_SIZE);
			pbuff1 = pstream_dst->get_write_buf(reinterpret_cast<unsigned int *>(&size1));
			if (pbuff1 == nullptr)
				return -1;
			size1_used = size - size_copied;
			memcpy(pbuff1, static_cast<char *>(pbuff) + size_copied, size1_used);
		}
		size = STREAM_BLOCK_SIZE;
		pbuff = pstream_src->get_read_buf(reinterpret_cast<unsigned int *>(&size));
	} while (NULL != pbuff);
	pstream_dst->fwd_write_ptr(size1_used);
	auto tl = pstream_dst->get_total_length();
	stream_src = std::move(stream_dst);
	return tl;
}

static const char *status_text(http_status s)
{
	switch (s) {
	case http_status::not_modified: return "Not Modified";
	case http_status::bad_request: return "Bad Request";
	case http_status::unauthorized: return "Unauthorized";
	case http_status::forbidden: return "Forbidden";
	case http_status::not_found: return "Not Found";
	case http_status::method_not_allowed: return "Method Not Allowed";
	case http_status::timeout: return "Request Timeout";
	case http_status::uri_too_long: return "URI Too Long";
	case http_status::range_insatisfiable: return "Range Not Satisfiable";
	case http_status::too_many_ranges: return "Too Many Ranges";
	case http_status::not_impl: return "Not Implemented";
	case http_status::bad_gateway: return "Bad FCGI Gateway";
	case http_status::service_unavailable: return "Service Unavailable";
	case http_status::resources_exhausted: return "Resources Exhausted";
	case http_status::gateway_timeout: return "Gateway Timeout";
	default: return "Server Error";
	}
}

std::string http_make_err_response(const http_context &ctx, http_status code)
{
	auto msg = status_text(code);
	if (static_cast<int>(code) >= 1000)
		code = static_cast<http_status>(static_cast<int>(code) / 10);
	char dstring[128];
	rfc1123_dstring(dstring, std::size(dstring));
	auto rsp = fmt::format(
		"HTTP/1.1 {} {}\r\n"
		"Date: {}\r\n"
		"Content-Length: {}\r\n"
	        "Content-Type: text/plain; charset=utf-8\r\n"
		"Connection: {}\r\n",
		static_cast<int>(code), msg, dstring, strlen(msg) + 2,
		ctx.b_close ? "close" : "keep-alive");
	if (!ctx.b_close)
		rsp += fmt::format("Keep-Alive: timeout={}\r\n", TOSEC(g_timeout));
	if (code == http_status::unauthorized) {
		rsp += "WWW-Authenticate: Basic realm=\"msrpc realm\", charset=\"utf-8\"\r\n";
		if (g_config_file->get_ll("http_auth_spnego")) {
			if (ctx.auth_method == auth_method::negotiate_b64 && !ctx.last_gss_output.empty())
				rsp += "WWW-Authenticate: Negotiate " + ctx.last_gss_output + "\r\n";
			else if (ctx.auth_method == auth_method::negotiate && !ctx.last_gss_output.empty())
				rsp += "WWW-Authenticate: Negotiate " +
				       base64_encode(ctx.last_gss_output) + "\r\n";
			else
				rsp += "WWW-Authenticate: Negotiate\r\n";
		}
	}
	rsp += "\r\n";
	rsp += msg;
	rsp += "\r\n";
	return rsp;
}

static tproc_status http_done(http_context *ctx, http_status code) try
{
	ctx->b_close = TRUE; /* rdbody not consumed yet */
	if (static_cast<int>(code) < 0)
		code = static_cast<http_status>(-static_cast<int>(code));
	if (hpm_processor_is_in_charge(ctx))
		hpm_processor_put_context(ctx);
	else if (mod_fastcgi_is_in_charge(ctx))
		mod_fastcgi_put_context(ctx);
	else if (mod_cache_is_in_charge(ctx))
		mod_cache_put_context(ctx);
	auto rsp = http_make_err_response(*ctx, code);
	ctx->stream_out.clear();
	ctx->stream_out.write(rsp.c_str(), rsp.size());
	ctx->total_length = rsp.size();
	ctx->bytes_rw = 0;
	ctx->sched_stat = hsched_stat::wrrep;
	return tproc_status::loop;
} catch (const std::bad_alloc &) {
	ctx->b_close = TRUE;
	ctx->total_length = 0;
	ctx->bytes_rw = 0;
	ctx->sched_stat = hsched_stat::wrrep;
	return tproc_status::loop;
}

static tproc_status http_end(http_context *ctx)
{
	if (hpm_processor_is_in_charge(ctx))
		hpm_processor_put_context(ctx);
	else if (mod_fastcgi_is_in_charge(ctx))
		mod_fastcgi_put_context(ctx);
	else if (mod_cache_is_in_charge(ctx))
		mod_cache_put_context(ctx);

	if (ctx->pchannel != nullptr) {
		if (ctx->channel_type == hchannel_type::in) {
			auto chan = static_cast<RPC_IN_CHANNEL *>(ctx->pchannel);
			auto conn = http_parser_get_vconnection(ctx->host,
			            ctx->port, chan->connection_cookie);
			if (conn != nullptr) {
				if (conn->pcontext_in == ctx)
					conn->pcontext_in = nullptr;
				conn.put();
			}
			g_inchannel_allocator->put(chan);
		} else {
			auto chan = static_cast<RPC_OUT_CHANNEL *>(ctx->pchannel);
			auto conn = http_parser_get_vconnection(ctx->host,
			            ctx->port, chan->connection_cookie);
			if (conn != nullptr) {
				if (conn->pcontext_out == ctx)
					conn->pcontext_out = nullptr;
				conn.put();
			}
			g_outchannel_allocator->put(chan);
		}
		ctx->pchannel = nullptr;
	}

	ctx->connection.reset();
	http_parser_context_clear(ctx);
	return tproc_status::close;
}

/**
 * Returns
 * %cont:		context need continue to be processed
 * %idle:		empty loop
 * %polling_rdonly:	put the socket into epoll queue
 * %polling_wronly:	put the socket into epoll queue
 * %sleeping:		need to sleep the context
 * %close:		need to cose the context
 */
static tproc_status htparse_initssl(http_context *pcontext)
{
	if (NULL == pcontext->connection.ssl) {
		pcontext->connection.ssl = SSL_new(g_ssl_ctx);
		if (NULL == pcontext->connection.ssl) {
			mlog(LV_ERR, "E-1185: ENOMEM");
			return http_done(pcontext, http_status::enomem_CL);
		}
		SSL_set_fd(pcontext->connection.ssl, pcontext->connection.sockd);
	}
	if (SSL_accept(pcontext->connection.ssl) >= 0) {
		pcontext->sched_stat = hsched_stat::rdhead;
		return tproc_status::cont;
	}
	auto ssl_errno = SSL_get_error(pcontext->connection.ssl, -1);
	if (ssl_errno != SSL_ERROR_WANT_READ && ssl_errno != SSL_ERROR_WANT_WRITE) {
		unsigned long e;
		char buf[256];
		while ((e = ERR_get_error()) != 0) {
			ERR_error_string_n(e, buf, std::size(buf));
			mlog(LV_DEBUG, "SSL_accept [%s]: %s", pcontext->connection.client_ip, buf);
		}
		return tproc_status::runoff;
	}
	auto current_time = tp_now();
	if (current_time - pcontext->connection.last_timestamp < g_timeout)
		return tproc_status::polling_rdonly;
	pcontext->log(LV_DEBUG, "I-1920: timeout");
	return http_done(pcontext, http_status::timeout);
}

static enum http_method http_method_lookup(const char *s)
{
	/* Ordered by approximate use count */
#define E(k, v) if (strcasecmp(s, #k) == 0) return http_method::v;
	E(GET, get)
	E(POST, post)
	E(HEAD, head)
	E(RPC_IN_DATA, rpcin)
	E(RPC_OUT_DATA, rpcout)
	E(OPTIONS, options)
	E(PUT, put)
	E(DELETE, xdelete)
	E(PATCH, patch)
	return *s != '\0' ? http_method::other : http_method::none;
#undef E
}

static tproc_status htparse_rdhead_no(http_context *pcontext, char *line,
    unsigned int line_length)
{
	auto &ctx = *pcontext;
	auto ptoken = static_cast<char *>(memchr(line, ' ', line_length));
	if (NULL == ptoken) {
		pcontext->log(LV_DEBUG, "D-1921: request line missing a URI");
		return http_done(pcontext, http_status::bad_request_CL);
	}
	size_t tmp_len = ptoken - line;
	if (tmp_len >= std::size(pcontext->request.method)) {
		pcontext->log(LV_DEBUG, "I-1922: request method error");
		return http_done(pcontext, http_status::bad_request_CL);
	}

	memcpy(pcontext->request.method, line, tmp_len);
	pcontext->request.method[tmp_len] = '\0';
	pcontext->request.imethod = http_method_lookup(pcontext->request.method);
	auto ptoken1 = static_cast<char *>(memchr(ptoken + 1, ' ', line_length - tmp_len - 1));
	if (NULL == ptoken1) {
		pcontext->log(LV_DEBUG, "D-1923: request line without HTTP version");
		return http_done(pcontext, http_status::bad_request_CL);
	}
	size_t tmp_len1 = ptoken1 - ptoken - 1;
	tmp_len = line_length - (ptoken1 + 6 - line);
	if (strncasecmp(&ptoken1[1], "HTTP/1.1", 8) == 0 &&
	    (ptoken1[9] == '\r' || ptoken1[9] == '\n' || ptoken1[9] == '\0')) {
		pcontext->b_close = false;
	} else if (strncasecmp(&ptoken1[1], "HTTP/1.0", 8) == 0 &&
	    (ptoken1[9] == '\r' || ptoken1[9] == '\n' || ptoken1[9] == '\0')) {
		pcontext->b_close = TRUE;
	} else {
		pcontext->log(LV_DEBUG, "I-1924: unrecognized HTTP protocol %.*s",
			static_cast<int>(tmp_len), &ptoken1[1]);
		return http_done(pcontext, http_status::bad_request_CL);
	}
	if (tmp_len1 == 0)
		return http_done(pcontext, http_status::bad_request_CL);
	if (tmp_len1 >= http_request::uri_limit)
		return http_done(pcontext, http_status::uri_too_long_CL);
	if (!mod_rewrite_process(ptoken + 1,
	    tmp_len1, pcontext->request.f_request_uri)) {
		pcontext->request.f_request_uri = std::string_view(&ptoken[1], tmp_len1);
	} else if (ctx.request.f_request_uri.size() == 0) {
		ctx.log(LV_ERR, "mod_rewrite left a zero-length URI");
		return http_done(pcontext, http_status::bad_request_CL);
		/*
		 * Since mod_rewrite_process uses a uri_limit-long buffer, size
		 * won't be exceeded anymore.
		 */
	}
	memcpy(pcontext->request.version, ptoken1 + 6, tmp_len);
	pcontext->request.version[tmp_len] = '\0';
	return tproc_status::runoff;
}

static tproc_status htparse_rdhead_mt(http_context *pcontext, char *line,
    unsigned int line_length) try
{
	auto &ctx = *pcontext;
	auto ptoken = static_cast<char *>(memchr(line, ':', line_length));
	if (NULL == ptoken) {
		pcontext->log(LV_DEBUG, "D-1925: request header has no colon");
		return http_done(pcontext, http_status::bad_request_CL);
	}

	size_t tmp_len = ptoken - line;
	char field_name[64];
	memcpy(field_name, line, tmp_len);
	field_name[tmp_len] = '\0';
	HX_strrtrim(field_name);
	HX_strltrim(field_name);

	ptoken++;
	while (static_cast<size_t>(ptoken - line) < line_length) {
		if (*ptoken != ' ' && *ptoken != '\t')
			break;
		ptoken++;
	}
	tmp_len = line_length - static_cast<size_t>(ptoken - line);
	if (0 == strcasecmp(field_name, "Host")) {
		char input[264]{}; /* [255long.name]:12345 */
		if (tmp_len >= sizeof(input)) {
			ctx.log(LV_DEBUG, "Host field of HTTP request too long");
			return http_done(pcontext, http_status::bad_request_CL);
		}
		strncpy(input, ptoken, tmp_len);
		char domain[256];
		*domain = '\0';
		if (HX_addrport_split(input, domain, std::size(domain), nullptr) > 0)
			ctx.request.f_host = domain;
	} else if (0 == strcasecmp(field_name, "User-Agent")) {
		pcontext->request.f_user_agent = std::string_view(ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name, "Accept")) {
		pcontext->request.f_accept = std::string_view(ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Accept-Language")) {
		pcontext->request.f_accept_language = std::string_view(ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Accept-Encoding")) {
		pcontext->request.f_accept_encoding = std::string_view(ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Content-Type")) {
		pcontext->request.f_content_type = std::string_view(ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Content-Length")) {
		if (tmp_len >= 32) {
			ctx.log(LV_DEBUG, "Content-Length too long");
			return http_done(&ctx, http_status::bad_request_CL);
		}
		std::string s(ptoken, tmp_len);
		char *end = nullptr;
		ctx.request.content_len = strtoull(s.c_str(), &end, 10);
		if (end == nullptr || *end != '\0')
			return http_done(pcontext, http_status::bad_request_CL);
	} else if (0 == strcasecmp(field_name,
		"Transfer-Encoding")) {
		std::string s(ptoken, tmp_len);
		ctx.request.b_chunked = strcasecmp(s.c_str(), "chunked") == 0;
	} else if (0 == strcasecmp(field_name, "Cookie")) {
		auto &j = pcontext->request.f_cookie;
		if (!j.empty())
			j += ", ";
		j.append(ptoken, tmp_len);
	} else {
		if (strcasecmp(field_name, "Connection") == 0 &&
		    strncasecmp(ptoken, "keep-alive", tmp_len) == 0)
			/* for "Connection: Upgrade",
				we treat it as "close" */
			pcontext->b_close = FALSE;
		if (strcasecmp(field_name, "Connection") == 0 &&
		    strncasecmp(ptoken, "close", tmp_len) == 0)
			pcontext->b_close = TRUE;
		pcontext->request.f_others[field_name] = std::string_view(ptoken, tmp_len);
	}
	return tproc_status::runoff;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1085: ENOMEM");
	return http_done(pcontext, http_status::enomem_CL);
}

static tproc_status htp_auth_basic(http_context *pcontext) try
{
	pcontext->auth_method = auth_method::basic;
	if (system_services_judge_user != nullptr &&
	    !system_services_judge_user(pcontext->username)) {
		pcontext->log(LV_DEBUG,
			"user %s is denied by user filter",
			pcontext->username);
		pcontext->auth_status = http_status::service_unavailable;
		return tproc_status::runoff;
	}

	sql_meta_result mres;
	if (system_services_auth_login(pcontext->username, pcontext->password,
	    USER_PRIVILEGE_EXCH, mres)) {
		/* Success */
		gx_strlcpy(pcontext->username, mres.username.c_str(), std::size(pcontext->username));
		gx_strlcpy(pcontext->maildir, mres.maildir.c_str(), std::size(pcontext->maildir));
		gx_strlcpy(pcontext->lang, mres.lang.c_str(), std::size(pcontext->lang));
		if ('\0' == pcontext->maildir[0]) {
			pcontext->log(LV_ERR, "maildir for \"%s\" absent: %s",
				pcontext->username, mres.errstr.c_str());
			pcontext->auth_status = http_status::service_unavailable;
			return tproc_status::runoff;
		}

		if (*pcontext->lang == '\0')
			gx_strlcpy(pcontext->lang, znul(g_config_file->get_value("user_default_lang")), sizeof(pcontext->lang));
		pcontext->auth_status = http_status::ok;
		pcontext->log(LV_DEBUG, "htp_auth success");
		return tproc_status::runoff;
	}

	pcontext->auth_status = http_status::unauthorized;
	pcontext->log(LV_ERR, "login failed: \"%s\": %s",
		pcontext->username, mres.errstr.c_str());
	pcontext->auth_times ++;
	if (system_services_add_user_into_temp_list != nullptr &&
	    pcontext->auth_times >= g_max_auth_times)
		system_services_add_user_into_temp_list(
			pcontext->username, g_block_auth_fail);
	return tproc_status::runoff;
} catch (const std::bad_alloc &) {
	pcontext->b_close = TRUE;
	pcontext->total_length = 0;
	pcontext->bytes_rw = 0;
	pcontext->sched_stat = hsched_stat::wrrep;
	return tproc_status::loop;
}

static void ntlm_stop(struct HXproc &pi)
{
	if (pi.p_pid <= 0)
		return;
	if (pi.p_stdin >= 0)
		close(pi.p_stdin);
	if (pi.p_stdout >= 0)
		close(pi.p_stdout);
	if (pi.p_stderr >= 0)
		close(pi.p_stderr);
	mlog(LV_DEBUG, "NTLM(%ld) terminating the ntlm_auth worker", static_cast<long>(pi.p_pid));
	kill(pi.p_pid, SIGKILL);
	waitpid(pi.p_pid, nullptr, 0);
	pi.p_pid = 0;
}

static int htp_auth_finalize(http_context &ctx, const char *user)
{
	sql_meta_result mres;
	auto err = system_services_auth_meta(user, 0, mres);
	if (err != 0) {
		mlog(LV_DEBUG, "ntlm/krb auth success on \"%s\", but not found in Gromox", user);
		return 0;
	}
	gx_strlcpy(ctx.username, mres.username.c_str(), std::size(ctx.username));
	*ctx.password = '\0';
	gx_strlcpy(ctx.maildir, mres.maildir.c_str(), std::size(ctx.maildir));
	if (*ctx.maildir == '\0') {
		ctx.log(LV_ERR, "maildir for \"%s\" absent: %s",
			ctx.username, mres.errstr.c_str());
		return -1;
	}
	gx_strlcpy(ctx.lang, mres.lang.c_str(), std::size(ctx.lang));
	if (*ctx.lang == '\0')
		gx_strlcpy(ctx.lang, znul(g_config_file->get_value("user_default_lang")), sizeof(ctx.lang));
	return 1;
}

static int htp_auth_ntlmssp(http_context &ctx, const char *prog,
    const char *encinput, std::string &output)
{
	auto encsize = strlen(encinput);
	auto &pinfo = ctx.ntlm_proc;
	output.clear();

	if (pinfo.p_pid <= 0) {
		if (prog == nullptr || *prog == '\0')
			prog = "/usr/bin/ntlm_auth --helper-protocol=squid-2.5-ntlmssp";
		auto args = HX_split(prog, " ", nullptr, 0);
		auto cl_0 = make_scope_exit([&]() { HX_zvecfree(args); });
		pinfo.p_flags = HXPROC_STDIN | HXPROC_STDOUT | HXPROC_STDERR;
		auto ret = HXproc_run_async(&args[0], &pinfo);
		if (ret < 0) {
			mlog(LV_ERR, "execv ntlm_auth: %s", strerror(-ret));
			return -1;
		}
		mlog(LV_DEBUG, "ntlm_auth is pid %d", pinfo.p_pid);
		if (HXio_fullwrite(pinfo.p_stdin, "YR ", 3) < 0) {
			mlog(LV_ERR, "write ntlm_auth: %s", strerror(errno));
			return -1;
		}
		mlog(LV_DEBUG, "NTLM> YR %s", encinput);
	} else {
		if (HXio_fullwrite(pinfo.p_stdin, "KK ", 3) < 0) {
			mlog(LV_ERR, "write ntlm_auth: %s", strerror(errno));
			return -1;
		}
		mlog(LV_DEBUG, "NTLM> KK %s", encinput);
	}
	if (HXio_fullwrite(pinfo.p_stdin, encinput, encsize) < 0 ||
	    HXio_fullwrite(pinfo.p_stdin, "\n", 1) < 0) {
		mlog(LV_ERR, "write ntlm_auth: %s", strerror(errno));
		return -1;
	}

	struct pollfd pfd[] = {{pinfo.p_stdout, POLLIN}, {pinfo.p_stderr, POLLIN}};
 retry:
	auto ret = poll(pfd, std::size(pfd), 10 * 1000);
	if (ret < 0) {
		if (errno == EINTR)
			goto retry;
		mlog(LV_INFO, "ntlm_auth poll: %s", strerror(errno));
		return -1;
	} else if (ret == 0) {
		mlog(LV_INFO, "ntlm_auth poll timeout");
		return -1;
	}

	output.clear();
	output.resize(8192);
	if (pfd[1].revents & POLLIN) {
		/* Drain stderr first */
		auto bytes = read(pinfo.p_stderr, output.data(), output.size());
		if (bytes > 0) {
			output[bytes] = '\0';
			HX_chomp(output.data());
			output.resize(strlen(output.c_str()));
			mlog(LV_DEBUG, "ntlm_auth(stderr):%c%s",
				output.find('\n') != output.npos ? '\n' : ' ',
				output.c_str());
			goto retry;
		}
	}
	auto bytes = read(pinfo.p_stdout, output.data(), output.size());
	if (bytes < 0) {
		mlog(LV_ERR, "ntlm_auth(stdout) error: %s", strerror(errno));
		return -1;
	} else if (bytes == 0) {
		mlog(LV_ERR, "ntlm_auth(stdout) EOF");
		return -1;
	}
	output[bytes] = '\0';
	HX_chomp(output.data());
	output.resize(strlen(output.c_str()));
	mlog(LV_DEBUG, "NTLM(%d)< %s", static_cast<int>(pinfo.p_pid), output.c_str());

	if (output[0] == 'T' && output[1] == 'T') { // TT
		output.erase(0, 3);
		return -99; /* MOAR */
	}
	output.clear();
	if (output[0] == 'A' && output[1] == 'F') // AF
		/*
		 * The AF response contains the winbind (Unix-side) username.
		 * Depending on smb.conf "winbind use default domain", this can
		 * be just "user5", or it can be "DOMAIN\user5". Either way, an
		 * altnames entry is needed for this.
		 */
		return htp_auth_finalize(ctx, output.c_str());
	else if (output[0] == 'N' && output[1] == 'A')
		return 0;
	return -1;
}

#ifdef HAVE_GSSAPI
const char gss_display_status_fail_message[] = "Call to gss_display_status failed. Reason: ";

static void krblog2(const char *msg, OM_uint32 code, OM_uint32 type)
{
	gss_buffer_desc gss_msg = GSS_C_EMPTY_BUFFER;
	OM_uint32 status = 0, context = 0;
	do {
		auto result = gss_display_status(&status, code, type,
		              GSS_C_NULL_OID, &context, &gss_msg);
		if (result == GSS_S_COMPLETE)
			mlog(LV_WARN, "E-9996: %s: %s", msg, static_cast<const char *>(gss_msg.value));
		else if (result == GSS_S_BAD_MECH)
			mlog(LV_WARN, "E-9995: %s: %s", gss_display_status_fail_message,
				"unsupported mechanism type was requested.");
		else if (result == GSS_S_BAD_STATUS)
			mlog(LV_WARN, "E-9994: %s: %s", gss_display_status_fail_message,
				"status value was not recognized, or the status type was neither GSS_C_GSS_CODE nor GSS_C_MECH_CODE.");
		gss_release_buffer(&status, &gss_msg);
	} while (context != 0);
}

static void krblog(const char* msg, OM_uint32 major, OM_uint32 minor)
{
	krblog2(msg, major, GSS_C_GSS_CODE);
	krblog2(msg, minor, GSS_C_MECH_CODE);
}

/**
 * returns negative for complete failure, returns 0 for auth-unsuccesful, 1 for
 * auth-success, 99 for GSS continue.
 */
static int auth_krb(http_context &ctx, const char *input, size_t isize,
    std::string &output)
{
	OM_uint32 status{};
	gss_name_t gss_srv_name{}, gss_username{};
	gss_buffer_desc gss_input_buf{}, gss_user_buf{}, gss_output_token{};
	auto cl_0 = make_scope_exit([&]() {
		if (gss_output_token.length != 0)
			gss_release_buffer(&status, &gss_output_token);
		if (gss_user_buf.length != 0)
			gss_release_buffer(&status, &gss_user_buf);
		if (gss_username != GSS_C_NO_NAME)
			gss_release_name(&status, &gss_username);
		if (gss_srv_name != GSS_C_NO_NAME)
			gss_release_name(&status, &gss_srv_name);
	});

	if (ctx.m_gss_srv_creds == GSS_C_NO_CREDENTIAL) {
		ctx.m_gss_ctx = GSS_C_NO_CONTEXT;
		auto p = g_config_file->get_value("http_krb_service_principal");
		std::string principal;
		if (p != nullptr && *p != '\0')
			principal = p;
		else
			principal = "gromox@"s + p;
		mlog(LV_DEBUG, "krb service principal = \"%s\"", principal.c_str());
		gss_input_buf.value  = principal.data();
		gss_input_buf.length = principal.length() + 1;
		auto ret = gss_import_name(&status, &gss_input_buf,
		           GSS_C_NT_HOSTBASED_SERVICE, &gss_srv_name);
		if (ret != GSS_S_COMPLETE) {
			krblog("Unable to import server name", ret, status);
			return 0;
		}
		ret = gss_acquire_cred(&status, gss_srv_name, GSS_C_INDEFINITE,
		      GSS_C_NO_OID_SET, GSS_C_ACCEPT, &ctx.m_gss_srv_creds,
		      nullptr, nullptr);
		if (ret != GSS_S_COMPLETE) {
			krblog("Unable to acquire credentials handle", ret, status);
			return 0;
		}
	}

	gss_input_buf.value  = deconst(input);
	gss_input_buf.length = isize;
	auto ret = gss_accept_sec_context(&status, &ctx.m_gss_ctx,
	           ctx.m_gss_srv_creds, &gss_input_buf, GSS_C_NO_CHANNEL_BINDINGS,
	           &gss_username, nullptr, &gss_output_token, nullptr, nullptr, nullptr);
	if (gss_output_token.length != 0)
		output.assign(static_cast<const char *>(gss_output_token.value), gss_output_token.length);
	else
		output.clear();

	if (ret == GSS_S_CONTINUE_NEEDED)
		return -99; /* MOAR */
	output.clear();
	if (ret != GSS_S_COMPLETE) {
		krblog("Unable to accept security context", ret, status);
		return 0;
	}

	ret = gss_display_name(&status, gss_username, &gss_user_buf, nullptr);
	if (ret != 0) {
		krblog("Unable to convert username", ret, status);
		return 0;
	}
	std::string ub(static_cast<const char *>(gss_user_buf.value), gss_user_buf.length);
	mlog(LV_DEBUG, "Kerberos username: %s", ub.c_str());
	return htp_auth_finalize(ctx, ub.c_str());
}
#endif

static tproc_status htp_auth_spnego(http_context &ctx, const char *past_method)
{
	bool rq_ntlmssp = strncmp(past_method, "TlRMTVNT", 8) == 0;
	auto the_helper = g_config_file->get_value(rq_ntlmssp ? "ntlmssp_program" : "gss_program");

	if (strcmp(the_helper, "internal-gss") != 0) {
		auto ret = htp_auth_ntlmssp(ctx, the_helper, past_method,
		           ctx.last_gss_output);
		ctx.auth_status = ret <= 0 ? http_status::unauthorized : http_status::ok;
		ctx.auth_method = auth_method::negotiate_b64;
		if (ret <= 0 && ret != -99)
			ntlm_stop(ctx.ntlm_proc);
	} else {
#ifdef HAVE_GSSAPI
		char decoded[4096];
		size_t decode_len = 0;
		if (decode64(past_method, strlen(past_method), decoded,
		    std::size(decoded), &decode_len) != 0)
			return tproc_status::runoff;
		auto ret = auth_krb(ctx, decoded, decode_len, ctx.last_gss_output);
		ctx.auth_status = ret <= 0 ? http_status::unauthorized : http_status::ok;
		ctx.auth_method = auth_method::negotiate;
#else
		static bool y = false;
		if (!y)
			mlog(LV_DEBUG, "Cannot handle Negotiate request: software built without GSSAPI");
		y = true;
#endif
	}
	return tproc_status::runoff;
}

/*
 * Implementation notes.
 *
 * This function (and its subordinates) will, in general, only touch
 * ctx.auth_status and then return tproc_status::runoff, so that the caller can
 * invoke the right methods to get body processing going, depending on the
 * outcome of htp_auth.
 *
 * Only if the request is to be hard-aborted can htp_auth return with a
 * different status from http_done().
 */
static tproc_status htp_auth(http_context &ctx)
{
	auto line = http_parser_request_head(ctx.request.f_others, "Authorization");
	if (line == nullptr && ctx.auth_status == http_status::ok &&
	    (ctx.auth_method == auth_method::negotiate ||
	    ctx.auth_method == auth_method::negotiate_b64))
		/*
		 * Negotiate validity is stateful (and requires both sides to
		 * use Keep-Alive properly).
		 */
		return tproc_status::runoff;
	/* Under anything else, it resets */
	ctx.auth_method = auth_method::none;
	ctx.auth_status = http_status::none;
	if (line == nullptr) {
		if (g_enforce_auth)
			ctx.auth_status = http_status::unauthorized;
		return tproc_status::runoff;
	}
	/* http://www.iana.org/assignments/http-authschemes */
	auto method = line;
	auto past_method = line;
	while (*past_method != '\0' && !HX_isspace(*past_method))
		++past_method;
	*past_method++ = '\0';
	while (HX_isspace(*past_method))
		++past_method;
	if (strcasecmp(method, "Basic") == 0 &&
	    g_config_file->get_ll("http_auth_basic")) {
		char decoded[1024];
		size_t decode_len = 0;
		if (decode64(past_method, strlen(past_method), decoded, std::size(decoded), &decode_len) != 0)
			return tproc_status::runoff;
		auto p = strchr(decoded, ':');
		if (p == nullptr)
			return tproc_status::runoff;
		*p++ = '\0';
		gx_strlcpy(ctx.username, decoded, std::size(ctx.username));
		gx_strlcpy(ctx.password, p, std::size(ctx.password));
		auto ret = htp_auth_basic(&ctx);
		if (ret != tproc_status::runoff)
			return ret;
	} else if (strcasecmp(method, "Negotiate") == 0 &&
	    g_config_file->get_ll("http_auth_spnego")) {
		auto ret = htp_auth_spnego(ctx, past_method);
		if (ret != tproc_status::runoff)
			return ret;
	}

	if (g_enforce_auth && ctx.auth_status != http_status::ok)
		ctx.auth_status = http_status::unauthorized;
	return tproc_status::runoff;
}

static tproc_status htp_delegate_rpc(http_context *pcontext,
    size_t stream_1_written)
{
	auto tmp_len = pcontext->request.f_request_uri.size();
	if (0 == tmp_len || tmp_len >= 1024) {
		pcontext->log(LV_DEBUG,
			"I-1926: rpcproxy request method error");
		return http_done(pcontext, http_status::bad_request);
	}
	char tmp_buff[2048];
	gx_strlcpy(tmp_buff, pcontext->request.f_request_uri.c_str(), std::size(tmp_buff));
	char *ptoken;
	if (0 == strncmp(tmp_buff, "/rpc/rpcproxy.dll?", 18)) {
		ptoken = tmp_buff + 18;
	} else if (0 == strncmp(tmp_buff,
	    "/rpcwithcert/rpcproxy.dll?", 26)) {
		ptoken = tmp_buff + 26;
	} else {
		pcontext->log(LV_DEBUG,
			"I-1928: rpcproxy request method error");
		return http_done(pcontext, http_status::bad_request);
	}
	auto ptoken1 = strchr(tmp_buff, ':');
	if (NULL == ptoken1) {
		pcontext->log(LV_DEBUG,
			"I-1929: rpcproxy request method error");
		return http_done(pcontext, http_status::bad_request);
	}
	*ptoken1 = '\0';
	if (ptoken1 - ptoken > 128) {
		pcontext->log(LV_DEBUG,
			"I-1930: rpcproxy request method error");
		return http_done(pcontext, http_status::bad_request);
	}
	ptoken1++;
	gx_strlcpy(pcontext->host, ptoken, std::size(pcontext->host));
	pcontext->port = strtol(ptoken1, nullptr, 0);
	if (pcontext->auth_status != http_status::ok) {
		pcontext->log(LV_DEBUG,
			"I-1931: authentication needed");
		return http_done(pcontext, http_status::unauthorized);
	}

	pcontext->total_length = pcontext->request.content_len;
	/* ECHO request 0x0 ~ 0x10, MS-RPCH 2.1.2.15 */
	if (pcontext->total_length > 0x10) {
		if (pcontext->request.imethod == http_method::rpcin) {
			pcontext->channel_type = hchannel_type::in;
			pcontext->pchannel = g_inchannel_allocator->get();
			if (pcontext->pchannel == nullptr)
				return http_done(pcontext, http_status::enomem_CL);
		} else {
			pcontext->channel_type = hchannel_type::out;
			pcontext->pchannel = g_outchannel_allocator->get();
			if (pcontext->pchannel == nullptr)
				return http_done(pcontext, http_status::enomem_CL);
		}
	}
	pcontext->bytes_rw = stream_1_written;
	return tproc_status::loop;
}

static tproc_status htp_delegate_hpm(http_context *pcontext)
{
	pcontext->bytes_rw = 0;
	pcontext->total_length = 0;

	auto ret = http_write_request(pcontext);
	if (ret != http_status::ok)
		return http_done(pcontext, ret);
	if (!pcontext->request.b_end)
		return tproc_status::loop;
	if (!hpm_processor_proc(pcontext))
		return http_done(pcontext, http_status::bad_request);
	pcontext->sched_stat = hsched_stat::wrrep;
	if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
		mlog(LV_ERR, "E-1184: ENOMEM");
		return http_done(pcontext, http_status::enomem_CL);
	}
	if (pcontext->stream_out.get_total_length() == 0)
		return tproc_status::loop;
	unsigned int tmp_len = STREAM_BLOCK_SIZE;
	pcontext->write_buff = pcontext->stream_out.get_read_buf(&tmp_len);
	pcontext->write_length = tmp_len;
	return tproc_status::loop;
}

static tproc_status htp_delegate_fcgi(http_context *pcontext)
{
	pcontext->bytes_rw = 0;
	pcontext->total_length = 0;

	auto ret = http_write_request(pcontext);
	if (ret != http_status::ok)
		return http_done(pcontext, ret);
	if (!pcontext->request.b_end)
		return tproc_status::loop;
	if (!mod_fastcgi_relay_content(pcontext))
 		return http_done(pcontext, http_status::bad_gateway);
	pcontext->sched_stat = hsched_stat::wrrep;
	if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
		mlog(LV_ERR, "E-1183: ENOMEM");
		return http_done(pcontext, http_status::enomem_CL);
	}
	return tproc_status::loop;
}

static tproc_status htp_delegate_cache(http_context *pcontext)
{
	pcontext->bytes_rw = 0;
	pcontext->total_length = 0;

	auto ret = http_write_request(pcontext);
	if (ret != http_status::ok)
		return http_done(pcontext, ret);
	if (!pcontext->request.b_end)
		return tproc_status::loop;
	if (!mod_cache_discard_content(pcontext))
		return http_done(pcontext, http_status::bad_gateway);
	pcontext->sched_stat = hsched_stat::wrrep;
	if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
		mlog(LV_ERR, "E-1182: ENOMEM");
		return http_done(pcontext, http_status::enomem_CL);
	}
	return tproc_status::loop;
}

static tproc_status http_done_soft(http_context &ctx, enum http_status status) try
{
	auto rsp = http_make_err_response(ctx, status);
	ctx.stream_out.clear();
	ctx.stream_out.write(rsp.c_str(), rsp.size());
	/* Force-feed to mod_cache, which will discard rqbody */
	return htp_delegate_cache(&ctx);
} catch (const std::bad_alloc &) {
	ctx.b_close = TRUE;
	ctx.total_length = 0;
	ctx.bytes_rw = 0;
	ctx.sched_stat = hsched_stat::wrrep;
	return tproc_status::loop;
}

static tproc_status htparse_rdhead_st(http_context *pcontext, ssize_t actual_read)
{
	while (true) {
		pcontext->stream_in.try_mark_line();
		switch (pcontext->stream_in.has_newline()) {
		case STREAM_LINE_FAIL:
			pcontext->log(LV_DEBUG,
				"I-1933: request header line too long");
			return http_done(pcontext, http_status::bad_request_CL);
		case STREAM_LINE_UNAVAILABLE:
			if (actual_read > 0)
				return tproc_status::cont;
			return tproc_status::polling_rdonly;
		case STREAM_LINE_AVAILABLE:
			/* continue to process line below */
			break;
		}

		char *line = nullptr;
		auto line_length = pcontext->stream_in.readline(&line);
		if (0 != line_length) {
			auto ret = *pcontext->request.method == '\0' ?
			           htparse_rdhead_no(pcontext, line, line_length) :
			           htparse_rdhead_mt(pcontext, line, line_length);
			if (ret != tproc_status::runoff)
				return ret;
			continue;
		} else if (*pcontext->request.method == '\0') {
			/* extraneous blank lines before Request-Line */
			continue;
		}

		/* met the end of request header */
		pcontext->sched_stat = hsched_stat::rdbody;
		if (pcontext->request.f_host.empty())
			pcontext->request.f_host = pcontext->connection.server_ip;
		if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
			mlog(LV_ERR, "E-1181: ENOMEM");
			return http_done(pcontext, http_status::enomem_CL);
		}
		auto stream_1_written = pcontext->stream_in.get_total_length();
		auto ret = htp_auth(*pcontext);
		if (ret != tproc_status::runoff)
			return ret;
		if (pcontext->auth_status >= http_status::bad_request)
			return http_done_soft(*pcontext, http_status::unauthorized);
		if (pcontext->request.imethod == http_method::rpcin ||
		    pcontext->request.imethod == http_method::rpcout)
			return htp_delegate_rpc(pcontext, stream_1_written);
		auto status = hpm_processor_take_request(pcontext);
		if (status == http_status::ok)
			return htp_delegate_hpm(pcontext);
		else if (status != http_status::none)
			return http_done_soft(*pcontext, status);
		status = mod_fastcgi_take_request(pcontext);
		if (status == http_status::ok)
			return htp_delegate_fcgi(pcontext);
		else if (status != http_status::none)
			return http_done_soft(*pcontext, status);
		status = mod_cache_take_request(pcontext);
		if (status == http_status::ok)
			return htp_delegate_cache(pcontext);
		else if (status != http_status::none)
			return http_done_soft(*pcontext, status);
		return http_done_soft(*pcontext, http_status::not_found);
	}
	return tproc_status::runoff;
}

static char *now_str(char *buf, size_t bufsize)
{
	using namespace std::chrono;
	auto now   = system_clock::now();
	auto now_t = system_clock::to_time_t(now);
	struct tm now_tm;
	strftime(buf, bufsize, "%T", localtime_r(&now_t, &now_tm));
	auto z = strlen(buf);
	snprintf(&buf[z], bufsize - z, ".%06lu",
	         static_cast<unsigned long>(duration_cast<microseconds>(now.time_since_epoch()).count() % 1000000UL));
	return buf;
}

static ssize_t htparse_readsock(HTTP_CONTEXT *pcontext, const char *tag,
    void *pbuff, unsigned int size)
{
	ssize_t actual_read = pcontext->connection.ssl != nullptr ?
	                      SSL_read(pcontext->connection.ssl, pbuff, size) :
	                      read(pcontext->connection.sockd, pbuff, size);
	if (actual_read <= 0)
		return actual_read;
	if (g_http_debug) {
		auto &co = pcontext->connection;
		char tbuf[24];
		now_str(tbuf, std::size(tbuf));
		fprintf(stderr, "\e[1m<< %s [%s]:%hu->[%s]:%hu %zd bytes\e[0m\n",
		        now_str(tbuf, std::size(tbuf)),
		        co.client_ip, co.client_port,
		        co.server_ip, co.server_port, actual_read);
		auto pfx = utf8_printable_prefix(pbuff, actual_read);
		if (pfx == static_cast<size_t>(actual_read)) {
			fflush(stderr);
			if (HXio_fullwrite(STDERR_FILENO, pbuff, actual_read) < 0)
				/* ignore */;
		} else {
			fflush(stderr);
			if (HXio_fullwrite(STDERR_FILENO, pbuff, pfx) < 0)
				/* ignore */;
			HX_hexdump(stderr, &static_cast<const char *>(pbuff)[pfx], actual_read - pfx);
		}
		fprintf(stderr, "\n<<-%s\n", tag);
	}
	return actual_read;
}

static tproc_status htparse_rdhead(http_context *pcontext)
{
	unsigned int size = STREAM_BLOCK_SIZE;
	auto pbuff = pcontext->stream_in.get_write_buf(&size);
	if (NULL == pbuff) {
		mlog(LV_ERR, "E-1180: ENOMEM");
		return http_done(pcontext, http_status::enomem_CL);
	}
	auto actual_read = htparse_readsock(pcontext, "EOH", pbuff, size);
	auto current_time = tp_now();
	if (0 == actual_read) {
		pcontext->log(LV_DEBUG, "connection lost");
		return tproc_status::runoff;
	} else if (actual_read > 0) {
		pcontext->connection.last_timestamp = current_time;
		pcontext->stream_in.fwd_write_ptr(actual_read);
		return htparse_rdhead_st(pcontext, actual_read);
	}
	if (EAGAIN != errno) {
		pcontext->log(LV_DEBUG, "connection lost");
		return tproc_status::runoff;
	}
	/* check if context is timed out */
	if (current_time - pcontext->connection.last_timestamp < g_timeout)
		return htparse_rdhead_st(pcontext, actual_read);
	pcontext->log(LV_DEBUG, "I-1934: timeout");
	return http_done(pcontext, http_status::timeout);
}

static tproc_status htparse_wrrep_nobuf(http_context *pcontext)
{
	if (hpm_processor_is_in_charge(pcontext)) {
		switch (hpm_processor_retrieve_response(pcontext)) {
		case HPM_RETRIEVE_ERROR:
			return http_done(pcontext, http_status::bad_request);
		case HPM_RETRIEVE_WRITE:
			break;
		case HPM_RETRIEVE_NONE:
			return tproc_status::cont;
		case HPM_RETRIEVE_WAIT:
			pcontext->sched_stat = hsched_stat::wait;
			return tproc_status::idle;
		case HPM_RETRIEVE_DONE:
			if (pcontext->b_close)
				return tproc_status::runoff;
			pcontext->request.clear();
			hpm_processor_put_context(pcontext);
			pcontext->sched_stat = hsched_stat::rdhead;
			pcontext->stream_out.clear();
			return tproc_status::cont;
		}
	} else if (mod_fastcgi_is_in_charge(pcontext)) {
		switch (mod_fastcgi_check_response(pcontext)) {
		case RESPONSE_WAITING:
			return tproc_status::cont;
		case RESPONSE_TIMEOUT:
			pcontext->log(LV_DEBUG,
				"fastcgi execution timeout");
			return http_done(pcontext, http_status::gateway_timeout);
		}
		if (mod_fastcgi_check_responded(pcontext)) {
			if (!mod_fastcgi_read_response(pcontext) &&
			    pcontext->stream_out.get_total_length() == 0) {
				if (pcontext->b_close)
					return tproc_status::runoff;
				pcontext->request.clear();
				pcontext->sched_stat = hsched_stat::rdhead;
				pcontext->stream_out.clear();
				return tproc_status::cont;
			}
		} else if (!mod_fastcgi_read_response(pcontext)) {
			return http_done(pcontext, http_status::bad_gateway);
		}
	} else if (mod_cache_is_in_charge(pcontext) &&
	    !mod_cache_read_response(pcontext)) {
		if (!mod_cache_check_responded(pcontext))
			return http_done(pcontext, http_status::bad_request);
		if (pcontext->stream_out.get_total_length() == 0) {
			if (pcontext->b_close)
				return tproc_status::runoff;
			pcontext->request.clear();
			pcontext->sched_stat = hsched_stat::rdhead;
			pcontext->stream_out.clear();
			return tproc_status::cont;
		}
	} else if (pcontext->request.imethod != http_method::rpcin &&
	    pcontext->request.imethod != http_method::rpcout) {
		if (pcontext->stream_out.get_total_length() == 0) {
			if (pcontext->b_close)
				return tproc_status::runoff;
			pcontext->request.clear();
			pcontext->sched_stat = hsched_stat::rdhead;
			pcontext->stream_out.clear();
			return tproc_status::cont;
		}
	}

	pcontext->write_offset = 0;
	unsigned int tmp_len;
	if (pcontext->channel_type == hchannel_type::out &&
	    static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->channel_stat == hchannel_stat::opened) {
		/* stream_out is shared resource of vconnection,
			lock it first before operating */
		auto chan = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
		auto pvconnection = http_parser_get_vconnection(pcontext->host,
		                    pcontext->port, chan->connection_cookie);
		if (pvconnection == nullptr) {
			pcontext->log(LV_DEBUG,
				"virtual connection error in hash table");
			return tproc_status::runoff;
		}
		auto pnode = double_list_get_head(&chan->pdu_list);
		if (NULL == pnode) {
			pvconnection.put();
			pcontext->sched_stat = hsched_stat::wait;
			return tproc_status::idle;
		}
		pcontext->write_buff = static_cast<BLOB_NODE *>(pnode->pdata)->blob.pb;
		tmp_len = static_cast<BLOB_NODE *>(pnode->pdata)->blob.cb;
	} else {
		tmp_len = STREAM_BLOCK_SIZE;
		pcontext->write_buff = pcontext->stream_out.get_read_buf(&tmp_len);
		// if write_buff is nullptr, then tmp_len was set to 0
	}

	/* if context is set to write response state, there's
	 * always data in stream_out. so we did not check
	 * whether pcontext->write_buff pointer is NULL. */
	pcontext->write_length = tmp_len;
	return tproc_status::runoff;
}

static tproc_status htparse_wrrep(http_context *pcontext)
{
	if (NULL == pcontext->write_buff) {
		auto ret = htparse_wrrep_nobuf(pcontext);
		if (ret != tproc_status::runoff)
			return ret;
	}

	ssize_t written_len = pcontext->write_length - pcontext->write_offset; /*int-int*/
	if (written_len < 0)
		mlog(LV_WARN, "W-1533: wl=%zd. report me.", written_len);
	if (pcontext->channel_type == hchannel_type::out &&
	    static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->channel_stat == hchannel_stat::opened) {
		auto pchannel_out = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
		if (pchannel_out->available_window < 1024)
			return tproc_status::idle;
		if (written_len >= 0 && static_cast<size_t>(written_len) >
		    pchannel_out->available_window)
			written_len = pchannel_out->available_window;
	}
	if (pcontext->write_buff == nullptr && written_len > 0) {
		mlog(LV_WARN, "W-1534: wl=%zd. report me.", written_len);
		written_len = 0;
	}
	if (g_http_debug) {
		auto &co = pcontext->connection;
		char tbuf[24];
		fprintf(stderr, "\e[1m>> %s [%s]:%hu->[%s]:%hu %zd bytes\e[0m\n",
		        now_str(tbuf, std::size(tbuf)),
		        co.server_ip, co.server_port,
		        co.client_ip, co.client_port, written_len);
		auto pfx = utf8_printable_prefix(pcontext->write_buff, written_len);
		if (pfx == static_cast<size_t>(written_len)) {
			fflush(stderr);
			if (HXio_fullwrite(STDERR_FILENO, pcontext->write_buff, written_len) < 0)
				/* ignore */;
		} else {
			/*
			 * Unlike in htparse_readsock, here the write buffer
			 * contains both HTTP headers, MH chunks and ROP
			 * response buffer. Try to separate them so that the
			 * hexdump starts at the ROP part.
			 */
			auto b = static_cast<const uint8_t *>(pcontext->write_buff);
			if (HXio_fullwrite(STDERR_FILENO, b, pfx) < 0)
				/* ignore */;
			HX_hexdump(stderr, &b[pfx], written_len - pfx);
		}
		fprintf(stderr, ">>-EOP\n");
	}
	if (pcontext->write_buff == nullptr)
		written_len = 0;
	else if (pcontext->connection.ssl != nullptr)
		written_len = SSL_write(pcontext->connection.ssl,
			      reinterpret_cast<char *>(pcontext->write_buff) + pcontext->write_offset,
			written_len);
	else if (pcontext->write_buff != nullptr)
		written_len = write(pcontext->connection.sockd,
			      reinterpret_cast<char *>(pcontext->write_buff) + pcontext->write_offset,
			written_len);

	auto current_time = tp_now();
	if (0 == written_len) {
		pcontext->log(LV_DEBUG, "connection lost");
		return tproc_status::runoff;
	} else if (written_len < 0) {
		if (EAGAIN != errno) {
			pcontext->log(LV_DEBUG, "connection lost");
			return tproc_status::runoff;
		}
		/* check if context is timed out */
		if (current_time - pcontext->connection.last_timestamp < g_timeout)
			return tproc_status::polling_wronly;
		pcontext->log(LV_DEBUG, "timeout");
		return tproc_status::runoff;
	}
	pcontext->connection.last_timestamp = current_time;
	pcontext->write_offset += written_len;
	pcontext->bytes_rw += written_len;
	if (pcontext->channel_type == hchannel_type::out &&
	    static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->channel_stat == hchannel_stat::opened) {
		auto pchannel_out = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
		auto pvconnection = http_parser_get_vconnection(pcontext->host,
				pcontext->port, pchannel_out->connection_cookie);
		auto pnode = double_list_get_head(&pchannel_out->pdu_list);
		if (!static_cast<BLOB_NODE *>(pnode->pdata)->b_rts) {
			pchannel_out->available_window -= written_len;
			pchannel_out->bytes_sent += written_len;
		}
	}

	if (pcontext->write_offset < pcontext->write_length)
		return tproc_status::cont;
	pcontext->write_offset = 0;
	pcontext->write_buff = NULL;
	pcontext->write_length = 0;
	if (pcontext->channel_type == hchannel_type::out &&
	    static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->channel_stat == hchannel_stat::opened) {
		/* stream_out is shared resource of vconnection,
			lock it first before operating */
		auto hch = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
		auto pvconnection = http_parser_get_vconnection(pcontext->host,
		                    pcontext->port, hch->connection_cookie);
		if (pvconnection == nullptr) {
			pcontext->log(LV_DEBUG,
				"virtual connection error in hash table");
			return tproc_status::runoff;
		}
		auto pnode = double_list_pop_front(&static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->pdu_list);
		if (pnode != nullptr) {
			free(static_cast<BLOB_NODE *>(pnode->pdata)->blob.pb);
			pdu_processor_free_blob(static_cast<BLOB_NODE *>(pnode->pdata));
		}
		pnode = double_list_get_head(&hch->pdu_list);
		if (pnode != nullptr) {
			pcontext->write_buff = static_cast<BLOB_NODE *>(pnode->pdata)->blob.pb;
			pcontext->write_length = static_cast<BLOB_NODE *>(pnode->pdata)->blob.cb;
		} else if (pcontext->total_length > 0 &&
		    pcontext->total_length - pcontext->bytes_rw <= MAX_RECLYING_REMAINING &&
		    !hch->b_obsolete) {
			/* begin of out channel recycling */
			if (pdu_processor_rts_outr2_a2(hch->pcall)) {
				pdu_processor_output_pdu(hch->pcall, &hch->pdu_list);
				hch->b_obsolete = TRUE;
			}
		} else {
			pcontext->sched_stat = hsched_stat::wait;
		}
		return tproc_status::cont;
	}

	unsigned int tmp_len = STREAM_BLOCK_SIZE;
	pcontext->write_buff = pcontext->stream_out.get_read_buf(&tmp_len);
	pcontext->write_length = tmp_len;
	if (pcontext->write_buff != nullptr)
		return tproc_status::cont;
	if (pcontext->channel_type == hchannel_type::out &&
	    (static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->channel_stat == hchannel_stat::waitinchannel ||
	    static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->channel_stat == hchannel_stat::waitrecycled)) {
		/* to wait in channel for completing
			out channel handshaking */
		pcontext->sched_stat = hsched_stat::wait;
	} else if (hpm_processor_is_in_charge(pcontext) ||
	    mod_fastcgi_is_in_charge(pcontext) ||
	    mod_cache_is_in_charge(pcontext)) {
		pcontext->stream_out.clear();
		return tproc_status::cont;
	} else {
		if (pcontext->b_close)
			return tproc_status::runoff;
		pcontext->request.clear();
		pcontext->sched_stat = hsched_stat::rdhead;
	}
	pcontext->stream_out.clear();
	return tproc_status::cont;
}

static tproc_status htparse_rdbody_nochan2(http_context *pcontext)
{
	unsigned int size = STREAM_BLOCK_SIZE;
	auto pbuff = pcontext->stream_in.get_write_buf(&size);
	if (NULL == pbuff) {
		mlog(LV_ERR, "E-1179: ENOMEM");
		return http_done(pcontext, http_status::bad_request);
	}
	auto actual_read = htparse_readsock(pcontext, "EOB", pbuff, size);
	auto current_time = tp_now();
	if (0 == actual_read) {
		pcontext->log(LV_DEBUG, "connection lost");
		return tproc_status::endproc;
	} else if (actual_read > 0) {
		pcontext->connection.last_timestamp = current_time;
		pcontext->stream_in.fwd_write_ptr(actual_read);
		auto ret = http_write_request(pcontext);
		if (ret != http_status::ok)
			return http_done(pcontext, ret);
		if (!pcontext->request.b_end)
			return tproc_status::cont;
		if (hpm_processor_is_in_charge(pcontext)) {
			if (!hpm_processor_proc(pcontext))
				return http_done(pcontext, http_status::bad_request);
		} else if (mod_fastcgi_is_in_charge(pcontext)) {
			if (!mod_fastcgi_relay_content(pcontext))
				return http_done(pcontext, http_status::bad_gateway);
		} else if (mod_cache_is_in_charge(pcontext) ||
		    pcontext->auth_status >= http_status::bad_request /*unwinder_in_charge*/) {
			if (!mod_cache_discard_content(pcontext))
				return http_done(pcontext, http_status::bad_gateway);
		}
		pcontext->sched_stat = hsched_stat::wrrep;
		if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
			mlog(LV_ERR, "E-1178: ENOMEM");
			return http_done(pcontext, http_status::enomem_CL);
		}
		if (hpm_processor_is_in_charge(pcontext)) {
			if (pcontext->stream_out.get_total_length() != 0) {
				unsigned int tmp_len = STREAM_BLOCK_SIZE;
				pcontext->write_buff = pcontext->stream_out.get_read_buf(&tmp_len);
				pcontext->write_length = tmp_len;
			}
			return tproc_status::cont;
		} else if (mod_fastcgi_is_in_charge(pcontext)) {
			return tproc_status::cont;
		} else if (mod_cache_is_in_charge(pcontext)) {
			return tproc_status::cont;
		} else if (pcontext->auth_status >= http_status::bad_request /*unwinder_in_charge*/) {
			return tproc_status::cont;
		}
		/* rpc_is_in_charge */
		pcontext->bytes_rw += actual_read;
		if (pcontext->bytes_rw < pcontext->total_length)
			return tproc_status::cont;
		return tproc_status::runoff;
	}
	if (EAGAIN != errno) {
		pcontext->log(LV_DEBUG, "connection lost");
		return tproc_status::endproc;
	}
	/* check if context is timed out */
	if (current_time - pcontext->connection.last_timestamp < g_timeout)
		return tproc_status::polling_rdonly;
	pcontext->log(LV_DEBUG, "I-1935: timeout");
	return http_done(pcontext, http_status::timeout);
}

static tproc_status htparse_rdbody_nochan(http_context *pcontext)
{
	if (0 == pcontext->total_length ||
	    pcontext->bytes_rw < pcontext->total_length) {
		auto ret = htparse_rdbody_nochan2(pcontext);
		if (ret == tproc_status::endproc)
			return tproc_status::runoff;
		if (ret != tproc_status::runoff)
			return ret;
	}
	if (pcontext->request.imethod != http_method::rpcin &&
	    pcontext->request.imethod != http_method::rpcout) {
		pcontext->log(LV_DEBUG, "I-1936: unrecognized HTTP method \"%s\"", pcontext->request.method);
		/* other http request here if wanted */
		return http_done(pcontext, http_status::method_not_allowed);
	}
	/* ECHO request */
	char response_buff[1024];
	auto response_len = gx_snprintf(response_buff, std::size(response_buff),
		"HTTP/1.1 200 Success\r\n"
		"Connection: Keep-Alive\r\n"
		"Keep-Alive: timeout=%ld\r\n"
		"Content-Length: 20\r\n"
		"Content-Type: application/rpc\r\n\r\n", TOSEC(g_timeout));
	pdu_processor_rts_echo(response_buff + response_len);
	response_len += 20;
	pcontext->stream_out.write(response_buff, response_len);
	pcontext->total_length = response_len;
	pcontext->bytes_rw = 0;
	pcontext->sched_stat = hsched_stat::wrrep;
	if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
		mlog(LV_ERR, "E-1176: ENOMEM");
		return http_done(pcontext, http_status::enomem_CL);
	}
	return tproc_status::cont;
}

static tproc_status htparse_rdbody(http_context *pcontext)
{
	if (pcontext->pchannel == nullptr ||
	    (pcontext->channel_type != hchannel_type::in &&
	    pcontext->channel_type != hchannel_type::out))
		return htparse_rdbody_nochan(pcontext);

	auto pchannel_in  = pcontext->channel_type == hchannel_type::in ?
	                    static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel)  : nullptr;
	auto pchannel_out = pcontext->channel_type == hchannel_type::out ?
	                    static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel) : nullptr;
	auto frag_length  = pcontext->channel_type == hchannel_type::in ?
	                    pchannel_in->frag_length : pchannel_out->frag_length;
	auto tmp_len = pcontext->stream_in.get_total_length();
	if (tmp_len < DCERPC_FRAG_LEN_OFFSET + 2 ||
	    (frag_length > 0 && tmp_len < frag_length)) {
		unsigned int size = STREAM_BLOCK_SIZE;
		auto pbuff = pcontext->stream_in.get_write_buf(&size);
		if (NULL == pbuff) {
			mlog(LV_ERR, "E-1175: ENOMEM");
			return http_done(pcontext, http_status::enomem_CL);
		}

		auto actual_read = htparse_readsock(pcontext, "EOB", pbuff, size);
		auto current_time = tp_now();
		if (0 == actual_read) {
			pcontext->log(LV_DEBUG, "connection lost");
			return tproc_status::runoff;
		} else if (actual_read > 0) {
			pcontext->bytes_rw += actual_read;
			if (pcontext->bytes_rw > pcontext->total_length) {
				pcontext->log(LV_DEBUG,
					"content length overflow when reading body");
				return tproc_status::runoff;
			}
			pcontext->connection.last_timestamp = current_time;
			pcontext->stream_in.fwd_write_ptr(actual_read);
		} else {
			if (EAGAIN != errno) {
				pcontext->log(LV_DEBUG, "connection lost");
				return tproc_status::runoff;
			}
			/* check if context is timed out */
			if (current_time - pcontext->connection.last_timestamp < g_timeout)
				return tproc_status::polling_rdonly;
			pcontext->log(LV_DEBUG, "I-1937: timeout");
			return http_done(pcontext, http_status::timeout);
		}
	}

	unsigned int tmp_len2 = STREAM_BLOCK_SIZE;
	auto pbuff = pcontext->stream_in.get_read_buf(&tmp_len2);
	if (pbuff == nullptr)
		return tproc_status::polling_rdonly;
	tmp_len = tmp_len2;
	pcontext->stream_in.rewind_read_ptr(tmp_len);
	if (tmp_len < DCERPC_FRAG_LEN_OFFSET + 2)
		return tproc_status::cont;

	if (0 == frag_length) {
		static_assert(std::is_same_v<decltype(frag_length), uint16_t>, "");
		auto pbd = static_cast<uint8_t *>(pbuff);
		auto pfrag = &pbd[DCERPC_FRAG_LEN_OFFSET];
		frag_length = (pbd[DCERPC_DREP_OFFSET] & DCERPC_DREP_LE) ?
			      le16p_to_cpu(pfrag) : be16p_to_cpu(pfrag);
		if (pcontext->channel_type == hchannel_type::in)
			pchannel_in->frag_length = frag_length;
		else
			pchannel_out->frag_length = frag_length;
	}

	if (tmp_len < frag_length)
		return tproc_status::cont;
	g_context_key = pcontext;
	DCERPC_CALL *pcall = nullptr;
	auto result = pdu_processor_rts_input(static_cast<char *>(pbuff),
		 frag_length, &pcall);
	if (pcontext->channel_type == hchannel_type::in &&
	    pchannel_in->channel_stat == hchannel_stat::opened) {
		if (PDU_PROCESSOR_ERROR == result) {
			/* ignore rts processing error under this condition */
			result = PDU_PROCESSOR_INPUT;
		} else if (PDU_PROCESSOR_FORWARD == result) {
			/* only under this condition, we can
			forward pdu to pdu processor */
			auto pvconnection = http_parser_get_vconnection(pcontext->host,
				pcontext->port, pchannel_in->connection_cookie);
			if (pvconnection == nullptr) {
				pcontext->log(LV_DEBUG,
					"virtual connection error in hash table");
				return tproc_status::runoff;
			}
			if (pvconnection->pcontext_in != pcontext ||
			    NULL == pvconnection->pprocessor) {
				pvconnection.put();
				pcontext->log(LV_DEBUG,
					"virtual connection error in hash table");
				return tproc_status::runoff;
			}
			result = pdu_processor_input(pvconnection->pprocessor.get(),
				 static_cast<char *>(pbuff), frag_length, &pcall);
			pchannel_in->available_window -= frag_length;
			pchannel_in->bytes_received += frag_length;
			if (pcall != nullptr &&
			    pvconnection->pcontext_out != nullptr &&
			    pchannel_in->available_window < static_cast<RPC_OUT_CHANNEL *>(pvconnection->pcontext_out->pchannel)->window_size / 2) {
				auto och = static_cast<RPC_OUT_CHANNEL *>(pvconnection->pcontext_out->pchannel);
				pchannel_in->available_window = och->window_size;
				pdu_processor_rts_flowcontrolack_withdestination(
					pcall, pchannel_in->bytes_received,
					pchannel_in->available_window,
					pchannel_in->channel_cookie);
				/* if it is a fragment pdu, we must
					make the flowcontrol output */
				if (PDU_PROCESSOR_INPUT == result) {
					pdu_processor_output_pdu(pcall, &och->pdu_list);
					pvconnection->pcontext_out->sched_stat = hsched_stat::wrrep;
					contexts_pool_signal(pvconnection->pcontext_out);
				}
			}
		}
	}

	pcontext->stream_in.fwd_read_ptr(frag_length);
	if (pcontext->channel_type == hchannel_type::in)
		pchannel_in->frag_length = 0;
	else
		pchannel_out->frag_length = 0;
	if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
		mlog(LV_ERR, "E-1174: ENOMEM");
		return http_done(pcontext, http_status::enomem_CL);
	}

	switch (result) {
	case PDU_PROCESSOR_ERROR:
	case PDU_PROCESSOR_FORWARD:
		pcontext->log(LV_DEBUG, "pdu process error!");
		return tproc_status::runoff;
	case PDU_PROCESSOR_INPUT:
		/* do nothing */
		return tproc_status::cont;
	case PDU_PROCESSOR_OUTPUT: {
		if (pcontext->channel_type == hchannel_type::out) {
			/* only under two conditions below, out channel
			   will produce PDU_PROCESSOR_OUTPUT */
			if (pchannel_out->channel_stat != hchannel_stat::openstart &&
			    pchannel_out->channel_stat != hchannel_stat::recycling) {
				pcontext->log(LV_DEBUG,
					"pdu process error! out channel can't output "
					"itself after virtual connection established");
				return tproc_status::runoff;
			}
			/* first send http response head */
			char dstring[128], response_buff[1024];
			rfc1123_dstring(dstring, std::size(dstring));
			auto response_len = gx_snprintf(
				response_buff, std::size(response_buff),
				"HTTP/1.1 200 Success\r\n"
				"Date: %s\r\n"
				"Cache-Control: private\r\n"
				"Content-Type: application/rpc\r\n"
				"Persistent-Auth: true\r\n"
				"Content-Length: %u\r\n\r\n",
				dstring, OUT_CHANNEL_MAX_LENGTH);
			pcontext->stream_out.write(response_buff, response_len);
			pcontext->total_length =
				OUT_CHANNEL_MAX_LENGTH + response_len;
			pdu_processor_output_stream(pcall, &pcontext->stream_out);
			/* never free this kind of pcall */
			pchannel_out->pcall = pcall;
			pcontext->bytes_rw = 0;
			pcontext->sched_stat = hsched_stat::wrrep;
			pchannel_out->channel_stat = pchannel_out->channel_stat == hchannel_stat::openstart ?
			                             hchannel_stat::waitinchannel : hchannel_stat::waitrecycled;
			return tproc_status::loop;
		}
		/* in channel here, find the corresponding out channel first! */
		auto pvconnection = http_parser_get_vconnection(pcontext->host,
			pcontext->port, pchannel_in->connection_cookie);
		if (pvconnection == nullptr) {
			pdu_processor_free_call(pcall);
			pcontext->log(LV_DEBUG,
				"cannot find virtual connection in hash table");
			return tproc_status::runoff;
		}

		if ((pcontext != pvconnection->pcontext_in &&
		    pcontext != pvconnection->pcontext_insucc)
		    || NULL == pvconnection->pcontext_out) {
			pvconnection.put();
			pdu_processor_free_call(pcall);
			pcontext->log(LV_DEBUG,
				"missing out channel in virtual connection");
			return tproc_status::runoff;
		}
		auto och = static_cast<RPC_OUT_CHANNEL *>(pvconnection->pcontext_out->pchannel);
		if (och->b_obsolete) {
			auto hch = static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel);
			pdu_processor_output_pdu(pcall, &hch->pdu_list);
			pvconnection.put();
			pdu_processor_free_call(pcall);
			return tproc_status::cont;
		}
		pdu_processor_output_pdu(pcall, &och->pdu_list);
		pvconnection->pcontext_out->sched_stat = hsched_stat::wrrep;
		contexts_pool_signal(pvconnection->pcontext_out);
		pvconnection.put();
		pdu_processor_free_call(pcall);
		return tproc_status::cont;
	}
	case PDU_PROCESSOR_TERMINATE:
		return tproc_status::runoff;
	}
	return tproc_status::runoff;
}

static tproc_status htparse_waitinchannel(http_context *pcontext,
    RPC_OUT_CHANNEL *pchannel_out)
{
	auto pvconnection = http_parser_get_vconnection(pcontext->host,
		pcontext->port, pchannel_out->connection_cookie);
	if (pvconnection != nullptr) {
		if (pvconnection->pcontext_out == pcontext
		    && NULL != pvconnection->pcontext_in) {
			auto pchannel_in = static_cast<RPC_IN_CHANNEL *>(pvconnection->pcontext_in->pchannel);
			pchannel_in->available_window =
				pchannel_out->window_size;
			pchannel_in->bytes_received = 0;
			pchannel_out->client_keepalive =
				pchannel_in->client_keepalive;
			if (!pdu_processor_rts_conn_c2(
			    pchannel_out->pcall, pchannel_out->window_size)) {
				pvconnection.put();
				pcontext->log(LV_DEBUG,
					"pdu process error! fail to setup conn/c2");
				return tproc_status::runoff;
			}
			pdu_processor_output_pdu(
				pchannel_out->pcall, &pchannel_out->pdu_list);
			pcontext->sched_stat = hsched_stat::wrrep;
			pchannel_out->channel_stat = hchannel_stat::opened;
			return tproc_status::loop;
		}
		pvconnection.put();
	}

	auto current_time = tp_now();
	/* check if context is timed out */
	if (current_time - pcontext->connection.last_timestamp < OUT_CHANNEL_MAX_WAIT)
		return tproc_status::idle;
	pcontext->log(LV_DEBUG, "no correpoding in "
		"channel coming during maximum waiting interval");
	return tproc_status::runoff;
}

static tproc_status htparse_waitrecycled(http_context *pcontext,
    RPC_OUT_CHANNEL *pchannel_out)
{
	auto pvconnection = http_parser_get_vconnection(pcontext->host,
		pcontext->port, pchannel_out->connection_cookie);
	if (pvconnection != nullptr) {
		if (pvconnection->pcontext_out == pcontext
		    && NULL != pvconnection->pcontext_in) {
			auto pchannel_in = static_cast<RPC_IN_CHANNEL *>(pvconnection->pcontext_in->pchannel);
			pchannel_out->client_keepalive =
				pchannel_in->client_keepalive;
			pchannel_out->channel_stat = hchannel_stat::opened;
			DOUBLE_LIST_NODE *pnode;
			while ((pnode = double_list_pop_front(&pchannel_in->pdu_list)) != nullptr)
				double_list_append_as_tail(
					&pchannel_out->pdu_list, pnode);
			pcontext->sched_stat = double_list_get_nodes_num(&pchannel_out->pdu_list) == 0 ?
			                       hsched_stat::wait : hsched_stat::wrrep;
			return tproc_status::loop;
		}
		pvconnection.put();
	}

	auto current_time = tp_now();
	/* check if context is timed out */
	if (current_time - pcontext->connection.last_timestamp < OUT_CHANNEL_MAX_WAIT)
		return tproc_status::idle;
	pcontext->log(LV_DEBUG, "channel is not "
		"recycled during maximum waiting interval");
	return tproc_status::runoff;
}

static tproc_status htparse_wait(http_context *pcontext)
{
	if (hpm_processor_is_in_charge(pcontext))
		return tproc_status::idle;
	/* only hpm_processor or out channel can be set to hsched_stat::wait */
	auto pchannel_out = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
	switch (pchannel_out->channel_stat) {
	case hchannel_stat::waitinchannel:
		return htparse_waitinchannel(pcontext, pchannel_out);
	case hchannel_stat::waitrecycled:
		return htparse_waitrecycled(pcontext, pchannel_out);
	case hchannel_stat::recycled:
		return tproc_status::runoff;
	default:
		break;
	}

	char tmp_buff;
	if (recv(pcontext->connection.sockd, &tmp_buff, 1, MSG_PEEK) == 0) {
		pcontext->log(LV_DEBUG, "connection lost");
		return tproc_status::runoff;
	}

	auto current_time = tp_now();
	/* check keep alive */
	if (current_time - pcontext->connection.last_timestamp <
	    pchannel_out->client_keepalive / 2)
		return tproc_status::idle;
	if (!pdu_processor_rts_ping(pchannel_out->pcall))
		return tproc_status::idle;
	/* stream_out is shared resource of vconnection,
		lock it first before operating */
	auto hch = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
	auto pvconnection = http_parser_get_vconnection(pcontext->host,
	                    pcontext->port, hch->connection_cookie);
	pdu_processor_output_pdu(
		pchannel_out->pcall, &pchannel_out->pdu_list);
	pcontext->sched_stat = hsched_stat::wrrep;
	return tproc_status::loop;
}

tproc_status http_parser_process(schedule_context *vcontext)
{
	auto pcontext = static_cast<http_context *>(vcontext);
	auto ret = tproc_status::runoff;
	do {
		switch (pcontext->sched_stat) {
		case hsched_stat::initssl: ret = htparse_initssl(pcontext); break;
		case hsched_stat::rdhead:  ret = htparse_rdhead(pcontext);  break;
		case hsched_stat::rdbody:  ret = htparse_rdbody(pcontext);  break;
		case hsched_stat::wrrep:   ret = htparse_wrrep(pcontext);   break;
		case hsched_stat::wait:    ret = htparse_wait(pcontext);    break;
		default: continue;
		}
	} while (ret == tproc_status::loop);
	if (ret != tproc_status::runoff)
		return ret;
	return http_end(pcontext);
}

void http_parser_shutdown_async()
{
	g_async_stop = true;
}

void http_parser_vconnection_async_reply(const char *host,
	int port, const char *connection_cookie, DCERPC_CALL *pcall)
{
	/* system is going to stop now */
	if (g_async_stop) {
		mlog(LV_DEBUG, "noticed async_stop");
		return;
	}
	auto pvconnection = http_parser_get_vconnection(host, port, connection_cookie);
	if (pvconnection == nullptr)
		return;
	if (pvconnection->pcontext_out == nullptr)
		return;
	auto och = static_cast<RPC_OUT_CHANNEL *>(pvconnection->pcontext_out->pchannel);
	if (och->b_obsolete) {
		if (NULL != pvconnection->pcontext_in) {
			auto ich = static_cast<RPC_IN_CHANNEL *>(pvconnection->pcontext_in->pchannel);
			pdu_processor_output_pdu(pcall, &ich->pdu_list);
			return;
		}
	} else {
		pdu_processor_output_pdu(pcall, &och->pdu_list);
	}
	pvconnection->pcontext_out->sched_stat = hsched_stat::wrrep;
	contexts_pool_signal(pvconnection->pcontext_out);
}

int http_parser_get_param(int param)
{
    switch (param) {
    case MAX_AUTH_TIMES:
        return g_max_auth_times;
    case BLOCK_AUTH_FAIL:
        return g_block_auth_fail;
    case HTTP_SESSION_TIMEOUT:
		return std::chrono::duration_cast<std::chrono::seconds>(g_timeout).count();
	case HTTP_SUPPORT_TLS:
		return g_support_tls;
    default:
        return 0;
    }
}

SCHEDULE_CONTEXT **http_parser_get_contexts_list()
{
	return g_context_list2.data();
}

http_context::http_context() :
	stream_in(&g_blocks_allocator), stream_out(stream_in.allocator)
{
	auto pcontext = this;
	pcontext->node.pdata = pcontext;
#ifdef HAVE_GSSAPI
	m_gss_srv_creds = GSS_C_NO_CREDENTIAL;
	m_gss_ctx = GSS_C_NO_CONTEXT;
#endif
}

static void http_parser_context_clear(HTTP_CONTEXT *pcontext)
{
    if (NULL == pcontext) {
        return;
    }
	auto &ctx = *pcontext;
	ntlm_stop(ctx.ntlm_proc);
	pcontext->connection.reset();
	pcontext->sched_stat = hsched_stat::initssl;
	pcontext->request.clear();
	pcontext->stream_in.clear();
	pcontext->stream_out.clear();
	pcontext->write_buff = NULL;
	pcontext->write_offset = 0;
	pcontext->write_length = 0;
	pcontext->b_close = TRUE;
	pcontext->auth_status = http_status::none;
	pcontext->auth_times = 0;
	pcontext->username[0] = '\0';
	pcontext->password[0] = '\0';
	pcontext->maildir[0] = '\0';
	pcontext->lang[0] = '\0';
	pcontext->channel_type = hchannel_type::none;
	pcontext->pchannel = NULL;
	if (mod_fastcgi_is_in_charge(pcontext))
		mod_fastcgi_put_context(pcontext);
}

http_context::~http_context()
{
	auto pcontext = this;
#ifdef HAVE_GSSAPI
	OM_uint32 st;
	if (m_gss_srv_creds != nullptr)
		gss_release_cred(&st, &m_gss_srv_creds);
	if (m_gss_ctx != nullptr)
		gss_delete_sec_context(&st, &m_gss_ctx, GSS_C_NO_BUFFER);
#endif
	if (hpm_processor_is_in_charge(pcontext))
		hpm_processor_put_context(pcontext);
	else if (mod_fastcgi_is_in_charge(pcontext))
		mod_fastcgi_put_context(pcontext);
	else if (mod_cache_is_in_charge(pcontext))
		mod_cache_put_context(pcontext);
}

void http_context::log(int level, const char *format, ...) const
{
	bool dolog = level < LV_DEBUG || g_http_debug;
	if (!dolog)
		return;
	va_list ap;
	char log_buf[2048];

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	va_end(ap);
	log_buf[sizeof(log_buf) - 1] = '\0';
	
	if (*username == '\0')
		mlog(level, "ctxid=%u, host=[%s]:%hu  %s", context_id,
			connection.client_ip, connection.client_port, log_buf);
	else
		mlog(level, "user=%s, host=[%s]:%hu  %s", username,
			connection.client_ip, connection.client_port, log_buf);

}

HTTP_CONTEXT* http_parser_get_context()
{
	return g_context_key;
}

void http_parser_set_context(int context_id)
{
	if (context_id < 0 ||
	    static_cast<size_t>(context_id) >= g_context_num)
		g_context_key = nullptr;
	else
		g_context_key = &g_context_list[context_id];
}

bool http_parser_get_password(const char *username, char *password)
{
	HTTP_CONTEXT *pcontext;
	
	pcontext = http_parser_get_context();
	if (pcontext == nullptr)
		return false;
	if (strcasecmp(username, pcontext->username) != 0)
		return false;
	strncpy(password, pcontext->password, 128);
	return true;
}

BOOL http_context::try_create_vconnection()
{
	auto pcontext = this;
	const char *conn_cookie;
	
	if (pcontext->channel_type == hchannel_type::in) {
		auto chan = static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel);
		conn_cookie = chan->connection_cookie;
	} else if (pcontext->channel_type == hchannel_type::out) {
		auto chan = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
		conn_cookie = chan->connection_cookie;
	} else {
		return FALSE;
	}
 RETRY_QUERY:
	auto pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, conn_cookie);
	if (pvconnection != nullptr) {
		if (pcontext->channel_type == hchannel_type::out) {
			pvconnection->pcontext_out = pcontext;
			return TRUE;
		}
		pvconnection->pcontext_in = pcontext;
		if (pvconnection->pcontext_out != nullptr)
			contexts_pool_signal(pvconnection->pcontext_out);
		return TRUE;
	}

	std::unique_lock vc_hold(g_vconnection_lock);
	if (g_vconnection_hash.size() >= g_context_num + 1) {
		pcontext->log(LV_DEBUG, "W-1293: vconn hash full");
		return false;
	}
	decltype(g_vconnection_hash.try_emplace(""s)) xp;
	try {
		auto hash_key = conn_cookie + ":"s +
				std::to_string(pcontext->port) + ":" +
				pcontext->host;
		HX_strlower(hash_key.data());
		xp = g_vconnection_hash.try_emplace(std::move(hash_key));
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1292: ENOMEM");
		return false;
	}
	if (!xp.second) {
		pcontext->log(LV_DEBUG, "W-1291: vconn suddenly started existing");
		goto RETRY_QUERY;
	}
	auto nc = &xp.first->second;
	nc->pprocessor = pdu_processor_create(pcontext->host, pcontext->port);
	if (nc->pprocessor == nullptr) {
		g_vconnection_hash.erase(xp.first);
		pcontext->log(LV_DEBUG,
			"fail to create processor on %s:%d",
			pcontext->host, pcontext->port);
		return FALSE;
	}
	if (pcontext->channel_type == hchannel_type::out)
		nc->pcontext_out = pcontext;
	else
		nc->pcontext_in = pcontext;
	vc_hold.unlock();
	return TRUE;
}

void http_context::set_outchannel_flowcontrol(uint32_t bytes_received,
    uint32_t available_window)
{
	auto pcontext = this;
	if (pcontext->channel_type != hchannel_type::in)
		return;
	auto hch = static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel);
	auto pvconnection = http_parser_get_vconnection(pcontext->host,
	                    pcontext->port, hch->connection_cookie);
	if (pvconnection == nullptr)
		return;
	if (pvconnection->pcontext_out == nullptr)
		return;
	auto pchannel_out = static_cast<RPC_OUT_CHANNEL *>(pvconnection->pcontext_out->pchannel);
	if (bytes_received + available_window > pchannel_out->bytes_sent) {
		pchannel_out->available_window = bytes_received
			+ available_window - pchannel_out->bytes_sent;
		contexts_pool_signal(pvconnection->pcontext_out);
	} else {
		pchannel_out->available_window = 0;
	}
}

BOOL http_context::recycle_inchannel(const char *predecessor_cookie)
{
	auto pcontext = this;
	if (pcontext->channel_type != hchannel_type::in)
		return FALSE;
	auto hch = static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel);
	auto pvconnection = http_parser_get_vconnection(pcontext->host,
	                    pcontext->port, hch->connection_cookie);
	if (pvconnection == nullptr ||
	    pvconnection->pcontext_in == nullptr ||
	    strcmp(predecessor_cookie, static_cast<RPC_IN_CHANNEL *>(pvconnection->pcontext_in->pchannel)->channel_cookie) != 0)
		return false;
	auto ich = static_cast<RPC_IN_CHANNEL *>(pvconnection->pcontext_in->pchannel);
	hch->life_time = ich->life_time;
	hch->client_keepalive = ich->client_keepalive;
	hch->available_window = ich->available_window;
	hch->bytes_received = ich->bytes_received;
	strcpy(hch->assoc_group_id, ich->assoc_group_id);
	pvconnection->pcontext_insucc = pcontext;
	return TRUE;
}

BOOL http_context::recycle_outchannel(const char *predecessor_cookie)
{
	auto pcontext = this;
	if (pcontext->channel_type != hchannel_type::out)
		return FALSE;
	auto hch = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
	auto pvconnection = http_parser_get_vconnection(pcontext->host,
	                    pcontext->port, hch->connection_cookie);
	if (pvconnection == nullptr ||
	    pvconnection->pcontext_out == nullptr ||
	    strcmp(predecessor_cookie, static_cast<RPC_OUT_CHANNEL *>(pvconnection->pcontext_out->pchannel)->channel_cookie) != 0)
		return false;
	auto och = static_cast<RPC_OUT_CHANNEL *>(pvconnection->pcontext_out->pchannel);
	if (!och->b_obsolete)
		return FALSE;
	auto pcall = och->pcall;
	if (!pdu_processor_rts_outr2_a6(pcall))
		return FALSE;
	pdu_processor_output_pdu(pcall, &och->pdu_list);
	pvconnection->pcontext_out->sched_stat = hsched_stat::wrrep;
	contexts_pool_signal(pvconnection->pcontext_out);
	hch->client_keepalive = och->client_keepalive;
	hch->available_window = och->window_size;
	hch->window_size = och->window_size;
	pvconnection->pcontext_outsucc = pcontext;
	return TRUE;
}

BOOL http_context::activate_inrecycling(const char *successor_cookie)
{
	auto pcontext = this;
	if (pcontext->channel_type != hchannel_type::in)
		return FALSE;
	auto hch = static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel);
	auto pvconnection = http_parser_get_vconnection(pcontext->host,
	                    pcontext->port, hch->connection_cookie);
	if (pvconnection == nullptr ||
	    pvconnection->pcontext_insucc != pcontext ||
	    strcmp(successor_cookie, static_cast<RPC_IN_CHANNEL *>(pvconnection->pcontext_insucc->pchannel)->channel_cookie) != 0)
		return false;
	if (NULL != pvconnection->pcontext_in) {
		auto pchannel_in = static_cast<RPC_IN_CHANNEL *>(pvconnection->pcontext_in->pchannel);
		pchannel_in->channel_stat = hchannel_stat::recycled;
	}
	pvconnection->pcontext_in = pcontext;
	hch->channel_stat = hchannel_stat::opened;
	pvconnection->pcontext_insucc = NULL;
	return TRUE;
}

BOOL http_context::activate_outrecycling(const char *successor_cookie)
{
	auto pcontext = this;
	if (pcontext->channel_type != hchannel_type::in)
		return FALSE;
	auto hch = static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel);
	auto pvconnection = http_parser_get_vconnection(pcontext->host,
	                    pcontext->port, hch->connection_cookie);
	if (pvconnection == nullptr ||
	    pvconnection->pcontext_in != pcontext ||
	    pvconnection->pcontext_out == nullptr ||
	    pvconnection->pcontext_outsucc == nullptr ||
	    strcmp(successor_cookie, static_cast<RPC_OUT_CHANNEL *>(pvconnection->pcontext_outsucc->pchannel)->channel_cookie) != 0)
		return false;
	auto pchannel_out = static_cast<RPC_OUT_CHANNEL *>(pvconnection->pcontext_out->pchannel);
	if (!pdu_processor_rts_outr2_b3(pchannel_out->pcall)) {
		pvconnection.put();
		pcontext->log(LV_DEBUG,
			"pdu process error! fail to setup r2/b3");
		return FALSE;
	}
	pdu_processor_output_pdu(
		pchannel_out->pcall, &pchannel_out->pdu_list);
	pvconnection->pcontext_out->sched_stat = hsched_stat::wrrep;
	contexts_pool_signal(pvconnection->pcontext_out);
	pvconnection->pcontext_out = pvconnection->pcontext_outsucc;
	pvconnection->pcontext_outsucc = NULL;
	contexts_pool_signal(pvconnection->pcontext_out);
	return TRUE;
}

void http_context::set_keep_alive(time_duration keepalive)
{
	auto pcontext = this;
	auto hch = static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel);
	auto pvconnection = http_parser_get_vconnection(pcontext->host,
	                    pcontext->port, hch->connection_cookie);
	if (pvconnection == nullptr || pvconnection->pcontext_in != pcontext)
		return;
	auto pchannel_in = static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel);
	pchannel_in->client_keepalive = keepalive;
	if (NULL != pvconnection->pcontext_out) {
		auto pchannel_out = static_cast<RPC_OUT_CHANNEL *>(pvconnection->pcontext_out->pchannel);
		pchannel_out->client_keepalive = keepalive;
	}
}

RPC_IN_CHANNEL::RPC_IN_CHANNEL()
{
	double_list_init(&pdu_list);
}

RPC_IN_CHANNEL::~RPC_IN_CHANNEL()
{
	DOUBLE_LIST_NODE *pnode;

	while ((pnode = double_list_pop_front(&pdu_list)) != nullptr) {
		auto bnode = static_cast<BLOB_NODE *>(pnode->pdata);
		free(bnode->blob.pb);
		pdu_processor_free_blob(bnode);
	}
	double_list_free(&pdu_list);
}

RPC_OUT_CHANNEL::RPC_OUT_CHANNEL()
{
	double_list_init(&pdu_list);
}

RPC_OUT_CHANNEL::~RPC_OUT_CHANNEL()
{
	DOUBLE_LIST_NODE *pnode;

	if (pcall != nullptr) {
		pdu_processor_free_call(pcall);
		pcall = nullptr;
	}
	while ((pnode = double_list_pop_front(&pdu_list)) != nullptr) {
		auto bnode = static_cast<BLOB_NODE *>(pnode->pdata);
		free(bnode->blob.pb);
		pdu_processor_free_blob(bnode);
	}
	double_list_free(&pdu_list);
}
