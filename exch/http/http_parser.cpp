// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
/* http parser is a module, which first read data from socket, parses rpc over http and
   relay the stream to pdu processor. it also process other http request
 */ 
#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <libHX/io.h>
#include <libHX/misc.h>
#include <libHX/string.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/cryptoutil.hpp>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/fileio.h>
#include <gromox/hpm_common.h>
#include <gromox/mail_func.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "hpm_processor.h"
#include "http_parser.h"
#include "mod_cache.hpp"
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
static thread_local HTTP_CONTEXT *g_context_key;
static alloc_limiter<file_block> g_file_allocator{"g_file_allocator.d"};
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
	fprintf(stderr, "%-3zu  %-2d  ", i, cn.sockd);
	fprintf(stderr, "[%s]:%hu->[%s]:%hu\n",
	        cn.client_ip, cn.client_port, cn.server_ip, cn.server_port);
	const char *chtyp = "NONE";
	switch (ctx.channel_type) {
	case CHANNEL_TYPE_NONE: chtyp = "NONE"; break;
	case CHANNEL_TYPE_IN: chtyp = "IN"; break;
	case CHANNEL_TYPE_OUT: chtyp = "OUT"; break;
	default: chtyp = "?"; break;
	}
	fprintf(stderr, "   %4s  [%s]:%hu  %s\n",
		chtyp, ctx.host, ctx.port, ctx.username);
}

void http_report()
{
	/* There is no lock surrounding these structures, and they can be in an undefined state */
	fprintf(stderr, "HTTP Contexts:\n");
	fprintf(stderr, "Ctx  fd  src->host\n");
	fprintf(stderr, "   ChTy  RPCEndpoint, Username\n");
	fprintf(stderr, "-------------------------------------------------------------------------------\n");
	for (size_t i = 0; i < g_context_num; ++i) {
		httpctx_report(g_context_list[i], i);
	}
	fprintf(stderr, "\n");
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
	gx_strlcpy(g_certificate_path, certificate_path, GX_ARRAY_SIZE(g_certificate_path));
	if (NULL != cb_passwd) {
		gx_strlcpy(g_certificate_passwd, cb_passwd, GX_ARRAY_SIZE(g_certificate_passwd));
	} else {
		g_certificate_passwd[0] = '\0';
	}
	gx_strlcpy(g_private_key_path, key_path, GX_ARRAY_SIZE(g_private_key_path));
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
			printf("[http_parser]: Failed to init SSL context\n");
			return -1;
		}
		if ('\0' != g_certificate_passwd[0]) {
			SSL_CTX_set_default_passwd_cb_userdata(
				g_ssl_ctx, g_certificate_passwd);
		}
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
			fprintf(stderr, "[http_parser]: tls_min_proto value \"%s\" not accepted\n", mp);
			return -4;
		}
		try {
			g_ssl_mutex_buf = std::make_unique<std::mutex[]>(CRYPTO_num_locks());
		} catch (const std::bad_alloc &) {
			printf("[http_parser]: Failed to allocate SSL locking buffer\n");
			return -5;
		}
#ifdef OLD_SSL
		CRYPTO_THREADID_set_callback(http_parser_ssl_id);
		CRYPTO_set_locking_callback(http_parser_ssl_locking);
#endif
	}
	g_file_allocator = alloc_limiter<file_block>(16 * g_context_num,
	                   "http_file_allocator", "http.cfg:context_num");
	try {
		g_context_list = std::make_unique<HTTP_CONTEXT[]>(g_context_num);
		g_context_list2.resize(g_context_num);
		for (size_t i = 0; i < g_context_num; ++i) {
			g_context_list[i].context_id = i;
			g_context_list2[i] = &g_context_list[i];
		}
	} catch (const std::bad_alloc &) {
		printf("[http_parser]: Failed to allocate HTTP contexts\n");
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
	
	snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff), "%s:%d:%s", conn_cookie, port, host);
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

static BOOL http_parser_request_head(MEM_FILE *pfile_others,
	const char *field_name, char *field_value, int buff_len)
{
	int tmp_len;
	int name_len;
	char name_buff[64];
	
	pfile_others->seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	name_len = strlen(field_name);
	if (name_len >= 64) {
		return FALSE;
	}
	while (pfile_others->read(&tmp_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		if (name_len == tmp_len) {
			 pfile_others->read(name_buff, tmp_len);
			 if (0 == strncasecmp(name_buff, field_name, name_len)) {
				 pfile_others->read(&tmp_len, sizeof(uint32_t));
				 if (tmp_len >= buff_len) {
					 return FALSE;
				 }
				 pfile_others->read(field_value, tmp_len);
				 field_value[tmp_len] = '\0';
				 return TRUE;
			 }
		} else {
			pfile_others->seek(MEM_FILE_READ_PTR, tmp_len, MEM_FILE_SEEK_CUR);
		}
		pfile_others->read(&tmp_len, sizeof(uint32_t));
		pfile_others->seek(MEM_FILE_READ_PTR, tmp_len, MEM_FILE_SEEK_CUR);
	}
	return FALSE;
}

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
			if (NULL == pbuff1) {
				return -1;
			}
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

static void http_4xx(HTTP_CONTEXT *ctx, const char *msg = "Bad Request",
    unsigned int code = 400)
{
	if (hpm_processor_is_in_charge(ctx))
		hpm_processor_put_context(ctx);
	else if (ctx->pfast_context != nullptr)
		mod_fastcgi_put_context(ctx);
	else if (mod_cache_is_in_charge(ctx))
		mod_cache_put_context(ctx);

	char dstring[128], response_buff[1024];
	rfc1123_dstring(dstring, arsizeof(dstring));
	auto response_len = gx_snprintf(response_buff, GX_ARRAY_SIZE(response_buff),
		"HTTP/1.1 %u %s\r\n"
		"Date: %s\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n", code, msg, dstring);
	ctx->stream_out.write(response_buff, response_len);
	ctx->total_length = response_len;
	ctx->bytes_rw = 0;
	ctx->b_close = TRUE;
	ctx->sched_stat = SCHED_STAT_WRREP;
}

static void http_5xx(HTTP_CONTEXT *ctx, const char *msg = "Internal Server Error",
    unsigned int code = 500)
{
	if (hpm_processor_is_in_charge(ctx))
		hpm_processor_put_context(ctx);
	else if (ctx->pfast_context != nullptr)
		mod_fastcgi_put_context(ctx);
	else if (mod_cache_is_in_charge(ctx))
		mod_cache_put_context(ctx);

	char dstring[128], response_buff[1024];
	rfc1123_dstring(dstring, arsizeof(dstring));
	auto response_len = gx_snprintf(response_buff, GX_ARRAY_SIZE(response_buff),
		"HTTP/1.1 %u %s\r\n"
		"Date: %s\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n", code, msg, dstring);
	ctx->stream_out.write(response_buff, response_len);
	ctx->total_length = response_len;
	ctx->bytes_rw = 0;
	ctx->b_close = TRUE;
	ctx->sched_stat = SCHED_STAT_WRREP;
}

static int http_end(HTTP_CONTEXT *ctx)
{
	if (hpm_processor_is_in_charge(ctx))
		hpm_processor_put_context(ctx);
	else if (ctx->pfast_context != nullptr)
		mod_fastcgi_put_context(ctx);
	else if (mod_cache_is_in_charge(ctx))
		mod_cache_put_context(ctx);

	if (ctx->pchannel != nullptr) {
		if (ctx->channel_type == CHANNEL_TYPE_IN) {
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
	if (system_services_container_remove_ip != nullptr)
		system_services_container_remove_ip(ctx->connection.client_ip);
	http_parser_context_clear(ctx);
	return PROCESS_CLOSE;
}

enum { X_LOOP = -1, X_RUNOFF = -2, };

/* 
 * process a context
 * @param
 *         pcontext             indicate the context object
 * @return
 *         PROCESS_CONTINUE			context need continue to be processed 
 *         PROCESS_IDLE				empty loop
 *         PROCESS_POLLING_RDONLY	put the socket into epoll queue
 *         PROCESS_POLLING_WRONLY	put the socket into epoll queue
 *         PROCESS_SLEEPING			need to sleep the context
 *         PROCESS_CLOSE			need to cose the context
 */
static int htparse_initssl(HTTP_CONTEXT *pcontext)
{
	if (NULL == pcontext->connection.ssl) {
		pcontext->connection.ssl = SSL_new(g_ssl_ctx);
		if (NULL == pcontext->connection.ssl) {
			http_parser_log_info(pcontext, LV_DEBUG, "out of SSL object");
			http_5xx(pcontext, "Resources exhausted", 503);
			return X_LOOP;
		}
		SSL_set_fd(pcontext->connection.ssl, pcontext->connection.sockd);
	}
	if (SSL_accept(pcontext->connection.ssl) >= 0) {
		pcontext->sched_stat = SCHED_STAT_RDHEAD;
		return PROCESS_CONTINUE;
	}
	auto ssl_errno = SSL_get_error(pcontext->connection.ssl, -1);
	if (ssl_errno != SSL_ERROR_WANT_READ && ssl_errno != SSL_ERROR_WANT_WRITE) {
		http_parser_log_info(pcontext, LV_DEBUG, "fail to accept"
				" SSL connection, errno is %d", ssl_errno);
		return X_RUNOFF;
	}
	auto current_time = tp_now();
	if (CALCULATE_INTERVAL(current_time,
	    pcontext->connection.last_timestamp) < g_timeout) {
		return PROCESS_POLLING_RDONLY;
	}
	http_parser_log_info(pcontext, LV_DEBUG, "I-1920: timeout");
	http_4xx(pcontext, "Request Timeout", 408);
	return X_LOOP;
}

static int htparse_rdhead_no(HTTP_CONTEXT *pcontext, char *line, unsigned int line_length)
{
	auto ptoken = static_cast<char *>(memchr(line, ' ', line_length));
	if (NULL == ptoken) {
		http_parser_log_info(pcontext, LV_DEBUG, "I-1921: request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	size_t tmp_len = ptoken - line;
	if (tmp_len >= 32) {
		http_parser_log_info(pcontext, LV_DEBUG, "I-1922: request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}

	memcpy(pcontext->request.method, line, tmp_len);
	pcontext->request.method[tmp_len] = '\0';
	auto ptoken1 = static_cast<char *>(memchr(ptoken + 1, ' ', line_length - tmp_len - 1));
	if (NULL == ptoken1) {
		http_parser_log_info(pcontext, LV_DEBUG, "I-1923: request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	size_t tmp_len1 = ptoken1 - ptoken - 1;
	tmp_len = line_length - (ptoken1 + 6 - line);
	if (0 != strncasecmp(ptoken1 + 1,
	    "HTTP/", 5) || tmp_len >= 8) {
		http_parser_log_info(pcontext, LV_DEBUG, "I-1924: request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	if (!mod_rewrite_process(ptoken + 1,
	    tmp_len1, &pcontext->request.f_request_uri))
		pcontext->request.f_request_uri.write(ptoken + 1, tmp_len1);
	memcpy(pcontext->request.version, ptoken1 + 6, tmp_len);
	pcontext->request.version[tmp_len] = '\0';
	return X_RUNOFF;
}

static int htparse_rdhead_mt(HTTP_CONTEXT *pcontext, char *line, unsigned int line_length)
{
	auto ptoken = static_cast<char *>(memchr(line, ':', line_length));
	if (NULL == ptoken) {
		http_parser_log_info(pcontext, LV_DEBUG, "I-1925: request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}

	size_t tmp_len = ptoken - line;
	char field_name[64];
	memcpy(field_name, line, tmp_len);
	field_name[tmp_len] = '\0';
	HX_strrtrim(field_name);
	HX_strltrim(field_name);

	ptoken++;
	while (static_cast<size_t>(ptoken - line) < line_length) {
		if (' ' != *ptoken && '\t' != *ptoken) {
			break;
		}
		ptoken++;
	}
	tmp_len = line_length - static_cast<size_t>(ptoken - line);
	if (0 == strcasecmp(field_name, "Host")) {
		pcontext->request.f_host.write(ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name, "User-Agent")) {
		pcontext->request.f_user_agent.write(ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name, "Accept")) {
		pcontext->request.f_accept.write(ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Accept-Language")) {
		pcontext->request.f_accept_language.write(ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Accept-Encoding")) {
		pcontext->request.f_accept_encoding.write(ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Content-Type")) {
		pcontext->request.f_content_type.write(ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Content-Length")) {
		pcontext->request.f_content_length.write(ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Transfer-Encoding")) {
		pcontext->request.f_transfer_encoding.write(ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name, "Cookie")) {
		pcontext->request.f_cookie.write(ptoken, tmp_len);
	} else {
		if (0 == strcasecmp(field_name, "Connection") &&
		    0 == strncasecmp(ptoken, "keep-alive", tmp_len)) {
			/* for "Connection: Upgrade",
				we treat it as "close" */
			pcontext->b_close = FALSE;
		}
		uint32_t tmp_len1 = strlen(field_name);
		pcontext->request.f_others.write(&tmp_len1, sizeof(uint32_t));
		pcontext->request.f_others.write(field_name, tmp_len1);
		pcontext->request.f_others.write(&tmp_len, sizeof(uint32_t));
		pcontext->request.f_others.write(ptoken, tmp_len);
	}
	return X_RUNOFF;
}

static int htp_auth(HTTP_CONTEXT *pcontext)
{
	if (system_services_judge_user != nullptr &&
	    !system_services_judge_user(pcontext->username)) {
		char dstring[128], response_buff[1024];
		rfc1123_dstring(dstring, arsizeof(dstring));
		auto response_len = gx_snprintf(
			response_buff, GX_ARRAY_SIZE(response_buff),
			"HTTP/1.1 503 L-689 Service Unavailable\r\n"
			"Date: %s\r\n"
			"Content-Length: 0\r\n"
			"Connection: close\r\n"
			"\r\n", dstring);
		pcontext->stream_out.write(response_buff, response_len);
		pcontext->total_length = response_len;
		pcontext->bytes_rw = 0;
		pcontext->b_close = TRUE;
		pcontext->sched_stat = SCHED_STAT_WRREP;
		http_parser_log_info(pcontext, LV_DEBUG,
			"user %s is denied by user filter",
			pcontext->username);
		return X_LOOP;
	}

	char reason[256];
	if (system_services_auth_login(pcontext->username, pcontext->password,
	    pcontext->maildir, arsizeof(pcontext->maildir), pcontext->lang,
	    arsizeof(pcontext->lang), reason, arsizeof(reason),
	    USER_PRIVILEGE_EXCH)) {
		if ('\0' == pcontext->maildir[0]) {
			char dstring[128], response_buff[1024];
			rfc1123_dstring(dstring, arsizeof(dstring));
			auto response_len = gx_snprintf(
				response_buff, GX_ARRAY_SIZE(response_buff),
				"HTTP/1.1 401 Unauthorized\r\n"
				"Date: %s\r\n"
				"Content-Length: 0\r\n"
				"Keep-Alive: timeout=%ld\r\n"
				"Connection: close\r\n"
				"WWW-Authenticate: Basic realm=\"msrpc realm\"\r\n"
				"\r\n", dstring, TOSEC(g_timeout));
			pcontext->stream_out.write(response_buff, response_len);
			pcontext->total_length = response_len;
			pcontext->bytes_rw = 0;
			pcontext->b_close = TRUE;
			pcontext->sched_stat = SCHED_STAT_WRREP;
			http_parser_log_info(pcontext, LV_ERR, "maildir for \"%s\" absent: %s", pcontext->username, reason);
			return X_LOOP;
		}

		if ('\0' == pcontext->lang[0]) {
			gx_strlcpy(pcontext->lang, resource_get_string("USER_DEFAULT_LANG"),
			           GX_ARRAY_SIZE(pcontext->lang));
		}
		pcontext->b_authed = TRUE;
		http_parser_log_info(pcontext, LV_DEBUG, "login success");
		return X_RUNOFF;
	}

	pcontext->b_authed = FALSE;
	http_parser_log_info(pcontext, LV_ERR, "login failed: \"%s\": %s", pcontext->username, reason);
	pcontext->auth_times ++;
	if (system_services_add_user_into_temp_list != nullptr &&
	    pcontext->auth_times >= g_max_auth_times)
		system_services_add_user_into_temp_list(
			pcontext->username, g_block_auth_fail);
	char dstring[128], response_buff[1024];
	rfc1123_dstring(dstring, arsizeof(dstring));
	auto response_len = gx_snprintf(
		response_buff, GX_ARRAY_SIZE(response_buff),
		"HTTP/1.1 401 Unauthorized\r\n"
		"Date: %s\r\n"
		"Keep-Alive: timeout=%ld\r\n"
		"Connection: close\r\n"
		"Content-Type: text/plain; charset=ascii\r\n"
		"Content-Length: 2\r\n"
		"WWW-Authenticate: Basic realm=\"msrpc realm\"\r\n"
		"\r\n\r\n", dstring, TOSEC(g_timeout));
	pcontext->stream_out.write(response_buff, response_len);
	pcontext->total_length = response_len;
	pcontext->bytes_rw = 0;
	pcontext->b_close = TRUE;
	pcontext->sched_stat = SCHED_STAT_WRREP;
	return X_LOOP;
}

static int htp_delegate_rpc(HTTP_CONTEXT *pcontext, size_t stream_1_written)
{
	auto tmp_len = pcontext->request.f_request_uri.get_total_length();
	if (0 == tmp_len || tmp_len >= 1024) {
		http_parser_log_info(pcontext, LV_DEBUG,
			"I-1926: rpcproxy request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	char tmp_buff[2048];
	tmp_len = pcontext->request.f_request_uri.read(tmp_buff, 1024);
	if (tmp_len == MEM_END_OF_FILE) {
		http_parser_log_info(pcontext, LV_DEBUG, "I-1927: rpcproxy request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	tmp_buff[tmp_len] = '\0';

	char *ptoken;
	if (0 == strncmp(tmp_buff, "/rpc/rpcproxy.dll?", 18)) {
		ptoken = tmp_buff + 18;
	} else if (0 == strncmp(tmp_buff,
	    "/rpcwithcert/rpcproxy.dll?", 26)) {
		ptoken = tmp_buff + 26;
	} else {
		http_parser_log_info(pcontext, LV_DEBUG,
			"I-1928: rpcproxy request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	auto ptoken1 = strchr(tmp_buff, ':');
	if (NULL == ptoken1) {
		http_parser_log_info(pcontext, LV_DEBUG,
			"I-1929: rpcproxy request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	*ptoken1 = '\0';
	if (ptoken1 - ptoken > 128) {
		http_parser_log_info(pcontext, LV_DEBUG,
			"I-1930: rpcproxy request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	ptoken1++;
	gx_strlcpy(pcontext->host, ptoken, GX_ARRAY_SIZE(pcontext->host));
	pcontext->port = strtol(ptoken1, nullptr, 0);

	if (!pcontext->b_authed) {
		char dstring[128], response_buff[1024];
		rfc1123_dstring(dstring, arsizeof(dstring));
		auto response_len = gx_snprintf(
			response_buff, GX_ARRAY_SIZE(response_buff),
			"HTTP/1.1 401 Unauthorized\r\n"
			"Date: %s\r\n"
			"Content-Length: 0\r\n"
			"Keep-Alive: timeout=%ld\r\n"
			"Connection: close\r\n"
			"WWW-Authenticate: Basic realm=\"msrpc realm\"\r\n"
			"\r\n", dstring, TOSEC(g_timeout));
		pcontext->stream_out.write(response_buff, response_len);
		pcontext->total_length = response_len;
		pcontext->bytes_rw = 0;
		pcontext->b_close = TRUE;
		pcontext->sched_stat = SCHED_STAT_WRREP;
		http_parser_log_info(pcontext, LV_DEBUG,
			"I-1931: authentication needed");
		return X_LOOP;
	}

	tmp_len = pcontext->request.f_content_length.read(tmp_buff, 256);
	if (MEM_END_OF_FILE == tmp_len) {
		http_parser_log_info(pcontext, LV_DEBUG,
			"I-1932: content-length of rpcproxy request error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	pcontext->total_length = strtoull(tmp_buff, nullptr, 0);

	/* ECHO request 0x0 ~ 0x10, MS-RPCH 2.1.2.15 */
	if (pcontext->total_length > 0x10) {
		if (0 == strcmp(pcontext->request.method, "RPC_IN_DATA")) {
			pcontext->channel_type = CHANNEL_TYPE_IN;
			pcontext->pchannel = g_inchannel_allocator->get();
			if (NULL == pcontext->pchannel) {
				http_5xx(pcontext, "Resources exhausted", 503);
				return X_LOOP;
			}
		} else {
			pcontext->channel_type = CHANNEL_TYPE_OUT;
			pcontext->pchannel = g_outchannel_allocator->get();
			if (NULL == pcontext->pchannel) {
				http_5xx(pcontext, "Resources exhausted", 503);
				return X_LOOP;
			}
		}
	}
	pcontext->bytes_rw = stream_1_written;
	pcontext->sched_stat = SCHED_STAT_RDBODY;
	return X_LOOP;
}

static int htp_delegate_hpm(HTTP_CONTEXT *pcontext)
{
	/* let HPMs decide the read/write bytes */
	pcontext->bytes_rw = 0;
	pcontext->total_length = 0;

	if (!hpm_processor_write_request(pcontext)) {
		http_5xx(pcontext);
		return X_LOOP;
	}
	if (!hpm_processor_check_end_of_request(pcontext)) {
		pcontext->sched_stat = SCHED_STAT_RDBODY;
		return X_LOOP;
	}
	if (!hpm_processor_proc(pcontext)) {
		http_5xx(pcontext);
		return X_LOOP;
	}
	pcontext->sched_stat = SCHED_STAT_WRREP;
	if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
		http_parser_log_info(pcontext, LV_DEBUG, "out of memory");
		http_5xx(pcontext, "Resources exhausted", 503);
		return X_LOOP;
	}
	if (pcontext->stream_out.get_total_length() == 0)
		return X_LOOP;
	unsigned int tmp_len = STREAM_BLOCK_SIZE;
	pcontext->write_buff = pcontext->stream_out.get_read_buf(&tmp_len);
	pcontext->write_length = tmp_len;
	return X_LOOP;
}

static int htp_delegate_fcgi(HTTP_CONTEXT *pcontext)
{
	/* let mod_fastcgi decide the read/write bytes */
	pcontext->bytes_rw = 0;
	pcontext->total_length = 0;

	if (!mod_fastcgi_write_request(pcontext)) {
		http_5xx(pcontext);
		return X_LOOP;
	}
	if (!mod_fastcgi_check_end_of_read(pcontext)) {
		pcontext->sched_stat = SCHED_STAT_RDBODY;
		return X_LOOP;
	}
	if (!mod_fastcgi_relay_content(pcontext)) {
		http_5xx(pcontext, "Bad FastCGI Gateway", 502);
		return X_LOOP;
	}
	pcontext->sched_stat = SCHED_STAT_WRREP;
	if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
		http_parser_log_info(pcontext, LV_DEBUG, "out of memory");
		http_5xx(pcontext, "Resources exhausted", 503);
		return X_LOOP;
	}
	return X_LOOP;
}

static int htp_delegate_cache(HTTP_CONTEXT *pcontext)
{
	/* let mod_cache decide the read/write bytes */
	pcontext->bytes_rw = 0;
	pcontext->total_length = 0;
	pcontext->sched_stat = SCHED_STAT_WRREP;
	if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
		http_parser_log_info(pcontext, LV_DEBUG, "out of memory");
		http_5xx(pcontext, "Resources exhausted", 503);
		return X_LOOP;
	}
	return X_LOOP;
}

static int htparse_rdhead_st(HTTP_CONTEXT *pcontext, ssize_t actual_read)
{
	while (true) {
		pcontext->stream_in.try_mark_line();
		switch (pcontext->stream_in.has_newline()) {
		case STREAM_LINE_FAIL:
			http_parser_log_info(pcontext, LV_DEBUG,
				"I-1933: request header line too long");
			http_4xx(pcontext);
			return X_LOOP;
		case STREAM_LINE_UNAVAILABLE:
			if (actual_read > 0) {
				return PROCESS_CONTINUE;
			}
			return PROCESS_POLLING_RDONLY;
		case STREAM_LINE_AVAILABLE:
			/* continue to process line below */
			break;
		}

		char *line = nullptr;
		auto line_length = pcontext->stream_in.readline(&line);
		if (0 != line_length) {
			int ret;
			if ('\0' == pcontext->request.method[0]) {
				ret = htparse_rdhead_no(pcontext, line, line_length);
			} else {
				ret = htparse_rdhead_mt(pcontext, line, line_length);
			}
			if (ret != X_RUNOFF)
				return ret;
			continue;
		}

		/* met the end of request header */
		if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
			http_parser_log_info(pcontext, LV_DEBUG, "out of memory");
			http_5xx(pcontext, "Resources exhausted", 503);
			return X_LOOP;
		}
		auto stream_1_written = pcontext->stream_in.get_total_length();

		char tmp_buff[2048], tmp_buff1[1024];
		size_t decode_len = 0;
		char *ptoken = nullptr;
		if (http_parser_request_head(&pcontext->request.f_others,
		    "Authorization", tmp_buff, GX_ARRAY_SIZE(tmp_buff)) &&
		    strncasecmp(tmp_buff, "Basic ", 6) == 0 &&
		    decode64(tmp_buff + 6, strlen(tmp_buff + 6), tmp_buff1,
		    arsizeof(tmp_buff1), &decode_len) == 0 &&
		    (ptoken = strchr(tmp_buff1, ':')) != nullptr) {
			*ptoken = '\0';
			ptoken++;
			gx_strlcpy(pcontext->username, tmp_buff1, GX_ARRAY_SIZE(pcontext->username));
			gx_strlcpy(pcontext->password, ptoken, GX_ARRAY_SIZE(pcontext->password));
			auto ret = htp_auth(pcontext);
			if (ret != X_RUNOFF)
				return ret;
		}

		if (0 == strcasecmp(pcontext->request.method, "RPC_IN_DATA") ||
		    0 == strcasecmp(pcontext->request.method, "RPC_OUT_DATA")) {
			return htp_delegate_rpc(pcontext, stream_1_written);
		}
		if (hpm_processor_take_request(pcontext))
			return htp_delegate_hpm(pcontext);
		if (mod_fastcgi_take_request(pcontext))
			return htp_delegate_fcgi(pcontext);
		if (mod_cache_take_request(pcontext))
			return htp_delegate_cache(pcontext);
		/* other http request here if wanted */
		char dstring[128], response_buff[1024];
		rfc1123_dstring(dstring, arsizeof(dstring));
		auto response_len = gx_snprintf(response_buff, GX_ARRAY_SIZE(response_buff),
					"HTTP/1.1 404 Not Found\r\n"
					"Date: %s\r\n"
					"Connection: close\r\n"
					"Content-Length: 134\r\n\r\n"
					"<html>\r\n"
					"<head><title>404 Not Found</title></head>\r\n"
					"<body bgcolor=\"white\">\r\n"
					"<center><h1>404 Not Found</h1></center>\r\n"
					"</body>\r\n"
					"</html>\r\n",
					dstring);
		pcontext->stream_out.write(response_buff, response_len);
		pcontext->total_length = response_len;
		pcontext->bytes_rw = 0;
		pcontext->b_close = TRUE;
		pcontext->sched_stat = SCHED_STAT_WRREP;
		return X_LOOP;
	}
	return X_RUNOFF;
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
		fprintf(stderr, "<< ctx %p recv %zd\n", pcontext, actual_read);
		fflush(stderr);
		bool ascii = true;
		for (ssize_t i = 0; i < actual_read; ++i) {
			auto c = static_cast<const uint8_t *>(pbuff)[i];
			if (!isprint(c) && c != '\r' && c != '\n') {
				ascii = false;
				break;
			}
		}
		if (ascii) {
			if (HXio_fullwrite(STDERR_FILENO, pbuff, actual_read) < 0)
				/* ignore */;
		} else {
			HX_hexdump(stderr, pbuff, actual_read);
		}
		fprintf(stderr, "\n<<-%s\n", tag);
	}
	return actual_read;
}

static int htparse_rdhead(HTTP_CONTEXT *pcontext)
{
	unsigned int size = STREAM_BLOCK_SIZE;
	auto pbuff = pcontext->stream_in.get_write_buf(&size);
	if (NULL == pbuff) {
		http_parser_log_info(pcontext, LV_DEBUG, "out of memory");
		http_5xx(pcontext, "Resources exhausted", 503);
		return X_LOOP;
	}
	auto actual_read = htparse_readsock(pcontext, "EOH", pbuff, size);
	auto current_time = tp_now();
	if (0 == actual_read) {
		http_parser_log_info(pcontext, LV_DEBUG, "connection lost");
		return X_RUNOFF;
	} else if (actual_read > 0) {
		pcontext->connection.last_timestamp = current_time;
		pcontext->stream_in.fwd_write_ptr(actual_read);
		return htparse_rdhead_st(pcontext, actual_read);
	}
	if (EAGAIN != errno) {
		http_parser_log_info(pcontext, LV_DEBUG, "connection lost");
		return X_RUNOFF;
	}
	/* check if context is timed out */
	if (CALCULATE_INTERVAL(current_time,
	    pcontext->connection.last_timestamp) < g_timeout) {
		return htparse_rdhead_st(pcontext, actual_read);
	}
	http_parser_log_info(pcontext, LV_DEBUG, "I-1934: timeout");
	http_4xx(pcontext, "Request Timeout", 408);
	return X_LOOP;
}

static int htparse_wrrep_nobuf(HTTP_CONTEXT *pcontext)
{
	if (hpm_processor_is_in_charge(pcontext)) {
		switch (hpm_processor_retrieve_response(pcontext)) {
		case HPM_RETRIEVE_ERROR:
			http_5xx(pcontext);
			return X_LOOP;
		case HPM_RETRIEVE_WRITE:
			break;
		case HPM_RETRIEVE_NONE:
			return PROCESS_CONTINUE;
		case HPM_RETRIEVE_WAIT:
			pcontext->sched_stat = SCHED_STAT_WAIT;
			return PROCESS_IDLE;
		case HPM_RETRIEVE_DONE:
			if (pcontext->b_close)
				return X_RUNOFF;
			pcontext->request.clear();
			hpm_processor_put_context(pcontext);
			pcontext->sched_stat = SCHED_STAT_RDHEAD;
			pcontext->stream_out.clear();
			return PROCESS_CONTINUE;
		}
	} else if (NULL != pcontext->pfast_context) {
		switch (mod_fastcgi_check_response(pcontext)) {
		case RESPONSE_WAITING:
			return PROCESS_CONTINUE;
		case RESPONSE_TIMEOUT:
			http_parser_log_info(pcontext, LV_DEBUG,
				"fastcgi execution timeout");
			http_5xx(pcontext, "FastCGI Timeout", 504);
			return X_LOOP;
		}
		if (mod_fastcgi_check_responded(pcontext)) {
			if (!mod_fastcgi_read_response(pcontext) &&
			    pcontext->stream_out.get_total_length() == 0) {
				if (pcontext->b_close)
					return X_RUNOFF;
				pcontext->request.clear();
				pcontext->sched_stat = SCHED_STAT_RDHEAD;
				pcontext->stream_out.clear();
				return PROCESS_CONTINUE;
			}
		} else if (!mod_fastcgi_read_response(pcontext)) {
			http_5xx(pcontext, "Bad FastCGI Gateway", 502);
			return X_LOOP;
		}
	} else if (mod_cache_is_in_charge(pcontext) &&
	    !mod_cache_read_response(pcontext)) {
		if (!mod_cache_check_responded(pcontext)) {
			http_5xx(pcontext);
			return X_LOOP;
		}
		if (pcontext->stream_out.get_total_length() == 0) {
			if (pcontext->b_close)
				return X_RUNOFF;
			pcontext->request.clear();
			pcontext->sched_stat = SCHED_STAT_RDHEAD;
			pcontext->stream_out.clear();
			return PROCESS_CONTINUE;
		}
	}

	pcontext->write_offset = 0;
	unsigned int tmp_len;
	if (CHANNEL_TYPE_OUT == pcontext->channel_type &&
	    static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->channel_stat == CHANNEL_STAT_OPENED) {
		/* stream_out is shared resource of vconnection,
			lock it first before operating */
		auto chan = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
		auto pvconnection = http_parser_get_vconnection(pcontext->host,
		                    pcontext->port, chan->connection_cookie);
		if (pvconnection == nullptr) {
			http_parser_log_info(pcontext, LV_DEBUG,
				"virtual connection error in hash table");
			return X_RUNOFF;
		}
		auto pnode = double_list_get_head(&chan->pdu_list);
		if (NULL == pnode) {
			pvconnection.put();
			pcontext->sched_stat = SCHED_STAT_WAIT;
			return PROCESS_IDLE;
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
	return X_RUNOFF;
}

static int htparse_wrrep(HTTP_CONTEXT *pcontext)
{
	if (NULL == pcontext->write_buff) {
		auto ret = htparse_wrrep_nobuf(pcontext);
		if (ret != X_RUNOFF)
			return ret;
	}

	ssize_t written_len = pcontext->write_length - pcontext->write_offset; /*int-int*/
	if (written_len < 0)
		fprintf(stderr, "W-1533: wl=%zd. report me.\n", written_len);
	if (CHANNEL_TYPE_OUT == pcontext->channel_type &&
	    static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->channel_stat == CHANNEL_STAT_OPENED) {
		auto pchannel_out = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
		if (pchannel_out->available_window < 1024) {
			return PROCESS_IDLE;
		}
		if (written_len >= 0 && static_cast<size_t>(written_len) >
		    pchannel_out->available_window)
			written_len = pchannel_out->available_window;
	}
	if (pcontext->write_buff == nullptr && written_len > 0)
		fprintf(stderr, "W-1534: wl=%zd. report me.\n", written_len);
	if (g_http_debug) {
		auto s = static_cast<const char *>(pcontext->write_buff);
		fprintf(stderr, ">> ctx %p send %zd\n%.*s\n>>-EOP\n", pcontext,
		        written_len, (int)written_len, znul(s));
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
		http_parser_log_info(pcontext, LV_DEBUG, "connection lost");
		return X_RUNOFF;
	} else if (written_len < 0) {
		if (EAGAIN != errno) {
			http_parser_log_info(pcontext, LV_DEBUG, "connection lost");
			return X_RUNOFF;
		}
		/* check if context is timed out */
		if (CALCULATE_INTERVAL(current_time,
		    pcontext->connection.last_timestamp) < g_timeout) {
			return PROCESS_POLLING_WRONLY;
		}
		http_parser_log_info(pcontext, LV_DEBUG, "timeout");
		return X_RUNOFF;
	}
	pcontext->connection.last_timestamp = current_time;
	pcontext->write_offset += written_len;
	pcontext->bytes_rw += written_len;
	if (CHANNEL_TYPE_OUT == pcontext->channel_type &&
	    static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->channel_stat == CHANNEL_STAT_OPENED) {
		auto pchannel_out = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
		auto pvconnection = http_parser_get_vconnection(pcontext->host,
				pcontext->port, pchannel_out->connection_cookie);
		auto pnode = double_list_get_head(&pchannel_out->pdu_list);
		if (!static_cast<BLOB_NODE *>(pnode->pdata)->b_rts) {
			pchannel_out->available_window -= written_len;
			pchannel_out->bytes_sent += written_len;
		}
	}

	if (pcontext->write_offset < pcontext->write_length) {
		return PROCESS_CONTINUE;
	}
	pcontext->write_offset = 0;
	pcontext->write_buff = NULL;
	pcontext->write_length = 0;
	if (CHANNEL_TYPE_OUT == pcontext->channel_type &&
	    static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->channel_stat == CHANNEL_STAT_OPENED) {
		/* stream_out is shared resource of vconnection,
			lock it first before operating */
		auto hch = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
		auto pvconnection = http_parser_get_vconnection(pcontext->host,
		                    pcontext->port, hch->connection_cookie);
		if (pvconnection == nullptr) {
			http_parser_log_info(pcontext, LV_DEBUG,
				"virtual connection error in hash table");
			return X_RUNOFF;
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
			pcontext->sched_stat = SCHED_STAT_WAIT;
		}
		return PROCESS_CONTINUE;
	}

	unsigned int tmp_len = STREAM_BLOCK_SIZE;
	pcontext->write_buff = pcontext->stream_out.get_read_buf(&tmp_len);
	pcontext->write_length = tmp_len;
	if (pcontext->write_buff != nullptr) {
		return PROCESS_CONTINUE;
	}
	if (CHANNEL_TYPE_OUT == pcontext->channel_type &&
	    (static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->channel_stat == CHANNEL_STAT_WAITINCHANNEL ||
	    static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->channel_stat == CHANNEL_STAT_WAITRECYCLED)) {
		/* to wait in channel for completing
			out channel handshaking */
		pcontext->sched_stat = SCHED_STAT_WAIT;
	} else if (NULL != pcontext->pfast_context ||
	    hpm_processor_is_in_charge(pcontext) ||
	    mod_cache_is_in_charge(pcontext)) {
		pcontext->stream_out.clear();
		return PROCESS_CONTINUE;
	} else {
		if (pcontext->b_close)
			return X_RUNOFF;
		pcontext->request.clear();
		pcontext->sched_stat = SCHED_STAT_RDHEAD;
	}
	pcontext->stream_out.clear();
	return PROCESS_CONTINUE;
}

static int htparse_rdbody_nochan2(HTTP_CONTEXT *pcontext)
{
	unsigned int size = STREAM_BLOCK_SIZE;
	auto pbuff = pcontext->stream_in.get_write_buf(&size);
	if (NULL == pbuff) {
		http_parser_log_info(pcontext, LV_DEBUG, "out of memory");
		http_5xx(pcontext);
		return X_LOOP;
	}
	auto actual_read = htparse_readsock(pcontext, "EOB", pbuff, size);
	auto current_time = tp_now();
	if (0 == actual_read) {
		http_parser_log_info(pcontext, LV_DEBUG, "connection lost");
		return X_RUNOFF;
	} else if (actual_read > 0) {
		pcontext->connection.last_timestamp = current_time;
		pcontext->stream_in.fwd_write_ptr(actual_read);
		if (hpm_processor_is_in_charge(pcontext)) {
			if (!hpm_processor_write_request(pcontext)) {
				http_5xx(pcontext);
				return X_LOOP;
			}
			if (!hpm_processor_check_end_of_request(
			    pcontext)) {
				return PROCESS_CONTINUE;
			}
			if (!hpm_processor_proc(pcontext)) {
				http_5xx(pcontext);
				return X_LOOP;
			}
			pcontext->sched_stat = SCHED_STAT_WRREP;
			if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
				http_parser_log_info(pcontext, LV_DEBUG, "out of memory");
				http_5xx(pcontext, "Resources exhausted", 503);
				return X_LOOP;
			}
			if (pcontext->stream_out.get_total_length() != 0) {
				unsigned int tmp_len = STREAM_BLOCK_SIZE;
				pcontext->write_buff = pcontext->stream_out.get_read_buf(&tmp_len);
				pcontext->write_length = tmp_len;
			}
			return PROCESS_CONTINUE;
		} else if (NULL != pcontext->pfast_context) {
			if (!mod_fastcgi_write_request(pcontext)) {
				http_5xx(pcontext);
				return X_LOOP;
			}
			if (!mod_fastcgi_check_end_of_read(pcontext)) {
				return PROCESS_CONTINUE;
			}
			if (!mod_fastcgi_relay_content(pcontext)) {
				http_5xx(pcontext, "Bad FastCGI Gateway", 502);
				return X_LOOP;
			}
			pcontext->sched_stat = SCHED_STAT_WRREP;
			if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
				http_parser_log_info(pcontext, LV_DEBUG, "out of memory");
				http_5xx(pcontext, "Resources exhausted", 503);
				return X_LOOP;
			}
			return PROCESS_CONTINUE;
		}
		pcontext->bytes_rw += actual_read;
		if (pcontext->bytes_rw < pcontext->total_length) {
			return PROCESS_CONTINUE;
		}
		return X_RUNOFF;
	}
	if (EAGAIN != errno) {
		http_parser_log_info(pcontext, LV_DEBUG, "connection lost");
		return X_RUNOFF;
	}
	/* check if context is timed out */
	if (CALCULATE_INTERVAL(current_time,
	    pcontext->connection.last_timestamp) < g_timeout) {
		return PROCESS_POLLING_RDONLY;
	}
	http_parser_log_info(pcontext, LV_DEBUG, "I-1935: timeout");
	http_4xx(pcontext, "Request Timeout", 408);
	return X_LOOP;
}

static int htparse_rdbody_nochan(HTTP_CONTEXT *pcontext)
{
	if (0 == pcontext->total_length ||
	    pcontext->bytes_rw < pcontext->total_length) {
		auto ret = htparse_rdbody_nochan2(pcontext);
		if (ret != X_RUNOFF)
			return ret;
	}

	if (strcasecmp(pcontext->request.method, "RPC_IN_DATA") != 0 &&
	    strcasecmp(pcontext->request.method, "RPC_OUT_DATA") != 0) {
		http_parser_log_info(pcontext, LV_DEBUG, "I-1936: unrecognized HTTP method \"%s\"", pcontext->request.method);
		/* other http request here if wanted */
		http_4xx(pcontext, "Method Not Allowed", 405);
		return X_LOOP;
	}
	/* ECHO request */
	char response_buff[1024];
	auto response_len = gx_snprintf(response_buff, GX_ARRAY_SIZE(response_buff),
		"HTTP/1.1 200 Success\r\n"
		"Connection: Keep-Alive\r\n"
		"Content-Length: 20\r\n"
		"Content-Type: application/rpc\r\n\r\n");
	pdu_processor_rts_echo(response_buff + response_len);
	response_len += 20;
	pcontext->stream_out.write(response_buff, response_len);
	pcontext->total_length = response_len;
	pcontext->bytes_rw = 0;
	pcontext->sched_stat = SCHED_STAT_WRREP;
	if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
		http_parser_log_info(pcontext, LV_DEBUG, "out of memory");
		http_5xx(pcontext, "Resources exhausted", 503);
		return X_LOOP;
	}
	return PROCESS_CONTINUE;
}

static int htparse_rdbody(HTTP_CONTEXT *pcontext)
{
	if (pcontext->pchannel == nullptr ||
	    (pcontext->channel_type != CHANNEL_TYPE_IN &&
	    pcontext->channel_type != CHANNEL_TYPE_OUT))
		return htparse_rdbody_nochan(pcontext);

	auto pchannel_in = pcontext->channel_type == CHANNEL_TYPE_IN ? static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel) : nullptr;
	auto pchannel_out = pcontext->channel_type == CHANNEL_TYPE_OUT ? static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel) : nullptr;
	auto frag_length = pcontext->channel_type == CHANNEL_TYPE_IN ?
			   pchannel_in->frag_length : pchannel_out->frag_length;
	auto tmp_len = pcontext->stream_in.get_total_length();
	if (tmp_len < DCERPC_FRAG_LEN_OFFSET + 2 ||
	    (frag_length > 0 && tmp_len < frag_length)) {
		unsigned int size = STREAM_BLOCK_SIZE;
		auto pbuff = pcontext->stream_in.get_write_buf(&size);
		if (NULL == pbuff) {
			http_parser_log_info(pcontext, LV_DEBUG, "out of memory");
			http_5xx(pcontext, "Resources exhausted", 503);
			return X_LOOP;
		}

		auto actual_read = htparse_readsock(pcontext, "EOB", pbuff, size);
		auto current_time = tp_now();
		if (0 == actual_read) {
			http_parser_log_info(pcontext, LV_DEBUG, "connection lost");
			return X_RUNOFF;
		} else if (actual_read > 0) {
			pcontext->bytes_rw += actual_read;
			if (pcontext->bytes_rw > pcontext->total_length) {
				http_parser_log_info(pcontext, LV_DEBUG,
					"content length overflow when reading body");
				return X_RUNOFF;
			}
			pcontext->connection.last_timestamp = current_time;
			pcontext->stream_in.fwd_write_ptr(actual_read);
		} else {
			if (EAGAIN != errno) {
				http_parser_log_info(pcontext, LV_DEBUG, "connection lost");
				return X_RUNOFF;
			}
			/* check if context is timed out */
			if (CALCULATE_INTERVAL(current_time, pcontext->connection.last_timestamp) < g_timeout) {
				return PROCESS_POLLING_RDONLY;
			}
			http_parser_log_info(pcontext, LV_DEBUG, "I-1937: timeout");
			http_4xx(pcontext, "Request Timeout", 408);
			return X_LOOP;
		}
	}

	unsigned int tmp_len2 = STREAM_BLOCK_SIZE;
	auto pbuff = pcontext->stream_in.get_read_buf(&tmp_len2);
	if (NULL == pbuff) {
		return PROCESS_POLLING_RDONLY;
	}
	tmp_len = tmp_len2;
	pcontext->stream_in.rewind_read_ptr(tmp_len);
	if (tmp_len < DCERPC_FRAG_LEN_OFFSET + 2) {
		return PROCESS_CONTINUE;
	}

	if (0 == frag_length) {
		static_assert(std::is_same_v<decltype(frag_length), uint16_t>, "");
		auto pbd = static_cast<uint8_t *>(pbuff);
		auto pfrag = &pbd[DCERPC_FRAG_LEN_OFFSET];
		frag_length = (pbd[DCERPC_DREP_OFFSET] & DCERPC_DREP_LE) ?
			      le16p_to_cpu(pfrag) : be16p_to_cpu(pfrag);
		if (CHANNEL_TYPE_IN == pcontext->channel_type) {
			pchannel_in->frag_length = frag_length;
		} else {
			pchannel_out->frag_length = frag_length;
		}
	}

	if (tmp_len < frag_length) {
		return PROCESS_CONTINUE;
	}

	g_context_key = pcontext;
	DCERPC_CALL *pcall = nullptr;
	auto result = pdu_processor_rts_input(static_cast<char *>(pbuff),
		 frag_length, &pcall);
	if (CHANNEL_TYPE_IN == pcontext->channel_type &&
	    CHANNEL_STAT_OPENED == pchannel_in->channel_stat) {
		if (PDU_PROCESSOR_ERROR == result) {
			/* ignore rts processing error under this condition */
			result = PDU_PROCESSOR_INPUT;
		} else if (PDU_PROCESSOR_FORWARD == result) {
			/* only under this condition, we can
			forward pdu to pdu processor */
			auto pvconnection = http_parser_get_vconnection(pcontext->host,
				pcontext->port, pchannel_in->connection_cookie);
			if (pvconnection == nullptr) {
				http_parser_log_info(pcontext, LV_DEBUG,
					"virtual connection error in hash table");
				return X_RUNOFF;
			}
			if (pvconnection->pcontext_in != pcontext ||
			    NULL == pvconnection->pprocessor) {
				pvconnection.put();
				http_parser_log_info(pcontext, LV_DEBUG,
					"virtual connection error in hash table");
				return X_RUNOFF;
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
					pvconnection->pcontext_out->sched_stat =
						SCHED_STAT_WRREP;
					contexts_pool_signal(pvconnection->pcontext_out);
				}
			}
		}
	}

	pcontext->stream_in.fwd_read_ptr(frag_length);
	if (CHANNEL_TYPE_IN == pcontext->channel_type) {
		pchannel_in->frag_length = 0;
	} else {
		pchannel_out->frag_length = 0;
	}
	if (http_parser_reconstruct_stream(pcontext->stream_in) < 0) {
		http_parser_log_info(pcontext, LV_DEBUG, "out of memory");
		http_5xx(pcontext, "Resources exhausted", 503);
		return X_LOOP;
	}

	switch (result) {
	case PDU_PROCESSOR_ERROR:
	case PDU_PROCESSOR_FORWARD:
		http_parser_log_info(pcontext, LV_DEBUG, "pdu process error!");
		return X_RUNOFF;
	case PDU_PROCESSOR_INPUT:
		/* do nothing */
		return PROCESS_CONTINUE;
	case PDU_PROCESSOR_OUTPUT: {
		if (CHANNEL_TYPE_OUT == pcontext->channel_type) {
			/* only under two conditions below, out channel
			   will produce PDU_PROCESSOR_OUTPUT */
			if (pchannel_out->channel_stat != CHANNEL_STAT_OPENSTART &&
			    pchannel_out->channel_stat != CHANNEL_STAT_RECYCLING) {
				http_parser_log_info(pcontext, LV_DEBUG,
					"pdu process error! out channel can't output "
					"itself after virtual connection established");
				return X_RUNOFF;
			}
			/* first send http response head */
			char dstring[128], response_buff[1024];
			rfc1123_dstring(dstring, arsizeof(dstring));
			auto response_len = gx_snprintf(
				response_buff, GX_ARRAY_SIZE(response_buff),
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
			pcontext->sched_stat = SCHED_STAT_WRREP;
			if (CHANNEL_STAT_OPENSTART == pchannel_out->channel_stat) {
				pchannel_out->channel_stat =
					CHANNEL_STAT_WAITINCHANNEL;
			} else {
				pchannel_out->channel_stat =
					CHANNEL_STAT_WAITRECYCLED;
			}
			return X_LOOP;
		}
		/* in channel here, find the corresponding out channel first! */
		auto pvconnection = http_parser_get_vconnection(pcontext->host,
			pcontext->port, pchannel_in->connection_cookie);
		if (pvconnection == nullptr) {
			pdu_processor_free_call(pcall);
			http_parser_log_info(pcontext, LV_DEBUG,
				"cannot find virtual connection in hash table");
			return X_RUNOFF;
		}

		if ((pcontext != pvconnection->pcontext_in &&
		    pcontext != pvconnection->pcontext_insucc)
		    || NULL == pvconnection->pcontext_out) {
			pvconnection.put();
			pdu_processor_free_call(pcall);
			http_parser_log_info(pcontext, LV_DEBUG,
				"missing out channel in virtual connection");
			return X_RUNOFF;
		}
		auto och = static_cast<RPC_OUT_CHANNEL *>(pvconnection->pcontext_out->pchannel);
		if (och->b_obsolete) {
			auto hch = static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel);
			pdu_processor_output_pdu(pcall, &hch->pdu_list);
			pvconnection.put();
			pdu_processor_free_call(pcall);
			return PROCESS_CONTINUE;
		}
		pdu_processor_output_pdu(pcall, &och->pdu_list);
		pvconnection->pcontext_out->sched_stat = SCHED_STAT_WRREP;
		contexts_pool_signal(pvconnection->pcontext_out);
		pvconnection.put();
		pdu_processor_free_call(pcall);
		return PROCESS_CONTINUE;
	}
	case PDU_PROCESSOR_TERMINATE:
		return X_RUNOFF;
	}
	return X_RUNOFF;
}

static int htparse_waitinchannel(HTTP_CONTEXT *pcontext, RPC_OUT_CHANNEL *pchannel_out)
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
				http_parser_log_info(pcontext, LV_DEBUG,
					"pdu process error! fail to setup conn/c2");
				return X_RUNOFF;
			}
			pdu_processor_output_pdu(
				pchannel_out->pcall, &pchannel_out->pdu_list);
			pcontext->sched_stat = SCHED_STAT_WRREP;
			pchannel_out->channel_stat = CHANNEL_STAT_OPENED;
			return X_LOOP;
		}
		pvconnection.put();
	}

	auto current_time = tp_now();
	/* check if context is timed out */
	if (CALCULATE_INTERVAL(current_time, pcontext->connection.last_timestamp) <
	    OUT_CHANNEL_MAX_WAIT) {
		return PROCESS_IDLE;
	}
	http_parser_log_info(pcontext, LV_DEBUG, "no correpoding in "
		"channel coming during maximum waiting interval");
	return X_RUNOFF;
}

static int htparse_waitrecycled(HTTP_CONTEXT *pcontext, RPC_OUT_CHANNEL *pchannel_out)
{
	auto pvconnection = http_parser_get_vconnection(pcontext->host,
		pcontext->port, pchannel_out->connection_cookie);
	if (pvconnection != nullptr) {
		if (pvconnection->pcontext_out == pcontext
		    && NULL != pvconnection->pcontext_in) {
			auto pchannel_in = static_cast<RPC_IN_CHANNEL *>(pvconnection->pcontext_in->pchannel);
			pchannel_out->client_keepalive =
				pchannel_in->client_keepalive;
			pchannel_out->channel_stat = CHANNEL_STAT_OPENED;
			DOUBLE_LIST_NODE *pnode;
			while ((pnode = double_list_pop_front(&pchannel_in->pdu_list)) != nullptr)
				double_list_append_as_tail(
					&pchannel_out->pdu_list, pnode);
			if (0 == double_list_get_nodes_num(
			    &pchannel_out->pdu_list)) {
				pcontext->sched_stat = SCHED_STAT_WAIT;
			} else {
				pcontext->sched_stat = SCHED_STAT_WRREP;
			}
			return X_LOOP;
		}
		pvconnection.put();
	}

	auto current_time = tp_now();
	/* check if context is timed out */
	if (CALCULATE_INTERVAL(current_time, pcontext->connection.last_timestamp) <
	    OUT_CHANNEL_MAX_WAIT) {
		return PROCESS_IDLE;
	}
	http_parser_log_info(pcontext, LV_DEBUG, "channel is not "
		"recycled during maximum waiting interval");
	return X_RUNOFF;
}

static int htparse_wait(HTTP_CONTEXT *pcontext)
{
	if (hpm_processor_is_in_charge(pcontext))
		return PROCESS_IDLE;
	/* only hpm_processor or out channel can be set to SCHED_STAT_WAIT */
	auto pchannel_out = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
	if (CHANNEL_STAT_WAITINCHANNEL == pchannel_out->channel_stat) {
		return htparse_waitinchannel(pcontext, pchannel_out);
	} else if (CHANNEL_STAT_WAITRECYCLED == pchannel_out->channel_stat) {
		return htparse_waitrecycled(pcontext, pchannel_out);
	} else if (CHANNEL_STAT_RECYCLED == pchannel_out->channel_stat) {
		return X_RUNOFF;
	}

	char tmp_buff;
	if (recv(pcontext->connection.sockd, &tmp_buff, 1, MSG_PEEK) == 0) {
		http_parser_log_info(pcontext, LV_DEBUG, "connection lost");
		return X_RUNOFF;
	}

	auto current_time = tp_now();
	/* check keep alive */
	if (CALCULATE_INTERVAL(current_time, pcontext->connection.last_timestamp) <
	    pchannel_out->client_keepalive / 2)
		return PROCESS_IDLE;
	if (!pdu_processor_rts_ping(pchannel_out->pcall))
		return PROCESS_IDLE;
	/* stream_out is shared resource of vconnection,
		lock it first before operating */
	auto hch = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
	auto pvconnection = http_parser_get_vconnection(pcontext->host,
	                    pcontext->port, hch->connection_cookie);
	pdu_processor_output_pdu(
		pchannel_out->pcall, &pchannel_out->pdu_list);
	pcontext->sched_stat = SCHED_STAT_WRREP;
	return X_LOOP;
}

int http_parser_process(HTTP_CONTEXT *pcontext)
{
	int ret = X_RUNOFF;
	do {
		switch (pcontext->sched_stat) {
		case SCHED_STAT_INITSSL: ret = htparse_initssl(pcontext); break;
		case SCHED_STAT_RDHEAD: ret = htparse_rdhead(pcontext); break;
		case SCHED_STAT_RDBODY: ret = htparse_rdbody(pcontext); break;
		case SCHED_STAT_WRREP: ret = htparse_wrrep(pcontext); break;
		case SCHED_STAT_WAIT: ret = htparse_wait(pcontext); break;
		default: continue;
		}
	} while (ret == X_LOOP);
	if (ret != X_RUNOFF)
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
		printf("noticed async_stop\n");
		return;
	}
	auto pvconnection = http_parser_get_vconnection(host, port, connection_cookie);
	if (pvconnection == nullptr)
		return;
	if (NULL == pvconnection->pcontext_out) {
		return;
	}
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
	pvconnection->pcontext_out->sched_stat = SCHED_STAT_WRREP;
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

http_request::http_request(alloc_limiter<file_block> *b)
{
	mem_file_init(&f_request_uri, b);
	mem_file_init(&f_host, b);
	mem_file_init(&f_user_agent, b);
	mem_file_init(&f_accept, b);
	mem_file_init(&f_accept_language, b);
	mem_file_init(&f_accept_encoding, b);
	mem_file_init(&f_content_type, b);
	mem_file_init(&f_content_length, b);
	mem_file_init(&f_transfer_encoding, b);
	mem_file_init(&f_cookie, b);
	mem_file_init(&f_others, b);
}

http_request::~http_request()
{
	mem_file_free(&f_request_uri);
	mem_file_free(&f_host);
	mem_file_free(&f_user_agent);
	mem_file_free(&f_accept);
	mem_file_free(&f_accept_language);
	mem_file_free(&f_accept_encoding);
	mem_file_free(&f_content_type);
	mem_file_free(&f_content_length);
	mem_file_free(&f_transfer_encoding);
	mem_file_free(&f_cookie);
	mem_file_free(&f_others);
}

void http_request::clear()
{
	method[0] = '\0';
	version[0] = '\0';
	f_request_uri.clear();
	f_host.clear();
	f_user_agent.clear();
	f_accept.clear();
	f_accept_language.clear();
	f_accept_encoding.clear();
	f_content_type.clear();
	f_content_length.clear();
	f_transfer_encoding.clear();
	f_cookie.clear();
	f_others.clear();
}

http_context::http_context() :
	request(&g_file_allocator), stream_in(&g_blocks_allocator),
	stream_out(stream_in.allocator)
{
	auto pcontext = this;
	pcontext->node.pdata = pcontext;
}

static void http_parser_context_clear(HTTP_CONTEXT *pcontext)
{
    if (NULL == pcontext) {
        return;
    }
	pcontext->connection.reset();
	pcontext->sched_stat = 0;
	pcontext->request.clear();
	pcontext->stream_in.clear();
	pcontext->stream_out.clear();
	pcontext->write_buff = NULL;
	pcontext->write_offset = 0;
	pcontext->write_length = 0;
	pcontext->b_close = TRUE;
	pcontext->b_authed = FALSE;
	pcontext->auth_times = 0;
	pcontext->username[0] = '\0';
	pcontext->password[0] = '\0';
	pcontext->maildir[0] = '\0';
	pcontext->lang[0] = '\0';
	pcontext->channel_type = 0;
	pcontext->pchannel = NULL;
	pcontext->pfast_context = NULL;
}

http_context::~http_context()
{
	auto pcontext = this;
	if (hpm_processor_is_in_charge(pcontext))
		hpm_processor_put_context(pcontext);
	else if (pcontext->pfast_context != nullptr)
		mod_fastcgi_put_context(pcontext);
	else if (mod_cache_is_in_charge(pcontext))
		mod_cache_put_context(pcontext);
}

void http_parser_log_info(const HTTP_CONTEXT *pcontext, int level,
    const char *format, ...)
{
	va_list ap;
	char log_buf[2048];

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	va_end(ap);
	log_buf[sizeof(log_buf) - 1] = '\0';
	
	if ('\0' == pcontext->username[0]) {
		mlog(level, "ctxid=%u, host=[%s]  %s",
			pcontext->context_id, pcontext->connection.client_ip, log_buf);
	} else {
		mlog(level, "user=%s, host=[%s]  %s",
			pcontext->username, pcontext->connection.client_ip, log_buf);
	}

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
	if (NULL == pcontext) {
		return false;
	}
	
	if (0 != strcasecmp(username, pcontext->username)) {
		return false;
	}
	
	strncpy(password, pcontext->password, 128);
	return true;
}

BOOL http_parser_try_create_vconnection(HTTP_CONTEXT *pcontext)
{
	const char *conn_cookie;
	
	if (CHANNEL_TYPE_IN == pcontext->channel_type) {
		auto chan = static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel);
		conn_cookie = chan->connection_cookie;
	} else if (CHANNEL_TYPE_OUT == pcontext->channel_type) {
		auto chan = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
		conn_cookie = chan->connection_cookie;
	} else {
		return FALSE;
	}
 RETRY_QUERY:
	auto pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, conn_cookie);
	if (pvconnection != nullptr) {
		if (pcontext->channel_type == CHANNEL_TYPE_OUT) {
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
		http_parser_log_info(pcontext, LV_DEBUG, "W-1293: vconn hash full");
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
		http_parser_log_info(pcontext, LV_DEBUG, "W-1292: Out of memory\n");
		return false;
	}
	if (!xp.second) {
		http_parser_log_info(pcontext, LV_DEBUG, "W-1291: vconn suddenly started existing\n");
		goto RETRY_QUERY;
	}
	auto nc = &xp.first->second;
	nc->pprocessor = pdu_processor_create(pcontext->host, pcontext->port);
	if (nc->pprocessor == nullptr) {
		g_vconnection_hash.erase(xp.first);
		http_parser_log_info(pcontext, LV_DEBUG,
			"fail to create processor on %s:%d",
			pcontext->host, pcontext->port);
		return FALSE;
	}
	if (CHANNEL_TYPE_OUT == pcontext->channel_type) {
		nc->pcontext_out = pcontext;
	} else {
		nc->pcontext_in = pcontext;
	}
	vc_hold.unlock();
	return TRUE;
}

void http_parser_set_outchannel_flowcontrol(HTTP_CONTEXT *pcontext,
	uint32_t bytes_received, uint32_t available_window)
{
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return;
	}
	auto hch = static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel);
	auto pvconnection = http_parser_get_vconnection(pcontext->host,
	                    pcontext->port, hch->connection_cookie);
	if (pvconnection == nullptr)
		return;
	if (NULL == pvconnection->pcontext_out) {
		return;
	}
	auto pchannel_out = static_cast<RPC_OUT_CHANNEL *>(pvconnection->pcontext_out->pchannel);
	if (bytes_received + available_window > pchannel_out->bytes_sent) {
		pchannel_out->available_window = bytes_received
			+ available_window - pchannel_out->bytes_sent;
		contexts_pool_signal(pvconnection->pcontext_out);
	} else {
		pchannel_out->available_window = 0;
	}
}

BOOL http_parser_recycle_inchannel(
	HTTP_CONTEXT *pcontext, const char *predecessor_cookie)
{
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return FALSE;
	}
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

BOOL http_parser_recycle_outchannel(
	HTTP_CONTEXT *pcontext, const char *predecessor_cookie)
{
	if (CHANNEL_TYPE_OUT != pcontext->channel_type) {
		return FALSE;
	}
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
	pvconnection->pcontext_out->sched_stat = SCHED_STAT_WRREP;
	contexts_pool_signal(pvconnection->pcontext_out);
	hch->client_keepalive = och->client_keepalive;
	hch->available_window = och->window_size;
	hch->window_size = och->window_size;
	pvconnection->pcontext_outsucc = pcontext;
	return TRUE;
}

BOOL http_parser_activate_inrecycling(
	HTTP_CONTEXT *pcontext, const char *successor_cookie)
{
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return FALSE;
	}
	auto hch = static_cast<RPC_IN_CHANNEL *>(pcontext->pchannel);
	auto pvconnection = http_parser_get_vconnection(pcontext->host,
	                    pcontext->port, hch->connection_cookie);
	if (pvconnection == nullptr ||
	    pvconnection->pcontext_insucc != pcontext ||
	    strcmp(successor_cookie, static_cast<RPC_IN_CHANNEL *>(pvconnection->pcontext_insucc->pchannel)->channel_cookie) != 0)
		return false;
	if (NULL != pvconnection->pcontext_in) {
		auto pchannel_in = static_cast<RPC_IN_CHANNEL *>(pvconnection->pcontext_in->pchannel);
		pchannel_in->channel_stat = CHANNEL_STAT_RECYCLED;
	}
	pvconnection->pcontext_in = pcontext;
	hch->channel_stat = CHANNEL_STAT_OPENED;
	pvconnection->pcontext_insucc = NULL;
	return TRUE;
}

BOOL http_parser_activate_outrecycling(
	HTTP_CONTEXT *pcontext, const char *successor_cookie)
{
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return FALSE;
	}
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
		http_parser_log_info(pcontext, LV_DEBUG,
			"pdu process error! fail to setup r2/b3");
		return FALSE;
	}
	pdu_processor_output_pdu(
		pchannel_out->pcall, &pchannel_out->pdu_list);
	pvconnection->pcontext_out->sched_stat = SCHED_STAT_WRREP;
	contexts_pool_signal(pvconnection->pcontext_out);
	pvconnection->pcontext_out = pvconnection->pcontext_outsucc;
	pvconnection->pcontext_outsucc = NULL;
	contexts_pool_signal(pvconnection->pcontext_out);
	return TRUE;
}

void http_parser_set_keep_alive(HTTP_CONTEXT *pcontext, time_duration keepalive)
{
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
