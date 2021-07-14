// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
/* http parser is a module, which first read data from socket, parses rpc over http and
   relay the stream to pdu processor. it also process other http request
 */ 
#include <atomic>
#include <cassert>
#include <cerrno>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/util.hpp>
#include "pdu_ndr.h"
#include "resource.h"
#include "mod_cache.h"
#include <gromox/mail_func.hpp>
#include <gromox/lib_buffer.hpp>
#include "mod_rewrite.h"
#include "http_parser.h"
#include <gromox/threads_pool.hpp>
#include "hpm_processor.h"
#include "system_services.h"
#include "blocks_allocator.h"
#include <fcntl.h>
#include <cstdio>
#include <unistd.h>
#include <cstring>
#include <cstdarg>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/err.h>
#if (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2090000fL) || \
    (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x1010000fL)
#	define OLD_SSL 1
#endif
#define	MAX_RECLYING_REMAINING						0x4000000

#define OUT_CHANNEL_MAX_LENGTH						0x40000000

using namespace gromox;

namespace {
struct VIRTUAL_CONNECTION {
	~VIRTUAL_CONNECTION();
	std::atomic<int> reference{0};
	std::mutex lock;
	bool locked = false;
	PDU_PROCESSOR *pprocessor = nullptr;
	HTTP_CONTEXT *pcontext_in = nullptr, *pcontext_insucc = nullptr;
	HTTP_CONTEXT *pcontext_out = nullptr, *pcontext_outsucc = nullptr;
};
}

static std::unordered_map<std::string, VIRTUAL_CONNECTION> g_vconnection_hash;

namespace {
class VCONN_REF {
	public:
	VCONN_REF() = default;
	explicit VCONN_REF(VIRTUAL_CONNECTION *p, decltype(g_vconnection_hash)::iterator i) :
		pvconnection(p), m_hold(p->lock), m_iter(std::move(i)) {}
	VCONN_REF(VCONN_REF &&) = delete;
	~VCONN_REF() { put(); }
	void operator=(VCONN_REF &&) = delete;
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

static size_t g_context_num;
static std::atomic<bool> g_async_stop{false};
static BOOL g_support_ssl;
static SSL_CTX *g_ssl_ctx;
static int g_max_auth_times;
static int g_block_auth_fail;
static unsigned int g_timeout;
static pthread_key_t g_context_key;
static LIB_BUFFER *g_file_allocator;
static std::vector<HTTP_CONTEXT> g_context_list;
static std::vector<SCHEDULE_CONTEXT *> g_context_list2;
static char g_certificate_path[256];
static char g_private_key_path[256];
static char g_certificate_passwd[1024];
static std::unique_ptr<std::mutex[]> g_ssl_mutex_buf;
static LIB_BUFFER *g_inchannel_allocator;
static LIB_BUFFER *g_outchannel_allocator;
static std::mutex g_vconnection_lock;

static void http_parser_context_clear(HTTP_CONTEXT *pcontext);
static void http_parser_request_clear(HTTP_REQUEST *prequest);

void http_parser_init(size_t context_num, unsigned int timeout,
	int max_auth_times, int block_auth_fail, BOOL support_ssl,
	const char *certificate_path, const char *cb_passwd,
	const char *key_path)
{
    g_context_num           = context_num;
    g_timeout               = timeout;
	g_max_auth_times        = max_auth_times;
	g_block_auth_fail       = block_auth_fail;
	g_support_ssl           = support_ssl;
	g_async_stop = false;
	
	if (TRUE == support_ssl) {
		gx_strlcpy(g_certificate_path, certificate_path, GX_ARRAY_SIZE(g_certificate_path));
		if (NULL != cb_passwd) {
			gx_strlcpy(g_certificate_passwd, cb_passwd, GX_ARRAY_SIZE(g_certificate_passwd));
		} else {
			g_certificate_passwd[0] = '\0';
		}
		gx_strlcpy(g_private_key_path, key_path, GX_ARRAY_SIZE(g_private_key_path));
	}
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
		pdu_processor_destroy(pprocessor);
}

/* 
 * run the http parser module
 *    @return
 *         0    success
 *        <>0    fail    
 */
int http_parser_run()
{
	pthread_key_create(&g_context_key, NULL);
	if (TRUE == g_support_ssl) {
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
	g_file_allocator = lib_buffer_init(FILE_ALLOC_SIZE,
							g_context_num * 16, TRUE);
	if (NULL == g_file_allocator) {
		printf("[http_parser]: Failed to init mem file allocator\n");
		return -6;
	}
	try {
		g_context_list.resize(g_context_num);
		g_context_list2.resize(g_context_num);
		for (size_t i = 0; i < g_context_num; ++i) {
			g_context_list[i].context_id = i;
			g_context_list2[i] = &g_context_list[i];
		}
	} catch (const std::bad_alloc &) {
		printf("[http_parser]: Failed to allocate HTTP contexts\n");
        return -8;
    }
	g_inchannel_allocator = lib_buffer_init(
		sizeof(RPC_IN_CHANNEL), g_context_num, TRUE);
	if (NULL == g_inchannel_allocator) {
		return -9;
	}
	g_outchannel_allocator = lib_buffer_init(
		sizeof(RPC_OUT_CHANNEL), g_context_num, TRUE);
	if (NULL == g_outchannel_allocator) {
		return -10;
	}
    return 0;
}

/* 
 * stop the http parser module
 * @return
 *          0  success
 *         <>0 fail
 */
int http_parser_stop()
{
	if (NULL != g_inchannel_allocator) {
		lib_buffer_free(g_inchannel_allocator);
		g_inchannel_allocator = NULL;
	}
	if (NULL != g_outchannel_allocator) {
		lib_buffer_free(g_outchannel_allocator);
		g_outchannel_allocator = NULL;
	}
	g_context_list2.clear();
	g_context_list.clear();
	g_vconnection_hash.clear();
	if (NULL != g_file_allocator) {
		lib_buffer_free(g_file_allocator);
		g_file_allocator = NULL;
	}
	if (TRUE == g_support_ssl && NULL != g_ssl_ctx) {
		SSL_CTX_free(g_ssl_ctx);
		g_ssl_ctx = NULL;
	}
	if (TRUE == g_support_ssl && NULL != g_ssl_mutex_buf) {
		CRYPTO_set_id_callback(NULL);
		CRYPTO_set_locking_callback(NULL);
		g_ssl_mutex_buf.reset();
	}
	pthread_key_delete(g_context_key);
    return 0;
}

int http_parser_threads_event_proc(int action)
{
	return 0;
}

int http_parser_get_context_socket(SCHEDULE_CONTEXT *ctx)
{
	return static_cast<HTTP_CONTEXT *>(ctx)->connection.sockd;
}

struct timeval http_parser_get_context_timestamp(SCHEDULE_CONTEXT *ctx)
{
	return static_cast<HTTP_CONTEXT *>(ctx)->connection.last_timestamp;
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
	
	mem_file_seek(pfile_others, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	name_len = strlen(field_name);
	if (name_len >= 64) {
		return FALSE;
	}
	while (MEM_END_OF_FILE != mem_file_read(
		pfile_others, &tmp_len, sizeof(int))) {
		if (name_len == tmp_len) {
			 mem_file_read(pfile_others, name_buff, tmp_len);
			 if (0 == strncasecmp(name_buff, field_name, name_len)) {
				 mem_file_read(pfile_others, &tmp_len, sizeof(int));
				 if (tmp_len >= buff_len) {
					 return FALSE;
				 }
				 mem_file_read(pfile_others, field_value, tmp_len);
				 field_value[tmp_len] = '\0';
				 return TRUE;
			 }
		} else {
			mem_file_seek(pfile_others, MEM_FILE_READ_PTR,
							tmp_len, MEM_FILE_SEEK_CUR);
		}
		mem_file_read(pfile_others, &tmp_len, sizeof(int));
		mem_file_seek(pfile_others, MEM_FILE_READ_PTR,
						tmp_len, MEM_FILE_SEEK_CUR);
	}
	return FALSE;
}

static int http_parser_reconstruct_stream(
	STREAM *pstream_src, STREAM *pstream_dst)
{
	int size;
	int size1;
	int size1_used;
	
	stream_init(pstream_dst, blocks_allocator_get_allocator());
	size = STREAM_BLOCK_SIZE;
	auto pbuff = stream_getbuffer_for_reading(pstream_src,
	             reinterpret_cast<unsigned int *>(&size));
	if (NULL == pbuff) {
		return 0;
	}
	size1 = STREAM_BLOCK_SIZE;
	auto pbuff1 = stream_getbuffer_for_writing(pstream_dst,
	              reinterpret_cast<unsigned int *>(&size1));
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
			stream_forward_writing_ptr(pstream_dst, STREAM_BLOCK_SIZE);
			pbuff1 = stream_getbuffer_for_writing(pstream_dst,
			         reinterpret_cast<unsigned int *>(&size1));
			if (NULL == pbuff1) {
				stream_free(pstream_dst);
				return -1;
			}
			size1_used = size - size_copied;
			memcpy(pbuff1, static_cast<char *>(pbuff) + size_copied, size1_used);
		}
		size = STREAM_BLOCK_SIZE;
		pbuff = stream_getbuffer_for_reading(pstream_src,
		        reinterpret_cast<unsigned int *>(&size));
	} while (NULL != pbuff);
	stream_forward_writing_ptr(pstream_dst, size1_used);
	return stream_get_total_length(pstream_dst);
}

static void http_4xx(HTTP_CONTEXT *ctx, const char *msg = "Bad Request",
    unsigned int code = 400)
{
	if (hpm_processor_check_context(ctx))
		hpm_processor_put_context(ctx);
	else if (ctx->pfast_context != nullptr)
		mod_fastcgi_put_context(ctx);
	else if (mod_cache_check_caching(ctx))
		mod_cache_put_context(ctx);

	char dstring[128], response_buff[1024];
	rfc1123_dstring(dstring, arsizeof(dstring));
	auto response_len = gx_snprintf(response_buff, GX_ARRAY_SIZE(response_buff),
		"HTTP/1.1 %u %s\r\n"
		"Date: %s\r\n"
		"Server: %s\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n", code, msg, dstring, resource_get_string("HOST_ID"));
	stream_write(&ctx->stream_out, response_buff, response_len);
	ctx->total_length = response_len;
	ctx->bytes_rw = 0;
	ctx->b_close = TRUE;
	ctx->sched_stat = SCHED_STAT_WRREP;
}

static void http_5xx(HTTP_CONTEXT *ctx, const char *msg = "Internal Server Error",
    unsigned int code = 500)
{
	if (hpm_processor_check_context(ctx))
		hpm_processor_put_context(ctx);
	else if (ctx->pfast_context != nullptr)
		mod_fastcgi_put_context(ctx);
	else if (mod_cache_check_caching(ctx))
		mod_cache_put_context(ctx);

	char dstring[128], response_buff[1024];
	rfc1123_dstring(dstring, arsizeof(dstring));
	auto response_len = gx_snprintf(response_buff, GX_ARRAY_SIZE(response_buff),
		"HTTP/1.1 %u %s\r\n"
		"Date: %s\r\n"
		"Server: %s\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n", code, msg, dstring, resource_get_string("HOST_ID"));
	stream_write(&ctx->stream_out, response_buff, response_len);
	ctx->total_length = response_len;
	ctx->bytes_rw = 0;
	ctx->b_close = TRUE;
	ctx->sched_stat = SCHED_STAT_WRREP;
}

static int http_end(HTTP_CONTEXT *ctx)
{
	if (hpm_processor_check_context(ctx))
		hpm_processor_put_context(ctx);
	else if (ctx->pfast_context != nullptr)
		mod_fastcgi_put_context(ctx);
	else if (mod_cache_check_caching(ctx))
		mod_cache_put_context(ctx);

	if (ctx->pchannel != nullptr) {
		DOUBLE_LIST_NODE *pnode;
		if (ctx->channel_type == CHANNEL_TYPE_IN) {
			auto chan = static_cast<RPC_IN_CHANNEL *>(ctx->pchannel);
			auto conn = http_parser_get_vconnection(ctx->host,
			            ctx->port, chan->connection_cookie);
			if (conn != nullptr) {
				if (conn->pcontext_in == ctx)
					conn->pcontext_in = nullptr;
				conn.put();
			}
			while ((pnode = double_list_pop_front(&chan->pdu_list)) != nullptr) {
				free(static_cast<BLOB_NODE *>(pnode->pdata)->blob.data);
				pdu_processor_free_blob(static_cast<BLOB_NODE *>(pnode->pdata));
			}
			double_list_free(&chan->pdu_list);
			lib_buffer_put(g_inchannel_allocator, ctx->pchannel);
		} else {
			auto chan = static_cast<RPC_OUT_CHANNEL *>(ctx->pchannel);
			auto conn = http_parser_get_vconnection(ctx->host,
			            ctx->port, chan->connection_cookie);
			if (conn != nullptr) {
				if (conn->pcontext_out == ctx)
					conn->pcontext_out = nullptr;
				conn.put();
			}
			if (chan->pcall != nullptr) {
				pdu_processor_free_call(chan->pcall);
				chan->pcall = nullptr;
			}
			while ((pnode = double_list_pop_front(&chan->pdu_list)) != nullptr) {
				free(static_cast<BLOB_NODE *>(pnode->pdata)->blob.data);
				pdu_processor_free_blob(static_cast<BLOB_NODE *>(pnode->pdata));
			}
			double_list_free(&chan->pdu_list);
			lib_buffer_put(g_outchannel_allocator, ctx->pchannel);
		}
		ctx->pchannel = nullptr;
	}

	if (ctx->connection.ssl != nullptr) {
		SSL_shutdown(ctx->connection.ssl);
		SSL_free(ctx->connection.ssl);
		ctx->connection.ssl = nullptr;
	}
	close(ctx->connection.sockd);
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
			http_parser_log_info(pcontext, 6, "out of SSL object");
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
		http_parser_log_info(pcontext, 6, "fail to accept"
				" SSL connection, errno is %d", ssl_errno);
		return X_RUNOFF;
	}
	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	if (CALCULATE_INTERVAL(current_time,
	    pcontext->connection.last_timestamp) < g_timeout) {
		return PROCESS_POLLING_RDONLY;
	}
	http_parser_log_info(pcontext, 6, "time out");
	http_4xx(pcontext, "Request Timeout", 408);
	return X_LOOP;
}

static int htparse_rdhead_no(HTTP_CONTEXT *pcontext, char *line, unsigned int line_length)
{
	auto ptoken = static_cast<char *>(memchr(line, ' ', line_length));
	if (NULL == ptoken) {
		http_parser_log_info(pcontext, 6, "request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	size_t tmp_len = ptoken - line;
	if (tmp_len >= 32) {
		http_parser_log_info(pcontext, 6, "request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}

	memcpy(pcontext->request.method, line, tmp_len);
	pcontext->request.method[tmp_len] = '\0';
	auto ptoken1 = static_cast<char *>(memchr(ptoken + 1, ' ', line_length - tmp_len - 1));
	if (NULL == ptoken1) {
		http_parser_log_info(pcontext, 6, "request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	size_t tmp_len1 = ptoken1 - ptoken - 1;
	tmp_len = line_length - (ptoken1 + 6 - line);
	if (0 != strncasecmp(ptoken1 + 1,
	    "HTTP/", 5) || tmp_len >= 8) {
		http_parser_log_info(pcontext, 6, "request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	if (FALSE == mod_rewrite_process(ptoken + 1,
	    tmp_len1, &pcontext->request.f_request_uri)) {
	    mem_file_write(&pcontext->request.f_request_uri,
			ptoken + 1, tmp_len1);
	}
	memcpy(pcontext->request.version, ptoken1 + 6, tmp_len);
	pcontext->request.version[tmp_len] = '\0';
	return X_RUNOFF;
}

static int htparse_rdhead_mt(HTTP_CONTEXT *pcontext, char *line, unsigned int line_length)
{
	auto ptoken = static_cast<char *>(memchr(line, ':', line_length));
	if (NULL == ptoken) {
		http_parser_log_info(pcontext,
			6, "request method error");
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
	while (ptoken - line < line_length) {
		if (' ' != *ptoken && '\t' != *ptoken) {
			break;
		}
		ptoken++;
	}
	tmp_len = line_length - static_cast<size_t>(ptoken - line);
	if (0 == strcasecmp(field_name, "Host")) {
		mem_file_write(&pcontext->request.f_host,
			ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name, "User-Agent")) {
		mem_file_write(&pcontext->request.f_user_agent,
			ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name, "Accept")) {
		mem_file_write(&pcontext->request.f_accept,
			ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Accept-Language")) {
		mem_file_write(&pcontext->request.f_accept_language,
			ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Accept-Encoding")) {
		mem_file_write(&pcontext->request.f_accept_encoding,
			ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Content-Type")) {
		mem_file_write(&pcontext->request.f_content_type,
			ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Content-Length")) {
		mem_file_write(&pcontext->request.f_content_length,
			ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name,
		"Transfer-Encoding")) {
		mem_file_write(&pcontext->request.f_transfer_encoding,
			ptoken, tmp_len);
	} else if (0 == strcasecmp(field_name, "Cookie")) {
		mem_file_write(&pcontext->request.f_cookie,
			ptoken, tmp_len);
	} else {
		if (0 == strcasecmp(field_name, "Connection") &&
		    0 == strncasecmp(ptoken, "keep-alive", tmp_len)) {
			/* for "Connection: Upgrade",
				we treat it as "close" */
			pcontext->b_close = FALSE;
		}
		uint32_t tmp_len1 = strlen(field_name);
		mem_file_write(&pcontext->request.f_others, reinterpret_cast<char *>(&tmp_len1), sizeof(uint32_t));
		mem_file_write(&pcontext->request.f_others, field_name, tmp_len1);
		mem_file_write(&pcontext->request.f_others, reinterpret_cast<char *>(&tmp_len), sizeof(uint32_t));
		mem_file_write(&pcontext->request.f_others, ptoken, tmp_len);
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
			"Server: %s\r\n"
			"Content-Length: 0\r\n"
			"Connection: close\r\n"
			"\r\n", dstring, resource_get_string("HOST_ID"));
		stream_write(&pcontext->stream_out,
			response_buff, response_len);
		pcontext->total_length = response_len;
		pcontext->bytes_rw = 0;
		pcontext->b_close = TRUE;
		pcontext->sched_stat = SCHED_STAT_WRREP;
		http_parser_log_info(pcontext, 6,
			"user %s is denied by user filter",
			pcontext->username);
		return X_LOOP;
	}

	char reason[256];
	if (TRUE == system_services_auth_login(
	    pcontext->username, pcontext->password,
	    pcontext->maildir, pcontext->lang, reason, GX_ARRAY_SIZE(reason))) {
		if ('\0' == pcontext->maildir[0]) {
			char dstring[128], response_buff[1024];
			rfc1123_dstring(dstring, arsizeof(dstring));
			auto response_len = gx_snprintf(
				response_buff, GX_ARRAY_SIZE(response_buff),
				"HTTP/1.1 401 Unauthorized\r\n"
				"Date: %s\r\n"
				"Server: %s\r\n"
				"Content-Length: 0\r\n"
				"Keep-Alive: timeout=%d\r\n"
				"Connection: Keep-Alive\r\n"
				"WWW-Authenticate: Basic realm=\"msrpc realm\"\r\n"
				"\r\n", dstring, resource_get_string("HOST_ID"),
				g_timeout);
			stream_write(&pcontext->stream_out,
				response_buff, response_len);
			pcontext->total_length = response_len;
			pcontext->bytes_rw = 0;
			pcontext->sched_stat = SCHED_STAT_WRREP;
			http_parser_log_info(pcontext, 6, "can not get maildir");
			return X_LOOP;
		}

		if ('\0' == pcontext->lang[0]) {
			gx_strlcpy(pcontext->lang, resource_get_string("USER_DEFAULT_LANG"),
			           GX_ARRAY_SIZE(pcontext->lang));
		}
		pcontext->b_authed = TRUE;
		http_parser_log_info(pcontext, 6, "login success");
		return X_RUNOFF;
	}

	pcontext->b_authed = FALSE;
	http_parser_log_info(pcontext, 6, "login fail");
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
		"Server: %s\r\n"
		"Keep-Alive: timeout=%d\r\n"
		"Connection: Keep-Alive\r\n"
		"Content-Type: text/plain; charset=ascii\r\n"
		"Content-Length: %zu\r\n"
		"WWW-Authenticate: Basic realm=\"msrpc realm\"\r\n"
		"\r\n%s\r\n", dstring,
		resource_get_string("HOST_ID"),
		g_timeout, strlen(reason) + 2, reason);
	stream_write(&pcontext->stream_out,
		response_buff, response_len);
	pcontext->total_length = response_len;
	pcontext->bytes_rw = 0;
	pcontext->sched_stat = SCHED_STAT_WRREP;
	return X_LOOP;
}

static int htp_delegate_rpc(HTTP_CONTEXT *pcontext, const STREAM &stream_1)
{
	auto tmp_len = mem_file_get_total_length(
	               &pcontext->request.f_request_uri);
	if (0 == tmp_len || tmp_len >= 1024) {
		http_parser_log_info(pcontext, 6,
			"rpcproxy request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	char tmp_buff[2048];
	tmp_len = mem_file_read(
	          &pcontext->request.f_request_uri,
	          tmp_buff, 1024);
	if (tmp_len == MEM_END_OF_FILE) {
		http_parser_log_info(pcontext, 6, "rpcproxy request method error");
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
		http_parser_log_info(pcontext, 6,
			"rpcproxy request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	auto ptoken1 = strchr(tmp_buff, ':');
	if (NULL == ptoken1) {
		http_parser_log_info(pcontext, 6,
			"rpcproxy request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	*ptoken1 = '\0';
	if (ptoken1 - ptoken > 128) {
		http_parser_log_info(pcontext, 6,
			"rpcproxy request method error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	ptoken1++;
	gx_strlcpy(pcontext->host, ptoken, GX_ARRAY_SIZE(pcontext->host));
	pcontext->port = atoi(ptoken1);

	if (FALSE == pcontext->b_authed) {
		char dstring[128], response_buff[1024];
		rfc1123_dstring(dstring, arsizeof(dstring));
		auto response_len = gx_snprintf(
			response_buff, GX_ARRAY_SIZE(response_buff),
			"HTTP/1.1 401 Unauthorized\r\n"
			"Date: %s\r\n"
			"Server: %s\r\n"
			"Content-Length: 0\r\n"
			"Keep-Alive: timeout=%d\r\n"
			"Connection: Keep-Alive\r\n"
			"WWW-Authenticate: Basic realm=\"msrpc realm\"\r\n"
			"\r\n", dstring, resource_get_string("HOST_ID"),
			g_timeout);
		stream_write(&pcontext->stream_out,
			response_buff, response_len);
		pcontext->total_length = response_len;
		pcontext->bytes_rw = 0;
		pcontext->sched_stat = SCHED_STAT_WRREP;
		http_parser_log_info(pcontext, 6,
			"authentification needed");
		return X_LOOP;
	}

	tmp_len = mem_file_read(
	          &pcontext->request.f_content_length,
	          tmp_buff, 256);
	if (MEM_END_OF_FILE == tmp_len) {
		http_parser_log_info(pcontext, 6,
			"content-length of rpcproxy request error");
		http_4xx(pcontext);
		return X_LOOP;
	}
	pcontext->total_length = atoll(tmp_buff);

	/* ECHO request 0x0 ~ 0x10, MS-RPCH 2.1.2.15 */
	if (pcontext->total_length > 0x10) {
		if (0 == strcmp(pcontext->request.method, "RPC_IN_DATA")) {
			pcontext->channel_type = CHANNEL_TYPE_IN;
			pcontext->pchannel =
				lib_buffer_get(g_inchannel_allocator);
			if (NULL == pcontext->pchannel) {
				http_5xx(pcontext, "Resources exhausted", 503);
				return X_LOOP;
			}
			memset(pcontext->pchannel, 0, sizeof(RPC_IN_CHANNEL));
			double_list_init(&((RPC_IN_CHANNEL*)
				pcontext->pchannel)->pdu_list);
		} else {
			pcontext->channel_type = CHANNEL_TYPE_OUT;
			pcontext->pchannel =
				lib_buffer_get(g_outchannel_allocator);
			if (NULL == pcontext->pchannel) {
				http_5xx(pcontext, "Resources exhausted", 503);
				return X_LOOP;
			}
			memset(pcontext->pchannel, 0, sizeof(RPC_OUT_CHANNEL));
			double_list_init(&((RPC_OUT_CHANNEL*)
				pcontext->pchannel)->pdu_list);
		}
	}
	pcontext->bytes_rw = stream_get_total_length(&stream_1);
	pcontext->sched_stat = SCHED_STAT_RDBODY;
	return X_LOOP;
}

static int htp_delegate_hpm(HTTP_CONTEXT *pcontext)
{
	/* let mod_fastcgi decide the read/write bytes */
	pcontext->bytes_rw = 0;
	pcontext->total_length = 0;

	if (FALSE == hpm_processor_write_request(pcontext)) {
		http_5xx(pcontext);
		return X_LOOP;
	}
	if (!hpm_processor_check_end_of_request(pcontext)) {
		pcontext->sched_stat = SCHED_STAT_RDBODY;
		return X_LOOP;
	}
	if (FALSE == hpm_processor_proc(pcontext)) {
		http_5xx(pcontext);
		return X_LOOP;
	}
	pcontext->sched_stat = SCHED_STAT_WRREP;
	STREAM stream_2;
	if (http_parser_reconstruct_stream(&pcontext->stream_in, &stream_2) < 0) {
		http_parser_log_info(pcontext, 6, "out of memory");
		http_5xx(pcontext, "Resources exhausted", 503);
		return X_LOOP;
	}
	stream_free(&pcontext->stream_in);
	pcontext->stream_in = std::move(stream_2);
	if (stream_get_total_length(&pcontext->stream_out) == 0) {
		return X_LOOP;
	}
	unsigned int tmp_len = STREAM_BLOCK_SIZE;
	pcontext->write_buff = stream_getbuffer_for_reading(&pcontext->stream_out, &tmp_len);
	pcontext->write_length = tmp_len;
	return X_LOOP;
}

static int htp_delegate_fcgi(HTTP_CONTEXT *pcontext)
{
	/* let mod_fastcgi decide the read/write bytes */
	pcontext->bytes_rw = 0;
	pcontext->total_length = 0;

	if (FALSE == mod_fastcgi_write_request(pcontext)) {
		http_5xx(pcontext);
		return X_LOOP;
	}
	if (!mod_fastcgi_check_end_of_read(pcontext)) {
		pcontext->sched_stat = SCHED_STAT_RDBODY;
		return X_LOOP;
	}
	if (FALSE == mod_fastcgi_relay_content(pcontext)) {
		http_5xx(pcontext, "Bad FastCGI Gateway", 502);
		return X_LOOP;
	}
	pcontext->sched_stat = SCHED_STAT_WRREP;
	STREAM stream_3;
	if (http_parser_reconstruct_stream(&pcontext->stream_in, &stream_3) < 0) {
		http_parser_log_info(pcontext, 6, "out of memory");
		http_5xx(pcontext, "Resources exhausted", 503);
		return X_LOOP;
	}
	stream_free(&pcontext->stream_in);
	pcontext->stream_in = std::move(stream_3);
	return X_LOOP;
}

static int htp_delegate_cache(HTTP_CONTEXT *pcontext)
{
	/* let mod_cache decide the read/write bytes */
	pcontext->bytes_rw = 0;
	pcontext->total_length = 0;
	pcontext->sched_stat = SCHED_STAT_WRREP;
	STREAM stream_4;
	if (http_parser_reconstruct_stream(&pcontext->stream_in, &stream_4) < 0) {
		http_parser_log_info(pcontext, 6, "out of memory");
		http_5xx(pcontext, "Resources exhausted", 503);
		return X_LOOP;
	}
	stream_free(&pcontext->stream_in);
	pcontext->stream_in = std::move(stream_4);
	return X_LOOP;
}

static int htparse_rdhead_st(HTTP_CONTEXT *pcontext, ssize_t actual_read)
{
	while (TRUE) {
		stream_try_mark_line(&pcontext->stream_in);
		switch (stream_has_newline(&pcontext->stream_in)) {
		case STREAM_LINE_FAIL:
			http_parser_log_info(pcontext, 6,
				"request header line too long");
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
		auto line_length = stream_readline(&pcontext->stream_in, &line);
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

		/* meet the end of request header */
		STREAM stream_1;
		if (http_parser_reconstruct_stream(&pcontext->stream_in, &stream_1) < 0) {
			http_parser_log_info(pcontext, 6, "out of memory");
			http_5xx(pcontext, "Resources exhausted", 503);
			return X_LOOP;
		}
		stream_free(&pcontext->stream_in);
		pcontext->stream_in = stream_1;

		char tmp_buff[2048], tmp_buff1[1024];
		size_t decode_len = 0;
		char *ptoken = nullptr;
		if (http_parser_request_head(&pcontext->request.f_others,
		    "Authorization", tmp_buff, GX_ARRAY_SIZE(tmp_buff)) &&
		    strncasecmp(tmp_buff, "Basic ", 6) == 0 &&
		    decode64(tmp_buff + 6, strlen(tmp_buff + 6), tmp_buff1, &decode_len) == 0 &&
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
			return htp_delegate_rpc(pcontext, stream_1);
		}
		/* try to make hpm_processor take over the request */
		if (TRUE == hpm_processor_get_context(pcontext)) {
			return htp_delegate_hpm(pcontext);
		}
		/* try to make mod_fastcgi process the request */
		if (TRUE == mod_fastcgi_get_context(pcontext)) {
			return htp_delegate_fcgi(pcontext);
		}
		if (TRUE == mod_cache_get_context(pcontext)) {
			return htp_delegate_cache(pcontext);
		}
		/* other http request here if wanted */
		char dstring[128], response_buff[1024];
		rfc1123_dstring(dstring, arsizeof(dstring));
		auto response_len = gx_snprintf(response_buff, GX_ARRAY_SIZE(response_buff),
					"HTTP/1.1 404 Not Found\r\n"
					"Date: %s\r\n"
					"Server: %s\r\n"
					"Content-Length: 134\r\n\r\n"
					"<html>\r\n"
					"<head><title>404 Not Found</title></head>\r\n"
					"<body bgcolor=\"white\">\r\n"
					"<center><h1>404 Not Found</h1></center>\r\n"
					"</body>\r\n"
					"</html>\r\n",
					dstring, resource_get_string("HOST_ID"));
		stream_write(&pcontext->stream_out, response_buff, response_len);
		pcontext->total_length = response_len;
		pcontext->bytes_rw = 0;
		pcontext->sched_stat = SCHED_STAT_WRREP;
		return X_LOOP;
	}
	return X_RUNOFF;
}

static int htparse_rdhead(HTTP_CONTEXT *pcontext)
{
	unsigned int size = STREAM_BLOCK_SIZE;
	auto pbuff = stream_getbuffer_for_writing(&pcontext->stream_in, &size);
	if (NULL == pbuff) {
		http_parser_log_info(pcontext, 6, "out of memory");
		http_5xx(pcontext, "Resources exhausted", 503);
		return X_LOOP;
	}
	ssize_t actual_read = pcontext->connection.ssl != nullptr ?
			      SSL_read(pcontext->connection.ssl, pbuff, size) :
			      read(pcontext->connection.sockd, pbuff, size);
	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	if (0 == actual_read) {
		http_parser_log_info(pcontext, 6, "connection lost");
		return X_RUNOFF;
	} else if (actual_read > 0) {
		pcontext->connection.last_timestamp = current_time;
		stream_forward_writing_ptr(&pcontext->stream_in, actual_read);
		return htparse_rdhead_st(pcontext, actual_read);
	}
	if (EAGAIN != errno) {
		http_parser_log_info(pcontext, 6, "connection lost");
		return X_RUNOFF;
	}
	/* check if context is timed out */
	if (CALCULATE_INTERVAL(current_time,
	    pcontext->connection.last_timestamp) < g_timeout) {
		return htparse_rdhead_st(pcontext, actual_read);
	}
	http_parser_log_info(pcontext, 6, "time out");
	http_4xx(pcontext, "Request Timeout", 408);
	return X_LOOP;
}

static int htparse_wrrep_nobuf(HTTP_CONTEXT *pcontext)
{
	if (TRUE == hpm_processor_check_context(pcontext)) {
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
			if (TRUE == pcontext->b_close) {
				return X_RUNOFF;
			}
			http_parser_request_clear(&pcontext->request);
			hpm_processor_put_context(pcontext);
			pcontext->sched_stat = SCHED_STAT_RDHEAD;
			stream_clear(&pcontext->stream_out);
			return PROCESS_CONTINUE;
		case HPM_RETRIEVE_SOCKET: {
			unsigned int size = STREAM_BLOCK_SIZE;
			auto pbuff = stream_getbuffer_for_reading(&pcontext->stream_in, &size);
			if (pbuff != nullptr && !hpm_processor_send(pcontext, pbuff, size)) {
				http_parser_log_info(pcontext, 6,
					"connection closed by hpm");
				return X_RUNOFF;
			}
			stream_clear(&pcontext->stream_in);
			stream_clear(&pcontext->stream_out);
			http_parser_request_clear(&pcontext->request);
			unsigned int tmp_len = STREAM_BLOCK_SIZE;
			pcontext->write_buff = stream_getbuffer_for_writing(&pcontext->stream_out, &tmp_len);
			pcontext->write_length = 0;
			pcontext->write_offset = 0;
			pcontext->sched_stat = SCHED_STAT_SOCKET;
			return PROCESS_POLLING_RDWR;
		}
		}
	} else if (NULL != pcontext->pfast_context) {
		switch (mod_fastcgi_check_response(pcontext)) {
		case RESPONSE_WAITING:
			return PROCESS_CONTINUE;
		case RESPONSE_TIMEOUT:
			http_parser_log_info(pcontext, 6,
				"fastcgi excution time out");
			http_5xx(pcontext, "FastCGI Timeout", 504);
			return X_LOOP;
		}
		if (TRUE == mod_fastcgi_check_responded(pcontext)) {
			if (!mod_fastcgi_read_response(pcontext) &&
			    stream_get_total_length(&pcontext->stream_out) == 0) {
				if (TRUE == pcontext->b_close) {
					return X_RUNOFF;
				}
				http_parser_request_clear(&pcontext->request);
				pcontext->sched_stat = SCHED_STAT_RDHEAD;
				stream_clear(&pcontext->stream_out);
				return PROCESS_CONTINUE;
			}
		} else if (!mod_fastcgi_read_response(pcontext)) {
			http_5xx(pcontext, "Bad FastCGI Gateway", 502);
			return X_LOOP;
		}
	} else if (mod_cache_check_caching(pcontext) &&
	    !mod_cache_read_response(pcontext)) {
		if (FALSE == mod_cache_check_responded(pcontext)) {
			http_5xx(pcontext);
			return X_LOOP;
		}
		if (0 == stream_get_total_length(&pcontext->stream_out)) {
			if (TRUE == pcontext->b_close) {
				return X_RUNOFF;
			}
			http_parser_request_clear(&pcontext->request);
			pcontext->sched_stat = SCHED_STAT_RDHEAD;
			stream_clear(&pcontext->stream_out);
			return PROCESS_CONTINUE;
		}
	}

	pcontext->write_offset = 0;
	unsigned int tmp_len;
	if (CHANNEL_TYPE_OUT == pcontext->channel_type &&
	    CHANNEL_STAT_OPENED == ((RPC_OUT_CHANNEL*)
	    pcontext->pchannel)->channel_stat) {
		/* stream_out is shared resource of vconnection,
			lock it first before operating */
		auto pvconnection = http_parser_get_vconnection(
			pcontext->host, pcontext->port,
			((RPC_OUT_CHANNEL*)pcontext->pchannel)->connection_cookie);
		if (pvconnection == nullptr) {
			http_parser_log_info(pcontext, 6,
				"virtual connection error in hash table");
			return X_RUNOFF;
		}
		auto pnode = double_list_get_head(&static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->pdu_list);
		if (NULL == pnode) {
			pvconnection.put();
			pcontext->sched_stat = SCHED_STAT_WAIT;
			return PROCESS_IDLE;
		}
		pcontext->write_buff = ((BLOB_NODE*)pnode->pdata)->blob.data;
		tmp_len = ((BLOB_NODE*)pnode->pdata)->blob.length;
	} else {
		tmp_len = STREAM_BLOCK_SIZE;
		pcontext->write_buff = stream_getbuffer_for_reading(&pcontext->stream_out, &tmp_len);
	}

	/* if context is set to write response state, there's
		always data in stream_out. so we did not check
		wether pcontext->write_buff pointer is NULL */
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

	ssize_t written_len = pcontext->write_length - pcontext->write_offset;
	if (CHANNEL_TYPE_OUT == pcontext->channel_type &&
	    CHANNEL_STAT_OPENED == ((RPC_OUT_CHANNEL*)
	    pcontext->pchannel)->channel_stat) {
		auto pchannel_out = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
		if (pchannel_out->available_window < 1024) {
			return PROCESS_IDLE;
		}
		if (written_len > pchannel_out->available_window) {
			written_len = pchannel_out->available_window;
		}
	}
	if (NULL != pcontext->connection.ssl) {
		written_len = SSL_write(pcontext->connection.ssl,
			      reinterpret_cast<char *>(pcontext->write_buff) + pcontext->write_offset,
			written_len);
	} else {
		written_len = write(pcontext->connection.sockd,
			      reinterpret_cast<char *>(pcontext->write_buff) + pcontext->write_offset,
			written_len);
	}

	struct timeval current_time;
	gettimeofday(&current_time, NULL);

	if (0 == written_len) {
		http_parser_log_info(pcontext, 6, "connection lost");
		return X_RUNOFF;
	} else if (written_len < 0) {
		if (EAGAIN != errno) {
			http_parser_log_info(pcontext, 6, "connection lost");
			return X_RUNOFF;
		}
		/* check if context is timed out */
		if (CALCULATE_INTERVAL(current_time,
		    pcontext->connection.last_timestamp) < g_timeout) {
			return PROCESS_POLLING_WRONLY;
		}
		http_parser_log_info(pcontext, 6, "time out");
		return X_RUNOFF;
	}
	pcontext->connection.last_timestamp = current_time;
	pcontext->write_offset += written_len;
	pcontext->bytes_rw += written_len;
	if (CHANNEL_TYPE_OUT == pcontext->channel_type &&
	    CHANNEL_STAT_OPENED == ((RPC_OUT_CHANNEL*)
	    pcontext->pchannel)->channel_stat) {
		auto pchannel_out = static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel);
		auto pvconnection = http_parser_get_vconnection(pcontext->host,
				pcontext->port, pchannel_out->connection_cookie);
		auto pnode = double_list_get_head(&pchannel_out->pdu_list);
		if (FALSE == ((BLOB_NODE*)pnode->pdata)->b_rts) {
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
	    CHANNEL_STAT_OPENED == ((RPC_OUT_CHANNEL*)
	    pcontext->pchannel)->channel_stat) {
		/* stream_out is shared resource of vconnection,
			lock it first before operating */
		auto pvconnection = http_parser_get_vconnection(
			pcontext->host, pcontext->port,
			((RPC_OUT_CHANNEL*)pcontext->pchannel)->connection_cookie);
		if (pvconnection == nullptr) {
			http_parser_log_info(pcontext, 6,
				"virtual connection error in hash table");
			return X_RUNOFF;
		}
		auto pnode = double_list_pop_front(&static_cast<RPC_OUT_CHANNEL *>(pcontext->pchannel)->pdu_list);
		if (pnode != nullptr) {
			free(((BLOB_NODE*)pnode->pdata)->blob.data);
			pdu_processor_free_blob(static_cast<BLOB_NODE *>(pnode->pdata));
		}
		pnode = double_list_get_head(
			&((RPC_OUT_CHANNEL*)pcontext->pchannel)->pdu_list);
		if (pnode != nullptr) {
			pcontext->write_buff = static_cast<BLOB_NODE *>(pnode->pdata)->blob.data;
			pcontext->write_length = static_cast<BLOB_NODE *>(pnode->pdata)->blob.length;
		} else if (pcontext->total_length > 0 &&
		    pcontext->total_length - pcontext->bytes_rw <=
		    MAX_RECLYING_REMAINING && FALSE ==
		    ((RPC_OUT_CHANNEL *)pcontext->pchannel)->b_obsolete) {
			/* begin of out channel recycling */
			if (TRUE == pdu_processor_rts_outr2_a2(
			    ((RPC_OUT_CHANNEL*)pcontext->pchannel)->pcall)) {
				pdu_processor_output_pdu(
					((RPC_OUT_CHANNEL*)pcontext->pchannel)->pcall,
					&((RPC_OUT_CHANNEL*)pcontext->pchannel)->pdu_list);
				((RPC_OUT_CHANNEL*)
				pcontext->pchannel)->b_obsolete = TRUE;
			}
		} else {
			pcontext->sched_stat = SCHED_STAT_WAIT;
		}
		return PROCESS_CONTINUE;
	}

	unsigned int tmp_len = STREAM_BLOCK_SIZE;
	pcontext->write_buff = stream_getbuffer_for_reading(&pcontext->stream_out, &tmp_len);
	pcontext->write_length = tmp_len;
	if (pcontext->write_buff != nullptr) {
		return PROCESS_CONTINUE;
	}
	if (CHANNEL_TYPE_OUT == pcontext->channel_type
	    && (CHANNEL_STAT_WAITINCHANNEL ==
	    ((RPC_OUT_CHANNEL*)pcontext->pchannel)->channel_stat
	    || CHANNEL_STAT_WAITRECYCLED ==
	    ((RPC_OUT_CHANNEL*)pcontext->pchannel)->channel_stat)) {
		/* to wait in channel for completing
			out channel handshaking */
		pcontext->sched_stat = SCHED_STAT_WAIT;
	} else if (NULL != pcontext->pfast_context ||
	    TRUE == hpm_processor_check_context(pcontext)
	    || TRUE == mod_cache_check_caching(pcontext)) {
		stream_clear(&pcontext->stream_out);
		return PROCESS_CONTINUE;
	} else {
		if (TRUE == pcontext->b_close) {
			return X_RUNOFF;
		}
		http_parser_request_clear(&pcontext->request);
		pcontext->sched_stat = SCHED_STAT_RDHEAD;
	}
	stream_clear(&pcontext->stream_out);
	return PROCESS_CONTINUE;
}

static int htparse_rdbody_nochan2(HTTP_CONTEXT *pcontext)
{
	unsigned int size = STREAM_BLOCK_SIZE;
	auto pbuff = stream_getbuffer_for_writing(&pcontext->stream_in, &size);
	if (NULL == pbuff) {
		http_parser_log_info(pcontext, 6, "out of memory");
		http_5xx(pcontext);
		return X_LOOP;
	}
	ssize_t actual_read = pcontext->connection.ssl != nullptr ?
			      SSL_read(pcontext->connection.ssl, pbuff, size) :
			      read(pcontext->connection.sockd, pbuff, size);
	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	if (0 == actual_read) {
		http_parser_log_info(pcontext, 6, "connection lost");
		return X_RUNOFF;
	} else if (actual_read > 0) {
		pcontext->connection.last_timestamp = current_time;
		stream_forward_writing_ptr(
			&pcontext->stream_in, actual_read);
		if (TRUE == hpm_processor_check_context(pcontext)) {
			if (FALSE == hpm_processor_write_request(pcontext)) {
				http_5xx(pcontext);
				return X_LOOP;
			}
			if (!hpm_processor_check_end_of_request(
			    pcontext)) {
				return PROCESS_CONTINUE;
			}
			if (FALSE == hpm_processor_proc(pcontext)) {
				http_5xx(pcontext);
				return X_LOOP;
			}
			pcontext->sched_stat = SCHED_STAT_WRREP;
			STREAM stream_5;
			if (http_parser_reconstruct_stream(&pcontext->stream_in, &stream_5) < 0) {
				http_parser_log_info(pcontext, 6, "out of memory");
				http_5xx(pcontext, "Resources exhausted", 503);
				return X_LOOP;
			}
			stream_free(&pcontext->stream_in);
			pcontext->stream_in = std::move(stream_5);
			if (0 != stream_get_total_length(
			    &pcontext->stream_out)) {
				unsigned int tmp_len = STREAM_BLOCK_SIZE;
				pcontext->write_buff = stream_getbuffer_for_reading(&pcontext->stream_out, &tmp_len);
				pcontext->write_length = tmp_len;
			}
			return PROCESS_CONTINUE;
		} else if (NULL != pcontext->pfast_context) {
			if (FALSE == mod_fastcgi_write_request(pcontext)) {
				http_5xx(pcontext);
				return X_LOOP;
			}
			if (!mod_fastcgi_check_end_of_read(pcontext)) {
				return PROCESS_CONTINUE;
			}
			if (FALSE == mod_fastcgi_relay_content(pcontext)) {
				http_5xx(pcontext, "Bad FastCGI Gateway", 502);
				return X_LOOP;
			}
			pcontext->sched_stat = SCHED_STAT_WRREP;
			STREAM stream_6;
			if (http_parser_reconstruct_stream(&pcontext->stream_in, &stream_6) < 0) {
				http_parser_log_info(pcontext, 6, "out of memory");
				http_5xx(pcontext, "Resources exhausted", 503);
				return X_LOOP;
			}
			stream_free(&pcontext->stream_in);
			pcontext->stream_in = std::move(stream_6);
			return PROCESS_CONTINUE;
		}
		pcontext->bytes_rw += actual_read;
		if (pcontext->bytes_rw < pcontext->total_length) {
			return PROCESS_CONTINUE;
		}
	}
	if (EAGAIN != errno) {
		http_parser_log_info(pcontext, 6, "connection lost");
		return X_RUNOFF;
	}
	/* check if context is timed out */
	if (CALCULATE_INTERVAL(current_time,
	    pcontext->connection.last_timestamp) < g_timeout) {
		return PROCESS_POLLING_RDONLY;
	}
	http_parser_log_info(pcontext, 6, "time out");
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
		/* other http request here if wanted */
		http_4xx(pcontext);
		return X_LOOP;
	}
	/* ECHO request */
	char response_buff[1024];
	auto response_len = gx_snprintf(response_buff, GX_ARRAY_SIZE(response_buff),
		"HTTP/1.1 200 Success\r\n"
		"Connection: Keep-Alive\r\n"
		"Content-length: 20\r\n"
		"Content-Type: application/rpc\r\n\r\n");
	pdu_processor_rts_echo(response_buff + response_len);
	response_len += 20;
	stream_write(&pcontext->stream_out,
		response_buff, response_len);
	pcontext->total_length = response_len;
	pcontext->bytes_rw = 0;
	pcontext->sched_stat = SCHED_STAT_WRREP;

	STREAM stream_7;
	if (http_parser_reconstruct_stream(&pcontext->stream_in, &stream_7) < 0) {
		http_parser_log_info(pcontext, 6, "out of memory");
		http_5xx(pcontext, "Resources exhausted", 503);
		return X_LOOP;
	}
	stream_free(&pcontext->stream_in);
	pcontext->stream_in = std::move(stream_7);
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
	auto tmp_len = stream_get_total_length(&pcontext->stream_in);
	if (tmp_len < DCERPC_FRAG_LEN_OFFSET + 2 ||
	    (frag_length > 0 && tmp_len < frag_length)) {
		unsigned int size = STREAM_BLOCK_SIZE;
		auto pbuff = stream_getbuffer_for_writing(&pcontext->stream_in, &size);
		if (NULL == pbuff) {
			http_parser_log_info(pcontext, 6, "out of memory");
			http_5xx(pcontext, "Resources exhausted", 503);
			return X_LOOP;
		}

		ssize_t actual_read = pcontext->connection.ssl != nullptr ?
				      SSL_read(pcontext->connection.ssl, pbuff, size) :
				      read(pcontext->connection.sockd, pbuff, size);
		struct timeval current_time;
		gettimeofday(&current_time, NULL);
		if (0 == actual_read) {
			http_parser_log_info(pcontext, 6, "connection lost");
			return X_RUNOFF;
		} else if (actual_read > 0) {
			pcontext->bytes_rw += actual_read;
			if (pcontext->bytes_rw > pcontext->total_length) {
				http_parser_log_info(pcontext, 6,
					"content length overflow when reading body");
				return X_RUNOFF;
			}
			pcontext->connection.last_timestamp = current_time;
			stream_forward_writing_ptr(&pcontext->stream_in, actual_read);
		} else {
			if (EAGAIN != errno) {
				http_parser_log_info(pcontext, 6, "connection lost");
				return X_RUNOFF;
			}
			/* check if context is timed out */
			if (CALCULATE_INTERVAL(current_time, pcontext->connection.last_timestamp) < g_timeout) {
				return PROCESS_POLLING_RDONLY;
			}
			http_parser_log_info(pcontext, 6, "time out");
			http_4xx(pcontext, "Request Timeout", 408);
			return X_LOOP;
		}
	}

	unsigned int tmp_len2 = STREAM_BLOCK_SIZE;
	auto pbuff = stream_getbuffer_for_reading(&pcontext->stream_in, &tmp_len2);
	if (NULL == pbuff) {
		return PROCESS_POLLING_RDONLY;
	}
	tmp_len = tmp_len2;
	stream_backward_reading_ptr(&pcontext->stream_in, tmp_len);
	if (tmp_len < DCERPC_FRAG_LEN_OFFSET + 2) {
		return PROCESS_CONTINUE;
	}

	if (0 == frag_length) {
		static_assert(std::is_same_v<decltype(frag_length), uint16_t>, "");
		auto pbd = static_cast<uint8_t *>(pbuff);
		memcpy(&frag_length, &pbd[DCERPC_FRAG_LEN_OFFSET], sizeof(uint16_t));
		frag_length = (pbd[DCERPC_DREP_OFFSET] & DCERPC_DREP_LE) ?
			      le16_to_cpu(frag_length) : be16_to_cpu(frag_length);
		if (CHANNEL_TYPE_IN == pcontext->channel_type) {
			pchannel_in->frag_length = frag_length;
		} else {
			pchannel_out->frag_length = frag_length;
		}
	}

	if (tmp_len < frag_length) {
		return PROCESS_CONTINUE;
	}

	pthread_setspecific(g_context_key, (const void*)pcontext);
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
				http_parser_log_info(pcontext, 6,
					"virtual connection error in hash table");
				return X_RUNOFF;
			}
			if (pvconnection->pcontext_in != pcontext ||
			    NULL == pvconnection->pprocessor) {
				pvconnection.put();
				http_parser_log_info(pcontext, 6,
					"virtual connection error in hash table");
				return X_RUNOFF;
			}
			result = pdu_processor_input(pvconnection->pprocessor,
				 static_cast<char *>(pbuff), frag_length, &pcall);
			pchannel_in->available_window -= frag_length;
			pchannel_in->bytes_received += frag_length;
			if (NULL != pcall && NULL != pvconnection->pcontext_out
			    && pchannel_in->available_window <((RPC_OUT_CHANNEL*)
			    pvconnection->pcontext_out->pchannel)->window_size/2) {
				pchannel_in->available_window = ((RPC_OUT_CHANNEL*)
					pvconnection->pcontext_out->pchannel)->window_size;
				pdu_processor_rts_flowcontrolack_withdestination(
					pcall, pchannel_in->bytes_received,
					pchannel_in->available_window,
					pchannel_in->channel_cookie);
				/* if it is a fragment pdu, we must
					make the flowcontrol output */
				if (PDU_PROCESSOR_INPUT == result) {
					pdu_processor_output_pdu(pcall, &((RPC_OUT_CHANNEL*)
						pvconnection->pcontext_out->pchannel)->pdu_list);
					pvconnection->pcontext_out->sched_stat =
						SCHED_STAT_WRREP;
					contexts_pool_signal((SCHEDULE_CONTEXT*)
						pvconnection->pcontext_out);
				}
			}
		}
	}

	stream_forward_reading_ptr(&pcontext->stream_in, frag_length);
	if (CHANNEL_TYPE_IN == pcontext->channel_type) {
		pchannel_in->frag_length = 0;
	} else {
		pchannel_out->frag_length = 0;
	}

	STREAM stream_8;
	if (http_parser_reconstruct_stream(&pcontext->stream_in, &stream_8) < 0) {
		http_parser_log_info(pcontext, 6, "out of memory");
		http_5xx(pcontext, "Resources exhausted", 503);
		return X_LOOP;
	}
	stream_free(&pcontext->stream_in);
	pcontext->stream_in = std::move(stream_8);

	switch (result) {
	case PDU_PROCESSOR_ERROR:
	case PDU_PROCESSOR_FORWARD:
		http_parser_log_info(pcontext, 6, "pdu process error!");
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
				http_parser_log_info(pcontext, 6,
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
				"Content-length: %u\r\n\r\n",
				dstring, OUT_CHANNEL_MAX_LENGTH);
			stream_write(&pcontext->stream_out,
				response_buff, response_len);
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
			http_parser_log_info(pcontext, 6,
				"cannot find virtual connection in hash table");
			return X_RUNOFF;
		}

		if ((pcontext != pvconnection->pcontext_in &&
		    pcontext != pvconnection->pcontext_insucc)
		    || NULL == pvconnection->pcontext_out) {
			pvconnection.put();
			pdu_processor_free_call(pcall);
			http_parser_log_info(pcontext, 6,
				"missing out channel in virtual connection");
			return X_RUNOFF;
		}
		if (TRUE == ((RPC_OUT_CHANNEL*)
		    pvconnection->pcontext_out->pchannel)->b_obsolete) {
			pdu_processor_output_pdu(pcall,
				&((RPC_IN_CHANNEL*)pcontext->pchannel)->pdu_list);
			pvconnection.put();
			pdu_processor_free_call(pcall);
			return PROCESS_CONTINUE;
		}
		pdu_processor_output_pdu(
			pcall, &((RPC_OUT_CHANNEL*)
			pvconnection->pcontext_out->pchannel)->pdu_list);
		pvconnection->pcontext_out->sched_stat = SCHED_STAT_WRREP;
		contexts_pool_signal((SCHEDULE_CONTEXT*)
					pvconnection->pcontext_out);
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
			if (FALSE == pdu_processor_rts_conn_c2(
			    pchannel_out->pcall, pchannel_out->window_size)) {
				pvconnection.put();
				http_parser_log_info(pcontext, 6,
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

	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	/* check if context is timed out */
	if (CALCULATE_INTERVAL(current_time, pcontext->connection.last_timestamp) <
	    OUT_CHANNEL_MAX_WAIT) {
		return PROCESS_IDLE;
	}
	http_parser_log_info(pcontext, 6, "no correpoding in "
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

	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	/* check if context is timed out */
	if (CALCULATE_INTERVAL(current_time, pcontext->connection.last_timestamp) <
	    OUT_CHANNEL_MAX_WAIT) {
		return PROCESS_IDLE;
	}
	http_parser_log_info(pcontext, 6, "channel is not "
		"recycled during maximum waiting interval");
	return X_RUNOFF;
}

static int htparse_wait(HTTP_CONTEXT *pcontext)
{
	if (TRUE == hpm_processor_check_context(pcontext)) {
		return PROCESS_IDLE;
	}
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
		http_parser_log_info(pcontext, 6, "connection lost");
		return X_RUNOFF;
	}

	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	/* check keep alive */
	if (CALCULATE_INTERVAL(current_time, pcontext->connection.last_timestamp) <
		pchannel_out->client_keepalive/2000) {
		return PROCESS_IDLE;
	}
	if (FALSE == pdu_processor_rts_ping(pchannel_out->pcall)) {
		return PROCESS_IDLE;
	}
	/* stream_out is shared resource of vconnection,
		lock it first before operating */
	auto pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, ((RPC_OUT_CHANNEL*)
		pcontext->pchannel)->connection_cookie);
	pdu_processor_output_pdu(
		pchannel_out->pcall, &pchannel_out->pdu_list);
	pcontext->sched_stat = SCHED_STAT_WRREP;
	return X_LOOP;
}

static int htparse_socket(HTTP_CONTEXT *pcontext)
{
	if (0 == pcontext->write_length) {
		auto tmp_len = hpm_processor_receive(pcontext,
			static_cast<char *>(pcontext->write_buff),
			STREAM_BLOCK_SIZE);
		if (0 == tmp_len) {
			http_parser_log_info(pcontext, 6,
				"connection closed by hpm");
			return X_RUNOFF;
		} else if (tmp_len > 0) {
			pcontext->write_length = tmp_len;
			pcontext->write_offset = 0;
		}
	}
	if (pcontext->write_length > pcontext->write_offset) {
		ssize_t written_len = pcontext->write_length - pcontext->write_offset;
		if (NULL != pcontext->connection.ssl) {
			written_len = SSL_write(pcontext->connection.ssl,
				      static_cast<char *>(pcontext->write_buff) + pcontext->write_offset,
				written_len);
		} else {
			written_len = write(pcontext->connection.sockd,
				      static_cast<char *>(pcontext->write_buff) + pcontext->write_offset,
				written_len);
		}

		struct timeval current_time;
		gettimeofday(&current_time, NULL);

		if (0 == written_len) {
			http_parser_log_info(pcontext, 6, "connection lost");
			return X_RUNOFF;
		} else if (written_len > 0) {
			pcontext->connection.last_timestamp = current_time;
			pcontext->write_offset += written_len;
			if (pcontext->write_offset >= pcontext->write_length) {
				pcontext->write_offset = 0;
				pcontext->write_length = 0;
			}
		} else {
			if (EAGAIN != errno) {
				http_parser_log_info(pcontext, 6, "connection lost");
				return X_RUNOFF;
			}
			/* check if context is timed out */
			if (CALCULATE_INTERVAL(current_time, pcontext->connection.last_timestamp) < g_timeout) {
				return PROCESS_POLLING_WRONLY;
			}
			http_parser_log_info(pcontext, 6, "time out");
			return X_RUNOFF;
		}
	}
	char tmp_buff[2048];
	ssize_t actual_read = pcontext->connection.ssl == nullptr ?
			      read(pcontext->connection.sockd, tmp_buff, sizeof(tmp_buff)) :
			      SSL_read(pcontext->connection.ssl, tmp_buff, sizeof(tmp_buff));
	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	if (0 == actual_read) {
		http_parser_log_info(pcontext, 6, "connection lost");
		return X_RUNOFF;
	} else if (actual_read > 0) {
		pcontext->connection.last_timestamp = current_time;
		if (FALSE == hpm_processor_send(
		    pcontext, tmp_buff, actual_read)) {
			http_parser_log_info(pcontext, 6,
				"connection closed by hpm");
			return X_RUNOFF;
		}
		return PROCESS_POLLING_RDONLY;
	}
	if (EAGAIN != errno) {
		http_parser_log_info(pcontext, 6, "connection lost");
		return X_RUNOFF;
	}
	/* check if context is timed out */
	if (CALCULATE_INTERVAL(current_time, pcontext->connection.last_timestamp) < g_timeout) {
		return PROCESS_POLLING_RDONLY;
	}
	http_parser_log_info(pcontext, 6, "time out");
	return X_RUNOFF;
}

int http_parser_process(HTTP_CONTEXT *pcontext)
{
	static constexpr int (*func[])(HTTP_CONTEXT *) = {
		htparse_initssl, htparse_rdhead, htparse_rdbody, htparse_wrrep,
		htparse_wait, htparse_socket,
	};
	int ret = X_RUNOFF;
	do {
		if (pcontext->sched_stat < GX_ARRAY_SIZE(func))
			ret = func[pcontext->sched_stat](pcontext);
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
	if (TRUE == ((RPC_OUT_CHANNEL*)
		pvconnection->pcontext_out->pchannel)->b_obsolete) {
		if (NULL != pvconnection->pcontext_in) {
			pdu_processor_output_pdu(pcall, &((RPC_IN_CHANNEL*)
				pvconnection->pcontext_in->pchannel)->pdu_list);
			return;
		}
	} else {
		pdu_processor_output_pdu(pcall, &((RPC_OUT_CHANNEL*)
			pvconnection->pcontext_out->pchannel)->pdu_list);
	}
	pvconnection->pcontext_out->sched_stat = SCHED_STAT_WRREP;
	contexts_pool_signal((SCHEDULE_CONTEXT*)pvconnection->pcontext_out);
}

/*
 *    get http_parser's property
 *    @param
 *        param    indicate the parameter type
 *    @return
 *        value of property
 */
int http_parser_get_param(int param)
{
    switch (param) {
    case MAX_AUTH_TIMES:
        return g_max_auth_times;
    case BLOCK_AUTH_FAIL:
        return g_block_auth_fail;
    case HTTP_SESSION_TIMEOUT:
        return g_timeout;
	case HTTP_SUPPORT_SSL:
		return g_support_ssl;
    default:
        return 0;
    }
}

/* 
 *    get contexts list for contexts pool
 *    @return
 *        contexts array's address
 */
SCHEDULE_CONTEXT **http_parser_get_contexts_list()
{
	return g_context_list2.data();
}

/*
 *    set http_parser's property
 *    @param
 *        param    indicate the pram type
 *    @return
 *         0        success
 *        <>0        fail
 */
int http_parser_set_param(int param, int value)
{
    switch (param) {
    case MAX_AUTH_TIMES:
        g_max_auth_times = value;
        break;
    case HTTP_SESSION_TIMEOUT:
        g_timeout = value;
        break;
	case BLOCK_AUTH_FAIL:
		g_block_auth_fail = value;
		break;
    default:
        return -1;
    }
    return 0;
}

/*
 *    http context's construct function
 *    @param
 *        pcontext [in]    indicate the http context object
 */
HTTP_CONTEXT::HTTP_CONTEXT()
{
	auto pcontext = this;
    LIB_BUFFER *palloc_stream;
    
    palloc_stream = blocks_allocator_get_allocator();
    pcontext->connection.sockd = -1;
	mem_file_init(&pcontext->request.f_request_uri, g_file_allocator);
	mem_file_init(&pcontext->request.f_host, g_file_allocator);
	mem_file_init(&pcontext->request.f_user_agent, g_file_allocator);
	mem_file_init(&pcontext->request.f_accept, g_file_allocator);
	mem_file_init(&pcontext->request.f_accept_language, g_file_allocator);
	mem_file_init(&pcontext->request.f_accept_encoding, g_file_allocator);
	mem_file_init(&pcontext->request.f_content_type, g_file_allocator);
	mem_file_init(&pcontext->request.f_content_length, g_file_allocator);
	mem_file_init(&pcontext->request.f_transfer_encoding, g_file_allocator);
	mem_file_init(&pcontext->request.f_cookie, g_file_allocator);
	mem_file_init(&pcontext->request.f_others, g_file_allocator);
    stream_init(&pcontext->stream_in, palloc_stream);
	stream_init(&pcontext->stream_out, palloc_stream);
	pcontext->node.pdata = pcontext;
}

/*
 *    clear the http context object
 *    @param
 *        pcontext [in]    indicate the http context object
 */
static void http_parser_context_clear(HTTP_CONTEXT *pcontext)
{
    if (NULL == pcontext) {
        return;
    }
    memset(&pcontext->connection, 0, sizeof(CONNECTION));
    pcontext->connection.sockd = -1;
	pcontext->sched_stat = 0;
	
	http_parser_request_clear(&pcontext->request);
	
	stream_clear(&pcontext->stream_in);
	stream_clear(&pcontext->stream_out);
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

static void http_parser_request_clear(HTTP_REQUEST *prequest)
{
	
	prequest->method[0] = '\0';
	prequest->version[0] = '\0';
	mem_file_clear(&prequest->f_request_uri);
	mem_file_clear(&prequest->f_host);
	mem_file_clear(&prequest->f_user_agent);
	mem_file_clear(&prequest->f_accept);
	mem_file_clear(&prequest->f_accept_language);
	mem_file_clear(&prequest->f_accept_encoding);
	mem_file_clear(&prequest->f_content_type);
	mem_file_clear(&prequest->f_content_length);
	mem_file_clear(&prequest->f_transfer_encoding);
	mem_file_clear(&prequest->f_cookie);
	mem_file_clear(&prequest->f_others);
}

HTTP_CONTEXT::~HTTP_CONTEXT()
{
	auto pcontext = this;
	stream_free(&pcontext->stream_in);
	stream_free(&pcontext->stream_out);
	mem_file_free(&pcontext->request.f_request_uri);
	mem_file_free(&pcontext->request.f_host);
	mem_file_free(&pcontext->request.f_user_agent);
	mem_file_free(&pcontext->request.f_accept);
	mem_file_free(&pcontext->request.f_accept_language);
	mem_file_free(&pcontext->request.f_accept_encoding);
	mem_file_free(&pcontext->request.f_content_type);
	mem_file_free(&pcontext->request.f_content_length);
	mem_file_free(&pcontext->request.f_transfer_encoding);
	mem_file_free(&pcontext->request.f_cookie);
	mem_file_free(&pcontext->request.f_others);
	
	if (NULL != pcontext->connection.ssl) {
		SSL_shutdown(pcontext->connection.ssl);
		SSL_free(pcontext->connection.ssl);
		pcontext->connection.ssl = NULL;
	}
	if (-1 != pcontext->connection.sockd) {
		close(pcontext->connection.sockd);
	}
	if (TRUE == hpm_processor_check_context(pcontext)) {
		hpm_processor_put_context(pcontext);
	} else if (NULL != pcontext->pfast_context) {
		mod_fastcgi_put_context(pcontext);
	} else if (TRUE == mod_cache_check_caching(pcontext)) {
		mod_cache_put_context(pcontext);
	}
}

void http_parser_log_info(HTTP_CONTEXT *pcontext, int level,
    const char *format, ...)
{
	va_list ap;
	char log_buf[2048];

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	va_end(ap);
	log_buf[sizeof(log_buf) - 1] = '\0';
	
	if ('\0' == pcontext->username[0]) {
		system_services_log_info(level, "context-ID: %u, IP: %s  %s",
			pcontext->context_id, pcontext->connection.client_ip, log_buf);
	} else {
		system_services_log_info(level, "user: %s, IP: %s  %s",
			pcontext->username, pcontext->connection.client_ip, log_buf);
	}

}

HTTP_CONTEXT* http_parser_get_context()
{
	return (HTTP_CONTEXT*)pthread_getspecific(g_context_key);
}

void http_parser_set_context(int context_id)
{
	if (context_id < 0 ||
	    static_cast<size_t>(context_id) >= g_context_list.size())
		pthread_setspecific(g_context_key, nullptr);
	else
		pthread_setspecific(g_context_key, &g_context_list[context_id]);
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
		conn_cookie = ((RPC_IN_CHANNEL*)
			pcontext->pchannel)->connection_cookie;
	} else if (CHANNEL_TYPE_OUT == pcontext->channel_type) {
		conn_cookie = ((RPC_OUT_CHANNEL*)
			pcontext->pchannel)->connection_cookie;
	} else {
		return FALSE;
	}
 RETRY_QUERY:
	auto pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, conn_cookie);
	if (pvconnection == nullptr) {
		std::unique_lock vc_hold(g_vconnection_lock);
		if (g_vconnection_hash.size() >= g_context_num + 1) {
			http_parser_log_info(pcontext, 6, "W-1293: vconn hash full");
			return false;
		}
		char hash_key[256];
		snprintf(hash_key, GX_ARRAY_SIZE(hash_key), "%s:%hu:%s",
			conn_cookie, pcontext->port, pcontext->host);
		HX_strlower(hash_key);
		decltype(g_vconnection_hash.try_emplace(hash_key)) xp;
		try {
			xp = g_vconnection_hash.try_emplace(hash_key);
		} catch (const std::bad_alloc &) {
			http_parser_log_info(pcontext, 6, "W-1292: Out of memory\n");
			return false;
		}
		if (!xp.second) {
			http_parser_log_info(pcontext, 6, "W-1291: vconn suddenly started existing\n");
			goto RETRY_QUERY;
		}
		auto nc = &xp.first->second;
		nc->pprocessor = pdu_processor_create(pcontext->host, pcontext->port);
		if (nc->pprocessor == nullptr) {
			g_vconnection_hash.erase(xp.first);
			http_parser_log_info(pcontext, 6,
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
	} else {
		if (CHANNEL_TYPE_OUT == pcontext->channel_type) {
			pvconnection->pcontext_out = pcontext;
		} else {
			pvconnection->pcontext_in = pcontext;
			if (NULL != pvconnection->pcontext_out) {
				contexts_pool_signal((SCHEDULE_CONTEXT*)
							pvconnection->pcontext_out);
			}
		}
	}
	return TRUE;
}

void http_parser_set_outchannel_flowcontrol(HTTP_CONTEXT *pcontext,
	uint32_t bytes_received, uint32_t available_window)
{
	RPC_OUT_CHANNEL *pchannel_out;
	
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return;
	}
	auto pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, ((RPC_IN_CHANNEL*)
		pcontext->pchannel)->connection_cookie);
	if (pvconnection == nullptr)
		return;
	if (NULL == pvconnection->pcontext_out) {
		return;
	}
	pchannel_out = (RPC_OUT_CHANNEL*)pvconnection->pcontext_out->pchannel;
	if (bytes_received + available_window > pchannel_out->bytes_sent) {
		pchannel_out->available_window = bytes_received
			+ available_window - pchannel_out->bytes_sent;
		contexts_pool_signal((SCHEDULE_CONTEXT*)pvconnection->pcontext_out);
	} else {
		pchannel_out->available_window = 0;
	}
}

BOOL http_parser_recycle_inchannel(
	HTTP_CONTEXT *pcontext, char *predecessor_cookie)
{
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return FALSE;
	}
	auto pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, ((RPC_IN_CHANNEL*)
		pcontext->pchannel)->connection_cookie);
	
	if (pvconnection != nullptr) {
		if (NULL != pvconnection->pcontext_in &&
			0 == strcmp(predecessor_cookie, ((RPC_IN_CHANNEL*)
			pvconnection->pcontext_in->pchannel)->channel_cookie)) {
			((RPC_IN_CHANNEL*)pcontext->pchannel)->life_time =
				((RPC_IN_CHANNEL*)
				pvconnection->pcontext_in->pchannel)->life_time;
			((RPC_IN_CHANNEL*)pcontext->pchannel)->client_keepalive =
				((RPC_IN_CHANNEL*)
				pvconnection->pcontext_in->pchannel)->client_keepalive;
			((RPC_IN_CHANNEL*)pcontext->pchannel)->available_window =
				((RPC_IN_CHANNEL*)
				pvconnection->pcontext_in->pchannel)->available_window;
			((RPC_IN_CHANNEL*)pcontext->pchannel)->bytes_received =
				((RPC_IN_CHANNEL*)
				pvconnection->pcontext_in->pchannel)->bytes_received;
			strcpy(((RPC_IN_CHANNEL*)pcontext->pchannel)->assoc_group_id,
				((RPC_IN_CHANNEL*)
				pvconnection->pcontext_in->pchannel)->assoc_group_id);
			pvconnection->pcontext_insucc = pcontext;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL http_parser_recycle_outchannel(
	HTTP_CONTEXT *pcontext, char *predecessor_cookie)
{
	DCERPC_CALL *pcall;
	
	if (CHANNEL_TYPE_OUT != pcontext->channel_type) {
		return FALSE;
	}
	auto pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, ((RPC_OUT_CHANNEL*)
		pcontext->pchannel)->connection_cookie);
	if (pvconnection != nullptr) {
		if (NULL != pvconnection->pcontext_out &&
			0 == strcmp(predecessor_cookie, ((RPC_OUT_CHANNEL*)
			pvconnection->pcontext_out->pchannel)->channel_cookie)) {
			if (FALSE == ((RPC_OUT_CHANNEL*)
				pvconnection->pcontext_out->pchannel)->b_obsolete) {
				return FALSE;
			}
			pcall = ((RPC_OUT_CHANNEL*)
				pvconnection->pcontext_out->pchannel)->pcall;
			if (FALSE == pdu_processor_rts_outr2_a6(pcall)) {
				return FALSE;
			}
			pdu_processor_output_pdu(pcall, &((RPC_OUT_CHANNEL*)
				pvconnection->pcontext_out->pchannel)->pdu_list);
			pvconnection->pcontext_out->sched_stat = SCHED_STAT_WRREP;
			contexts_pool_signal((SCHEDULE_CONTEXT*)
						pvconnection->pcontext_out);
			((RPC_OUT_CHANNEL*)pcontext->pchannel)->client_keepalive =
				((RPC_OUT_CHANNEL*)
				pvconnection->pcontext_out->pchannel)->client_keepalive;
			((RPC_OUT_CHANNEL*)pcontext->pchannel)->available_window =
				((RPC_OUT_CHANNEL*)
				pvconnection->pcontext_out->pchannel)->window_size;
			((RPC_OUT_CHANNEL*)pcontext->pchannel)->window_size =
				((RPC_OUT_CHANNEL*)
				pvconnection->pcontext_out->pchannel)->window_size;
			pvconnection->pcontext_outsucc = pcontext;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL http_parser_activate_inrecycling(
	HTTP_CONTEXT *pcontext, const char *successor_cookie)
{
	RPC_IN_CHANNEL *pchannel_in;
	
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return FALSE;
	}
	auto pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, ((RPC_IN_CHANNEL*)
		pcontext->pchannel)->connection_cookie);
	if (pvconnection != nullptr) {
		if (pcontext == pvconnection->pcontext_insucc &&
			0 == strcmp(successor_cookie, ((RPC_IN_CHANNEL*)
			pvconnection->pcontext_insucc->pchannel)->channel_cookie)) {
			if (NULL != pvconnection->pcontext_in) {
				pchannel_in = static_cast<RPC_IN_CHANNEL *>(pvconnection->pcontext_in->pchannel);
				pchannel_in->channel_stat = CHANNEL_STAT_RECYCLED;
			}
			pvconnection->pcontext_in = pcontext;
			((RPC_IN_CHANNEL*)pcontext->pchannel)->channel_stat =
												CHANNEL_STAT_OPENED;
			pvconnection->pcontext_insucc = NULL;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL http_parser_activate_outrecycling(
	HTTP_CONTEXT *pcontext, const char *successor_cookie)
{
	RPC_OUT_CHANNEL *pchannel_out;
	
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return FALSE;
	}
	auto pvconnection = http_parser_get_vconnection(pcontext->host, pcontext->port,
		((RPC_IN_CHANNEL*)pcontext->pchannel)->connection_cookie);
	if (pvconnection != nullptr) {
		if (pcontext == pvconnection->pcontext_in &&
			NULL != pvconnection->pcontext_out &&
			NULL != pvconnection->pcontext_outsucc &&
			0 == strcmp(successor_cookie, ((RPC_OUT_CHANNEL*)
			pvconnection->pcontext_outsucc->pchannel)->channel_cookie)) {
			pchannel_out = (RPC_OUT_CHANNEL*)
				pvconnection->pcontext_out->pchannel;
			if (FALSE == pdu_processor_rts_outr2_b3(pchannel_out->pcall)) {
				pvconnection.put();
				http_parser_log_info(pcontext, 6,
					"pdu process error! fail to setup r2/b3");
				return FALSE;
			}
			pdu_processor_output_pdu(
				pchannel_out->pcall, &pchannel_out->pdu_list);
			pvconnection->pcontext_out->sched_stat = SCHED_STAT_WRREP;
			contexts_pool_signal((SCHEDULE_CONTEXT*)
						pvconnection->pcontext_out);
			pvconnection->pcontext_out = pvconnection->pcontext_outsucc;
			pvconnection->pcontext_outsucc = NULL;
			contexts_pool_signal((SCHEDULE_CONTEXT*)
						pvconnection->pcontext_out);
			return TRUE;
		}
	}
	return FALSE;
}

void http_parser_set_keep_alive(HTTP_CONTEXT *pcontext, uint32_t keepalive)
{
	RPC_IN_CHANNEL *pchannel_in;
	RPC_OUT_CHANNEL *pchannel_out;
	
	auto pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, ((RPC_IN_CHANNEL*)
		pcontext->pchannel)->connection_cookie);
	if (pvconnection != nullptr) {
		if (pcontext == pvconnection->pcontext_in) {
			pchannel_in = (RPC_IN_CHANNEL*)pcontext->pchannel;
			pchannel_in->client_keepalive = keepalive;
			if (NULL != pvconnection->pcontext_out) {
				pchannel_out = (RPC_OUT_CHANNEL*)
					pvconnection->pcontext_out->pchannel;
				pchannel_out->client_keepalive = keepalive;
			}
		}
	}
}
