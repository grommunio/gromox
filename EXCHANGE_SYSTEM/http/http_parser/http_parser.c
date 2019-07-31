/* http parser is a module, which first read data from socket, parses rpc over http and
   relay the stream to pdu processor. it also process other http request
 */ 

#include "util.h"
#include "pdu_ndr.h"
#include "resource.h"
#include "str_hash.h"
#include "mod_cache.h"
#include "mail_func.h"
#include "lib_buffer.h"
#include "mod_rewrite.h"
#include "http_parser.h"
#include "endian_macro.h"
#include "threads_pool.h"
#include "hpm_processor.h"
#include "system_services.h"
#include "blocks_allocator.h"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/err.h>


#define	MAX_RECLYING_REMAINING						0x4000000

#define OUT_CHANNEL_MAX_LENGTH						0x40000000

typedef struct _VIRTUAL_CONNECTION {
	char hash_key[256];
	volatile int reference;
	pthread_mutex_t lock;
	PDU_PROCESSOR *pprocessor;
	HTTP_CONTEXT  *pcontext_in;
	HTTP_CONTEXT  *pcontext_insucc;
	HTTP_CONTEXT  *pcontext_out;
	HTTP_CONTEXT  *pcontext_outsucc;
} VIRTUAL_CONNECTION;

 enum {
	SW_USUAL = 0,
	SW_SLASH,
	SW_DOT,
	SW_DOT_DOT,
	SW_QUOTED,
	SW_QUOTED_SECOND
};

static uint32_t  g_uri_usual[] = {
    0xffffdbfe, /* 1111 1111 1111 1111  1101 1011 1111 1110 */

                /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
    0x7fff37d6, /* 0111 1111 1111 1111  0011 0111 1101 0110 */

                /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */

    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
};

static int g_context_num;
static BOOL g_async_stop;
static BOOL g_support_ssl;
static SSL_CTX *g_ssl_ctx;
static int g_max_auth_times;
static int g_block_auth_fail;
static unsigned int g_timeout;
static pthread_key_t g_context_key;
static LIB_BUFFER *g_file_allocator;
static HTTP_CONTEXT *g_context_list;
static char g_certificate_path[256];
static char g_private_key_path[256];
static char g_certificate_passwd[1024];
static pthread_mutex_t *g_ssl_mutex_buf;
static LIB_BUFFER *g_inchannel_allocator;
static LIB_BUFFER *g_outchannel_allocator;
static pthread_mutex_t g_vconnection_lock;
static STR_HASH_TABLE *g_vconnection_hash;

static void http_parser_context_init(HTTP_CONTEXT *pcontext);

static void http_parser_context_clear(HTTP_CONTEXT *pcontext);

static void http_parser_context_free(HTTP_CONTEXT *pcontext);

static void http_parser_request_clear(HTTP_REQUEST *prequest);

static void http_parser_ssl_locking(int mode,
	int n, const char *file, int line);

static void http_parser_ssl_id(CRYPTO_THREADID* id);


BOOL http_parser_parse_uri(const char *uri_buff, char *parsed_uri)
{
	int tmp_len;
	const char *p;
	const char *uri_end;
	const char *args_start;
	int state, quoted_state;
    char c, ch, decoded, *u;
    
	decoded = '\0';
	quoted_state = SW_USUAL;
	state = SW_USUAL;
	p = uri_buff;
	uri_end = uri_buff + strlen(uri_buff);
	u = parsed_uri;
	args_start = NULL;
	ch = *p ++;
	while (p <= uri_end) {
		switch (state) {
		case SW_USUAL:
			if (g_uri_usual[ch >> 5] & (1U << (ch & 0x1f))) {
				*u++ = ch;
				ch = *p++;
				break;
			}
			switch (ch) {
			case '/':
				state = SW_SLASH;
				*u ++ = ch;
				break;
			case '%':
				quoted_state = state;
				state = SW_QUOTED;
				break;
			case '?':
				args_start = p;
				goto PARSE_ARGS;
			case '#':
				goto PARSE_DONE;
			default:
				*u ++ = ch;
				break;
			}
			ch = *p ++;
			break;
		case SW_SLASH:
			if (g_uri_usual[ch >> 5] & (1U << (ch & 0x1f))) {
				state = SW_USUAL;
				*u ++ = ch;
				ch = *p ++;
				break;
			}
			switch (ch) {
			case '/':
				/* merge slash */
				break;
			case '.':
				state = SW_DOT;
				*u ++ = ch;
				break;
			case '%':
				quoted_state = state;
				state = SW_QUOTED;
				break;
			case '?':
				args_start = p;
				goto PARSE_ARGS;
			case '#':
				goto PARSE_DONE;
			default:
				state = SW_USUAL;
				*u ++ = ch;
				break;
			}
			ch = *p ++;
			break;
		case SW_DOT:
			if (g_uri_usual[ch >> 5] & (1U << (ch & 0x1f))) {
				state = SW_USUAL;
				*u ++ = ch;
				ch = *p ++;
				break;
			}
			switch (ch) {
			case '/':
				state = SW_SLASH;
				u --;
				break;
			case '.':
				state = SW_DOT_DOT;
				*u ++ = ch;
				break;
			case '%':
				quoted_state = state;
				state = SW_QUOTED;
				break;
			case '?':
				args_start = p;
				goto PARSE_ARGS;
			case '#':
				goto PARSE_DONE;
			default:
				state = SW_USUAL;
				*u ++ = ch;
				break;
			}
			ch = *p ++;
			break;
		case SW_DOT_DOT:
			if (g_uri_usual[ch >> 5] & (1U << (ch & 0x1f))) {
				state = SW_USUAL;
				*u ++ = ch;
				ch = *p ++;
				break;
			}
			switch (ch) {
			case '/':
				state = SW_SLASH;
				u -= 5;
				for ( ;; ) {
					if (u < parsed_uri) {
						return FALSE;
					}
					if ('/' == *u) {
						u ++;
						break;
					}
					u --;
				}
				break;
			case '%':
				quoted_state = state;
				state = SW_QUOTED;
				break;
			case '?':
				args_start = p;
				goto PARSE_ARGS;
			case '#':
				goto PARSE_DONE;
			default:
				state = SW_USUAL;
				*u ++ = ch;
				break;
			}
			ch = *p ++;
			break;
		case SW_QUOTED:
			if (ch >= '0' && ch <= '9') {
				decoded = (uint8_t)(ch - '0');
				state = SW_QUOTED_SECOND;
				ch = *p ++;
				break;
			}
			c = (uint8_t)(ch | 0x20);
			if (c >= 'a' && c <= 'f') {
				decoded = (uint8_t)(c - 'a' + 10);
				state = SW_QUOTED_SECOND;
				ch = *p ++;
				break;
			}
			return FALSE;
		case SW_QUOTED_SECOND:
			if (ch >= '0' && ch <= '9') {
				ch = (uint8_t)((decoded << 4) + (ch - '0'));
				if ('%' == ch || '#' == ch) {
					state = SW_USUAL;
					*u ++ = ch;
					ch = *p ++;
					break;

				} else if ('\0' == ch) {
					return FALSE;
				}
				state = quoted_state;
				break;
			}

			c = (uint8_t)(ch | 0x20);
			if (c >= 'a' && c <= 'f') {
				ch = (uint8_t) ((decoded << 4) + (c - 'a') + 10);
				if ('?' == ch) {
					state = SW_USUAL;
					*u ++ = ch;
					ch = *p ++;
					break;

				}
				state = quoted_state;
				break;
			}
			return FALSE;
		}
	}
PARSE_ARGS:
    while (p < uri_end) {
        if (*p ++ != '#') {
            continue;
        }
		tmp_len = p - args_start;
		memcpy(u, args_start, tmp_len);
		u += tmp_len;
        break;
    }
PARSE_DONE:
	*u = '\0';
    return TRUE;
}

void http_parser_init(int context_num, unsigned int timeout,
	int max_auth_times, int block_auth_fail, BOOL support_ssl,
	const char *certificate_path, const char *cb_passwd,
	const char *key_path)
{
    g_context_num           = context_num;
    g_timeout               = timeout;
	g_max_auth_times        = max_auth_times;
	g_block_auth_fail       = block_auth_fail;
	g_support_ssl           = support_ssl;
	g_ssl_mutex_buf         = NULL;
	g_async_stop            = FALSE;
	pthread_mutex_init(&g_vconnection_lock, NULL);
	
	if (TRUE == support_ssl) {
		strcpy(g_certificate_path, certificate_path);
		if (NULL != cb_passwd) {
			strcpy(g_certificate_passwd, cb_passwd);
		} else {
			g_certificate_passwd[0] = '\0';
		}
		strcpy(g_private_key_path, key_path);
	}
}

/* 
 * run the http parser module
 *    @return
 *         0    success
 *        <>0    fail    
 */
int http_parser_run()
{
    int i;
	
	pthread_key_create(&g_context_key, NULL);
	if (TRUE == g_support_ssl) {
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();
		g_ssl_ctx = SSL_CTX_new(SSLv23_server_method());
		if (NULL == g_ssl_ctx) {
			printf("[http_parser]: fail to init ssl context\n");
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
		g_ssl_mutex_buf = malloc(CRYPTO_num_locks()*sizeof(pthread_mutex_t));
		if (NULL == g_ssl_mutex_buf) {
			printf("[http_parser]: fail to allocate ssl locking buffer\n");
			return -5;
		}
		for (i=0; i<CRYPTO_num_locks(); i++) {
			pthread_mutex_init(&g_ssl_mutex_buf[i], NULL);
		}
		CRYPTO_THREADID_set_callback(http_parser_ssl_id);
		CRYPTO_set_locking_callback(http_parser_ssl_locking);
	}
	g_file_allocator = lib_buffer_init(FILE_ALLOC_SIZE,
							g_context_num * 16, TRUE);
	if (NULL == g_file_allocator) {
		printf("[http_parser]: fail to init mem file allocator\n");
		return -6;
	}
	g_vconnection_hash = str_hash_init(g_context_num + 1,
						sizeof(VIRTUAL_CONNECTION), NULL);
	if (NULL == g_vconnection_hash) {
		printf("[http_parser]: fail to init select hash table\n");
		return -7;
	}
    g_context_list = malloc(sizeof(HTTP_CONTEXT)*g_context_num);
    if (NULL== g_context_list) {
        printf("[http_parser]: fail to allocate http contexts\n");
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
    for (i=0; i<g_context_num; i++) {
        http_parser_context_init(g_context_list + i);
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
	int i;
	STR_HASH_ITER *iter;
	VIRTUAL_CONNECTION *pvconnection;
	
	if (NULL != g_inchannel_allocator) {
		lib_buffer_free(g_inchannel_allocator);
		g_inchannel_allocator = NULL;
	}
	if (NULL != g_outchannel_allocator) {
		lib_buffer_free(g_outchannel_allocator);
		g_outchannel_allocator = NULL;
	}
	if (NULL != g_context_list) {
		for (i=0; i<g_context_num; i++) {
			http_parser_context_free(g_context_list + i);
		}
		free(g_context_list);
		g_context_list = NULL;
	}
	if (NULL != g_vconnection_hash) {
		iter = str_hash_iter_init(g_vconnection_hash);
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			pvconnection = str_hash_iter_get_value(iter, NULL);
			if (NULL != pvconnection->pprocessor) {
				pdu_processor_destroy(pvconnection->pprocessor);
			}
		}
		str_hash_iter_free(iter);
		str_hash_free(g_vconnection_hash);
		g_vconnection_hash = NULL;
	}
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
		for (i=0; i<CRYPTO_num_locks(); i++) {
			pthread_mutex_destroy(&g_ssl_mutex_buf[i]);
		}
		free(g_ssl_mutex_buf);
		g_ssl_mutex_buf = NULL;
	}
	pthread_key_delete(g_context_key);
    return 0;
}

void http_parser_free()
{
	pthread_mutex_destroy(&g_vconnection_lock);
}

int http_parser_threads_event_proc(int action)
{
	return 0;
}

int http_parser_get_context_socket(HTTP_CONTEXT *pcontext)
{
	return pcontext->connection.sockd;
}

struct timeval http_parser_get_context_timestamp(HTTP_CONTEXT *pcontext)
{
	return pcontext->connection.last_timestamp;
}

static VIRTUAL_CONNECTION* http_parser_get_vconnection(
	const char *host, int port, const char *conn_cookie)
{
	char tmp_buff[256];
	VIRTUAL_CONNECTION *pvconnection;
	
	snprintf(tmp_buff, 256, "%s:%d:%s", conn_cookie, port, host);
	lower_string(tmp_buff);
	pthread_mutex_lock(&g_vconnection_lock);
	pvconnection = str_hash_query(g_vconnection_hash, tmp_buff);
	if (NULL != pvconnection) {
		pvconnection->reference ++;
	}
	pthread_mutex_unlock(&g_vconnection_lock);
	if (NULL != pvconnection) {
		pthread_mutex_lock(&pvconnection->lock);
	}
	return pvconnection;
}

static void http_parser_put_vconnection(VIRTUAL_CONNECTION *pvconnection)
{
	PDU_PROCESSOR *pprocessor;
	
	pthread_mutex_unlock(&pvconnection->lock);
	pprocessor = NULL;
	pthread_mutex_lock(&g_vconnection_lock);
	pvconnection->reference --;
	if (0 == pvconnection->reference &&
		NULL == pvconnection->pcontext_in &&
		NULL == pvconnection->pcontext_out) {
		pprocessor = pvconnection->pprocessor;
		str_hash_remove(g_vconnection_hash, pvconnection->hash_key);
	}
	pthread_mutex_unlock(&g_vconnection_lock);
	if (NULL != pprocessor) {
		pdu_processor_destroy(pprocessor);
	}
}

static void http_parser_rfc1123_dstring(char *dstring)
{
	time_t cur_time;
	struct tm tmp_tm;
	
	time(&cur_time);
	gmtime_r(&cur_time, &tmp_tm);
	
	strftime(dstring, 128, "%a, %d %b %Y %T GMT", &tmp_tm);
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
	char *pbuff;
	char *pbuff1;
	int size1_used;
	int size_copied;
	
	stream_init(pstream_dst, blocks_allocator_get_allocator());
	size = STREAM_BLOCK_SIZE;
	pbuff = stream_getbuffer_for_reading(pstream_src, &size);
	if (NULL == pbuff) {
		return 0;
	}
	size1 = STREAM_BLOCK_SIZE;
	pbuff1 = stream_getbuffer_for_writing(pstream_dst, &size1);
	/*
	 * do not need to check the pbuff pointer because it will
	 * never be NULL because of stream's characteristic
	 */
	size_copied = 0;
	size1_used = 0;
	do {
		if (size <= size1 - size1_used) {
			memcpy(pbuff1, pbuff, size);
			size1_used += size;
		} else {
			size_copied = size1 - size1_used;
			memcpy(pbuff1 + size1_used, pbuff, size_copied);
			size1 = STREAM_BLOCK_SIZE;
			size1_used = 0;
			stream_forward_writing_ptr(pstream_dst, STREAM_BLOCK_SIZE);
			pbuff1 = stream_getbuffer_for_writing(pstream_dst, &size1);
			if (NULL == pbuff1) {
				stream_free(pstream_dst);
				return -1;
			}
			size1_used = size - size_copied;
			memcpy(pbuff1, pbuff + size_copied, size1_used);
		}
		size = STREAM_BLOCK_SIZE;
		pbuff = stream_getbuffer_for_reading(pstream_src, &size);
	} while (NULL != pbuff);
	stream_forward_writing_ptr(pstream_dst, size1_used);
	return stream_get_total_length(pstream_dst);
}

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
int http_parser_process(HTTP_CONTEXT *pcontext)
{
	int result;
	char *line;
	char *pbuff;
	int tmp_len;
	int tmp_len1;
	char *ptoken;
	char *ptoken1;
	STREAM stream;
	int written_len;
	char reason[256];
	int response_len;
	size_t decode_len;
	char dstring[128];
	DCERPC_CALL *pcall;
	char field_name[64];
	char tmp_buff[1024];
	char tmp_buff1[1024];
	uint16_t frag_length;
	int size, line_length;
	DOUBLE_LIST_NODE *pnode;
	char response_buff[1024];
    int actual_read, ssl_errno;
    struct timeval current_time;
	RPC_IN_CHANNEL *pchannel_in;
	RPC_OUT_CHANNEL *pchannel_out;
	VIRTUAL_CONNECTION *pvconnection;
	

CONTEXT_PROCESSING:
	if (SCHED_STAT_INITSSL == pcontext->sched_stat) {
		if (NULL == pcontext->connection.ssl) {
			pcontext->connection.ssl = SSL_new(g_ssl_ctx);
			if (NULL == pcontext->connection.ssl) {
				http_parser_log_info(pcontext, 8, "out of SSL object");
				goto INERTNAL_SERVER_ERROR;
			}
			SSL_set_fd(pcontext->connection.ssl, pcontext->connection.sockd);
		}
		if (-1 == SSL_accept(pcontext->connection.ssl)) {
			ssl_errno = SSL_get_error(pcontext->connection.ssl, -1);
			if (SSL_ERROR_WANT_READ == ssl_errno ||
				SSL_ERROR_WANT_WRITE == ssl_errno) {
				gettimeofday(&current_time, NULL);
				if (CALCULATE_INTERVAL(current_time,
					pcontext->connection.last_timestamp) < g_timeout) {
					return PROCESS_POLLING_RDONLY;
				}
				http_parser_log_info(pcontext, 8, "time out");
				goto REQUEST_TIME_OUT;
			} else {
				http_parser_log_info(pcontext, 8, "fail to accept"
						" SSL connection, errno is %d", ssl_errno);
				goto END_PROCESSING;
			}
		} else {
			pcontext->sched_stat = SCHED_STAT_RDHEAD;
			return PROCESS_CONTINUE;
		}
	} else if (SCHED_STAT_RDHEAD == pcontext->sched_stat) {
		size = STREAM_BLOCK_SIZE;
		pbuff = stream_getbuffer_for_writing(&pcontext->stream_in, &size);
		if (NULL == pbuff) {
			http_parser_log_info(pcontext, 8, "out of memory");
			goto INERTNAL_SERVER_ERROR;
		}
		if (NULL != pcontext->connection.ssl) {
			actual_read = SSL_read(pcontext->connection.ssl, pbuff, size);
		} else {
			actual_read = read(pcontext->connection.sockd, pbuff, size);
		}
		gettimeofday(&current_time, NULL);
		if (0 == actual_read) {
			http_parser_log_info(pcontext, 8, "connection lost");
			goto END_PROCESSING;
		} else if (actual_read > 0) {
			pcontext->connection.last_timestamp = current_time;
			stream_forward_writing_ptr(&pcontext->stream_in, actual_read);
		} else {
			if (EAGAIN != errno) {
				http_parser_log_info(pcontext, 8, "connection lost");
				goto END_PROCESSING;
			}
			/* check if context is timed out */
			if (CALCULATE_INTERVAL(current_time,
				pcontext->connection.last_timestamp) >= g_timeout) {
				http_parser_log_info(pcontext, 8, "time out");
				goto REQUEST_TIME_OUT;
			}
			
			/* do not return immediately, check
				line in stream (eg. pipeline) */
		}
		
		while (TRUE) {
			stream_try_mark_line(&pcontext->stream_in);
			switch (stream_has_newline(&pcontext->stream_in)) {
			case STREAM_LINE_FAIL:
				http_parser_log_info(pcontext, 8,
					"request header line too long");
				goto BAD_HTTP_REQUEST;
			case STREAM_LINE_UNAVAILABLE:
				if (actual_read > 0) {
					return PROCESS_CONTINUE;
				} else {
					return PROCESS_POLLING_RDONLY;
				}
			case STREAM_LINE_AVAILABLE:
				/* continue to process line below */
				break;
			}
			
			line_length = stream_readline(&pcontext->stream_in, &line);
			
			if (0 != line_length) {
				if ('\0' == pcontext->request.method[0]) {
					ptoken = memchr(line, ' ', line_length);
					if (NULL == ptoken) {
						http_parser_log_info(pcontext,
							8, "request method error");
						goto BAD_HTTP_REQUEST;
					}
					tmp_len = ptoken - line;
					if (tmp_len >= 32) {
						http_parser_log_info(pcontext,
							8, "request method error");
						goto BAD_HTTP_REQUEST;
					}
					
					memcpy(pcontext->request.method, line, tmp_len);
					pcontext->request.method[tmp_len] = '\0';
					ptoken1 = memchr(ptoken + 1, ' ',
							line_length - tmp_len - 1);
					if (NULL == ptoken1) {
						http_parser_log_info(pcontext,
							8, "request method error");
						goto BAD_HTTP_REQUEST;
					}
					tmp_len1 = ptoken1 - ptoken - 1;
					tmp_len = line_length - (ptoken1 + 6 - line);
					if (0 != strncasecmp(ptoken1 + 1,
						"HTTP/", 5) || tmp_len >= 8) {
						http_parser_log_info(pcontext,
							8, "request method error");
						goto BAD_HTTP_REQUEST;
					}
					if (FALSE == mod_rewrite_process(ptoken + 1,
						tmp_len1, &pcontext->request.f_request_uri)) {
						mem_file_write(&pcontext->request.f_request_uri,
							ptoken + 1, tmp_len1);
					}
					memcpy(pcontext->request.version, ptoken1 + 6, tmp_len);
					pcontext->request.version[tmp_len] = '\0';
				} else {
					ptoken = memchr(line, ':', line_length);
					if (NULL == ptoken) {
						http_parser_log_info(pcontext,
							8, "request method error");
						goto BAD_HTTP_REQUEST;
					}
					
					tmp_len = ptoken - line;
					memcpy(field_name, line, tmp_len);
					field_name[tmp_len] = '\0';
					ltrim_string(field_name);
					rtrim_string(field_name);
					
					ptoken ++;
					while (ptoken - line < line_length) {
						if (' ' != *ptoken && '\t' != *ptoken) {
							break;
						}
						ptoken ++;
					}
					tmp_len = line_length - (ptoken - line);
					
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
							pcontext->b_close = FALSE;
						}
						tmp_len1 = strlen(field_name);
						mem_file_write(&pcontext->request.f_others, 
							(char*)&tmp_len1, sizeof(int));
						mem_file_write(&pcontext->request.f_others,
							field_name, tmp_len1);
						mem_file_write(&pcontext->request.f_others,
							(char*)&tmp_len, sizeof(int));
						mem_file_write(&pcontext->request.f_others,
							ptoken, tmp_len);
					}
				}
				continue;
			}
			
			/* meet the end of request header */
			if (http_parser_reconstruct_stream(
				&pcontext->stream_in, &stream) < 0) {
				http_parser_log_info(pcontext, 8, "out of memory");
				goto INERTNAL_SERVER_ERROR;
			}
			stream_free(&pcontext->stream_in);
			pcontext->stream_in = stream;
			
			if (TRUE == http_parser_request_head(
				&pcontext->request.f_others, "Authorization", tmp_buff,
				1024) && 0 == strncasecmp(tmp_buff, "Basic ", 6) &&
				0 == decode64(tmp_buff + 6, strlen(tmp_buff + 6), tmp_buff1,
				&decode_len) && NULL != (ptoken = strchr(tmp_buff1, ':'))) {
				
				*ptoken = '\0';
				ptoken ++;
				strncpy(pcontext->username, tmp_buff1, 256);
				strncpy(pcontext->password, ptoken, 128);
				
				if (FALSE == system_services_judge_user(pcontext->username)) {
					http_parser_rfc1123_dstring(dstring);
					response_len = snprintf(
						response_buff, sizeof(response_buff),
						"HTTP/1.1 503 Service Unavailable\r\n"
						"Date: %s\r\n"
						"Server: %s\r\n"
						"Content-Length: 0\r\n"
						"Connection: close\r\n"
						"\r\n", dstring, resource_get_string(RES_HOST_ID));
					stream_write(&pcontext->stream_out,
						response_buff, response_len);
					pcontext->total_length = response_len;
					pcontext->bytes_rw = 0;
					pcontext->b_close = TRUE;
					pcontext->sched_stat = SCHED_STAT_WRREP;
					http_parser_log_info(pcontext, 8,
						"user %s is denied by user filter",
						pcontext->username);
					goto CONTEXT_PROCESSING;
				}
				if (TRUE == system_services_auth_login(
					pcontext->username, pcontext->password,
					pcontext->maildir, pcontext->lang, reason, 256)) {
					if ('\0' == pcontext->maildir[0]) {
						http_parser_rfc1123_dstring(dstring);
						response_len = snprintf(
							response_buff, sizeof(response_buff),
							"HTTP/1.1 401 Unauthorized\r\n"
							"Date: %s\r\n"
							"Server: %s\r\n"
							"Content-Length: 0\r\n"
							"Keep-Alive: timeout=%d\r\n"
							"Connection: Keep-Alive\r\n"
							"WWW-Authenticate: Basic realm=\"msrpc realm\"\r\n"
							"\r\n", dstring, resource_get_string(RES_HOST_ID),
							g_timeout);
						stream_write(&pcontext->stream_out,
							response_buff, response_len);
						pcontext->total_length = response_len;
						pcontext->bytes_rw = 0;
						pcontext->sched_stat = SCHED_STAT_WRREP;
						http_parser_log_info(pcontext,
							8, "can not get maildir");
						goto CONTEXT_PROCESSING;
					}

					if ('\0' == pcontext->lang[0]) {
						strcpy(pcontext->lang,
							resource_get_string(RES_USER_DEFAULT_LANG));
					}
					pcontext->b_authed = TRUE;
					http_parser_log_info(pcontext, 8, "login success");
				} else {
					pcontext->b_authed = FALSE;
					http_parser_log_info(pcontext, 8, "login fail");
					pcontext->auth_times ++;
					if (pcontext->auth_times >= g_max_auth_times) {
						system_services_add_user_into_temp_list(
							pcontext->username, g_block_auth_fail);
					}
					http_parser_rfc1123_dstring(dstring);
					response_len = snprintf(
						response_buff, sizeof(response_buff),
						"HTTP/1.1 401 Unauthorized\r\n"
						"Date: %s\r\n"
						"Server: %s\r\n"
						"Keep-Alive: timeout=%d\r\n"
						"Connection: Keep-Alive\r\n"
						"Content-Type: text/plain; charset=ascii\r\n"
						"Content-Length: %d\r\n"
						"WWW-Authenticate: Basic realm=\"msrpc realm\"\r\n"
						"\r\n%s\r\n", dstring,
						resource_get_string(RES_HOST_ID),
						g_timeout, strlen(reason) + 2, reason);
					stream_write(&pcontext->stream_out,
						response_buff, response_len);
					pcontext->total_length = response_len;
					pcontext->bytes_rw = 0;
					pcontext->sched_stat = SCHED_STAT_WRREP;
					goto CONTEXT_PROCESSING;
				}
			}
			
			if (0 == strcasecmp(pcontext->request.method, "RPC_IN_DATA") ||
				0 == strcasecmp(pcontext->request.method, "RPC_OUT_DATA")) {
				tmp_len = mem_file_get_total_length(
					&pcontext->request.f_request_uri);
				if (0 == tmp_len || tmp_len >= 1024) {
					http_parser_log_info(pcontext, 8,
						"rpcproxy request method error");
					goto BAD_HTTP_REQUEST;
				}
				tmp_len = mem_file_read(
					&pcontext->request.f_request_uri,
					tmp_buff, 1024);
				tmp_buff[tmp_len] = '\0';
				
				if (0 == strncmp(tmp_buff, "/rpc/rpcproxy.dll?", 18)) {
					ptoken = tmp_buff + 18;
				} else if (0 == strncmp(tmp_buff,
					"/rpcwithcert/rpcproxy.dll?", 26)) {
					ptoken = tmp_buff + 26;
				} else {
					http_parser_log_info(pcontext, 8,
						"rpcproxy request method error");
					goto BAD_HTTP_REQUEST;
				}
				ptoken1 = strchr(tmp_buff, ':');
				if (NULL == ptoken1) {
					http_parser_log_info(pcontext, 8,
						"rpcproxy request method error");
					goto BAD_HTTP_REQUEST;
				}
				*ptoken1 = '\0';
				if (ptoken1 - ptoken > 128) {
					http_parser_log_info(pcontext, 8,
						"rpcproxy request method error");
					goto BAD_HTTP_REQUEST;
				}
				ptoken1 ++;
				strcpy(pcontext->host, ptoken);
				pcontext->port = atoi(ptoken1);
				
				if (FALSE == pcontext->b_authed) {
					http_parser_rfc1123_dstring(dstring);
					response_len = snprintf(
						response_buff, sizeof(response_buff),
						"HTTP/1.1 401 Unauthorized\r\n"
						"Date: %s\r\n"
						"Server: %s\r\n"
						"Content-Length: 0\r\n"
						"Keep-Alive: timeout=%d\r\n"
						"Connection: Keep-Alive\r\n"
						"WWW-Authenticate: Basic realm=\"msrpc realm\"\r\n"
						"\r\n", dstring, resource_get_string(RES_HOST_ID),
						g_timeout);
					stream_write(&pcontext->stream_out,
						response_buff, response_len);
					pcontext->total_length = response_len;
					pcontext->bytes_rw = 0;
					pcontext->sched_stat = SCHED_STAT_WRREP;
					http_parser_log_info(pcontext, 8,
						"authentification needed");
					goto CONTEXT_PROCESSING;
				}
				
				tmp_len = mem_file_read(
					&pcontext->request.f_content_length,
					tmp_buff, 256);
				if (MEM_END_OF_FILE == tmp_len) {
					http_parser_log_info(pcontext, 8,
						"content-length of rpcproxy request error");
					goto BAD_HTTP_REQUEST;
				}
				pcontext->total_length = atoll(tmp_buff);
				
				/* ECHO request 0x0 ~ 0x10, MS-RPCH 2.1.2.15 */
				if (pcontext->total_length > 0x10) {
					if (0 == strcmp(pcontext->request.method, "RPC_IN_DATA")) {
						pcontext->channel_type = CHANNEL_TYPE_IN;
						pcontext->pchannel =
							lib_buffer_get(g_inchannel_allocator);
						if (NULL == pcontext->pchannel) {
							goto INERTNAL_SERVER_ERROR;
						}	
						memset(pcontext->pchannel, 0, sizeof(RPC_IN_CHANNEL));
						double_list_init(&((RPC_IN_CHANNEL*)
							pcontext->pchannel)->pdu_list);
					} else {
						pcontext->channel_type = CHANNEL_TYPE_OUT;
						pcontext->pchannel =
							lib_buffer_get(g_outchannel_allocator);
						if (NULL == pcontext->pchannel) {
							goto INERTNAL_SERVER_ERROR;
						}
						memset(pcontext->pchannel, 0, sizeof(RPC_OUT_CHANNEL));
						double_list_init(&((RPC_OUT_CHANNEL*)
							pcontext->pchannel)->pdu_list);
					}
				}
				pcontext->bytes_rw = stream_get_total_length(&stream);
				pcontext->sched_stat = SCHED_STAT_RDBODY;
				goto CONTEXT_PROCESSING;
			}
			/* try to make hpm_processor take over the request */
			if (TRUE == hpm_processor_get_context(pcontext)) {
				/* let mod_fastcgi decide the read/write bytes */
				pcontext->bytes_rw = 0;
				pcontext->total_length = 0;
				
				if (FALSE == hpm_processor_write_request(pcontext)) {
					goto INERTNAL_SERVER_ERROR;
				}
				if (TRUE == hpm_processor_check_end_of_request(pcontext)) {
					if (FALSE == hpm_processor_proc(pcontext)) {
						goto INERTNAL_SERVER_ERROR;
					}
					pcontext->sched_stat = SCHED_STAT_WRREP;
					if (http_parser_reconstruct_stream(
						&pcontext->stream_in, &stream) < 0) {
						http_parser_log_info(pcontext, 8, "out of memory");
						goto INERTNAL_SERVER_ERROR;
					}
					stream_free(&pcontext->stream_in);
					pcontext->stream_in = stream;
					if (0 != stream_get_total_length(
						&pcontext->stream_out)) {
						tmp_len = STREAM_BLOCK_SIZE;
						pcontext->write_buff =
							stream_getbuffer_for_reading(
							&pcontext->stream_out, &tmp_len);
						pcontext->write_length = tmp_len;
					}
				} else {
					pcontext->sched_stat = SCHED_STAT_RDBODY;
				}
				goto CONTEXT_PROCESSING;
			}
			/* try to make mod_fastcgi process the request */
			if (TRUE == mod_fastcgi_get_context(pcontext)) {
				/* let mod_fastcgi decide the read/write bytes */
				pcontext->bytes_rw = 0;
				pcontext->total_length = 0;
				
				if (FALSE == mod_fastcgi_write_request(pcontext)) {
					goto INERTNAL_SERVER_ERROR;
				}
				if (TRUE == mod_fastcgi_check_end_of_read(pcontext)) {
					if (FALSE == mod_fastcgi_relay_content(pcontext)) {
						goto INERTNAL_SERVER_ERROR;
					}
					pcontext->sched_stat = SCHED_STAT_WRREP;
					if (http_parser_reconstruct_stream(
						&pcontext->stream_in, &stream) < 0) {
						http_parser_log_info(pcontext, 8, "out of memory");
						goto INERTNAL_SERVER_ERROR;
					}
					stream_free(&pcontext->stream_in);
					pcontext->stream_in = stream;
				} else {
					pcontext->sched_stat = SCHED_STAT_RDBODY;
				}
				goto CONTEXT_PROCESSING;
			}
			if (TRUE == mod_cache_get_context(pcontext)) {
				/* let mod_cache decide the read/write bytes */
				pcontext->bytes_rw = 0;
				pcontext->total_length = 0;
				pcontext->sched_stat = SCHED_STAT_WRREP;
				if (http_parser_reconstruct_stream(
					&pcontext->stream_in, &stream) < 0) {
					http_parser_log_info(pcontext, 8, "out of memory");
					goto INERTNAL_SERVER_ERROR;
				}
				stream_free(&pcontext->stream_in);
				pcontext->stream_in = stream;
				goto CONTEXT_PROCESSING;
			}
			/* other http request here if wanted */
			http_parser_rfc1123_dstring(dstring);
			response_len = snprintf(response_buff, sizeof(response_buff),
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
						dstring, resource_get_string(RES_HOST_ID));
			stream_write(&pcontext->stream_out, response_buff, response_len);
			pcontext->total_length = response_len;
			pcontext->bytes_rw = 0;
			pcontext->sched_stat = SCHED_STAT_WRREP;
			goto CONTEXT_PROCESSING;
        }
	} else if (SCHED_STAT_WRREP == pcontext->sched_stat) {
		if (NULL == pcontext->write_buff) {
			if (TRUE == hpm_processor_check_context(pcontext)) {
				switch (hpm_processor_retrieve_response(pcontext)) {
				case HPM_RETRIEVE_ERROR:
					goto INERTNAL_SERVER_ERROR;
				case HPM_RETRIEVE_WRITE:
					break;
				case HPM_RETRIEVE_WAIT:
					pcontext->sched_stat = SCHED_STAT_WAIT;
					return PROCESS_IDLE;
				case HPM_RETRIEVE_DONE:
					if (TRUE == pcontext->b_close) {
						goto END_PROCESSING;
					} else {
						http_parser_request_clear(&pcontext->request);
						hpm_processor_put_context(pcontext);
						pcontext->sched_stat = SCHED_STAT_RDHEAD;
						stream_clear(&pcontext->stream_out);
						return PROCESS_CONTINUE;
					}
				}
			} else if (NULL != pcontext->pfast_context) {
				switch (mod_fastcgi_check_response(pcontext)) {
				case RESPONSE_WAITING:
					return PROCESS_CONTINUE;
				case RESPONSE_TIMEOUT:
					http_parser_log_info(pcontext, 8, "fastcgi excution time out");
					goto INERTNAL_SERVER_ERROR;
				}
				if (TRUE == mod_fastcgi_check_responded(pcontext)) {
					if (FALSE == mod_fastcgi_read_response(pcontext)) {
						if (0 == stream_get_total_length(
							&pcontext->stream_out)) {
							if (TRUE == pcontext->b_close) {
								goto END_PROCESSING;
							} else {
								http_parser_request_clear(&pcontext->request);
								pcontext->sched_stat = SCHED_STAT_RDHEAD;
								stream_clear(&pcontext->stream_out);
								return PROCESS_CONTINUE;
							}
						}
					}
				} else {
					if (FALSE == mod_fastcgi_read_response(pcontext)) {
						goto INERTNAL_SERVER_ERROR;
					}
				}
			} else if (TRUE == mod_cache_check_caching(pcontext)) {
				if (FALSE == mod_cache_read_response(pcontext)) {
					if (FALSE == mod_cache_check_responded(pcontext)) {
						goto INERTNAL_SERVER_ERROR;
					}
					if (0 == stream_get_total_length(&pcontext->stream_out)) {
						if (TRUE == pcontext->b_close) {
							goto END_PROCESSING;
						} else {
							http_parser_request_clear(&pcontext->request);
							pcontext->sched_stat = SCHED_STAT_RDHEAD;
							stream_clear(&pcontext->stream_out);
							return PROCESS_CONTINUE;
						}
					}
				}
			}
			pcontext->write_offset = 0;
			if (CHANNEL_TYPE_OUT == pcontext->channel_type &&
				CHANNEL_STAT_OPENED == ((RPC_OUT_CHANNEL*)
				pcontext->pchannel)->channel_stat) {
				/* stream_out is shared resource of vconnection,
					lock it first before operating */
				pvconnection = http_parser_get_vconnection(
					pcontext->host, pcontext->port,
					((RPC_OUT_CHANNEL*)pcontext->pchannel)->connection_cookie);
				if (NULL == pvconnection) {
					http_parser_log_info(pcontext, 8,
						"virtual connection error in hash table");
					goto END_PROCESSING;
				}
				pnode = double_list_get_head(
					&((RPC_OUT_CHANNEL*)pcontext->pchannel)->pdu_list);
				if (NULL == pnode) {
					http_parser_put_vconnection(pvconnection);
					pcontext->sched_stat = SCHED_STAT_WAIT;
					return PROCESS_IDLE;
				}
				pcontext->write_buff = ((BLOB_NODE*)pnode->pdata)->blob.data;
				tmp_len = ((BLOB_NODE*)pnode->pdata)->blob.length;
				http_parser_put_vconnection(pvconnection);
			} else {
				tmp_len = STREAM_BLOCK_SIZE;
				pcontext->write_buff = stream_getbuffer_for_reading(
									&pcontext->stream_out, &tmp_len);
			}
			
			/* if context is set to write response state, there's
				always data in stream_out. so we did not check
				wether pcontext->write_buff pointer is NULL */
			pcontext->write_length = tmp_len;
		}
		
		written_len = pcontext->write_length - pcontext->write_offset;
		if (CHANNEL_TYPE_OUT == pcontext->channel_type &&
			CHANNEL_STAT_OPENED == ((RPC_OUT_CHANNEL*)
			pcontext->pchannel)->channel_stat) {
			pchannel_out = (RPC_OUT_CHANNEL*)pcontext->pchannel;
			if (pchannel_out->available_window < 1024) {
				return PROCESS_IDLE;
			}
			if (written_len > pchannel_out->available_window) {
				written_len = pchannel_out->available_window;
			}
		}
		if (NULL != pcontext->connection.ssl) {
			written_len = SSL_write(pcontext->connection.ssl,
				pcontext->write_buff + pcontext->write_offset,
				written_len);
		} else {
			written_len = write(pcontext->connection.sockd,
				pcontext->write_buff + pcontext->write_offset,
				written_len);
		}

        gettimeofday(&current_time, NULL);
		
		if (0 == written_len) {
			http_parser_log_info(pcontext, 8, "connection lost");
			goto END_PROCESSING;
		} else if (written_len < 0) {
			if (EAGAIN != errno) {
				http_parser_log_info(pcontext, 8, "connection lost");
				goto END_PROCESSING;
			}
			/* check if context is timed out */
			if (CALCULATE_INTERVAL(current_time,
				pcontext->connection.last_timestamp) >= g_timeout) {
				http_parser_log_info(pcontext, 8, "time out");
				goto END_PROCESSING;
			} else {
				return PROCESS_POLLING_WRONLY;
			}
		}
        pcontext->connection.last_timestamp = current_time;
        pcontext->write_offset += written_len;
		pcontext->bytes_rw += written_len;
		if (CHANNEL_TYPE_OUT == pcontext->channel_type &&
			CHANNEL_STAT_OPENED == ((RPC_OUT_CHANNEL*)
			pcontext->pchannel)->channel_stat) {
			pvconnection = http_parser_get_vconnection(pcontext->host,
					pcontext->port, pchannel_out->connection_cookie);
			pnode = double_list_get_head(&pchannel_out->pdu_list);
			if (FALSE == ((BLOB_NODE*)pnode->pdata)->b_rts) {
				pchannel_out->available_window -= written_len;
				pchannel_out->bytes_sent += written_len;
			}
			if (NULL != pvconnection) {
				http_parser_put_vconnection(pvconnection);
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
			pvconnection = http_parser_get_vconnection(
				pcontext->host, pcontext->port,
				((RPC_OUT_CHANNEL*)pcontext->pchannel)->connection_cookie);
			if (NULL == pvconnection) {
				http_parser_log_info(pcontext, 8,
					"virtual connection error in hash table");
				goto END_PROCESSING;
			}
			pnode = double_list_get_from_head(
				&((RPC_OUT_CHANNEL*)pcontext->pchannel)->pdu_list);
			free(((BLOB_NODE*)pnode->pdata)->blob.data);
			pdu_processor_free_blob(pnode->pdata);
			pnode = double_list_get_head(
				&((RPC_OUT_CHANNEL*)pcontext->pchannel)->pdu_list);
			if (NULL == pnode) {
				if (pcontext->total_length > 0 &&
					pcontext->total_length - pcontext->bytes_rw <=
					MAX_RECLYING_REMAINING && FALSE ==
					((RPC_OUT_CHANNEL*)pcontext->pchannel)->b_obsolete) {
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
			} else {
				pcontext->write_buff =
					((BLOB_NODE*)pnode->pdata)->blob.data;
				pcontext->write_length =
					((BLOB_NODE*)pnode->pdata)->blob.length;
			}
			http_parser_put_vconnection(pvconnection);
		} else {
			tmp_len = STREAM_BLOCK_SIZE;
			pcontext->write_buff = stream_getbuffer_for_reading(
								&pcontext->stream_out, &tmp_len);
			pcontext->write_length = tmp_len;
			if (NULL == pcontext->write_buff) {
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
						goto END_PROCESSING;
					}
					http_parser_request_clear(&pcontext->request);
					pcontext->sched_stat = SCHED_STAT_RDHEAD;
				}
				stream_clear(&pcontext->stream_out);
			}
        }
        return PROCESS_CONTINUE;
	} else if (SCHED_STAT_RDBODY == pcontext->sched_stat) {
		if (NULL == pcontext->pchannel) {
			if (0 == pcontext->total_length ||
				pcontext->bytes_rw < pcontext->total_length) {
				size = STREAM_BLOCK_SIZE;
				pbuff = stream_getbuffer_for_writing(
						&pcontext->stream_in, &size);
				if (NULL == pbuff) {
					http_parser_log_info(pcontext, 8, "out of memory");
					goto INERTNAL_SERVER_ERROR;
				}
				if (NULL != pcontext->connection.ssl) {
					actual_read = SSL_read(
						pcontext->connection.ssl, pbuff, size);
				} else {
					actual_read = read(
						pcontext->connection.sockd, pbuff, size);
				}
				gettimeofday(&current_time, NULL);
				if (0 == actual_read) {
					http_parser_log_info(pcontext, 8, "connection lost");
					goto END_PROCESSING;
				} else if (actual_read > 0) {
					pcontext->connection.last_timestamp = current_time;
					stream_forward_writing_ptr(
						&pcontext->stream_in, actual_read);
					if (TRUE == hpm_processor_check_context(pcontext)) {
						if (FALSE == hpm_processor_write_request(pcontext)) {
							goto INERTNAL_SERVER_ERROR;
						}
						if (TRUE == hpm_processor_check_end_of_request(
							pcontext)) {
							if (FALSE == hpm_processor_proc(pcontext)) {
								goto INERTNAL_SERVER_ERROR;
							}
							pcontext->sched_stat = SCHED_STAT_WRREP;
							if (http_parser_reconstruct_stream(
								&pcontext->stream_in, &stream) < 0) {
								http_parser_log_info(pcontext,
										8, "out of memory");
								goto INERTNAL_SERVER_ERROR;
							}
							stream_free(&pcontext->stream_in);
							pcontext->stream_in = stream;
							if (0 != stream_get_total_length(
								&pcontext->stream_out)) {
								tmp_len = STREAM_BLOCK_SIZE;
								pcontext->write_buff =
									stream_getbuffer_for_reading(
									&pcontext->stream_out, &tmp_len);
								pcontext->write_length = tmp_len;
							}
						}
						return PROCESS_CONTINUE;
					} else if (NULL != pcontext->pfast_context) {
						if (FALSE == mod_fastcgi_write_request(pcontext)) {
							goto INERTNAL_SERVER_ERROR;
						}
						if (TRUE == mod_fastcgi_check_end_of_read(pcontext)) {
							if (FALSE == mod_fastcgi_relay_content(pcontext)) {
								goto INERTNAL_SERVER_ERROR;
							}
							pcontext->sched_stat = SCHED_STAT_WRREP;
							if (http_parser_reconstruct_stream(
								&pcontext->stream_in, &stream) < 0) {
								http_parser_log_info(pcontext,
									8, "out of memory");
								goto INERTNAL_SERVER_ERROR;
							}
							stream_free(&pcontext->stream_in);
							pcontext->stream_in = stream;
						}
						return PROCESS_CONTINUE;
					} else {
						pcontext->bytes_rw += actual_read;
						if (pcontext->bytes_rw < pcontext->total_length) {
							return PROCESS_CONTINUE;
						}
					}
				} else {
					if (EAGAIN != errno) {
						http_parser_log_info(pcontext, 8, "connection lost");
						goto END_PROCESSING;
					}
					/* check if context is timed out */
					if (CALCULATE_INTERVAL(current_time,
						pcontext->connection.last_timestamp) >= g_timeout) {
						http_parser_log_info(pcontext, 8, "time out");
						goto REQUEST_TIME_OUT;
					} else {
						return PROCESS_POLLING_RDONLY;
					}
				}
			}
			
			if (0 == strcasecmp(pcontext->request.method, "RPC_IN_DATA") ||
				0 == strcasecmp(pcontext->request.method, "RPC_OUT_DATA")) {
				/* ECHO request */
				response_len = snprintf(response_buff, sizeof(response_buff),
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
			} else {
				/* other http request here if wanted */
				goto BAD_HTTP_REQUEST;
			}
				
			if (http_parser_reconstruct_stream(
				&pcontext->stream_in, &stream) < 0) {
				http_parser_log_info(pcontext, 8, "out of memory");
				goto INERTNAL_SERVER_ERROR;
			}
			stream_free(&pcontext->stream_in);
			pcontext->stream_in = stream;
			return PROCESS_CONTINUE;
		}
		
		if (CHANNEL_TYPE_IN == pcontext->channel_type) {
			pchannel_in = (RPC_IN_CHANNEL*)pcontext->pchannel;
			frag_length = pchannel_in->frag_length;
		} else {
			pchannel_out = (RPC_OUT_CHANNEL*)pcontext->pchannel;
			frag_length = pchannel_out->frag_length;
		}
		tmp_len = stream_get_total_length(&pcontext->stream_in);
		if (tmp_len < DCERPC_FRAG_LEN_OFFSET + 2 ||
			(frag_length > 0 && tmp_len < frag_length)) {
			size = STREAM_BLOCK_SIZE;
			pbuff = stream_getbuffer_for_writing(
					&pcontext->stream_in, &size);
			if (NULL == pbuff) {
				http_parser_log_info(pcontext, 8, "out of memory");
				goto INERTNAL_SERVER_ERROR;
			}
			
			if (NULL != pcontext->connection.ssl) {
				actual_read = SSL_read(pcontext->connection.ssl, pbuff, size);
			} else {
				actual_read = read(pcontext->connection.sockd, pbuff, size);
			}
			gettimeofday(&current_time, NULL);
			if (0 == actual_read) {
				http_parser_log_info(pcontext, 8, "connection lost");
				goto END_PROCESSING;
			} else if (actual_read > 0) {
				pcontext->bytes_rw += actual_read;
				if (pcontext->bytes_rw > pcontext->total_length) {
					http_parser_log_info(pcontext, 8,
						"content length overflow when reading body");
					goto END_PROCESSING;
				}
				pcontext->connection.last_timestamp = current_time;
				stream_forward_writing_ptr(&pcontext->stream_in, actual_read);
			} else {
				if (EAGAIN != errno) {
					http_parser_log_info(pcontext, 8, "connection lost");
					goto END_PROCESSING;
				}
				/* check if context is timed out */
				if (CALCULATE_INTERVAL(current_time,
					pcontext->connection.last_timestamp) >= g_timeout) {
					http_parser_log_info(pcontext, 8, "time out");
					goto REQUEST_TIME_OUT;
				} else {
					return PROCESS_POLLING_RDONLY;
				}
			}
		}
		
		tmp_len = STREAM_BLOCK_SIZE;
		pbuff = stream_getbuffer_for_reading(&pcontext->stream_in, &tmp_len);
		if (NULL == pbuff) {
			return PROCESS_POLLING_RDONLY;
		}
		stream_backward_reading_ptr(&pcontext->stream_in, tmp_len);
		if (tmp_len < DCERPC_FRAG_LEN_OFFSET + 2) {
			return PROCESS_CONTINUE;
		}
		
		if (0 == frag_length) {
			if (CVAL(pbuff, DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
				frag_length = SVAL(pbuff, DCERPC_FRAG_LEN_OFFSET);
			} else {
				frag_length = RSVAL(pbuff, DCERPC_FRAG_LEN_OFFSET);
			}
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
		
		result = pdu_processor_rts_input(pbuff, frag_length, &pcall);
		
		if (CHANNEL_TYPE_IN == pcontext->channel_type &&
			CHANNEL_STAT_OPENED == pchannel_in->channel_stat) {
			if (PDU_PROCESSOR_ERROR == result) {
				/* ignore rts processing error under this condition */
				result = PDU_PROCESSOR_INPUT;
			} else if (PDU_PROCESSOR_FORWARD == result) {
				/* only under this condition, we can
					forward pdu to pdu processor */
				pvconnection = http_parser_get_vconnection(pcontext->host,
							pcontext->port, pchannel_in->connection_cookie);
				if (NULL == pvconnection) {
					http_parser_log_info(pcontext, 8,
						"virtual connection error in hash table");
					goto END_PROCESSING;
				}
				if (pvconnection->pcontext_in != pcontext ||
					NULL == pvconnection->pprocessor) {
					http_parser_put_vconnection(pvconnection);
					http_parser_log_info(pcontext, 8,
						"virtual connection error in hash table");
					goto END_PROCESSING;
				}
				result = pdu_processor_input(pvconnection->pprocessor,
											pbuff, frag_length, &pcall);
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
				http_parser_put_vconnection(pvconnection);
			}
		}
		
		stream_forward_reading_ptr(&pcontext->stream_in, frag_length);
		if (CHANNEL_TYPE_IN == pcontext->channel_type) {
			pchannel_in->frag_length = 0;
		} else {
			pchannel_out->frag_length = 0;
		}
		
		if (http_parser_reconstruct_stream(
			&pcontext->stream_in, &stream) < 0) {
			http_parser_log_info(pcontext, 8, "out of memory");
			goto INERTNAL_SERVER_ERROR;
		}
		stream_free(&pcontext->stream_in);
		pcontext->stream_in = stream;
		
		switch (result) {
		case PDU_PROCESSOR_ERROR:
		case PDU_PROCESSOR_FORWARD:
			http_parser_log_info(pcontext, 8, "pdu process error!");
			goto END_PROCESSING;
		case PDU_PROCESSOR_INPUT:
			/* do nothing */
			return PROCESS_CONTINUE;
		case PDU_PROCESSOR_OUTPUT:
			if (CHANNEL_TYPE_OUT == pcontext->channel_type) {
				/* only under two conditions below, out channel
				   will produce PDU_PROCESSOR_OUTPUT */ 
				if (CHANNEL_STAT_OPENSTART == pchannel_out->channel_stat ||
					CHANNEL_STAT_RECYCLING == pchannel_out->channel_stat) {
					/* first send http response head */
					http_parser_rfc1123_dstring(dstring);
					response_len = snprintf(
						response_buff, sizeof(response_buff),
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
					goto CONTEXT_PROCESSING;
				} else {
					http_parser_log_info(pcontext, 8,
						"pdu process error! out channel can't output "
						"itself after virtual connection established");
					goto END_PROCESSING;
				}
			}
			/* in channel here, find the corresponding out channel first! */
			pvconnection = http_parser_get_vconnection(pcontext->host,
						pcontext->port, pchannel_in->connection_cookie);
			if (NULL == pvconnection) {
				pdu_processor_free_call(pcall);
				http_parser_log_info(pcontext, 8,
					"cannot find virtual connection in hash table");
				goto END_PROCESSING;
			}
			
			if (pcontext != pvconnection->pcontext_in ||
				NULL == pvconnection->pcontext_out) {
				http_parser_put_vconnection(pvconnection);
				pdu_processor_free_call(pcall);
				http_parser_log_info(pcontext, 8,
					"missing out channel in virtual connection");
				goto END_PROCESSING;
			}
			if (TRUE == ((RPC_OUT_CHANNEL*)
				pvconnection->pcontext_out->pchannel)->b_obsolete) {
				pdu_processor_output_pdu(pcall,
					&((RPC_IN_CHANNEL*)pcontext->pchannel)->pdu_list);
				http_parser_put_vconnection(pvconnection);
				pdu_processor_free_call(pcall);
				return PROCESS_CONTINUE;
			} else {
				pdu_processor_output_pdu(
					pcall, &((RPC_OUT_CHANNEL*)
					pvconnection->pcontext_out->pchannel)->pdu_list);
			}
			pvconnection->pcontext_out->sched_stat = SCHED_STAT_WRREP;
			contexts_pool_signal((SCHEDULE_CONTEXT*)
						pvconnection->pcontext_out);
			http_parser_put_vconnection(pvconnection);
			pdu_processor_free_call(pcall);
			return PROCESS_CONTINUE;
		case PDU_PROCESSOR_TERMINATE:
			goto END_PROCESSING;
		}
	} else if (SCHED_STAT_WAIT == pcontext->sched_stat) {
		if (TRUE == hpm_processor_check_context(pcontext)) {
			return PROCESS_IDLE;
		}
		/* only hpm_processor or out channel can be set to SCHED_STAT_WAIT */
		pchannel_out = (RPC_OUT_CHANNEL*)pcontext->pchannel;
		if (CHANNEL_STAT_WAITINCHANNEL == pchannel_out->channel_stat) {
			pvconnection = http_parser_get_vconnection(pcontext->host,
					pcontext->port, pchannel_out->connection_cookie);
			if (NULL != pvconnection) {
				if (pvconnection->pcontext_out == pcontext
					&& NULL != pvconnection->pcontext_in) {
					pchannel_in = (RPC_IN_CHANNEL*)
						pvconnection->pcontext_in->pchannel;
					pchannel_in->available_window =
						pchannel_out->window_size;
					pchannel_in->bytes_received = 0;
					pchannel_out->client_keepalive =
						pchannel_in->client_keepalive;
					if (FALSE == pdu_processor_rts_conn_c2(
						pchannel_out->pcall, pchannel_out->window_size)) {
						http_parser_put_vconnection(pvconnection);
						http_parser_log_info(pcontext, 8,
							"pdu process error! fail to setup conn/c2");
						goto END_PROCESSING;
					}
					pdu_processor_output_pdu(
						pchannel_out->pcall, &pchannel_out->pdu_list);
					pcontext->sched_stat = SCHED_STAT_WRREP;
					pchannel_out->channel_stat = CHANNEL_STAT_OPENED;
					http_parser_put_vconnection(pvconnection);
					goto CONTEXT_PROCESSING;
				}
				http_parser_put_vconnection(pvconnection);
			}
			
			gettimeofday(&current_time, NULL);
			/* check if context is timed out */
			if (CALCULATE_INTERVAL(current_time,
				pcontext->connection.last_timestamp)
				>= OUT_CHANNEL_MAX_WAIT) {
				http_parser_log_info(pcontext, 8, "no correpoding in "
					"channel coming during maximum waiting interval");
				goto END_PROCESSING;
			}
			return PROCESS_IDLE;
		} else if (CHANNEL_STAT_WAITRECYCLED == pchannel_out->channel_stat) {
			pvconnection = http_parser_get_vconnection(pcontext->host,
					pcontext->port, pchannel_out->connection_cookie);
			if (NULL != pvconnection) {
				if (pvconnection->pcontext_out == pcontext
					&& NULL != pvconnection->pcontext_in) {
					pchannel_in = (RPC_IN_CHANNEL*)
						pvconnection->pcontext_in->pchannel;
					pchannel_out->client_keepalive =
						pchannel_in->client_keepalive;
					pchannel_out->channel_stat = CHANNEL_STAT_OPENED;
					while (pnode=double_list_get_from_head(
						&pchannel_in->pdu_list)) {
						double_list_append_as_tail(
							&pchannel_out->pdu_list, pnode);
					}
					if (0 == double_list_get_nodes_num(
						&pchannel_out->pdu_list)) {
						pcontext->sched_stat = SCHED_STAT_WAIT;
					} else {
						pcontext->sched_stat = SCHED_STAT_WRREP;
					}
					http_parser_put_vconnection(pvconnection);
					goto CONTEXT_PROCESSING;
				}
				http_parser_put_vconnection(pvconnection);
			}
			
			gettimeofday(&current_time, NULL);
			/* check if context is timed out */
			if (CALCULATE_INTERVAL(current_time,
				pcontext->connection.last_timestamp)
				>= OUT_CHANNEL_MAX_WAIT) {
				http_parser_log_info(pcontext, 8, "channel is not "
						"recycled during maximum waiting interval");
				goto END_PROCESSING;
			}
			return PROCESS_IDLE;
		} else if (CHANNEL_STAT_RECYCLED == pchannel_out->channel_stat) {
			goto END_PROCESSING;
		}
		
		if (0 == recv(pcontext->connection.sockd, tmp_buff, 1, MSG_PEEK)) {
			http_parser_log_info(pcontext, 8, "connection lost");
			goto END_PROCESSING;
		}
		
		gettimeofday(&current_time, NULL);
		/* check keep alive */
		if (CALCULATE_INTERVAL(current_time,
			pcontext->connection.last_timestamp) >=
			pchannel_out->client_keepalive/2000) {
			if (FALSE == pdu_processor_rts_ping(pchannel_out->pcall)) {
				return PROCESS_IDLE;
			}
			/* stream_out is shared resource of vconnection,
				lock it first before operating */
			pvconnection = http_parser_get_vconnection(
				pcontext->host, pcontext->port, ((RPC_OUT_CHANNEL*)
				pcontext->pchannel)->connection_cookie);
			pdu_processor_output_pdu(
				pchannel_out->pcall, &pchannel_out->pdu_list);
			pcontext->sched_stat = SCHED_STAT_WRREP;
			if (NULL != pvconnection) {
				http_parser_put_vconnection(pvconnection);
			}
			goto CONTEXT_PROCESSING;
		}
		
		return PROCESS_IDLE;
	}
	
BAD_HTTP_REQUEST:
	if (TRUE == hpm_processor_check_context(pcontext)) {
		hpm_processor_put_context(pcontext);
	} else if (NULL != pcontext->pfast_context) {
		mod_fastcgi_put_context(pcontext);
	} else if (TRUE == mod_cache_check_caching(pcontext)) {
		mod_cache_put_context(pcontext);
	}
	http_parser_rfc1123_dstring(dstring);
	response_len = snprintf(response_buff, sizeof(response_buff),
					"HTTP/1.1 400 Bad Request\r\n"
					"Date: %s\r\n"
					"Server: %s\r\n"
					"Content-Length: 0\r\n"
					"Connection: close\r\n"
					"\r\n", dstring, resource_get_string(RES_HOST_ID));
	stream_write(&pcontext->stream_out, response_buff, response_len);
	pcontext->total_length = response_len;
	pcontext->bytes_rw = 0;
	pcontext->b_close = TRUE;
	pcontext->sched_stat = SCHED_STAT_WRREP;
	goto CONTEXT_PROCESSING;

INERTNAL_SERVER_ERROR:
	if (TRUE == hpm_processor_check_context(pcontext)) {
		hpm_processor_put_context(pcontext);
	} else if (NULL != pcontext->pfast_context) {
		mod_fastcgi_put_context(pcontext);
	} else if (TRUE == mod_cache_check_caching(pcontext)) {
		mod_cache_put_context(pcontext);
	}
	http_parser_rfc1123_dstring(dstring);
	response_len = snprintf(response_buff, sizeof(response_buff),
					"HTTP/1.1 500 Internal Server Error\r\n"
					"Date: %s\r\n"
					"Server: %s\r\n"
					"Content-Length: 0\r\n"
					"Connection: close\r\n"
					"\r\n", dstring, resource_get_string(RES_HOST_ID));
	stream_write(&pcontext->stream_out, response_buff, response_len);
	pcontext->total_length = response_len;
	pcontext->bytes_rw = 0;
	pcontext->b_close = TRUE;
	pcontext->sched_stat = SCHED_STAT_WRREP;
	goto CONTEXT_PROCESSING;
	
REQUEST_TIME_OUT:
	if (TRUE == hpm_processor_check_context(pcontext)) {
		hpm_processor_put_context(pcontext);
	} else if (NULL != pcontext->pfast_context) {
		mod_fastcgi_put_context(pcontext);
	} else if (TRUE == mod_cache_check_caching(pcontext)) {
		mod_cache_put_context(pcontext);
	}
	http_parser_rfc1123_dstring(dstring);
	response_len = snprintf(response_buff, sizeof(response_buff),
					"HTTP/1.1 408 Request Timeout\r\n"
					"Date: %s\r\n"
					"Server: %s\r\n"
					"Content-Length: 0\r\n"
					"Connection: close\r\n"
					"\r\n", dstring, resource_get_string(RES_HOST_ID));
	stream_write(&pcontext->stream_out, response_buff, response_len);
	pcontext->total_length = response_len;
	pcontext->bytes_rw = 0;
	pcontext->b_close = TRUE;
	pcontext->sched_stat = SCHED_STAT_WRREP;
	goto CONTEXT_PROCESSING;
	
END_PROCESSING:
	if (TRUE == hpm_processor_check_context(pcontext)) {
		hpm_processor_put_context(pcontext);
	} else if (NULL != pcontext->pfast_context) {
		mod_fastcgi_put_context(pcontext);
	} else if (TRUE == mod_cache_check_caching(pcontext)) {
		mod_cache_put_context(pcontext);
	}
	if (NULL != pcontext->pchannel) {
		if (CHANNEL_TYPE_IN == pcontext->channel_type) {
			pchannel_in = (RPC_IN_CHANNEL*)pcontext->pchannel;
			pvconnection = http_parser_get_vconnection(pcontext->host,
					pcontext->port, pchannel_in->connection_cookie);
			if (NULL != pvconnection) {
				if (pcontext == pvconnection->pcontext_in) {
					pvconnection->pcontext_in = NULL;
				}
				http_parser_put_vconnection(pvconnection);
			}
			while (pnode=double_list_get_from_head(&pchannel_in->pdu_list)) {
				free(((BLOB_NODE*)pnode->pdata)->blob.data);
				pdu_processor_free_blob(pnode->pdata);
			}
			double_list_free(&pchannel_in->pdu_list);
			lib_buffer_put(g_inchannel_allocator, pcontext->pchannel);
		} else {
			pchannel_out = (RPC_OUT_CHANNEL*)pcontext->pchannel;
			pvconnection = http_parser_get_vconnection(pcontext->host,
					pcontext->port, pchannel_out->connection_cookie);
			if (NULL != pvconnection) {
				if (pcontext == pvconnection->pcontext_out) {
					pvconnection->pcontext_out = NULL;
				}
				http_parser_put_vconnection(pvconnection);
			}
			if (NULL != pchannel_out->pcall) {
				pdu_processor_free_call(pchannel_out->pcall);
				pchannel_out->pcall = NULL;
			}
			while (pnode=double_list_get_from_head(&pchannel_out->pdu_list)) {
				free(((BLOB_NODE*)pnode->pdata)->blob.data);
				pdu_processor_free_blob(pnode->pdata);
			}
			double_list_free(&pchannel_out->pdu_list);
			lib_buffer_put(g_outchannel_allocator, pcontext->pchannel);
		}
		pcontext->pchannel = NULL;
	}
	
	if (NULL != pcontext->connection.ssl) {
		SSL_shutdown(pcontext->connection.ssl);
		SSL_free(pcontext->connection.ssl);
		pcontext->connection.ssl = NULL;
	}
	close(pcontext->connection.sockd);
	system_services_container_remove_ip(pcontext->connection.client_ip);
	http_parser_context_clear(pcontext);
	return PROCESS_CLOSE;
}

void http_parser_shutdown_async()
{
	g_async_stop = TRUE;
}

void http_parser_vconnection_async_reply(const char *host,
	int port, const char *connection_cookie, DCERPC_CALL *pcall)
{
	VIRTUAL_CONNECTION *pvconnection;
	
	/* system is going to stop now */
	if (TRUE == g_async_stop) {
		return;
	}
	pvconnection = http_parser_get_vconnection(host, port, connection_cookie);
	if (NULL == pvconnection) {
		return;
	}
	if (NULL == pvconnection->pcontext_out) {
		http_parser_put_vconnection(pvconnection);
		return;
	}
	if (TRUE == ((RPC_OUT_CHANNEL*)
		pvconnection->pcontext_out->pchannel)->b_obsolete) {
		if (NULL != pvconnection->pcontext_in) {
			pdu_processor_output_pdu(pcall, &((RPC_IN_CHANNEL*)
				pvconnection->pcontext_in->pchannel)->pdu_list);
			http_parser_put_vconnection(pvconnection);
			return;
		}
	} else {
		pdu_processor_output_pdu(pcall, &((RPC_OUT_CHANNEL*)
			pvconnection->pcontext_out->pchannel)->pdu_list);
	}
	pvconnection->pcontext_out->sched_stat = SCHED_STAT_WRREP;
	contexts_pool_signal((SCHEDULE_CONTEXT*)pvconnection->pcontext_out);
	http_parser_put_vconnection(pvconnection);
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
HTTP_CONTEXT* http_parser_get_contexts_list()
{
    return g_context_list;
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
static void http_parser_context_init(HTTP_CONTEXT *pcontext)
{
    LIB_BUFFER *palloc_stream;
    
    if (NULL == pcontext) {
        return;
    }
    palloc_stream = blocks_allocator_get_allocator();
    memset(pcontext, 0, sizeof(HTTP_CONTEXT));
    pcontext->connection.sockd = -1;
	pcontext->b_close = TRUE;
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

static void http_parser_context_free(HTTP_CONTEXT *pcontext)
{
	if (NULL == pcontext) {
		return;
	}
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


void http_parser_log_info(HTTP_CONTEXT *pcontext, int level, char *format, ...)
{
	va_list ap;
	int context_id;
	char log_buf[2048];

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	log_buf[sizeof(log_buf) - 1] = '\0';
	
	if ('\0' == pcontext->username[0]) {
		context_id = pcontext - http_parser_get_contexts_list();
		system_services_log_info(level, "context-ID: %d, IP: %s  %s",
				context_id, pcontext->connection.client_ip, log_buf);
	} else {
		system_services_log_info(level, "user: %s, IP: %s  %s",
			pcontext->username, pcontext->connection.client_ip, log_buf);
	}

}

static void http_parser_ssl_locking(int mode,
	int n, const char *file, int line)
{
	if (mode&CRYPTO_LOCK) {
		pthread_mutex_lock(&g_ssl_mutex_buf[n]);
	} else {
		pthread_mutex_unlock(&g_ssl_mutex_buf[n]);
	}
}

static void http_parser_ssl_id(CRYPTO_THREADID* id)
{
	CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
}


HTTP_CONTEXT* http_parser_get_context()
{
	return (HTTP_CONTEXT*)pthread_getspecific(g_context_key);
}

void http_parser_set_context(int context_id)
{
	pthread_setspecific(g_context_key, g_context_list + context_id);
}

BOOL http_parser_get_password(const char *username, char *password)
{
	HTTP_CONTEXT *pcontext;
	
	pcontext = http_parser_get_context();
	if (NULL == pcontext) {
		return FALSE;
	}
	
	if (0 != strcasecmp(username, pcontext->username)) {
		return FALSE;
	}
	
	strncpy(password, pcontext->password, 128);
	return TRUE;
	
}

BOOL http_parser_try_create_vconnection(HTTP_CONTEXT *pcontext)
{
	const char *conn_cookie;
	VIRTUAL_CONNECTION tmp_conn;
	VIRTUAL_CONNECTION *pvconnection;
	
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
	pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, conn_cookie);
	if (NULL == pvconnection) {
		tmp_conn.reference = 0;
		tmp_conn.pprocessor = pdu_processor_create(
					pcontext->host, pcontext->port);
		if (NULL == tmp_conn.pprocessor) {
			http_parser_log_info(pcontext, 8,
				"fail to create processor on %s:%d",
				pcontext->host, pcontext->port);
			return FALSE;
		}
		if (CHANNEL_TYPE_OUT == pcontext->channel_type) {
			tmp_conn.pcontext_in = NULL;
			tmp_conn.pcontext_out = pcontext;
		} else {
			tmp_conn.pcontext_in = pcontext;
			tmp_conn.pcontext_out = NULL;
		}
		tmp_conn.pcontext_insucc = NULL;
		tmp_conn.pcontext_outsucc = NULL;
		snprintf(tmp_conn.hash_key, 256, "%s:%d:%s",
			conn_cookie, pcontext->port, pcontext->host);
		lower_string(tmp_conn.hash_key);
		pthread_mutex_lock(&g_vconnection_lock);
		if (1 != str_hash_add(g_vconnection_hash,
			tmp_conn.hash_key, &tmp_conn)) {
			pthread_mutex_unlock(&g_vconnection_lock);
			pdu_processor_destroy(tmp_conn.pprocessor);
			goto RETRY_QUERY;
		}
		pvconnection = str_hash_query(
			g_vconnection_hash, tmp_conn.hash_key);
		pthread_mutex_init(&pvconnection->lock, NULL);
		pthread_mutex_unlock(&g_vconnection_lock);
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
		http_parser_put_vconnection(pvconnection);
	}
	return TRUE;
}

void http_parser_set_outchannel_flowcontrol(HTTP_CONTEXT *pcontext,
	uint32_t bytes_received, uint32_t available_window)
{
	RPC_OUT_CHANNEL *pchannel_out;
	VIRTUAL_CONNECTION *pvconnection;
	
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return;
	}
	pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, ((RPC_IN_CHANNEL*)
		pcontext->pchannel)->connection_cookie);
	if (NULL == pvconnection) {
		return;
	}
	if (NULL == pvconnection->pcontext_out) {
		http_parser_put_vconnection(pvconnection);
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
	http_parser_put_vconnection(pvconnection);
}

BOOL http_parser_recycle_inchannel(
	HTTP_CONTEXT *pcontext, char *predecessor_cookie)
{
	VIRTUAL_CONNECTION *pvconnection;
	
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return FALSE;
	}
	pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, ((RPC_IN_CHANNEL*)
		pcontext->pchannel)->connection_cookie);
	
	if (NULL != pvconnection) {
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
			http_parser_put_vconnection(pvconnection);
			return TRUE;
		}
		http_parser_put_vconnection(pvconnection);
	}
	return FALSE;
}

BOOL http_parser_recycle_outchannel(
	HTTP_CONTEXT *pcontext, char *predecessor_cookie)
{
	VIRTUAL_CONNECTION *pvconnection;
	DCERPC_CALL *pcall;
	
	if (CHANNEL_TYPE_OUT != pcontext->channel_type) {
		return FALSE;
	}
	pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, ((RPC_OUT_CHANNEL*)
		pcontext->pchannel)->connection_cookie);
	if (NULL != pvconnection) {
		if (NULL != pvconnection->pcontext_out &&
			0 == strcmp(predecessor_cookie, ((RPC_OUT_CHANNEL*)
			pvconnection->pcontext_out->pchannel)->channel_cookie)) {
			if (FALSE == ((RPC_OUT_CHANNEL*)
				pvconnection->pcontext_out->pchannel)->b_obsolete) {
				http_parser_put_vconnection(pvconnection);
				return FALSE;
			}
			pcall = ((RPC_OUT_CHANNEL*)
				pvconnection->pcontext_out->pchannel)->pcall;
			if (FALSE == pdu_processor_rts_outr2_a6(pcall)) {
				http_parser_put_vconnection(pvconnection);
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
			http_parser_put_vconnection(pvconnection);
			return TRUE;
		}
		http_parser_put_vconnection(pvconnection);
	}
	return FALSE;
}

BOOL http_parser_activate_inrecycling(
	HTTP_CONTEXT *pcontext, const char *successor_cookie)
{
	VIRTUAL_CONNECTION *pvconnection;
	
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return FALSE;
	}
	pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, ((RPC_IN_CHANNEL*)
		pcontext->pchannel)->connection_cookie);
	
	if (NULL != pvconnection) {
		if (pcontext == pvconnection->pcontext_in &&
			NULL != pvconnection->pcontext_insucc &&
			0 == strcmp(successor_cookie, ((RPC_IN_CHANNEL*)
			pvconnection->pcontext_insucc->pchannel)->channel_cookie)) {
			((RPC_IN_CHANNEL*)pcontext->pchannel)->channel_stat =
											CHANNEL_STAT_RECYCLED;
			pvconnection->pcontext_in = pvconnection->pcontext_insucc;
			((RPC_IN_CHANNEL*)
				pvconnection->pcontext_in->pchannel)->channel_stat =
												CHANNEL_STAT_OPENED;
			pvconnection->pcontext_insucc = NULL;
			http_parser_put_vconnection(pvconnection);
			return TRUE;
		}
		http_parser_put_vconnection(pvconnection);
	}
	return FALSE;
}

BOOL http_parser_activate_outrecycling(
	HTTP_CONTEXT *pcontext, const char *successor_cookie)
{
	DCERPC_CALL *pcall;
	RPC_OUT_CHANNEL *pchannel_out;
	VIRTUAL_CONNECTION *pvconnection;
	
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return FALSE;
	}
	pvconnection = http_parser_get_vconnection(pcontext->host, pcontext->port,
		((RPC_IN_CHANNEL*)pcontext->pchannel)->connection_cookie);
	
	if (NULL != pvconnection) {
		if (pcontext == pvconnection->pcontext_in &&
			NULL != pvconnection->pcontext_out &&
			NULL != pvconnection->pcontext_outsucc &&
			0 == strcmp(successor_cookie, ((RPC_OUT_CHANNEL*)
			pvconnection->pcontext_outsucc->pchannel)->channel_cookie)) {
			pchannel_out = (RPC_OUT_CHANNEL*)
				pvconnection->pcontext_out->pchannel;
			if (FALSE == pdu_processor_rts_outr2_b3(pchannel_out->pcall)) {
				http_parser_put_vconnection(pvconnection);
				http_parser_log_info(pcontext, 8,
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
			http_parser_put_vconnection(pvconnection);
			return TRUE;
		}
		http_parser_put_vconnection(pvconnection);
	}
	return FALSE;
}

void http_parser_set_keep_alive(HTTP_CONTEXT *pcontext, uint32_t keepalive)
{
	RPC_IN_CHANNEL *pchannel_in;
	RPC_OUT_CHANNEL *pchannel_out;
	VIRTUAL_CONNECTION *pvconnection;
	
	pvconnection = http_parser_get_vconnection(
		pcontext->host, pcontext->port, ((RPC_IN_CHANNEL*)
		pcontext->pchannel)->connection_cookie);
	
	if (NULL != pvconnection) {
		if (pcontext == pvconnection->pcontext_in) {
			pchannel_in = (RPC_IN_CHANNEL*)pcontext->pchannel;
			pchannel_in->client_keepalive = keepalive;
			if (NULL != pvconnection->pcontext_out) {
				pchannel_out = (RPC_OUT_CHANNEL*)
					pvconnection->pcontext_out->pchannel;
				pchannel_out->client_keepalive = keepalive;
			}
		}
		http_parser_put_vconnection(pvconnection);
	}
}
