// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/* smtp parser is a module, which first read data from socket, parses the smtp 
 * commands and then do the corresponding action. 
 */ 
#include <cerrno>
#include <mutex>
#include <unistd.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "smtp_parser.h"
#include "smtp_cmd_handler.h"
#include <gromox/files_allocator.hpp>
#include "blocks_allocator.h"
#include <gromox/threads_pool.hpp>
#include "system_services.h"
#include "flusher.h"
#include "resource.h"
#include <gromox/lib_buffer.hpp>
#include <gromox/util.hpp>
#include <gromox/mail_func.hpp>
#include <pthread.h>
#include <cstring>
#include <cstdarg>
#include <cstdio>
#include <openssl/err.h>

#define READ_BUFFER_SIZE    4096
#define MAX_LINE_LENGTH     64*1024

#define CALCULATE_INTERVAL(a, b) \
	(((a).tv_usec >= (b).tv_usec) ? ((a).tv_sec - (b).tv_sec) : \
	((a).tv_sec - (b).tv_sec - 1))

/* the ratio must larger than 2 */
#define TLS_BUFFER_RATIO    3
#define TLS_BUFFER_BUS_ALLIN(size)                  \
		(sizeof(void*)*((int)((size)/sizeof(void*))+1))

#define SLEEP_BEFORE_CLOSE    usleep(1000)

/* return value for smtp_parser_parse_and_save_blkmime */
enum{
	ERROR_FOUND,
	TYPE_FOUND,
	BOUNDARY_FOUND
};

static int smtp_parser_dispatch_cmd(const char *cmd_line, int line_length, 
	SMTP_CONTEXT *pcontext);

static void smtp_parser_context_init(SMTP_CONTEXT *pcontext);

static void smtp_parser_context_clear(SMTP_CONTEXT *pcontext);

static void smtp_parser_reset_context_session(SMTP_CONTEXT *pcontext);

static void smtp_parser_context_free(SMTP_CONTEXT *pcontext);

static int smtp_parser_try_flush_mail(SMTP_CONTEXT *pcontext, BOOL is_whole);
static BOOL smtp_parser_pass_statistic(SMTP_CONTEXT *pcontext,
	char *reason, int length);
static void smtp_parser_reset_stream_reading(SMTP_CONTEXT *pcontext);

static int g_context_num;
static int g_threads_num;
static int g_ssl_port;
static BOOL g_domainlist_valid;
static BOOL g_need_auth;
static BOOL g_support_pipeline;
static BOOL g_support_starttls;
static BOOL g_force_starttls;
static size_t g_max_mail_length;
static size_t g_max_mail_sessions;
static size_t g_blktime_sessions;
static size_t g_flushing_size;
static unsigned int g_timeout;
static size_t g_auth_times;
static size_t g_blktime_auths;
static SMTP_CONTEXT *g_context_list;
static int g_block_ID;
static char g_certificate_path[256];
static char g_private_key_path[256];
static char g_certificate_passwd[1024];
static SSL_CTX *g_ssl_ctx;
static pthread_mutex_t *g_ssl_mutex_buf;

/* 
 * construct a smtp parser object
 * @param
 *        context_num        number of contexts
 *        threads_num        number of threads in the pool
 *        dm_valid           is domain list valid
 *        max_mail_length    maximum mail size
 *        max_mail_sessions  maximum mail sessions per connection
 *        blktime_sessions   block interval if max sessions is exceeded
 *        flushing_size      maximum size the stream can hold
 *        timeout            seconds if there's no data comes from connection
 *        auth_times         maximum authentification times, session permit
 *        blktime_auths      block interval if max auths is exceeded
 */
void smtp_parser_init(int context_num, int threads_num,
	BOOL dm_valid, BOOL need_auth, size_t max_mail_length,
	size_t max_mail_sessions, size_t blktime_sessions, size_t flushing_size,
	size_t timeout,  size_t auth_times, size_t blktime_auths,
	BOOL support_pipeline, BOOL support_starttls, BOOL force_starttls,
	const char *certificate_path, const char *cb_passwd, const char *key_path)
{
	g_context_num           = context_num;
	g_threads_num           = threads_num;
	g_domainlist_valid      = dm_valid;
	g_need_auth             = need_auth;
	g_max_mail_length       = max_mail_length;
	g_max_mail_sessions     = max_mail_sessions;
	g_blktime_sessions      = blktime_sessions;
	g_flushing_size         = flushing_size;
	g_auth_times            = auth_times;
	g_blktime_auths         = blktime_auths;
	g_timeout               = timeout;
	g_support_pipeline      = support_pipeline;
	g_support_starttls      = support_starttls;
	g_block_ID              = 0;
	g_ssl_mutex_buf         = NULL;
	if (TRUE == support_starttls) {
		g_force_starttls = force_starttls;
		HX_strlcpy(g_certificate_path, certificate_path, GX_ARRAY_SIZE(g_certificate_path));
		if (NULL != cb_passwd) {
			HX_strlcpy(g_certificate_passwd, cb_passwd, GX_ARRAY_SIZE(g_certificate_passwd));
		} else {
			g_certificate_passwd[0] = '\0';
		}
		HX_strlcpy(g_private_key_path, key_path, GX_ARRAY_SIZE(g_private_key_path));
	}
}

#if defined(LIBRESSL_VERSION_NUMBER) || (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x1010000fL)
static void smtp_parser_ssl_locking(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&g_ssl_mutex_buf[n]);
	else
		pthread_mutex_unlock(&g_ssl_mutex_buf[n]);
}

static void smtp_parser_ssl_id(CRYPTO_THREADID* id)
{
	CRYPTO_THREADID_set_numeric(id, (uintptr_t)pthread_self());
}
#endif

/* 
 * run the smtp parser module
 *    @return
 *         0    success
 *        <>0    fail    
 */
int smtp_parser_run()
{
	int i;
	
	if (TRUE == g_support_starttls) {
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();
		g_ssl_ctx = SSL_CTX_new(SSLv23_server_method());
		if (NULL == g_ssl_ctx) {
			printf("[smtp_parser]: Failed to init SSL context\n");
			return -1;
		}
		
		if ('\0' != g_certificate_passwd[0]) {
			SSL_CTX_set_default_passwd_cb_userdata(g_ssl_ctx,
				g_certificate_passwd);
		}

		if (SSL_CTX_use_certificate_chain_file(g_ssl_ctx,
			g_certificate_path) <= 0) {
			printf("[smtp_parser]: fail to use certificate file:");
			ERR_print_errors_fp(stdout);
			return -2;
		}
		
		if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, g_private_key_path,
			SSL_FILETYPE_PEM) <= 0) {
			printf("[smtp_parser]: fail to use private key file:");
			ERR_print_errors_fp(stdout);
			return -3;
		}

		if (1 != SSL_CTX_check_private_key(g_ssl_ctx)) {
			printf("[smtp_parser]: private key does not match certificate:");
			ERR_print_errors_fp(stdout);
			return -4;
		}

		g_ssl_mutex_buf = static_cast<pthread_mutex_t *>(malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t)));
		if (NULL == g_ssl_mutex_buf) {
			printf("[smtp_parser]: Failed to allocate SSL locking buffer\n");
			return -5;
		}
		for (i=0; i<CRYPTO_num_locks(); i++) {
			pthread_mutex_init(&g_ssl_mutex_buf[i], NULL);
		}
		CRYPTO_THREADID_set_callback(smtp_parser_ssl_id);
		CRYPTO_set_locking_callback(smtp_parser_ssl_locking);
	}
	g_context_list = static_cast<SMTP_CONTEXT *>(malloc(sizeof(SMTP_CONTEXT) * g_context_num));
	if (NULL== g_context_list) {
		printf("[smtp_parser]: Failed to allocate SMTP contexts\n");
		return -7;
	}
	for (i=0; i<g_context_num; i++) {
		smtp_parser_context_init(g_context_list + i);
	}
	if (!resource_get_integer("LISTEN_SSL_PORT", &g_ssl_port))
		g_ssl_port = 0;
	return 0;
}

/* 
 * stop the smtp parser module
 * @return
 *          0  success
 *         <>0 fail
 */
int smtp_parser_stop()
{
	int i;

	if (NULL != g_context_list) {
		for (i=0; i<g_context_num; i++) {
			smtp_parser_context_free(g_context_list + i);
		}
		free(g_context_list);
		g_context_list = NULL;        
	}

	if (TRUE == g_support_starttls && NULL != g_ssl_ctx) {
		SSL_CTX_free(g_ssl_ctx);
		g_ssl_ctx = NULL;
	}

	if (TRUE == g_support_starttls && NULL != g_ssl_mutex_buf) {
		CRYPTO_set_id_callback(NULL);
		CRYPTO_set_locking_callback(NULL);
		for (i=0; i<CRYPTO_num_locks(); i++) {
			pthread_mutex_destroy(&g_ssl_mutex_buf[i]);
		}
		free(g_ssl_mutex_buf);
		g_ssl_mutex_buf = NULL;
	}
	return 0;
}

/* 
 * smtp parser's destruct function 
 */
void smtp_parser_free()
{
	g_context_num       = 0;
	g_max_mail_length   = 0;
	g_max_mail_sessions = 0;
	g_flushing_size     = 0;
	g_timeout           = 0x7FFFFFFF;
	g_auth_times        = 0;
}

int smtp_parser_get_context_socket(SMTP_CONTEXT *pcontext)
{
	return pcontext->connection.sockd;
}

struct timeval smtp_parser_get_context_timestamp(SMTP_CONTEXT *pcontext)
{
	return pcontext->connection.last_timestamp;
}

/*
 *    threads event procedure for smtp parser
 *    @param
 *        action    indicate the event of thread
 *    @return
 *         0    success
 *        <>0    fail
 */
int smtp_parser_threads_event_proc(int action)
{
	switch (action) {
	case THREAD_CREATE:
		break;
	case THREAD_DESTROY:
		break;
	}
	return 0;
}

int smtp_parser_process(SMTP_CONTEXT *pcontext)
{
	char *line, reply_buf[1024];
	int actual_read, ssl_errno;
	int size = READ_BUFFER_SIZE, line_length;
	struct timeval current_time;
	const char *host_ID;
	char *smtp_reply_str;
	char *smtp_reply_str2;
	char *pbuff;
	int len, string_length;
	BOOL b_should_flush = FALSE;

	/*========================================================================*/
	/* first check the context is flushed last time */
	if (FLUSH_RESULT_OK == pcontext->flusher.flush_result) {
		if (FLUSH_WHOLE_MAIL == pcontext->flusher.flush_action) {
			pcontext->session_num ++;
			/* 250 Ok <flush ID> */
			smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172005, 1,
							  &string_length);
			string_length -= 2;

			memcpy(reply_buf, smtp_reply_str, string_length);
			string_length += sprintf(reply_buf + string_length, 
							" queue-id: %d\r\n", pcontext->flusher.flush_ID);
			if (NULL != pcontext->connection.ssl) {
				SSL_write(pcontext->connection.ssl, reply_buf, string_length);
			} else {
				write(pcontext->connection.sockd, reply_buf, string_length);
			}
			smtp_parser_log_info(pcontext, 0, "return OK, queue-id:%d",
							pcontext->flusher.flush_ID);
			smtp_parser_reset_context_session(pcontext);
			if (TRUE == pcontext->is_splitted) {
				stream_free(&pcontext->stream);
				pcontext->stream = pcontext->stream_second;
				pcontext->is_splitted = FALSE;
				goto CMD_PROCESS;
			}
			return PROCESS_CONTINUE;
		} else {
			stream_clear(&pcontext->stream);
			size = STREAM_BLOCK_SIZE;
			auto pbuff = static_cast<char *>(stream_getbuffer_for_writing(&pcontext->stream,
			             reinterpret_cast<unsigned int *>(&size)));
			/* 
			 * do not need to check the pbuff pointer because it will never
			 * be NULL because of stream's characteristic
			 */
			
			/* 
			 when state is parsing block content, check if need to rewrite
			 the part of boundary string into the clear stream
			 */
			if (MULTI_PARTS_MAIL == pcontext->mail.head.mail_part) {
				if (PARSING_BLOCK_CONTENT == pcontext->block_info.state ||
					PARSING_NEST_MIME == pcontext->block_info.state) {
					memcpy(pbuff, pcontext->block_info.block_mime,
						   pcontext->block_info.block_mime_len);
					stream_forward_writing_ptr(&pcontext->stream,
							pcontext->block_info.block_mime_len);
					pcontext->block_info.block_mime_len = 0;
					pcontext->pre_rstlen = 0;
				} else {
					/* or, copy the last 4 bytes into the clear stream */
					memcpy(pbuff, pcontext->last_bytes, 4);
					stream_forward_writing_ptr(&pcontext->stream, 4);
					pcontext->pre_rstlen = 4;
				}
			} else if (SINGLE_PART_MAIL == pcontext->mail.head.mail_part) {
				memcpy(pbuff, pcontext->last_bytes, 4);
				stream_forward_writing_ptr(&pcontext->stream, 4);
				pcontext->pre_rstlen = 4;
			}
			pcontext->flusher.flush_result = FLUSH_NONE;
			/* let the context continue to be processed */
		}
	} else if (FLUSH_TEMP_FAIL == pcontext->flusher.flush_result) {
		/* 451 Temporary internal failure - queue message failed */
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2174014, 1,
						 &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
		smtp_parser_log_info(pcontext, 8, "flushing queue temporary fail");
		smtp_parser_reset_context_session(pcontext);
		return PROCESS_CONTINUE;
	} else if (FLUSH_PERMANENT_FAIL == pcontext->flusher.flush_result) {
		/* 554 Message is infected by virus */
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175036, 1,
						 &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
		smtp_parser_log_info(pcontext, 8, "flushing queue permanent failure");
		if (NULL != pcontext->connection.ssl) {
			SSL_shutdown(pcontext->connection.ssl);
			SSL_free(pcontext->connection.ssl);
			pcontext->connection.ssl = NULL;
		}
		SLEEP_BEFORE_CLOSE;
		close(pcontext->connection.sockd);
		if (system_services_container_remove_ip != nullptr)
			system_services_container_remove_ip(pcontext->connection.client_ip);
		smtp_parser_context_clear(pcontext);
		return PROCESS_CLOSE;
	}
	
	if (T_STARTTLS_CMD == pcontext->last_cmd) {
		if (NULL == pcontext->connection.ssl) {
			pcontext->connection.ssl = SSL_new(g_ssl_ctx);
			if (NULL == pcontext->connection.ssl) {
				/* 452 Temporary internal failure - failed to initialize TLS */
				smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2174018, 1,
									&string_length);
				write(pcontext->connection.sockd, smtp_reply_str, string_length);
				smtp_parser_log_info(pcontext, 8, "out of SSL object");
				SLEEP_BEFORE_CLOSE;
				close(pcontext->connection.sockd);
				if (system_services_container_remove_ip != nullptr)
					system_services_container_remove_ip(pcontext->connection.client_ip);
		        smtp_parser_context_clear(pcontext);
			    return PROCESS_CLOSE;        
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
				/* 451 Timeout */
				smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2174012, 1,
									&string_length);
				write(pcontext->connection.sockd, smtp_reply_str, string_length);
				smtp_parser_log_info(pcontext, 0, "time out");
				SLEEP_BEFORE_CLOSE;
			}
			SSL_free(pcontext->connection.ssl);
			pcontext->connection.ssl = NULL;
			close(pcontext->connection.sockd);
			if (system_services_container_remove_ip != nullptr)
				system_services_container_remove_ip(pcontext->connection.client_ip);
			smtp_parser_context_clear(pcontext);
			return PROCESS_CLOSE;
		} else {
			pcontext->last_cmd = T_NONE_CMD;
			if (pcontext->connection.server_port == g_ssl_port) {
				/* 220 <domain> Service ready */
				smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172002, 1,
						                 &string_length);
				smtp_reply_str2 = resource_get_smtp_code(SMTP_CODE_2172002, 2,
						                 &string_length);
				host_ID = resource_get_string("HOST_ID");
				len = sprintf(reply_buf, "%s%s%s", smtp_reply_str, host_ID,
						      smtp_reply_str2);
				SSL_write(pcontext->connection.ssl, reply_buf, len);
			}
		}
	}

	/*========================================================================*/
	/* read buffer from socket into stream */
	pbuff = static_cast<char *>(stream_getbuffer_for_writing(&pcontext->stream,
	        reinterpret_cast<unsigned int *>(&size)));
	if (NULL == pbuff) {
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2174016, 1,
						 &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
	       write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
		smtp_parser_log_info(pcontext, 8, "out of memory");
		if (0 != pcontext->flusher.flush_ID) {
			flusher_cancel(pcontext);
		}
		if (NULL != pcontext->connection.ssl) {
			SSL_shutdown(pcontext->connection.ssl);
			SSL_free(pcontext->connection.ssl);
			pcontext->connection.ssl = NULL;
		}
		SLEEP_BEFORE_CLOSE;
		close(pcontext->connection.sockd);
		if (system_services_container_remove_ip != nullptr)
			system_services_container_remove_ip(pcontext->connection.client_ip);
		smtp_parser_context_clear(pcontext);
		return PROCESS_CLOSE;
	}
	if (NULL != pcontext->connection.ssl) {
		actual_read = SSL_read(pcontext->connection.ssl, pbuff, size);
	} else {
		actual_read = read(pcontext->connection.sockd, pbuff, size);
	}
	gettimeofday(&current_time, NULL);
	if (0 == actual_read) {
 LOST_READ:
		if (0 != pcontext->flusher.flush_ID) {
			flusher_cancel(pcontext);
		}
		if (NULL != pcontext->connection.ssl) {
			SSL_shutdown(pcontext->connection.ssl);
			SSL_free(pcontext->connection.ssl);
			pcontext->connection.ssl = NULL;
		}
		smtp_parser_log_info(pcontext, 0, "connection lost");
		close(pcontext->connection.sockd);
		if (system_services_container_remove_ip != nullptr)
			system_services_container_remove_ip(pcontext->connection.client_ip);
		smtp_parser_context_clear(pcontext);
		return PROCESS_CLOSE;
	} else if (actual_read > 0) {
		pcontext->connection.last_timestamp = current_time;
		stream_forward_writing_ptr(&pcontext->stream, actual_read);
	} else {
		if (EAGAIN != errno) {
			goto LOST_READ;
		}
		/* check if context is timed out */
		if (CALCULATE_INTERVAL(current_time,pcontext->connection.last_timestamp)
			>= g_timeout) {
			/* 451 Timeout */
			smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2174012, 1,
							 &string_length);
			if (NULL != pcontext->connection.ssl) {
				SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
			} else {
				write(pcontext->connection.sockd, smtp_reply_str, string_length);
			}
			smtp_parser_log_info(pcontext, 0, "time out");
			if (0 != pcontext->flusher.flush_ID) {
				flusher_cancel(pcontext);
			}
			if (NULL != pcontext->connection.ssl) {
				SSL_shutdown(pcontext->connection.ssl);
				SSL_free(pcontext->connection.ssl);
				pcontext->connection.ssl = NULL;
			}
			SLEEP_BEFORE_CLOSE;
			close(pcontext->connection.sockd);
			if (system_services_container_remove_ip != nullptr)
				system_services_container_remove_ip(pcontext->connection.client_ip);
			smtp_parser_context_clear(pcontext);
			return PROCESS_CLOSE;
		} else {
			return PROCESS_POLLING_RDONLY;
		}
	}
	/*========================================================================*/
	/* envelop command is met */
 CMD_PROCESS:
	if (T_DATA_CMD != pcontext->last_cmd) {    
		stream_try_mark_line(&pcontext->stream);
		switch (stream_has_newline(&pcontext->stream)) {
		case STREAM_LINE_FAIL:
			smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175025, 1,
							 &string_length);
			if (NULL != pcontext->connection.ssl) {
				SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
			} else {
				write(pcontext->connection.sockd, smtp_reply_str, string_length);
			}
			smtp_parser_log_info(pcontext, 0, "envelop line too long");
			if (NULL != pcontext->connection.ssl) {
				SSL_shutdown(pcontext->connection.ssl);
				SSL_free(pcontext->connection.ssl);
				pcontext->connection.ssl = NULL;
			}
			SLEEP_BEFORE_CLOSE;
			close(pcontext->connection.sockd);
			if (system_services_container_remove_ip != nullptr)
				system_services_container_remove_ip(pcontext->connection.client_ip);
			smtp_parser_context_clear(pcontext);
			return PROCESS_CLOSE;        
		case STREAM_LINE_UNAVAILABLE:
			return PROCESS_CONTINUE;
		case STREAM_LINE_AVAILABLE:
			do{
				line_length = stream_readline(&pcontext->stream, &line);
				if (0 != line_length) {
					switch (smtp_parser_dispatch_cmd(line, line_length, 
							pcontext)) {
					case DISPATCH_SHOULD_CLOSE:
						if (NULL != pcontext->connection.ssl) {
							SSL_shutdown(pcontext->connection.ssl);
							SSL_free(pcontext->connection.ssl);
							pcontext->connection.ssl = NULL;
						}
						SLEEP_BEFORE_CLOSE;
						close(pcontext->connection.sockd);
						if (system_services_container_remove_ip != nullptr)
							system_services_container_remove_ip(pcontext->connection.client_ip);
						smtp_parser_context_clear(pcontext);
						return PROCESS_CLOSE;
					case DISPATCH_CONTINUE:
						break;
					case DISPATCH_BREAK:
						/*
						 * Caution: The stream object is different, so we
						 should get the pbuff from the new stream object and 
						 backward the read ptr to zero as if the steam has 
						 * never been changed.
						 */
						actual_read = STREAM_BLOCK_SIZE;
						pbuff = static_cast<char *>(stream_getbuffer_for_reading(&pcontext->stream,
						        reinterpret_cast<unsigned int *>(&actual_read)));
						stream_backward_reading_ptr(&pcontext->stream, 
								actual_read);
						goto DATA_PROCESS;
					default:
						debug_info("[smtp_parser] :error occurs in "
									"smtp_dispatch_cmd\n");
						if (NULL != pcontext->connection.ssl) {
							SSL_shutdown(pcontext->connection.ssl);
							SSL_free(pcontext->connection.ssl);
							pcontext->connection.ssl = NULL;
						}
						close(pcontext->connection.sockd);
						if (system_services_container_remove_ip != nullptr)
							system_services_container_remove_ip(pcontext->connection.client_ip);
						smtp_parser_context_clear(pcontext);
						return PROCESS_CLOSE;
					}
				}
				stream_try_mark_line(&pcontext->stream);
			} while (STREAM_LINE_AVAILABLE == stream_has_newline(
					 &pcontext->stream));
			return PROCESS_CONTINUE;
		}
	} else {
	/*=======================================================================*/
	/* data command is met */
 DATA_PROCESS:
		if (stream_get_total_length(&pcontext->stream) >= g_flushing_size) {
			b_should_flush = TRUE;
		}
		
		if (actual_read >= 4) {
			memcpy(pcontext->last_bytes, pbuff + actual_read - 4, 4);
		} else {
			memmove(pcontext->last_bytes, pcontext->last_bytes + actual_read, 4 - actual_read);
			memcpy(pcontext->last_bytes + 4 - actual_read, pbuff, actual_read);
		}
		stream_try_mark_eom(&pcontext->stream);
		
		switch (stream_has_eom(&pcontext->stream)) {
		case STREAM_EOM_NET:
			stream_split_eom(&pcontext->stream, NULL);
			pcontext->last_cmd = T_END_MAIL;
			return smtp_parser_try_flush_mail(pcontext, TRUE);
		case STREAM_EOM_DIRTY:
			stream_init(&pcontext->stream_second, blocks_allocator_get_allocator());
			stream_split_eom(&pcontext->stream, &pcontext->stream_second);
			pcontext->is_splitted = TRUE;
			pcontext->last_cmd = T_END_MAIL;
			return smtp_parser_try_flush_mail(pcontext, TRUE);
		default:
			if (FALSE == b_should_flush) {
				return PROCESS_CONTINUE;
			} else {
				return smtp_parser_try_flush_mail(pcontext, FALSE);
			}
		}
	}

	if (NULL != pcontext->connection.ssl) {
		SSL_shutdown(pcontext->connection.ssl);
		SSL_free(pcontext->connection.ssl);
		pcontext->connection.ssl = NULL;
	}

	if (pcontext->connection.sockd >= 0) {
		close(pcontext->connection.sockd);
	}
	if (system_services_container_remove_ip != nullptr)
		system_services_container_remove_ip(pcontext->connection.client_ip);
	smtp_parser_context_clear(pcontext);
	return PROCESS_CLOSE;
}
	

static int smtp_parser_try_flush_mail(SMTP_CONTEXT *pcontext, BOOL is_whole)
{
	char buff[1024];
	char *smtp_reply_str;
	int string_length;
	
	pcontext->total_length += stream_get_total_length(&pcontext->stream) -
							  pcontext->pre_rstlen;
	if (pcontext->total_length >= g_max_mail_length && is_whole == FALSE) {
		/* 552 message exceeds fixed maximum message size */
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175021, 1,
						 &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
		smtp_parser_log_info(pcontext, 8, "close session because of exceeding "
				 "maximum size of message");
		if (0 != pcontext->flusher.flush_ID) {
			flusher_cancel(pcontext);
		}
		if (NULL != pcontext->connection.ssl) {
			SSL_shutdown(pcontext->connection.ssl);
			SSL_free(pcontext->connection.ssl);
			pcontext->connection.ssl = NULL;
		}
		SLEEP_BEFORE_CLOSE;
		close(pcontext->connection.sockd);
		if (system_services_container_remove_ip != nullptr)
			system_services_container_remove_ip(pcontext->connection.client_ip);
		smtp_parser_context_clear(pcontext);
		return PROCESS_CLOSE;
	}
	smtp_parser_reset_stream_reading(pcontext);
	if (TRUE == is_whole) {
		pcontext->flusher.flush_action = FLUSH_WHOLE_MAIL;
	} else {
		pcontext->flusher.flush_action = FLUSH_PART_MAIL;
	}
	/* a mail is recieved pass it in anti-spamming auditor&filter&statistic */
	if (is_whole && !smtp_parser_pass_statistic(pcontext, buff, 1024)) {
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, buff, strlen(buff));
		} else {
			write(pcontext->connection.sockd, buff, strlen(buff));
		}
		if (0 != pcontext->flusher.flush_ID) {
			flusher_cancel(pcontext);
		}
		if (NULL != pcontext->connection.ssl) {
			SSL_shutdown(pcontext->connection.ssl);
			SSL_free(pcontext->connection.ssl);
			pcontext->connection.ssl = NULL;
		}
		SLEEP_BEFORE_CLOSE;
		close(pcontext->connection.sockd);
		if (system_services_container_remove_ip != nullptr)
			system_services_container_remove_ip(pcontext->connection.client_ip);
		smtp_parser_context_clear(pcontext);
		return PROCESS_CLOSE;
	}

	stream_reset_reading(&pcontext->stream);
	/* 
	 when block_info state is parsing block content and the possible boundary
	 string appears in the last of stream, copy the unfinished line into 
	 block_info's block_mime. after the context is flushed, rewrite the 
	 unfinished line into the clear stream. under the other conditions, always 
	 ignore the last 4 bytes.
	 */
	if (FALSE == is_whole) {
		if((PARSING_BLOCK_CONTENT != pcontext->block_info.state &&
		   PARSING_NEST_MIME != pcontext->block_info.state) ||
		   SINGLE_PART_MAIL == pcontext->mail.head.mail_part) {
			stream_backward_writing_ptr(&pcontext->stream, 4);
		} else {
			stream_backward_writing_ptr(&pcontext->stream, 
				pcontext->block_info.block_mime_len);
		}
	}    
	flusher_put_to_queue(pcontext);
	return PROCESS_SLEEPING;
}

/*
 *   pass the mail into statistic
 *   @param
 *       pcontext [in]    indicate the context object
 *       reason [out]     buffer for echo the reason in case of FALSE
 *       length           length of reason buffer
 */
static BOOL smtp_parser_pass_statistic(SMTP_CONTEXT *pcontext, char *reason,
	int length)
{
	pcontext->mail.body.mail_length = pcontext->total_length;
	return TRUE;
}

/*
 *    get smtp_parser's property
 *    @param
 *        param    indicate the parameter type
 *    @return
 *        value of property
 */
long smtp_parser_get_param(int param)
{
	switch (param) {
	case MAX_MAIL_LENGTH:
		return g_max_mail_length;
	case SMTP_MAX_MAILS:
		return g_max_mail_sessions;
	case BLOCK_TIME_EXCEED_SESSIONS:
		return g_blktime_sessions;
	case SMTP_NEED_AUTH:
		return g_need_auth;
	case MAX_FLUSHING_SIZE:
		return g_flushing_size;
	case MAX_AUTH_TIMES:
		return g_auth_times;
	case BLOCK_TIME_EXCEED_AUTHS:
		return g_blktime_auths;
	case SMTP_SESSION_TIMEOUT:
		return g_timeout;
	case SMTP_SUPPORT_PIPELINE:
		return g_support_pipeline;
	case SMTP_SUPPORT_STARTTLS:
		return g_support_starttls;
	case SMTP_FORCE_STARTTLS:
		return g_force_starttls;
	default:
		return 0;
	}
}

/* 
 *    get contexts list for contexts pool
 *    @return
 *        contexts array's address
 */
SMTP_CONTEXT* smtp_parser_get_contexts_list()
{
	return g_context_list;
}

/*
 *    set smtp_parser's property
 *    @param
 *        param    indicate the pram type
 *    @return
 *         0        success
 *        <>0        fail
 */
int smtp_parser_set_param(int param, long value)
{
	switch (param) {
	case MAX_AUTH_TIMES:
		g_auth_times = (int)value;
		break;
	case SMTP_SESSION_TIMEOUT:
		g_timeout = (int)value;
		break;
	case BLOCK_TIME_EXCEED_SESSIONS:
		g_blktime_sessions = (int)value;
		break;
	case MAX_MAIL_LENGTH:
		g_max_mail_length = value;
		break;
	case SMTP_NEED_AUTH:
		if (0 == value) {
			g_need_auth = FALSE;
		} else {
			g_need_auth = TRUE;
		}
		break;
	case BLOCK_TIME_EXCEED_AUTHS:
		g_blktime_auths = (int)value;
		break;
	case SMTP_MAX_MAILS:
		g_max_mail_sessions = (int)value;
		break;
	case SMTP_SUPPORT_PIPELINE:
		if (0 == value) {
			g_support_pipeline = FALSE;
		} else {
			g_support_pipeline = TRUE;
		}
		break;
	case SMTP_FORCE_STARTTLS:
		if (0 == value) {
			g_force_starttls = FALSE;
		} else {
			g_force_starttls = TRUE;
		}
		break;
	default:
		return -1;
	}
	return 0;
}

BOOL smtp_parser_validate_domainlist(BOOL b_valid)
{
	g_domainlist_valid = b_valid;
	return TRUE;
}

BOOL smtp_parser_domainlist_valid()
{
	return g_domainlist_valid;
}

/* 
 *    dispatch the smtp command to the corresponding procedure
 *    @param
 *        cmd_line [in]        command string
 *        line_length            length of command line
 *        pcontext [in, out]    context object
 *     @return
 *         DISPATCH_CONTINUE        continue to dispatch command
 *         DISPATCH_SHOULD_CLOSE    quit command is read
 *         DISPATCH_BREAK            data command is met
 */
static int smtp_parser_dispatch_cmd(const char *cmd_line, int line_length, 
	SMTP_CONTEXT *pcontext)
{
	int string_length;
	const char* smtp_reply_str;
	
	/* check the line length */
	if (line_length > 1000) {
		/* 500 syntax error - line too long */
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175002, 1,
						 &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
		return DISPATCH_CONTINUE;
	}
	if (pcontext->session_num == g_max_mail_sessions &&
		(4 != line_length || 0 != strncasecmp(cmd_line, "QUIT", 4))) {
		/* reach the maximum of mail transactions */
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2175029,1,
						 &string_length);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, smtp_reply_str, string_length);
		} else {
			write(pcontext->connection.sockd, smtp_reply_str, string_length);
		}
		if (system_services_add_ip_into_temp_list != nullptr)
			system_services_add_ip_into_temp_list(pcontext->connection.client_ip,
				g_blktime_sessions);
		smtp_parser_log_info(pcontext, 8, "add %s into temporary list because"
							" it exceeds the maximum mail number on session",
							pcontext->connection.client_ip);
		return DISPATCH_SHOULD_CLOSE; 
	}
	/*========================================================================*/
	if (0 == strncasecmp(cmd_line, "HELO", 4)) {
		return smtp_cmd_handler_helo(cmd_line, line_length, pcontext);    
	/*========================================================================*/
	} else if (0 == strncasecmp(cmd_line, "EHLO", 4)) {
		return smtp_cmd_handler_ehlo(cmd_line, line_length, pcontext);
	/*========================================================================*/
	} else if (0 == strncasecmp(cmd_line, "STARTTLS", 8)) {
		return smtp_cmd_handler_starttls(cmd_line, line_length, pcontext);
	/*========================================================================*/
	} else if (0 == strncasecmp(cmd_line, "AUTH", 4)) {
		return smtp_cmd_handler_auth(cmd_line, line_length, pcontext);    
	/*========================================================================*/
	} else if (0 == strncasecmp(cmd_line, "MAIL", 4)) {
		return smtp_cmd_handler_mail(cmd_line, line_length, pcontext);    
	/*========================================================================*/
	} else if (0 == strncasecmp(cmd_line, "RCPT", 4)) {
		return smtp_cmd_handler_rcpt(cmd_line, line_length, pcontext);    
	/*========================================================================*/
	} else if (0 == strncasecmp(cmd_line, "DATA", 4)) {
		return smtp_cmd_handler_data(cmd_line, line_length, pcontext);    
	/*========================================================================*/
	} else if (0 == strncasecmp(cmd_line, "RSET", 4)) {
		return smtp_cmd_handler_rset(cmd_line, line_length, pcontext);    
	/*========================================================================*/
	} else if (0 == strncasecmp(cmd_line, "NOOP", 4)) {
		return smtp_cmd_handler_noop(cmd_line, line_length, pcontext);    
	/*========================================================================*/
	} else if (0 == strncasecmp(cmd_line, "HELP", 4)) {
		return smtp_cmd_handler_help(cmd_line, line_length, pcontext);    
	/*========================================================================*/
	} else if (0 == strncasecmp(cmd_line, "VRFY", 4)) {
		return smtp_cmd_handler_vrfy(cmd_line, line_length, pcontext);    
	/*========================================================================*/
	} else if (0 == strncasecmp(cmd_line, "QUIT", 4)) {
		return smtp_cmd_handler_quit(cmd_line, line_length, pcontext);    
	/*========================================================================*/
	} else if (0 == strncasecmp(cmd_line, "ETRN", 4)) {
		return smtp_cmd_handler_etrn(cmd_line, line_length, pcontext);    
	/*========================================================================*/
	} else {
		return smtp_cmd_handler_else(cmd_line, line_length, pcontext);    
	}
}

/*
 *    reset the smtp context
 *    @param
 *        pcontext [in]    indicate the smtp context object
 */
void smtp_parser_reset_context_envelop(SMTP_CONTEXT *pcontext)
{
	if (TRUE == pcontext->mail.envelop.is_login) {
		pcontext->mail.envelop.auth_times = 0;
	}
	/* prevent some client send reset after auth */
	/* pcontext->mail.envelop.is_login = FALSE; */
	pcontext->mail.envelop.from[0] = '\0';
	/* pcontext->mail.envelop.username[0] = '\0'; */
	strcpy(pcontext->mail.envelop.parsed_domain, "unknown");
	mem_file_clear(&pcontext->mail.envelop.f_rcpt_to);
}

/*
 *    smtp context's construct function
 *    @param
 *        pcontext [in]    indicate the smtp context object
 */
static void smtp_parser_context_init(SMTP_CONTEXT *pcontext)
{
	LIB_BUFFER *palloc_stream, *palloc_file;
	
	if (NULL == pcontext) {
		return;
	}
	palloc_stream = blocks_allocator_get_allocator();
	palloc_file = files_allocator_get_allocator();
	memset(pcontext, 0, sizeof(SMTP_CONTEXT));
	pcontext->connection.sockd = -1;
	mem_file_init(&pcontext->block_info.f_last_blkmime, palloc_file);
	mem_file_init(&pcontext->mail.envelop.f_rcpt_to, palloc_file);
	mem_file_init(&pcontext->mail.head.f_mime_to, palloc_file);
	mem_file_init(&pcontext->mail.head.f_mime_from, palloc_file);
	mem_file_init(&pcontext->mail.head.f_mime_cc, palloc_file);
	mem_file_init(&pcontext->mail.head.f_mime_delivered_to, palloc_file);
	mem_file_init(&pcontext->mail.head.f_xmailer, palloc_file);
	mem_file_init(&pcontext->mail.head.f_subject, palloc_file);
	mem_file_init(&pcontext->mail.head.f_content_type, palloc_file);
	mem_file_init(&pcontext->mail.head.f_others, palloc_file);
	mem_file_init(&pcontext->mail.body.f_mail_parts, palloc_file);
	stream_init(&pcontext->stream, palloc_stream);
}

/*
 *    clear the smtp context object
 *    @param
 *        pcontext [in]    indicate the smtp context object
 */
static void smtp_parser_context_clear(SMTP_CONTEXT *pcontext)
{
	if (NULL == pcontext) {
		return;
	}
	memset(&pcontext->connection, 0, sizeof(CONNECTION));
	pcontext->connection.sockd      = -1;
	pcontext->session_num           = 0;
	if (TRUE == pcontext->is_splitted) {
		stream_free(&pcontext->stream_second);
		pcontext->is_splitted = FALSE;
	}
	pcontext->mail.envelop.is_login = FALSE;
	pcontext->mail.envelop.is_relay = FALSE;
	memset(&pcontext->mail.envelop.username, 0, 256);
	smtp_parser_reset_context_session(pcontext);    
}

/*
 *    reset the session when /r/n./r/n is met
 *    @param
 *        pcontext [in, out]    indicate the context object
 */
static void smtp_parser_reset_context_session(SMTP_CONTEXT *pcontext)
{
	if (NULL == pcontext) {
		return;
	}
	memset(&pcontext->ext_data, 0, sizeof(EXT_DATA));
	memset(&pcontext->last_bytes, 0, 4);
	memset(&pcontext->block_info.block_type, 0, 256);
	memset(&pcontext->block_info.block_mime, 0, MAX_BLOCK_MIME_LEN);
	pcontext->block_info.block_mime_len    = 0;
	pcontext->block_info.last_block_ID     = 0;
	pcontext->block_info.state             = 0;
	pcontext->block_info.remains_len       = 0;
	pcontext->last_cmd                     = 0;
	pcontext->is_spam                      = FALSE;
	pcontext->total_length                 = 0;
	pcontext->pre_rstlen                   = 0;
	pcontext->mail.head.x_priority         = 0;
	pcontext->mail.head.mail_part          = 0;
	pcontext->mail.envelop.auth_times      = 0;
	pcontext->mail.body.mail_length        = 0;
	pcontext->mail.body.parts_num          = 0;
	stream_clear(&pcontext->stream);
	mem_file_clear(&pcontext->block_info.f_last_blkmime);
	strcpy(pcontext->mail.envelop.parsed_domain, "unknown");
	memset(&pcontext->mail.envelop.hello_domain, 0, 256);
	memset(&pcontext->mail.envelop.from, 0, 256);
	if (FALSE == pcontext->mail.envelop.is_login) {
		memset(&pcontext->mail.envelop.username, 0, 256);
	}
	mem_file_clear(&pcontext->mail.envelop.f_rcpt_to);
	mem_file_clear(&pcontext->mail.head.f_mime_to);
	mem_file_clear(&pcontext->mail.head.f_mime_from);
	mem_file_clear(&pcontext->mail.head.f_mime_cc);
	mem_file_clear(&pcontext->mail.head.f_mime_delivered_to);
	mem_file_clear(&pcontext->mail.head.f_xmailer);
	mem_file_clear(&pcontext->mail.head.f_subject);
	mem_file_clear(&pcontext->mail.head.f_content_type);
	mem_file_clear(&pcontext->mail.head.f_others);
	mem_file_clear(&pcontext->mail.body.f_mail_parts);
	memset(&pcontext->mail.head.x_original_ip, 0, sizeof(pcontext->mail.head.x_original_ip));
	memset(&pcontext->mail.head.compose_time, 0, 64);
	memset(&pcontext->flusher, 0, sizeof(FLUSH_INFO));
}

/*
 *    smtp context's destruct function
 *    @param
 *        pcontext [in]    indicate the smtp context object
 */
static void smtp_parser_context_free(SMTP_CONTEXT *pcontext)
{
	mem_file_free(&pcontext->block_info.f_last_blkmime);
	mem_file_free(&pcontext->mail.envelop.f_rcpt_to);
	mem_file_free(&pcontext->mail.head.f_mime_to);
	mem_file_free(&pcontext->mail.head.f_mime_from);
	mem_file_free(&pcontext->mail.head.f_mime_cc);
	mem_file_free(&pcontext->mail.head.f_mime_delivered_to);
	mem_file_free(&pcontext->mail.head.f_xmailer);
	mem_file_free(&pcontext->mail.head.f_subject);
	mem_file_free(&pcontext->mail.head.f_content_type);
	mem_file_free(&pcontext->mail.head.f_others);
	mem_file_free(&pcontext->mail.body.f_mail_parts);
	stream_free(&pcontext->stream);
	if (TRUE == pcontext->is_splitted) {
		stream_free(&pcontext->stream_second);
		pcontext->is_splitted = FALSE;
	}
	if (NULL != pcontext->connection.ssl) {
		SSL_shutdown(pcontext->connection.ssl);
		SSL_free(pcontext->connection.ssl);
		pcontext->connection.ssl = NULL;
	}
	if (-1 != pcontext->connection.sockd) {
		close(pcontext->connection.sockd);
		pcontext->connection.sockd = -1;
	}
}

/*
 *    reset the stream only for smtp parser
 *    @param
 *        pcontext [in, out] indicate the stream object
 */
static void smtp_parser_reset_stream_reading(SMTP_CONTEXT *pcontext)
{
	stream_reset_reading(&pcontext->stream);
	stream_forward_reading_ptr(&pcontext->stream, pcontext->pre_rstlen);
}

void smtp_parser_log_info(SMTP_CONTEXT *pcontext, int level,
    const char *format, ...)
{
	char log_buf[2048], rcpt_buff[2048];
	size_t size_read = 0, rcpt_len = 0, i;
	va_list ap;

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	va_end(ap);
	log_buf[sizeof(log_buf) - 1] = '\0';
	
	/* maximum record 8 rcpt to address */
	mem_file_seek(&pcontext->mail.envelop.f_rcpt_to, MEM_FILE_READ_PTR, 0, 
				  MEM_FILE_SEEK_BEGIN);
	for (i=0; i<8; i++) {
		size_read = mem_file_readline(&pcontext->mail.envelop.f_rcpt_to,
					rcpt_buff + rcpt_len, 256);
		if (size_read == MEM_END_OF_FILE) {
			break;
		}
		rcpt_len += size_read;
		rcpt_buff[rcpt_len] = ' ';
		rcpt_len ++;
	}
	rcpt_buff[rcpt_len] = '\0';
	
	system_services_log_info(level,"remote MTA IP: %s, FROM: %s, TO: %s %s",
		pcontext->connection.client_ip,
		pcontext->mail.envelop.from, rcpt_buff, log_buf);
}

int smtp_parser_get_extra_num(SMTP_CONTEXT *pcontext)
{
	return pcontext->ext_data.cur_pos;
}

const char* smtp_parser_get_extra_tag(SMTP_CONTEXT *pcontext, int pos)
{
	if (pos >= MAX_EXTRA_DATA_INDEX || pos < 0) {
		return NULL;
	}
	return pcontext->ext_data.ext_tag[pos];
}

const char* smtp_parser_get_extra_value(SMTP_CONTEXT *pcontext, int pos)
{
	if (pos >= MAX_EXTRA_DATA_INDEX || pos < 0) {
		return NULL;
	}
	return pcontext->ext_data.ext_data[pos];
}
