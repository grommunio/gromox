/* smtp parser is a module, which first read data from socket, parses the smtp 
 * commands and then do the corresponding action. 
 */ 
#include <unistd.h>
#include <libHX/defs.h>
#include "smtp_parser.h"
#include "smtp_cmd_handler.h"
#include "files_allocator.h"
#include "blocks_allocator.h"
#include "bndstack_allocator.h"
#include "threads_pool.h"
#include "system_services.h"
#include "anti_spamming.h"
#include "flusher.h"
#include "resource.h"
#include "lib_buffer.h"
#include "util.h"
#include "mail_func.h"
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
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

static BOOL smtp_parser_pass_auditor_filter(SMTP_CONTEXT *pcontext,
	BOOL is_whole, char *reason, int length);

static BOOL smtp_parser_pass_statistic(SMTP_CONTEXT *pcontext,
	char *reason, int length);
static int smtp_parser_get_block_ID(void);
static void smtp_parser_record_mime_field(SMTP_CONTEXT *pcontext,
	MIME_FIELD *pfield);

static int smtp_parser_parse_and_save_blkmime(SMTP_CONTEXT *pcontext,
	char *in_buff, int length);

static void smtp_parser_reset_stream_reading(SMTP_CONTEXT *pcontext);

static int g_context_num;
static int g_threads_num;
static int g_ssl_port;
static int g_mode;
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
static LIB_BUFFER *g_as_allocator;
static pthread_key_t g_as_buff_key;
static pthread_mutex_t g_block_ID_mutex;
static int g_block_ID;
static char g_certificate_path[256];
static char g_private_key_path[256];
static char g_certificate_passwd[1024];
static SSL_CTX *g_ssl_ctx;
static pthread_mutex_t *g_ssl_mutex_buf;



/*
 *    get a global unique block ID
 *    @return
 *        block ID
 */
static int smtp_parser_get_block_ID()
{
	pthread_mutex_lock(&g_block_ID_mutex);
	if (g_block_ID != 0x7FFFFFFF) {
		g_block_ID ++;
	} else {
		g_block_ID = 1;
	}
	pthread_mutex_unlock(&g_block_ID_mutex);
	return g_block_ID;
}

/* 
 * construct a smtp parser object
 * @param
 *        context_num        number of contexts
 *        threads_num        number of threads in the pool
 *        mode               indicate the running mode of smtp parser
 *        dm_valid           is domain list valid
 *        max_mail_length    maximum mail size
 *        max_mail_sessions  maximum mail sessions per connection
 *        blktime_sessions   block interval if max sessions is exceeded
 *        flushing_size      maximum size the stream can hold
 *        timeout            seconds if there's no data comes from connection
 *        auth_times         maximum authentification times, session permit
 *        blktime_auths      block interval if max auths is exceeded
 */
void smtp_parser_init(int context_num, int threads_num, int mode,
	BOOL dm_valid, BOOL need_auth, size_t max_mail_length,
	size_t max_mail_sessions, size_t blktime_sessions, size_t flushing_size,
	size_t timeout,  size_t auth_times, size_t blktime_auths,
	BOOL support_pipeline, BOOL support_starttls, BOOL force_starttls,
	const char *certificate_path, const char *cb_passwd, const char *key_path)
{
	g_context_num           = context_num;
	g_threads_num           = threads_num;
	g_mode                  = mode;
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
		strcpy(g_certificate_path, certificate_path);
		if (NULL != cb_passwd) {
			strcpy(g_certificate_passwd, cb_passwd);
		} else {
			g_certificate_passwd[0] = '\0';
		}
		strcpy(g_private_key_path, key_path);
	}
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void smtp_parser_ssl_locking(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&g_ssl_mutex_buf[n]);
	else
		pthread_mutex_unlock(&g_ssl_mutex_buf[n]);
}

static void smtp_parser_ssl_id(CRYPTO_THREADID* id)
{
	CRYPTO_THREADID_set_numeric(id, reinterpret_cast(uintptr_t, pthread_self()));
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
			printf("[smtp_parser]: fail to init ssl context\n");
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

		g_ssl_mutex_buf = malloc(CRYPTO_num_locks()*sizeof(pthread_mutex_t));
		if (NULL == g_ssl_mutex_buf) {
			printf("[smtp_parser]: fail to allocate ssl locking buffer\n");
			return -5;
		}
		for (i=0; i<CRYPTO_num_locks(); i++) {
			pthread_mutex_init(&g_ssl_mutex_buf[i], NULL);
		}
		CRYPTO_THREADID_set_callback(smtp_parser_ssl_id);
		CRYPTO_set_locking_callback(smtp_parser_ssl_locking);
	}
	/* 
	 to avoid that the thread is going to be released, by the threads pool is
	 immediatly creating a new thread, error may occur under this condition.
	 so double the g_as_allocator to avoid this program
	 */
	g_as_allocator = lib_buffer_init(TLS_BUFFER_BUS_ALLIN(g_flushing_size *
		TLS_BUFFER_RATIO), g_threads_num * 2, TRUE); 
	if (NULL == g_as_allocator) {
		printf("[smtp_parser]: fail to allocate anti-spamming memory\n");
		return -6;
	}
	g_context_list = malloc(sizeof(SMTP_CONTEXT)*g_context_num);
	if (NULL== g_context_list) {
		printf("[smtp_parser]: fail to allocate smtp contexts\n");
		return -7;
	}
	for (i=0; i<g_context_num; i++) {
		smtp_parser_context_init(g_context_list + i);
	}
	if (!resource_get_integer("LISTEN_SSL_PORT", &g_ssl_port))
		g_ssl_port = 0;
	pthread_key_create(&g_as_buff_key, NULL);
	pthread_mutex_init(&g_block_ID_mutex, NULL);
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

	if (NULL != g_as_allocator && NULL != g_context_list) {
		pthread_key_delete(g_as_buff_key);
		pthread_mutex_destroy(&g_block_ID_mutex);
	}
	if (NULL != g_as_allocator) {
		lib_buffer_free(g_as_allocator);
		g_as_allocator = NULL;
	}
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
	g_mode              = -1;
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
	void *pbuff;
	   
	switch (action) {
	case THREAD_CREATE:
		anti_spamming_threads_event_proc(PLUGIN_THREAD_CREATE);
		pbuff = lib_buffer_get(g_as_allocator);
		if (NULL == pbuff) {
			debug_info("[smtp_parser]: fatal error! fail to get memory from as"
						" allocator\n");
			return -1;
		}
		pthread_setspecific(g_as_buff_key, (const void*) pbuff);    
		break;
	case THREAD_DESTROY:
		anti_spamming_threads_event_proc(PLUGIN_THREAD_DESTROY);
		pbuff = (void*) pthread_getspecific(g_as_buff_key);
		if (NULL != pbuff) {
			lib_buffer_put(g_as_allocator, pbuff);
		}
		pthread_setspecific(g_as_buff_key, (const void*) NULL);    
		break;
	}
	return 0;
}

int smtp_parser_process(SMTP_CONTEXT *pcontext)
{
	char *pbuff, *line, reply_buf[1024];
	int actual_read, ssl_errno;
	int size = READ_BUFFER_SIZE, line_length;
	struct timeval current_time;
	const char *host_ID;
	char *smtp_reply_str;
	char *smtp_reply_str2;
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
			pbuff = stream_getbuffer_for_writing(&pcontext->stream, &size);
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
		smtp_parser_log_info(pcontext, 8, "flushing queue permanent fail");
		if (NULL != pcontext->connection.ssl) {
			SSL_shutdown(pcontext->connection.ssl);
			SSL_free(pcontext->connection.ssl);
			pcontext->connection.ssl = NULL;
		}
		SLEEP_BEFORE_CLOSE;
		close(pcontext->connection.sockd);
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
	            system_services_container_remove_ip(
					pcontext->connection.client_ip);
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
			system_services_container_remove_ip(
				pcontext->connection.client_ip);
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
	pbuff = stream_getbuffer_for_writing(&pcontext->stream, &size);
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
		if (0 != pcontext->block_info.last_block_ID) {
			anti_spamming_inform_filters(pcontext->block_info.block_type,
				pcontext, ACTION_BLOCK_FREE,pcontext->block_info.last_block_ID);
		}
		if (NULL != pcontext->connection.ssl) {
			SSL_shutdown(pcontext->connection.ssl);
			SSL_free(pcontext->connection.ssl);
			pcontext->connection.ssl = NULL;
		}
		SLEEP_BEFORE_CLOSE;
		close(pcontext->connection.sockd);
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
		if (0 != pcontext->block_info.last_block_ID) {
			anti_spamming_inform_filters(pcontext->block_info.block_type,
				pcontext, ACTION_BLOCK_FREE, 
				pcontext->block_info.last_block_ID);
		}
		if (NULL != pcontext->connection.ssl) {
			SSL_shutdown(pcontext->connection.ssl);
			SSL_free(pcontext->connection.ssl);
			pcontext->connection.ssl = NULL;
		}
		smtp_parser_log_info(pcontext, 0, "connection lost");
		close(pcontext->connection.sockd);
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
			if (0 != pcontext->block_info.last_block_ID) {
				anti_spamming_inform_filters(pcontext->block_info.block_type,
					pcontext, ACTION_BLOCK_FREE, 
					pcontext->block_info.last_block_ID);
			}
			if (NULL != pcontext->connection.ssl) {
				SSL_shutdown(pcontext->connection.ssl);
				SSL_free(pcontext->connection.ssl);
				pcontext->connection.ssl = NULL;
			}
			SLEEP_BEFORE_CLOSE;
			close(pcontext->connection.sockd);
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
						system_services_container_remove_ip(
							pcontext->connection.client_ip);
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
						pbuff = stream_getbuffer_for_reading(&pcontext->stream,
								&actual_read);
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
						system_services_container_remove_ip(
							pcontext->connection.client_ip);
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
	if (FALSE == smtp_parser_pass_auditor_filter(pcontext,is_whole,buff,1024)
	   ||(TRUE == is_whole && 
		 FALSE == smtp_parser_pass_statistic(pcontext, buff,1024))) {
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
 *    class the information in context and pass them by auditors and filters
 *    @param
 *        pcontext [in, out]    indicate the context object
 *        is_whole              whether it's the last part of a mail
 *        reason [out]          buffer for retrieving reason when fail to pass
 *        length                indicate the length of buffer
 *    @reason
 *        TRUE                  OK to pass
 *        FALSE                 fail to pass
 */
static BOOL smtp_parser_pass_auditor_filter(SMTP_CONTEXT *pcontext,
	BOOL is_whole, char *reason, int length)
{
	char *pbuff, *smtp_reply_str;
	char *ptls_buf, *parsed_buf;
	const char *boundary_string; 
	MIME_FIELD mime_field;
	int audit_result, size;
	size_t parsed_len, parsed_length;
	int boundary_length, type_len; 
	int filter_result, line_result, found_result;
	int current_offset, string_length;
	size_t data_read;
	BOOL remains_copied;
	char temp_line[MAX_LINE_LENGTH], tmp_reason[1024];
	BOUNDARY_STRING *pbnd;
	MAIL_BLOCK pass_mail_block;
	
	/* check if need to pass auditor */
	if (PARSING_MAIL_HEAD == pcontext->block_info.state) {
		/* retrieve mime head information from buffer */
		size = STREAM_BLOCK_SIZE;
		current_offset = 0;
		pbuff = stream_getbuffer_for_reading(&pcontext->stream, &size);
		while (current_offset < size && (parsed_length=parse_mime_field(pbuff + 
			  current_offset, size - current_offset, &mime_field))) {
			/* check if mime head is over */
			smtp_parser_record_mime_field(pcontext, &mime_field);
			current_offset += parsed_length;
			if ('\r' == pbuff[current_offset]) {
				current_offset ++;
				if ('\n' == pbuff[current_offset]) {
					current_offset ++;
				}
				break;
			}
			if ('\n' == pbuff[current_offset]) {
				current_offset ++;
				break;
			}
		}
		/* check if boundary string has already been met */
		if (pcontext->block_info.cur_bndstr.bndstr_len > 
			MAX_BOUNDARY_STRING_LENGTH - 1) {
			/* mime head error! no boundary string or too long */
			smtp_parser_log_info(pcontext, 8, "boundary string in mime head "
							"too long");    
			goto MIME_ERROR;
		}
		
		/* pass mime in mime head auditor */
		audit_result = anti_spamming_pass_auditors(pcontext, tmp_reason, 1024);
		if (MESSAGE_REJECT == audit_result) {
			snprintf(reason, length, "550 %s\r\n", tmp_reason);
			smtp_parser_log_info(pcontext, 8, 
							"illegal mail is cut! reason: %s", tmp_reason);
			return FALSE;
		} else if (MESSAGE_RETRYING == audit_result) {
			snprintf(reason, length, "450 %s\r\n", tmp_reason);
			smtp_parser_log_info(pcontext, 8, 
							"dubious mail is cut! reason: %s", tmp_reason);
			return FALSE;
		}
		/* 
		 if mail is a single part mail, record the mime head as block mime in
		 context
		 */
		if (SINGLE_PART_MAIL == pcontext->mail.head.mail_part) {
			if (ERROR_FOUND != smtp_parser_parse_and_save_blkmime(pcontext, 
								pbuff, current_offset)) {
				pcontext->block_info.state = PARSING_BLOCK_CONTENT;
			} else {
				smtp_parser_log_info(pcontext, 8, "found error in mime head of"
								" single part mail");    
				goto MIME_ERROR;
			}
		} else{
			pcontext->block_info.state = PARSING_NEST_MIME;
		}
		/* may read too many bytes, which should be part of blocks */
		stream_backward_reading_ptr(&pcontext->stream, size - current_offset);
	}
	if (PARSING_END == pcontext->block_info.state) {
		return TRUE;
	}
	/* copy and arrange rest data in TLS buffer and search boundary string*/
	ptls_buf = pthread_getspecific(g_as_buff_key);
	/* prevent fatal error when system is too busy */
	if (NULL == ptls_buf) {
		printf("[smtp_parser]: fatal error when to get TLS buffer for "
				"anti-spamming\n");
		return TRUE;
	}
	memset(ptls_buf, 0, g_flushing_size);    /* zero partially */
	parsed_buf = ptls_buf + (size_t)(g_flushing_size * (TLS_BUFFER_RATIO / 2));
	/* 
	 check if rest bytes for decoding is left in block_info, if there exists
	 copy them first into ptls buffer    
	   */
	if (0 != pcontext->block_info.remains_len) {
		memcpy(ptls_buf, pcontext->block_info.remains_encode,
			   pcontext->block_info.remains_len);
		data_read = pcontext->block_info.remains_len;
		pcontext->block_info.remains_len = 0;
		remains_copied = TRUE;
	} else {
		data_read = 0;
		remains_copied = FALSE;
	}
	/* begin to extract the blocks of a mail */
	if (SINGLE_PART_MAIL == pcontext->mail.head.mail_part) {
		while (TRUE) {
			size = MAX_LINE_LENGTH;
			line_result = stream_copyline(&pcontext->stream, ptls_buf +
						  data_read, &size);
			data_read += size;

			if (STREAM_COPY_PART != line_result &&
				ENCODING_BASE64 != pcontext->block_info.encode_type) {
				memcpy(ptls_buf + data_read, "\r\n", 2);
				data_read += 2;
			}

			if (STREAM_COPY_OK != line_result &&
				STREAM_COPY_PART != line_result) {
				break;
			}
		}
		if ((STREAM_COPY_END == line_result||STREAM_COPY_TERM == line_result)) {
			if (0 == pcontext->block_info.last_block_ID) {
				pcontext->block_info.last_block_ID = smtp_parser_get_block_ID();
				pcontext->block_info.remains_len   = 0;
				pcontext->block_info.block_body_len= 0;
				anti_spamming_inform_filters(pcontext->block_info.block_type,
											pcontext, ACTION_BLOCK_NEW, 
											pcontext->block_info.last_block_ID);
			}
			if (ENCODING_BASE64 == pcontext->block_info.encode_type) {
				pcontext->block_info.remains_len = data_read % 4;
				parsed_len = data_read - pcontext->block_info.remains_len;
				if (pcontext->block_info.remains_len > 0) {
					memcpy(pcontext->block_info.remains_encode, ptls_buf +
							parsed_len, pcontext->block_info.remains_len);
				}
				pass_mail_block.original_length    = parsed_len;

				if (0 != decode64(ptls_buf,parsed_len,parsed_buf,&parsed_len)) {
					pass_mail_block.is_parsed = FALSE;
				} else {
					pass_mail_block.is_parsed = TRUE;
				}
			} else if (ENCODING_QUOTED_PRINTABLE == 
						pcontext->block_info.encode_type) {
				parsed_len    = qp_decode(parsed_buf, ptls_buf, data_read);
				pass_mail_block.original_length  = data_read;
				pass_mail_block.is_parsed        = TRUE;
			} else {
				pass_mail_block.original_length  = data_read;
				parsed_len                       = 0;
				pass_mail_block.is_parsed        = FALSE;
			}
			pcontext->block_info.block_body_len += data_read;
			pass_mail_block.block_ID     = pcontext->block_info.last_block_ID;
			pass_mail_block.fp_mime_info = &pcontext->block_info.f_last_blkmime;
			pass_mail_block.original_buff= ptls_buf;
			pass_mail_block.parsed_buff  = parsed_buf;
			pass_mail_block.parsed_length= parsed_len;
			filter_result = anti_spamming_pass_filters(
							pcontext->block_info.block_type,
							pcontext,
							&pass_mail_block,
							tmp_reason,
							sizeof(tmp_reason));
			if (MESSAGE_REJECT == filter_result ||
				MESSAGE_RETRYING == filter_result) {
				anti_spamming_inform_filters(pcontext->block_info.block_type,
										 pcontext, ACTION_BLOCK_FREE, 
										 pcontext->block_info.last_block_ID);
				goto REJECT_SPAM;
			}
			if (TRUE == is_whole) {
				anti_spamming_inform_filters(pcontext->block_info.block_type,
										 pcontext, ACTION_BLOCK_FREE, 
										 pcontext->block_info.last_block_ID);
				type_len = strlen(pcontext->block_info.block_type);
				mem_file_write(&pcontext->mail.body.f_mail_parts,
							   (char*)&type_len, sizeof(int));
				mem_file_write(&pcontext->mail.body.f_mail_parts,
							   pcontext->block_info.block_type,
							   type_len);
				mem_file_write(&pcontext->mail.body.f_mail_parts,
							   (char*)&pcontext->block_info.block_body_len,
							   sizeof(size_t));
				pcontext->mail.body.parts_num += 1;
			}
			return TRUE;
		} else {
			/* go directly to the MIME_ERROR sub-procedure! */
			if (0 != pcontext->block_info.last_block_ID) {
				anti_spamming_inform_filters(pcontext->block_info.block_type,
										 pcontext, ACTION_BLOCK_FREE, 
										 pcontext->block_info.last_block_ID);
			}
			smtp_parser_log_info(pcontext, 8, "single part mail line too long");
			goto MIME_ERROR;
		}
	} else {
		while (TRUE) {
			if (PARSING_BLOCK_HEAD == pcontext->block_info.state) {
				while (TRUE) {
					size = MAX_BLOCK_MIME_LEN -
							pcontext->block_info.block_mime_len;
					line_result = stream_copyline(&pcontext->stream,
								   pcontext->block_info.block_mime +
								   pcontext->block_info.block_mime_len, &size);
					pcontext->block_info.block_mime_len += size;
					if (pcontext->block_info.block_mime_len >=
						MAX_BLOCK_MIME_LEN - 1) {
						smtp_parser_log_info(pcontext, 8, 
							"block mime head too long");
						goto MIME_ERROR;
					}
					if (STREAM_COPY_OK == line_result) {
						if (0 != size) {
							pcontext->block_info.block_mime[
								pcontext->block_info.block_mime_len++] = '\r';
							pcontext->block_info.block_mime[
								pcontext->block_info.block_mime_len++] = '\n';
						}
					} else {
						break;
					}
					if (0 == size) {
						pcontext->block_info.state = PARSING_BLOCK_CONTENT;
						found_result = smtp_parser_parse_and_save_blkmime(
									   pcontext,pcontext->block_info.block_mime,
									   pcontext->block_info.block_mime_len);
						if (ERROR_FOUND == found_result) {
							smtp_parser_log_info(pcontext, 8, "find error in"
											" mime head of part");    
							goto MIME_ERROR;
						} else if (TYPE_FOUND == found_result) {
							pcontext->block_info.state = PARSING_BLOCK_CONTENT;
							break;
						} else if (BOUNDARY_FOUND == found_result) {
							pcontext->block_info.state = PARSING_NEST_MIME;
							break;
						}
					}
				}
				if (STREAM_COPY_OK == line_result) {
					continue;
				}
				if (STREAM_COPY_PART == line_result) {
					smtp_parser_log_info(pcontext, 8, "line too long in mail");    
					goto MIME_ERROR;
				}
				if (TRUE == is_whole &&
					pcontext->block_info.state != PARSING_END) {
					if (0 != pcontext->block_info.last_block_ID) {
						anti_spamming_inform_filters(
							pcontext->block_info.block_type,
							pcontext, ACTION_BLOCK_FREE,
							pcontext->block_info.last_block_ID);
					}
					pcontext->block_info.state = PARSING_END;
				}
				return TRUE;
			} else if(PARSING_BLOCK_CONTENT == pcontext->block_info.state) {
				boundary_string = pcontext->block_info.cur_bndstr.bndstr;
				boundary_length = pcontext->block_info.cur_bndstr.bndstr_len;
				if (FALSE == remains_copied) {
					data_read = 0;
				} else {
					remains_copied = FALSE;
				}
				while (TRUE) {
					size = MAX_LINE_LENGTH;
					line_result = stream_copyline(&pcontext->stream, ptls_buf +
									data_read, &size);
					if (STREAM_COPY_OK != line_result &&
						STREAM_COPY_PART != line_result) {
						break;
					}
					if (ptls_buf[data_read] == '-' &&
						ptls_buf[data_read + 1] == '-') {
						if (0 == strncmp(boundary_string, ptls_buf + data_read +
							2, boundary_length)) {
							/* block end is found */
							if (0 == pcontext->block_info.last_block_ID) {
								pcontext->block_info.last_block_ID = 
									smtp_parser_get_block_ID();
								pcontext->block_info.block_body_len= 0;
								anti_spamming_inform_filters(
									pcontext->block_info.block_type,
									pcontext, ACTION_BLOCK_NEW, 
									pcontext->block_info.last_block_ID);
							}
							if (ENCODING_BASE64 ==
								pcontext->block_info.encode_type) {
								pcontext->block_info.remains_len = data_read%4;
								parsed_len = data_read - 
											 pcontext->block_info.remains_len;
								if (pcontext->block_info.remains_len > 0) {
									memcpy(pcontext->block_info.remains_encode,
										ptls_buf + parsed_len,
										pcontext->block_info.remains_len);
								}
								pass_mail_block.original_length = parsed_len;
								if (0 != decode64(ptls_buf, parsed_len, 
										parsed_buf, &parsed_len)) {
									pass_mail_block.is_parsed = FALSE;
								} else {
									pass_mail_block.is_parsed = TRUE;
								}
							} else if (ENCODING_QUOTED_PRINTABLE == 
										pcontext->block_info.encode_type) {
								parsed_len = qp_decode(parsed_buf, ptls_buf,
											 data_read);
								pass_mail_block.is_parsed        = TRUE;
								pass_mail_block.original_length  = data_read;
							} else {
								parsed_len                       = 0;
								pass_mail_block.original_length  = data_read;
								pass_mail_block.is_parsed        = FALSE;
							}

							pcontext->block_info.block_body_len += data_read;
							pass_mail_block.block_ID         = 
									pcontext->block_info.last_block_ID;
							pass_mail_block.fp_mime_info     = 
									&pcontext->block_info.f_last_blkmime;
							pass_mail_block.original_buff    = ptls_buf;
							pass_mail_block.parsed_buff      = parsed_buf;
							pass_mail_block.parsed_length    = parsed_len;

							filter_result =anti_spamming_pass_filters(
										   pcontext->block_info.block_type,
										   pcontext,
										   &pass_mail_block,
										   tmp_reason, sizeof(tmp_reason));
							anti_spamming_inform_filters(
										pcontext->block_info.block_type,
										pcontext, ACTION_BLOCK_FREE, 
										pcontext->block_info.last_block_ID);
							if (MESSAGE_REJECT == filter_result ||
								MESSAGE_RETRYING == filter_result) {
								goto REJECT_SPAM;
							}
							type_len = strlen(pcontext->block_info.block_type);
							mem_file_write(&pcontext->mail.body.f_mail_parts,
										   (char*)&type_len, sizeof(int));
							mem_file_write(&pcontext->mail.body.f_mail_parts,
										   pcontext->block_info.block_type,
										   type_len);
							mem_file_write(&pcontext->mail.body.f_mail_parts,
									(char*)&pcontext->block_info.block_body_len,
									sizeof(size_t));
							pcontext->mail.body.parts_num += 1;
							/* check if --boundary string-- is met */
							if (size == boundary_length + 4 &&
								ptls_buf[data_read + size - 1] == '-' &&
								ptls_buf[data_read + size - 2] == '-') {
								pbnd = (BOUNDARY_STRING*)vstack_get_top(
										&pcontext->block_info.stack_bndstr);
								/* last --bndstr-- is met */
								if (NULL == pbnd) {
									pcontext->block_info.state = PARSING_END;
									return TRUE;
								} else {
									/* clear block mime information */
									pcontext->block_info.block_mime_len = 0;
									pcontext->block_info.block_type[0] = '\0';
									mem_file_clear(
										&pcontext->block_info.f_last_blkmime);
									/* end of clear block mime information */
									pcontext->block_info.last_block_ID = 0;
									pcontext->block_info.cur_bndstr = *pbnd;
									pcontext->block_info.state =
										PARSING_NEST_MIME;
									vstack_pop(
										&pcontext->block_info.stack_bndstr);
									break;
								}
							} else {
								/* clear block mime information */
								pcontext->block_info.block_mime_len = 0;
								pcontext->block_info.block_type[0] = '\0';
								mem_file_clear(
									&pcontext->block_info.f_last_blkmime);
								/* end of clear block mime information */
								pcontext->block_info.last_block_ID = 0;
								pcontext->block_info.state = PARSING_BLOCK_HEAD;
								break;
							}
						}
					}
					data_read += size;
					if (STREAM_COPY_PART != line_result &&
						ENCODING_BASE64 != pcontext->block_info.encode_type) {
						memcpy(ptls_buf + data_read, "\r\n", 2);
						data_read += 2;
					}
				}
				if ((STREAM_COPY_END == line_result ||
					STREAM_COPY_TERM == line_result)) {
			/*
			 to check wether it's the last block of whole mail and end boundary
			 string is met. if not, inform filter plugins the end of block to
			 prevent memory leaks in these plugins
			 */
					if (TRUE == is_whole) {
						anti_spamming_inform_filters(
								pcontext->block_info.block_type,
								pcontext, ACTION_BLOCK_FREE,
								pcontext->block_info.last_block_ID);
						/* unfinished mail, make it pass */
						pcontext->block_info.state = PARSING_END;
						return TRUE;
					}
					if (0 != size && ptls_buf[data_read] == '-') {
				/* mime block now is used to save the last unterminated line */ 
						memcpy(pcontext->block_info.block_mime, ptls_buf + 
								 data_read, size);
						pcontext->block_info.block_mime_len = size;
						stream_backward_writing_ptr(&pcontext->stream, size);
					} else {
						pcontext->block_info.block_mime_len = 0;
					}
					if (0 == pcontext->block_info.last_block_ID) {
						pcontext->block_info.last_block_ID =
							smtp_parser_get_block_ID();
						pcontext->block_info.block_body_len= 0;
						anti_spamming_inform_filters(
							pcontext->block_info.block_type,
							pcontext, ACTION_BLOCK_NEW,
							pcontext->block_info.last_block_ID);
					}
					/* 
					 * append the size because the size has not been added in 
					 * the above while loop 
					 */
					if (0 != size && ptls_buf[data_read] != '-') {
						data_read    += size;
					} 
					if (ENCODING_BASE64 == pcontext->block_info.encode_type) {
						
						pcontext->block_info.remains_len = data_read % 4;
						parsed_len = data_read -
									 pcontext->block_info.remains_len;

						if (pcontext->block_info.remains_len > 0) {
							memcpy(pcontext->block_info.remains_encode,
								ptls_buf + parsed_len,
								pcontext->block_info.remains_len);
						}
						pass_mail_block.original_length = parsed_len;
						if (0 != decode64(ptls_buf, parsed_len, parsed_buf,
								&parsed_len)) {
							pass_mail_block.is_parsed = FALSE;
						} else {
							pass_mail_block.is_parsed = TRUE;
						}
					} else if (ENCODING_QUOTED_PRINTABLE == 
						pcontext->block_info.encode_type) {
						parsed_len = qp_decode(parsed_buf, ptls_buf, data_read);
						pass_mail_block.original_length  = data_read;
						pass_mail_block.is_parsed        = TRUE;
					} else {
						pass_mail_block.is_parsed        = FALSE;
						pass_mail_block.original_length  = data_read;
						parsed_len                       = 0;
					}

					pcontext->block_info.block_body_len += data_read;
					pass_mail_block.block_ID        = 
							pcontext->block_info.last_block_ID;
					pass_mail_block.fp_mime_info    = 
							&pcontext->block_info.f_last_blkmime;
					pass_mail_block.original_buff   = ptls_buf;
					pass_mail_block.parsed_buff     = parsed_buf;
					pass_mail_block.parsed_length   = parsed_len;

					filter_result = anti_spamming_pass_filters(
						pcontext->block_info.block_type,
						pcontext,
						&pass_mail_block,
						tmp_reason, sizeof(tmp_reason));

					if (MESSAGE_REJECT == filter_result ||
						MESSAGE_RETRYING == filter_result) {
						if (0 != pcontext->block_info.last_block_ID) {
							anti_spamming_inform_filters(
								pcontext->block_info.block_type,
								pcontext, ACTION_BLOCK_FREE,
								pcontext->block_info.last_block_ID);
						}
						goto REJECT_SPAM;
					} else {
						return TRUE;
					}
				 } else {
					if (PARSING_END == pcontext->block_info.state) {
						return TRUE;
					}
					continue;
				 }
			} else if (PARSING_NEST_MIME == pcontext->block_info.state) {
				while (TRUE) {
					size = MAX_LINE_LENGTH;
					line_result= stream_copyline(&pcontext->stream, temp_line,
								 &size);
					if (STREAM_COPY_OK != line_result &&
						STREAM_COPY_PART != line_result) {
						break;
					}
					if (0 != size) {
						if (temp_line[0] == '-' && temp_line[1] == '-'&&
							0 == strncmp(temp_line + 2,
							pcontext->block_info.cur_bndstr.bndstr,
							pcontext->block_info.cur_bndstr.bndstr_len)) {
							/* 
							 check if --boundstring-- is met, if it is 
							 continue to popup the boundary string from 
							 stack! else go to PARSING_BLOCK_HEAD
							*/
							if (temp_line[pcontext->block_info.
								cur_bndstr.bndstr_len + 2] != '-' ||
								temp_line[pcontext->block_info.
								cur_bndstr.bndstr_len + 3] != '-') {
								/* clear block mime information */
								pcontext->block_info.block_mime_len = 0;
								pcontext->block_info.block_type[0] = '\0';
								mem_file_clear(
									&pcontext->block_info.f_last_blkmime);
								/* end of clear block mime information */
								pcontext->block_info.last_block_ID = 0;
								pcontext->block_info.state = 
									PARSING_BLOCK_HEAD;
								break;
							} else {
								pbnd = (BOUNDARY_STRING*)vstack_get_top(
									   &pcontext->block_info.stack_bndstr);
								/* last --bndstr-- is met */
								if (NULL == pbnd) {
									pcontext->block_info.state = PARSING_END;
									return TRUE;
								} else {
									pcontext->block_info.cur_bndstr = *pbnd;
									vstack_pop(
										   &pcontext->block_info.stack_bndstr);
									continue;
								}
							}
						}
					}
				}
				if (STREAM_COPY_TERM == line_result ||
					STREAM_COPY_END == line_result) {
					if (TRUE == is_whole) {
						/* unfinished mail, make it pass */  
						pcontext->block_info.state = PARSING_END;
						return TRUE;
					}
					memcpy(pcontext->block_info.block_mime, temp_line, size);
					pcontext->block_info.block_mime_len = size;
					return TRUE;
				} else {
					continue;
				}
			} else {
				debug_info("[smtp_parser]: fatal error in "
							"smtp_parser_pass_auditor_filter\n");
			}
		}    
	}
MIME_ERROR:
	/* 451 Message doesn't conform to the EMIME standard. */
	smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2174013,1,&string_length);
	strncpy(reason, smtp_reply_str, length);
	return FALSE;
REJECT_SPAM:
	/* write reason from parsed buffer to user */
	if (MESSAGE_REJECT == filter_result) {
		smtp_parser_log_info(pcontext, 8, "illegal mail is cut! reason: %s", 
						 tmp_reason);
		snprintf(reason, length, "550 %s\r\n", tmp_reason);
	} else {
		smtp_parser_log_info(pcontext, 8, "dubious mail is cut! reason: %s", 
						 tmp_reason);
		snprintf(reason, length, "450 %s\r\n", tmp_reason);
	}
	return FALSE;
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
	int statistic_result;
	char tmp_reason[1024];

	pcontext->mail.body.mail_length = pcontext->total_length;
	statistic_result = anti_spamming_pass_statistics(pcontext, tmp_reason,1024);
	if (MESSAGE_REJECT == statistic_result) {
		/* write reason from parsed buffer to user */
		smtp_parser_log_info(pcontext, 8, "illegal mail is cut! reason: %s", 
							 tmp_reason);
		snprintf(reason, length, "550 %s\r\n", tmp_reason);
		return FALSE;
	} else if (MESSAGE_RETRYING == statistic_result) {
		/* write reason from parsed buffer to user */
		smtp_parser_log_info(pcontext, 8, "dubious mail is cut! reason: %s", 
							 tmp_reason);
		snprintf(reason, length, "450 %s\r\n", tmp_reason);
		return FALSE;
	}
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
	case SMTP_RUNNING_MODE:
		return g_mode;
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
	if (g_mode != SMTP_MODE_MIXTURE) {
		g_domainlist_valid = b_valid;
		return TRUE;
	} else {
		return FALSE;
	}
}

BOOL smtp_parser_domainlist_valid()
{
	if (SMTP_MODE_OUTBOUND == g_mode) {
		return TRUE;
	} else {
		return g_domainlist_valid;
	}
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
	if (NULL != system_services_auth_clear) {
		system_services_auth_clear(pcontext - 
		smtp_parser_get_contexts_list());
	}
}

/*
 *    smtp context's construct function
 *    @param
 *        pcontext [in]    indicate the smtp context object
 */
static void smtp_parser_context_init(SMTP_CONTEXT *pcontext)
{
	LIB_BUFFER *palloc_stream, *palloc_file, *palloc_bndstack;
	
	if (NULL == pcontext) {
		return;
	}
	palloc_stream = blocks_allocator_get_allocator();
	palloc_file = files_allocator_get_allocator();
	palloc_bndstack = bndstack_allocator_get_allocator();
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
	vstack_init(&pcontext->block_info.stack_bndstr, palloc_bndstack,
			   MAX_BOUNDARY_STRING_LENGTH, 8);
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
	vstack_clear(&pcontext->block_info.stack_bndstr);
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
	memset(&pcontext->block_info.cur_bndstr.bndstr, 0,
			MAX_BOUNDARY_STRING_LENGTH);
	pcontext->block_info.cur_bndstr.bndstr_len = 0;
	memset(&pcontext->mail.head.x_original_ip, 0, 16);
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
	vstack_free(&pcontext->block_info.stack_bndstr);
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
 *    record mime head field into mail body
 *    @param
 *        pcontext [in]    indicate the context object
 *        pfield [in]        indicate the mime field
 */
static void smtp_parser_record_mime_field(SMTP_CONTEXT *pcontext,
	MIME_FIELD *pfield)
{
	char *ptmp, *ptmp2;
	int len;
	
	switch (pfield->field_name_len) {
	case 2:
		if (0 == strncasecmp("To", pfield->field_name, 2)) {
			mem_file_write(&pcontext->mail.head.f_mime_to, pfield->field_value,
							pfield->field_value_len);
			mem_file_write(&pcontext->mail.head.f_mime_to, " ", 1);
			break;
		} else if (0 == strncasecmp("Cc", pfield->field_name, 2)) {
			mem_file_write(&pcontext->mail.head.f_mime_cc, pfield->field_value,
							pfield->field_value_len);
			mem_file_write(&pcontext->mail.head.f_mime_cc, " ", 1);
			break;
		}
		goto FIELD_DEFAULT;
	case 4:
		if (0 == strncasecmp("From", pfield->field_name, 4)) {
			mem_file_write(&pcontext->mail.head.f_mime_from, 
							pfield->field_value, pfield->field_value_len);        
			break;

		} else if (0 == strncasecmp("Date", pfield->field_name, 4)) {
			if (pfield->field_value_len < 63) {
				strncpy(pcontext->mail.head.compose_time, pfield->field_value, 
						pfield->field_value_len);
				break;
			}        
		}    
		goto FIELD_DEFAULT;
	case 7:
		if (0 == strncasecmp("Subject", pfield->field_name, 7)) {
			mem_file_write(&pcontext->mail.head.f_subject, pfield->field_value,
							pfield->field_value_len);        
			break;
		}
		goto FIELD_DEFAULT;
	case 8:
		if (0 == strncasecmp("X-Mailer", pfield->field_name, 8)) {
			mem_file_write(&pcontext->mail.head.f_xmailer, pfield->field_value,
							pfield->field_value_len);        
			break;
		}
		goto FIELD_DEFAULT;
	case 10:
		if (0 == strncasecmp("X-Priority", pfield->field_name, 10)) {
			pfield->field_value[pfield->field_value_len] = '\0';
			pcontext->mail.head.x_priority = atoi(pfield->field_value);
			break;
		} else if (0 == strncasecmp("User-Agent", pfield->field_name, 10)) {
			mem_file_write(&pcontext->mail.head.f_xmailer, pfield->field_value,
							pfield->field_value_len);        
			break;
		}
		goto FIELD_DEFAULT;
	case 12:
		if (0 == strncasecmp("Delivered-To", pfield->field_name, 12)) {
			mem_file_write(&pcontext->mail.head.f_mime_delivered_to,
							pfield->field_value, pfield->field_value_len);        
			break;
		} else if (0 == strncasecmp("Content-Type", pfield->field_name, 12)) {
			mem_file_write(&pcontext->mail.head.f_content_type,
							pfield->field_value, pfield->field_value_len);
			pfield->field_value[pfield->field_value_len] = '\0';
			ptmp = search_string(pfield->field_value, "boundary=",
				   pfield->field_value_len);
				   
			if (NULL != ptmp) {
				ptmp += 9;
				if('"' == ptmp[0] || '\'' == ptmp[0]) {
					ptmp ++;
				}
				if (0 == strncasecmp(pfield->field_value, "multipart/", 10)) {
					ptmp2 = strchr(ptmp, '"');
					if (NULL == ptmp2) {
						ptmp2 = strchr(ptmp, '\'');
					}
					if (NULL == ptmp2) {
						ptmp2 = strchr(ptmp, ';');
					}
					if (NULL == ptmp2) {
						len = strlen(ptmp);
					} else {
						len = (int)(ptmp2 - ptmp);
					}
					pcontext->block_info.cur_bndstr.bndstr_len = len;
					if (len < MAX_BOUNDARY_STRING_LENGTH) {
						memcpy(pcontext->block_info.cur_bndstr.bndstr, 
								ptmp, len);
						pcontext->block_info.cur_bndstr.bndstr[len] = '\0';
						pcontext->mail.head.mail_part = MULTI_PARTS_MAIL;
/*============================================================================*/
	/* for Encryption mail, there is no need to record boundary string */
						if (NULL != search_string(pfield->field_value, 
							"smime-type", pfield->field_value_len)) {
							pcontext->mail.head.mail_part = SINGLE_PART_MAIL;
						}
/*============================================================================*/
					}
				}
			}
			break;
		}
		goto FIELD_DEFAULT;
	case 16:
		if (0 == strncasecmp("X-Originating-IP", pfield->field_name, 16)) {
			pfield->field_value[pfield->field_value_len] = '\0';
			extract_ip(pfield->field_value, pcontext->mail.head.x_original_ip);
			break;
		}
		goto FIELD_DEFAULT;
	default:
		goto FIELD_DEFAULT;
	}
	return;
/* 
 * write the others field into mime file and the auditor plugins can  get the 
 * field that they want like those for filter plugins
 */
FIELD_DEFAULT:
	mem_file_write(&pcontext->mail.head.f_others,
		(char*)&pfield->field_name_len, sizeof(pfield->field_name_len));
	mem_file_write(&pcontext->mail.head.f_others, pfield->field_name, 
		pfield->field_name_len);
	mem_file_write(&pcontext->mail.head.f_others, 
		(char*)&pfield->field_value_len, sizeof(pfield->field_value_len));
	mem_file_write(&pcontext->mail.head.f_others, pfield->field_value, 
		pfield->field_value_len);
}

/*
 *    parser the mime head of certain block and extract type information, save 
 *    other infomation in a memory file
 *    @param
 *        pcontext [in, out]    indicate the context object
 *        in_buff [in]        buffer contains block mime head 
 *        length                length of in_buff
 *    @return
 *        TYPE_FOUND                success to find type
 *        BOUNDARY_FOUND            find boundary string
 *        ERROR_FOUND                error, found nothing
 */
static int smtp_parser_parse_and_save_blkmime(SMTP_CONTEXT *pcontext,
	char *in_buff, int length)
{
	int current_offset = 0, parsed_length = 0;
	MIME_FIELD mime_field;
	BOOL type_found = FALSE;
	int i, type_length, len;
	char *ptmp, *ptmp2;

	pcontext->block_info.encode_type = ENCODING_UNKNOWN;
	while (current_offset < length) {
		parsed_length = parse_mime_field(in_buff + current_offset,
						length - current_offset, &mime_field);
		/* if a empty line is meet, end of mail head parse */
		if (0 == parsed_length) {
			break;
		}

		/* check if mime head is over */
		mem_file_write(&pcontext->block_info.f_last_blkmime, 
						(char*)&mime_field.field_name_len,
						sizeof(mime_field.field_name_len));
		mem_file_write(&pcontext->block_info.f_last_blkmime,
						mime_field.field_name,
						mime_field.field_name_len);
		mem_file_write(&pcontext->block_info.f_last_blkmime,
					   (char*)&mime_field.field_value_len,
					   sizeof(mime_field.field_value_len));
		mem_file_write(&pcontext->block_info.f_last_blkmime,
						mime_field.field_value,
						mime_field.field_value_len);
		if (12 == mime_field.field_name_len &&
			0 == strncasecmp("Content-Type", mime_field.field_name, 12)) {
			/* 
			 * find if boundy string is contained in! if yes, that means parser
			 * is going to a nested block, and the new boundary string will be
			 * treated as the current boundary and the old one will be pushed 
			 * into boundary strings stack.
			 */
			mime_field.field_value[mime_field.field_value_len] = '\0';
			ptmp = search_string(mime_field.field_value, "boundary=",
					mime_field.field_value_len);
			if (NULL != ptmp) {
				ptmp += 9;
				if ('"' == ptmp[0] || '\'' == ptmp[0]) {
					ptmp ++;
				}
				if (0 == strncasecmp(mime_field.field_value, "multipart/", 10)) {
					ptmp2 = strchr(ptmp, '"');
					if (NULL == ptmp2) {
						ptmp2 = strchr(ptmp, '\'');
					}
					if (NULL == ptmp2) {
						ptmp2 = strchr(ptmp, ';');
					}
					if (NULL == ptmp2) {
						len = strlen(ptmp);
					} else {
						len = (int)(ptmp2 - ptmp);
					}
					if (len < MAX_BOUNDARY_STRING_LENGTH) {
						/* save the old boundary string in the stack */ 
						vstack_push(&pcontext->block_info.stack_bndstr,
								  &pcontext->block_info.cur_bndstr);
						memcpy(pcontext->block_info.cur_bndstr.bndstr,ptmp,len);
						pcontext->block_info.cur_bndstr.bndstr[len] = '\0';
						pcontext->block_info.cur_bndstr.bndstr_len = len;
						return BOUNDARY_FOUND;
					} else {
						smtp_parser_log_info(pcontext, 0, 
							"boundary string too long");
						return ERROR_FOUND;
					}
				}
			}
			for (i=0; i< mime_field.field_value_len; i++) {
				if(mime_field.field_value[i] == ';') {
					break;
				}
			}
			if (mime_field.field_value[i] == ';' && 
				i != mime_field.field_value_len && i < 256) {
				type_length = i;
			} else {
				if (i > 255) {
					i = 255;
				}
				type_length = i;
			}
			type_found = TRUE;
			memcpy(pcontext->block_info.block_type, 
					mime_field.field_value, type_length);
			pcontext->block_info.block_type[type_length] = '\0';
		} else if (25 == mime_field.field_name_len && 
			0 == strncasecmp(mime_field.field_name, 
			"Content-Transfer-Encoding", 25)) {
			if (6 == mime_field.field_value_len &&
				0 == strncasecmp(mime_field.field_value, "base64", 6)) {
				pcontext->block_info.encode_type    = ENCODING_BASE64;

			} else if (4 == mime_field.field_value_len &&
				0 == strncasecmp(mime_field.field_value, "7bit", 4)) {
				pcontext->block_info.encode_type    = ENCODING_7BIT;

			} else if (4 == mime_field.field_value_len &&
				0 == strncasecmp(mime_field.field_value, "8bit", 4)) {
				pcontext->block_info.encode_type    = ENCODING_8BIT;

			} else if (16 == mime_field.field_value_len &&
				0 == strncasecmp(mime_field.field_value, 
				"quoted-printable", 16)) {
				pcontext->block_info.encode_type    = ENCODING_QUOTED_PRINTABLE;
			} else {
				pcontext->block_info.encode_type    = ENCODING_UNKNOWN;
			}
		}
		current_offset += parsed_length;
	}
	/* 
	 append manually the content type "text/plain" for some old unix style mail
	 and encoding type is 8bit
	*/
	if (FALSE == type_found) {
		mime_field.field_name_len = 12;
		memcpy(mime_field.field_name, "Content-Type", 12);
		mime_field.field_value_len = 10;
		memcpy(mime_field.field_value, "text/plain", 10);
		mem_file_write(&pcontext->block_info.f_last_blkmime,
						(char*)&mime_field.field_name_len,
						sizeof(mime_field.field_name_len));
		mem_file_write(&pcontext->block_info.f_last_blkmime,
						mime_field.field_name,
						mime_field.field_name_len);
		mem_file_write(&pcontext->block_info.f_last_blkmime,
						(char*)&mime_field.field_value_len,
						sizeof(mime_field.field_value_len));
		mem_file_write(&pcontext->block_info.f_last_blkmime,
						mime_field.field_value,
						mime_field.field_value_len);
		mime_field.field_name_len = 25;
		memcpy(mime_field.field_name, "Content-Transfer-Encoding", 25);
		mime_field.field_value_len = 4;
		memcpy(mime_field.field_value, "8bit", 4);
		mem_file_write(&pcontext->block_info.f_last_blkmime,
						(char*)&mime_field.field_name_len,
						sizeof(mime_field.field_name_len));
		mem_file_write(&pcontext->block_info.f_last_blkmime,
						mime_field.field_name,
						mime_field.field_name_len);
		mem_file_write(&pcontext->block_info.f_last_blkmime,
						(char*)&mime_field.field_value_len,
						sizeof(mime_field.field_value_len));
		mem_file_write(&pcontext->block_info.f_last_blkmime,
						mime_field.field_value,
						mime_field.field_value_len);
		strcpy(pcontext->block_info.block_type, "text/plain");
		type_found = TRUE;
	}
	/* end of append the old unix style mail */

	return (TRUE == type_found)?TYPE_FOUND:ERROR_FOUND;
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
	
	switch (g_mode) {
	case SMTP_MODE_OUTBOUND:
		system_services_log_info(level, "user: %s, IP: %s, TO: %s %s", 
				pcontext->mail.envelop.username, 
				pcontext->connection.client_ip, rcpt_buff, log_buf);
		break;
	case SMTP_MODE_INBOUND:
		system_services_log_info(level,"remote MTA IP: %s, FROM: %s, TO: %s %s",
				pcontext->connection.client_ip,
				pcontext->mail.envelop.from, rcpt_buff, log_buf);
		break;
	case SMTP_MODE_MIXTURE:
		if (TRUE == pcontext->mail.envelop.is_outbound) {
			system_services_log_info(level, "user: %s, IP: %s, FROM: %s, TO: %s %s",
				pcontext->mail.envelop.username,
				pcontext->connection.client_ip,
				pcontext->mail.envelop.from,    
				rcpt_buff, log_buf);
		} else {
			system_services_log_info(level,"remote MTA IP: %s, FROM: %s, TO: %s %s",
				pcontext->connection.client_ip,
				pcontext->mail.envelop.from, rcpt_buff, log_buf);
		}
		break;
	}
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

BOOL smtp_parser_set_extra_value(SMTP_CONTEXT *pcontext, char* tag, char* pval)
{
	int i, index;
	BOOL b_found;
	
	if (NULL == tag || NULL == pval) {
		return FALSE;
	}
	if (pcontext->ext_data.cur_pos >= MAX_EXTRA_DATA_INDEX) {
		return FALSE;
	}
	if (strlen(tag) > MAX_EXTRA_DATA_TAGLEN - 1 ||
		strlen(pval) > MAX_EXTRA_DATA_DATALEN - 1) {
		return FALSE;
	}
	index = pcontext->ext_data.cur_pos;
	b_found = FALSE;
	for (i=0; i<pcontext->ext_data.cur_pos; i++) {
		if (0 == strcasecmp(tag, pcontext->ext_data.ext_tag[i])) {
			index = i;
			b_found = TRUE;
		}
	}
	if (TRUE == b_found) {
		strcpy(pcontext->ext_data.ext_data[index], pval);
	} else {
		strcpy(pcontext->ext_data.ext_data[index], pval);
		strcpy(pcontext->ext_data.ext_tag[index], tag);
		pcontext->ext_data.cur_pos++;
	}
	return TRUE;
}
