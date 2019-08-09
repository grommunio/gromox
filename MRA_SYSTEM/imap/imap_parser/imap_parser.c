/* imap parser is a module, which first read data from socket, parses the imap 
 * commands and then do the corresponding action. 
 */ 
 
#include "util.h"
#include "mjson.h"
#include "str_hash.h"
#include "dir_tree.h"
#include "resource.h"
#include "mime_pool.h"
#include "mail_func.h"
#include "lib_buffer.h"
#include "imap_parser.h"
#include "threads_pool.h"
#include "imap_cmd_parser.h"
#include "system_services.h"
#include "blocks_allocator.h"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/err.h>

#define CALCULATE_INTERVAL(a, b) \
    (((a).tv_usec >= (b).tv_usec) ? ((a).tv_sec - (b).tv_sec) : \
    ((a).tv_sec - (b).tv_sec - 1))


#define SLEEP_BEFORE_CLOSE		usleep(1000)

#define FILENUM_PER_MIME		8

#define SCAN_INTERVAL			3600

#define SELECT_INTERVAL			20*60


static void* thread_work_func(void *argp);

static void* scan_work_func(void *argp);

static void imap_parser_event_proc(char *event);

static void imap_parser_event_touch(char *username, char *folder);

static void imap_parser_event_flag(const char *username, const char *folder,
	const char *mid_string);

static int imap_parser_dispatch_cmd(int argc, char **argv, IMAP_CONTEXT *pcontext);

static void imap_parser_context_init(IMAP_CONTEXT *pcontext);

static void imap_parser_context_clear(IMAP_CONTEXT *pcontext);

static void imap_parser_context_free(IMAP_CONTEXT *pcontext);

static void imap_parser_ssl_locking(int mode, int n, const char * file, int line);

static void imap_parser_ssl_id(CRYPTO_THREADID* id);

static int g_squence_ID;
static int g_context_num;
static int g_average_num;
static size_t g_cache_size;
static unsigned int g_timeout;
static unsigned int g_autologout_time;
static int g_max_auth_times;
static int g_block_auth_fail;
static int g_ssl_port;
static pthread_t g_thr_id;
static pthread_t g_scan_id;
static BOOL g_notify_stop;
static IMAP_CONTEXT *g_context_list;
static LIB_BUFFER *g_alloc_file;
static LIB_BUFFER *g_alloc_mjson;
static LIB_BUFFER *g_alloc_xarray;
static LIB_BUFFER *g_alloc_dir;
static MIME_POOL *g_mime_pool;
static STR_HASH_TABLE *g_select_hash;
static pthread_mutex_t g_hash_lock;
static DOUBLE_LIST g_sleeping_list;
static pthread_mutex_t g_list_lock;
static pthread_mutex_t g_squence_lock;
static BOOL g_support_starttls;
static BOOL g_force_starttls;
static char g_certificate_path[256];
static char g_private_key_path[256];
static char g_certificate_passwd[1024];
static SSL_CTX *g_ssl_ctx;
static pthread_mutex_t *g_ssl_mutex_buf;


LIB_BUFFER* imap_parser_get_xpool()
{
	return g_alloc_xarray;
}

LIB_BUFFER* imap_parser_get_dpool()
{
	return g_alloc_dir;
}

void imap_parser_init(int context_num, int average_num, size_t cache_size,
	unsigned int timeout, unsigned int autologout_time, int max_auth_times,
	int block_auth_fail, BOOL support_starttls, BOOL force_starttls,
	const char *certificate_path, const char *cb_passwd, const char *key_path)
{
    g_context_num           = context_num;
	g_average_num           = average_num;
	g_cache_size            = cache_size;
    g_timeout               = timeout;
	g_autologout_time       = autologout_time;
	g_max_auth_times        = max_auth_times;
	g_block_auth_fail       = block_auth_fail;
	g_support_starttls      = support_starttls;
	g_ssl_mutex_buf         = NULL;
	g_notify_stop           = TRUE;
	pthread_mutex_init(&g_hash_lock, NULL);
	double_list_init(&g_sleeping_list);
	pthread_mutex_init(&g_list_lock, NULL);
	g_squence_ID = 0;
	pthread_mutex_init(&g_squence_lock, NULL);
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

/* 
 * run the imap parser module
 *    @return
 *         0    success
 *        <>0    fail    
 */
int imap_parser_run()
{
    int i, num;

	
	if (TRUE == g_support_starttls) {
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();
		g_ssl_ctx = SSL_CTX_new(SSLv23_server_method());
		if (NULL == g_ssl_ctx) {
			printf("[imap_parser]: fail to init ssl context\n");
			return -1;
		}
		
		if ('\0' != g_certificate_passwd[0]) {
			SSL_CTX_set_default_passwd_cb_userdata(g_ssl_ctx,
				g_certificate_passwd);
		}
		
		if (SSL_CTX_use_certificate_chain_file(g_ssl_ctx,
			g_certificate_path) <= 0) {
			printf("[imap_parser]: fail to use certificate file:");
			ERR_print_errors_fp(stdout);
			return -2;
		}
		
		if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, g_private_key_path,
			SSL_FILETYPE_PEM) <= 0) {
			printf("[imap_parser]: fail to use private key file:");
			ERR_print_errors_fp(stdout);
			return -3;
		}
		
		if (1 != SSL_CTX_check_private_key(g_ssl_ctx)) {
			printf("[imap_parser]: private key does not match certificate:");
			ERR_print_errors_fp(stdout);
			return -4;
		}

		g_ssl_mutex_buf = malloc(CRYPTO_num_locks()*sizeof(pthread_mutex_t));
		if (NULL == g_ssl_mutex_buf) {
			printf("[imap_parser]: fail to allocate ssl locking buffer\n");
			return -5;
		}
		
		for (i=0; i<CRYPTO_num_locks(); i++) {
			pthread_mutex_init(&g_ssl_mutex_buf[i], NULL);
		}
		CRYPTO_THREADID_set_callback(imap_parser_ssl_id);
		CRYPTO_set_locking_callback(imap_parser_ssl_locking);
	}

	g_select_hash = str_hash_init(g_context_num + 1, sizeof(DOUBLE_LIST), NULL);
	if (NULL == g_select_hash) {
		printf("[imap_parser]: fail to init select hash table\n");
		return -4;
	}
	
	num = 1024*g_context_num;
	if (num < 1024*1024) {
		num = 1024*1024;
	}
	g_alloc_file = lib_buffer_init(FILE_ALLOC_SIZE, num, TRUE);
	if (NULL == g_alloc_file) {
		printf("[imap_parser]: fail to init mem file allocator\n");
		return -5;
	}
	
	num = 4*g_context_num;
	if (num < 200) {
		num = 200;
	}

	if (num > 800) {
		num = 800;
	}
	g_mime_pool = mime_pool_init(num, FILENUM_PER_MIME, TRUE);
	if (NULL == g_mime_pool) {
		printf("[imap_parser]: fail to init mime pool\n");
		return -6;
	}
	
	g_alloc_xarray = xarray_allocator_init(sizeof(MITEM), g_average_num*g_context_num, TRUE);
	if (NULL == g_alloc_xarray) {
		printf("[imap_parser]: fail to init mem file allocator\n");
		return -7;
	}
	
	num = 10*g_context_num;
	if (num < 1000) {
		num = 1000;
	}
	g_alloc_dir = dir_tree_allocator_init(num, TRUE);
	if (NULL == g_alloc_dir) {
		printf("[imap_parser]: fail to init dir node allocator\n");
		return -8;
	}
	
	num = 4*g_context_num;
	if (num < 400) {
		num = 400;
	}
	g_alloc_mjson = mjson_allocator_init(num, TRUE);
	if (NULL == g_alloc_mjson) {
		printf("[imap_parser]: fail to init mjson allocator\n");
		return -9;
	}
	
    g_context_list = malloc(sizeof(IMAP_CONTEXT)*g_context_num);
    if (NULL== g_context_list) {
        printf("[imap_parser]: fail to allocate imap contexts\n");
        return -10;
    }
    for (i=0; i<g_context_num; i++) {
        imap_parser_context_init(g_context_list + i);
    }
	if (FALSE == resource_get_integer(RES_LISTEN_SSL_PORT, &g_ssl_port)) {
		g_ssl_port = 0;
	}
	
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_thr_id, NULL, thread_work_func, NULL)) {
		printf("[imap_parser]: fail to create sleeping list scanning thread\n");
		g_notify_stop = TRUE;
		return -11;
	}
	
	if (0 != pthread_create(&g_scan_id, NULL, scan_work_func, NULL)) {
		printf("[imap_parser]: fail to create select hash scanning thread\n");
		g_notify_stop = TRUE;
		pthread_join(g_thr_id, NULL);
		return -12;
	}
	system_services_install_event_stub(imap_parser_event_proc);
    return 0;
}

/* 
 * stop the imap parser module
 * @return
 *          0  success
 *         <>0 fail
 */
int imap_parser_stop()
{
	int i;

	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thr_id, NULL);
		pthread_join(g_scan_id, NULL);
	}
	
	
	if (NULL != g_context_list) {
       for (i=0; i<g_context_num; i++) {
            imap_parser_context_free(g_context_list + i);
        }
        free(g_context_list);
        g_context_list = NULL;        
    }

	if (NULL != g_alloc_file) {
		lib_buffer_free(g_alloc_file);
		g_alloc_file = NULL;
	}
	
	if (NULL != g_mime_pool) {
		mime_pool_free(g_mime_pool);
		g_mime_pool = NULL;
	}
	
	if (NULL != g_alloc_xarray) {
		lib_buffer_free(g_alloc_xarray);
		g_alloc_xarray = NULL;
	}
	
	if (NULL != g_alloc_dir) {
		lib_buffer_free(g_alloc_dir);
		g_alloc_dir = NULL;
	}
	
	if (NULL != g_alloc_mjson) {
		lib_buffer_free(g_alloc_mjson);
		g_alloc_mjson = NULL;
	}

	if (NULL != g_select_hash) {
		str_hash_free(g_select_hash);
		g_select_hash = NULL;
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
 * imap parser's destruct function 
 */
void imap_parser_free()
{
    pthread_mutex_destroy(&g_hash_lock);
	double_list_free(&g_sleeping_list);
	pthread_mutex_destroy(&g_list_lock);
	pthread_mutex_destroy(&g_squence_lock);
    g_context_num		= 0;
	g_cache_size	    = 0;
	g_autologout_time   = 0;
    g_timeout           = 0x7FFFFFFF;
	g_block_auth_fail   = 0;
}

int imap_parser_get_context_socket(IMAP_CONTEXT *pcontext)
{
	return pcontext->connection.sockd;
}

struct timeval imap_parser_get_context_timestamp(IMAP_CONTEXT *pcontext)
{
	return pcontext->connection.last_timestamp;
}

int imap_parser_threads_event_proc(int action)
{
    return 0;
}

int imap_parser_process(IMAP_CONTEXT *pcontext)
{
	int err;
	int argc;
	int exists;
	int recent;
    int i, len;
	int read_len;
	int temp_len;
	int ssl_errno;
	int written_len;
	int copy_result;
	size_t total_len;
	int string_length;
	const char *host_ID;
    char *imap_reply_str;
    char *imap_reply_str2;
	char* argv[128];
	char temp_path[256];
	char temp_buff[4096];
	char reply_buff[1024];
	char *ptr, *ptr1, *pbuff;
    struct timeval current_time;
	
CONTEXT_PROCESSING:
	if (SCHED_STAT_AUTOLOGOUT == pcontext->sched_stat) {
		imap_parser_log_info(pcontext, 8, "auto logout");
		/* IMAP_CODE_2160004: BYE Disconnected by autologout */
		imap_reply_str = resource_get_imap_code(IMAP_CODE_2160004, 1, &string_length);
		goto END_PROCESSING;
	} else if (SCHED_STAT_DISCINNECTED == pcontext->sched_stat) {
		imap_parser_log_info(pcontext, 8, "connection lost");
		imap_reply_str = NULL;
		goto END_PROCESSING;
	} else if (SCHED_STAT_STLS == pcontext->sched_stat) {
		if (NULL == pcontext->connection.ssl) {
			pcontext->connection.ssl = SSL_new(g_ssl_ctx);
			if (NULL == pcontext->connection.ssl) {
				/* IMAP_CODE_2180014: BAD internal error: fail to init SSL object */
				imap_reply_str = resource_get_imap_code(IMAP_CODE_2180014, 1, &string_length);
				write(pcontext->connection.sockd, imap_reply_str, string_length);
				imap_parser_log_info(pcontext, 8, "out of SSL object");
				SLEEP_BEFORE_CLOSE;
				close(pcontext->connection.sockd);
				system_services_container_remove_ip(
					pcontext->connection.client_ip);
				imap_parser_context_clear(pcontext);
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
				/* IMAP_CODE_2180011: BAD time out */
				imap_reply_str = resource_get_imap_code(IMAP_CODE_2180011, 1, &string_length);
				len = snprintf(reply_buff, 1024, "* %s", imap_reply_str);
				write(pcontext->connection.sockd, reply_buff, len);
				imap_parser_log_info(pcontext, 0, "time out");
				SLEEP_BEFORE_CLOSE;
			}
			SSL_free(pcontext->connection.ssl);
			pcontext->connection.ssl = NULL;
			close(pcontext->connection.sockd);
			system_services_container_remove_ip(
				pcontext->connection.client_ip);
			imap_parser_context_clear(pcontext);
			return PROCESS_CLOSE;
		} else {
			pcontext->sched_stat = SCHED_STAT_RDCMD;
			if (pcontext->connection.server_port == g_ssl_port) {
				/* IMAP_CODE_2170000: OK <domain> Service ready */
				imap_reply_str = resource_get_imap_code(IMAP_CODE_2170000, 1, &string_length);
				imap_reply_str2 = resource_get_imap_code(IMAP_CODE_2170000, 2, &string_length);
				host_ID = resource_get_string(RES_HOST_ID);
				len = sprintf(reply_buff, "* %s%s%s",
					imap_reply_str, host_ID, imap_reply_str2);
				SSL_write(pcontext->connection.ssl, reply_buff, len);
			}
			return PROCESS_CONTINUE;
		}
	} else if (SCHED_STAT_NOTIFYING == pcontext->sched_stat) {
		if (MIDB_RESULT_OK == system_services_summary_folder(pcontext->maildir,
			pcontext->selected_folder, &exists, &recent, NULL, NULL, NULL, NULL, &err)) {
			len = snprintf(temp_buff,  sizeof(temp_buff),
							"* %d RECENT\r\n"
							"* %d EXISTS\r\n",
							recent, exists);
			if (NULL != pcontext->connection.ssl) {
				SSL_write(pcontext->connection.ssl, temp_buff, len);
			} else {
				write(pcontext->connection.sockd, temp_buff, len);
			}
		}
		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_sleeping_list, &pcontext->sleeping_node);
		pcontext->sched_stat = SCHED_STAT_IDLING;
		pthread_mutex_unlock(&g_list_lock);
		return PROCESS_SLEEPING;
	} else if (SCHED_STAT_RDCMD == pcontext->sched_stat ||
		SCHED_STAT_APPENDED == pcontext->sched_stat ||
		SCHED_STAT_IDLING == pcontext->sched_stat) {
		if (NULL != pcontext->connection.ssl) {
			read_len = SSL_read(pcontext->connection.ssl, pcontext->read_buffer +
						pcontext->read_offset, 64*1024 - pcontext->read_offset);
		} else {
			read_len = read(pcontext->connection.sockd, pcontext->read_buffer +
						pcontext->read_offset, 64*1024 - pcontext->read_offset);
		}
		gettimeofday(&current_time, NULL);
		if (0 == read_len) {
			imap_parser_log_info(pcontext, 8, "connection lost");
			imap_reply_str = NULL;
			goto END_PROCESSING;
		} else if (read_len < 0) {
			if (EAGAIN != errno) {
				imap_parser_log_info(pcontext, 8, "connection lost");
				imap_reply_str = NULL;
				goto END_PROCESSING;
			}
			/* check if context is timed out */
			if (CALCULATE_INTERVAL(current_time,
				pcontext->connection.last_timestamp) >= g_timeout) {
				if (pcontext->proto_stat >= PROTO_STAT_AUTH) {
					pthread_mutex_lock(&g_list_lock);
					double_list_append_as_tail(&g_sleeping_list, &pcontext->sleeping_node);
					pthread_mutex_unlock(&g_list_lock);
					return PROCESS_SLEEPING;
				} else {
					/* IMAP_CODE_2180011: BAD time out */
					imap_reply_str = resource_get_imap_code(IMAP_CODE_2180011, 1, &string_length);
					goto END_PROCESSING;
				}
			} else {
				return PROCESS_POLLING_RDONLY;
			}
		}
	
		pcontext->connection.last_timestamp = current_time;	
		pcontext->read_offset += read_len;

		if (SCHED_STAT_APPENDED == pcontext->sched_stat ||
			SCHED_STAT_IDLING == pcontext->sched_stat) {
			goto CMD_PROCESSING;
		}
		
LITERAL_CHECKING:		
		if (NULL != pcontext->literal_ptr) {
			if (pcontext->read_buffer + pcontext->read_offset - pcontext->literal_ptr >= 
				pcontext->literal_len) {
				temp_len = pcontext->literal_ptr + pcontext->literal_len - pcontext->read_buffer;
				if (temp_len <=0 || temp_len >= 64*1024 ||
					pcontext->command_len + temp_len >= 64*1024) {
					/* IMAP_CODE_2180017: BAD literal size too large */
					imap_reply_str = resource_get_imap_code(IMAP_CODE_2180017, 1, &string_length);
					goto END_PROCESSING;
				}
				memcpy(pcontext->command_buffer + pcontext->command_len, pcontext->read_buffer,
					temp_len);
				pcontext->command_len += temp_len;
				pcontext->read_offset -= temp_len;
				if (pcontext->read_offset > 0 && pcontext->read_offset < 64*1024) {
					memmove(pcontext->read_buffer, pcontext->literal_ptr + pcontext->literal_len,
						pcontext->read_offset);
				} else {
					pcontext->read_offset = 0;	
				}
				pcontext->literal_ptr = NULL;
				pcontext->literal_len = 0;
			} else {
				return PROCESS_CONTINUE;
			}
		}
LITERAL_PROCESSING:
		for (i=0; i<pcontext->read_offset-3; i++) {
			if ('{' == pcontext->read_buffer[i] && NULL != (ptr = memchr(pcontext->read_buffer + i,
				'}', pcontext->read_offset - 2 - i)) && '\r' == ptr[1] && '\n' == ptr[2]) {
				if (ptr - pcontext->read_buffer - i > 16) {
					/* IMAP_CODE_2180017: BAD literal size too large */
					imap_reply_str = resource_get_imap_code(IMAP_CODE_2180017, 1, &string_length);
					goto END_PROCESSING;
				}
				
				pcontext->literal_ptr = ptr;
				temp_len = ptr - pcontext->read_buffer - i - 1;
				memcpy(temp_buff, pcontext->read_buffer + i + 1, temp_len);
				temp_buff[temp_len] = '\0';
				pcontext->literal_len = atoi(temp_buff);
				temp_len = 64*1024 - (ptr + 3 - pcontext->read_buffer) -
							pcontext->command_len - 2;
				if (temp_len <= 0 || temp_len >= 64*1024) {
					imap_parser_log_info(pcontext, 8, "fatal error in command buffer length");
					/* IMAP_CODE_2180017: BAD literal size too large */
					imap_reply_str = resource_get_imap_code(IMAP_CODE_2180017, 1, &string_length);
					goto END_PROCESSING;
				}
				if (pcontext->literal_len >= temp_len) {
					
					memcpy(pcontext->command_buffer + pcontext->command_len,
						pcontext->read_buffer, i);
					pcontext->command_len += i;
					argc = parse_imap_args(pcontext->command_buffer, pcontext->command_len,
							argv, sizeof(argv)/sizeof(char*));
					if (argc >= 4 && 0 == strcasecmp(argv[1], "APPEND")) {
						switch (imap_cmd_parser_append_begin(argc, argv, pcontext)) {
						case DISPATCH_CONTINUE:
							pcontext->current_len = pcontext->read_buffer + pcontext->read_offset - (ptr + 3);
							if (pcontext->current_len < 0) {
								imap_parser_log_info(pcontext, 8, "fatal error in read buffer length");
								/* IMAP_CODE_2180017: BAD literal size too large */
								imap_reply_str = resource_get_imap_code(IMAP_CODE_2180017, 1, &string_length);
								goto END_PROCESSING;
							} else {
								stream_write(&pcontext->stream, ptr + 3,  pcontext->current_len);
							}
							pcontext->sched_stat = SCHED_STAT_APPENDING;
							pcontext->read_offset = 0;
							pcontext->command_len = 0;
							/* IMAP_CODE_2160003 + Ready for additional command text */
							imap_reply_str = resource_get_imap_code(IMAP_CODE_2160003, 1, &string_length);
							if (NULL != pcontext->connection.ssl) {
								SSL_write(pcontext->connection.ssl, imap_reply_str, string_length);
							} else {
								write(pcontext->connection.sockd, imap_reply_str, string_length);
							}
							return PROCESS_CONTINUE;
						case DISPATCH_SHOULD_CLOSE:
							imap_reply_str = NULL;
							goto END_PROCESSING;
						case DISPATCH_BREAK:
							pcontext->read_offset -= ptr + 3 - pcontext->read_buffer;
							if (pcontext->read_offset > 0 && pcontext->read_offset < 64*1024) {
								memmove(pcontext->read_buffer, ptr + 3, pcontext->read_offset);
							} else {
								pcontext->read_offset = 0;
							}
							pcontext->literal_ptr = NULL;
							pcontext->literal_len = 0;
							pcontext->command_len = 0;
							goto LITERAL_PROCESSING;
						}
					}
					
					/* IMAP_CODE_2180017: BAD literal size too large */
					imap_reply_str = resource_get_imap_code(IMAP_CODE_2180017, 1, &string_length);
					len = snprintf(reply_buff, 1024, "* %s", imap_reply_str);
					if (NULL != pcontext->connection.ssl) {
						SSL_write(pcontext->connection.ssl, reply_buff, len);
					} else {
						write(pcontext->connection.sockd, reply_buff, len);
					}
					pcontext->read_offset -= (ptr + 3 - pcontext->read_buffer);
					if (pcontext->read_offset > 0 && pcontext->read_offset < 64*1024) {
						memmove(pcontext->read_buffer, ptr + 3, pcontext->read_offset);
					} else {
						pcontext->read_offset = 0;
					}
					pcontext->literal_ptr = NULL;
					pcontext->literal_len = 0;
					pcontext->command_len = 0;
					goto LITERAL_PROCESSING;
				}
				pcontext->read_offset -= 2;
				temp_len = pcontext->read_offset - (ptr + 1 - pcontext->read_buffer);
				if (temp_len > 0 && temp_len < 64*1024) {
					memmove(ptr + 1, ptr + 3, temp_len);
				}
				/* IMAP_CODE_2160003: + ready for additional command text */
				imap_reply_str = resource_get_imap_code(IMAP_CODE_2160003, 1, &string_length);
				if (NULL != pcontext->connection.ssl) {
					SSL_write(pcontext->connection.ssl, imap_reply_str, string_length);
				} else {
					write(pcontext->connection.sockd, imap_reply_str, string_length);
				}
				goto LITERAL_CHECKING;
			}
		}
CMD_PROCESSING:
		for (i=0; i<pcontext->read_offset-1; i++) {
			if ('\r' == pcontext->read_buffer[i] &&
				'\n' == pcontext->read_buffer[i + 1]) {
				if (i >= 64*1024 || pcontext->command_len + i >= 64*1024) {
					imap_parser_log_info(pcontext, 8, "fatal error in command buffer length");
					/* IMAP_CODE_2180017: BAD literal size too large */
					imap_reply_str = resource_get_imap_code(IMAP_CODE_2180017, 1, &string_length);
					goto END_PROCESSING;
				}
				memcpy(pcontext->command_buffer + pcontext->command_len,
						pcontext->read_buffer, i);
				pcontext->command_len += i;
				pcontext->command_buffer[pcontext->command_len] = '\0';
				pcontext->read_offset -= i + 2;
				if (pcontext->read_offset > 0 && pcontext->read_offset < 64*1024) {
					memmove(pcontext->read_buffer, pcontext->read_buffer + i + 2,
						pcontext->read_offset);
				} else {
					pcontext->read_offset = 0;
				}
					
				if (PROTO_STAT_USERNAME == pcontext->proto_stat) {
					argv[0] = pcontext->command_buffer;
					argv[1] = NULL;
					imap_cmd_parser_username(1, argv, pcontext);
					pcontext->command_len = 0;
					goto LITERAL_PROCESSING;
				} else if (PROTO_STAT_PASSWORD == pcontext->proto_stat) {
					argv[0] = pcontext->command_buffer;
					argv[1] = NULL;
					if (DISPATCH_SHOULD_CLOSE == imap_cmd_parser_password(
						1, argv, pcontext)) {
						imap_reply_str = NULL;
						goto END_PROCESSING;
					} else {
						pcontext->command_len = 0;
						goto LITERAL_PROCESSING;
					}
				}
				
				argc = parse_imap_args(pcontext->command_buffer,
					pcontext->command_len, argv, sizeof(argv)/sizeof(char*));
				
				if (SCHED_STAT_APPENDED == pcontext->sched_stat) {
					if (0 != argc) {
						if (-1 != pcontext->message_fd) {
							close(pcontext->message_fd);
							pcontext->message_fd = -1;
						}
						if ('\0' != pcontext->file_path[0]) {
							remove(pcontext->file_path);
							pcontext->file_path[0] = '\0';
						}
						/*IMAP_CODE_2180000: BAD command not support or parameter error */
						imap_reply_str = resource_get_imap_code(IMAP_CODE_2180000, 1,
											&string_length);
						string_length = snprintf(reply_buff, 1024, "%s %s",
											pcontext->tag_string, imap_reply_str);
						if (NULL != pcontext->connection.ssl) {
							SSL_write(pcontext->connection.ssl, reply_buff, string_length);
						} else {
							write(pcontext->connection.sockd, reply_buff, string_length);
						}
					} else {
						imap_cmd_parser_append_end(argc, argv, pcontext);
					}
					pcontext->sched_stat = SCHED_STAT_RDCMD;
					pcontext->literal_ptr = NULL;
					pcontext->literal_len = 0;
					pcontext->command_len = 0;
					goto LITERAL_PROCESSING;
				}
				
				if (SCHED_STAT_IDLING == pcontext->sched_stat) {
					if (1 != argc || 0 != strcasecmp(argv[0], "DONE")) {
						/* IMAP_CODE_2180018: BAD expected DONE */
						imap_reply_str = resource_get_imap_code(IMAP_CODE_2180018, 1,
											&string_length);
						
					} else {
						pcontext->sched_stat = SCHED_STAT_RDCMD;
						/* IMAP_CODE_2170027: OK IDLE completed */
						imap_reply_str = resource_get_imap_code(IMAP_CODE_2170027, 1,
											&string_length);
					}
					string_length = snprintf(reply_buff, 1024, "%s %s",
								pcontext->tag_string, imap_reply_str);
					if (NULL != pcontext->connection.ssl) {
						SSL_write(pcontext->connection.ssl, reply_buff, string_length);
					} else {
						write(pcontext->connection.sockd, reply_buff, string_length);
					}
					pcontext->command_len = 0;
					goto LITERAL_PROCESSING;
				}
				
				
				if (argc < 2 || strlen(argv[0]) >= 32) {
					/* IMAP_CODE_2180000: BAD command not support or parameter error */
					imap_reply_str = resource_get_imap_code(IMAP_CODE_2180000, 1, &string_length);
					if (argc <= 0 || strlen(argv[0]) >= 32) {
						string_length = snprintf(reply_buff, 1024, "* %s", imap_reply_str);
					} else {
						string_length = snprintf(reply_buff, 1024, "%s %s", argv[0], imap_reply_str);
					}
					if (NULL != pcontext->connection.ssl) {
						SSL_write(pcontext->connection.ssl, reply_buff, string_length);
					} else {
						write(pcontext->connection.sockd, reply_buff, string_length);
					}
					pcontext->command_len = 0;
					goto LITERAL_CHECKING;
				}
				
				switch (imap_parser_dispatch_cmd(argc, argv, pcontext)) {
				case DISPATCH_CONTINUE:
					pcontext->command_len = 0;
					goto LITERAL_PROCESSING;
				case DISPATCH_BREAK:
					pcontext->command_len = 0;
					goto CONTEXT_PROCESSING;
				case DISPATCH_SHOULD_CLOSE:
					imap_reply_str = NULL;
					goto END_PROCESSING;
				}
			}
		}
		
		if (64*1024 == pcontext->read_offset) {
			pcontext->read_offset = 0;
			pcontext->literal_ptr = NULL;
			pcontext->literal_len = 0;
			pcontext->command_len = 0;
			
			/* IMAP_CODE_2180000: BAD command not support or parameter error */
			imap_reply_str = resource_get_imap_code(IMAP_CODE_2180000, 1,
								&string_length);
			if (NULL != pcontext->connection.ssl) {
				SSL_write(pcontext->connection.ssl, imap_reply_str, string_length);
			} else {
				write(pcontext->connection.sockd, imap_reply_str, string_length);
			}
		}
		
		if (SCHED_STAT_IDLING == pcontext->sched_stat) {
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_sleeping_list, &pcontext->sleeping_node);
			pthread_mutex_unlock(&g_list_lock);
			return PROCESS_SLEEPING;
		}
		return PROCESS_CONTINUE;
	} else if (SCHED_STAT_APPENDING == pcontext->sched_stat) {
		pbuff = stream_getbuffer_for_writing(&pcontext->stream, &len);
		if (NULL == pbuff) {
			imap_parser_log_info(pcontext, 8, "out of memory");
			/* IMAP_CODE_2180009: BAD internal error: fail to get stream buffer */
			imap_reply_str = resource_get_imap_code(IMAP_CODE_2180009, 1, &string_length);
			goto END_PROCESSING;
		}
		if (NULL != pcontext->connection.ssl) {
			read_len = SSL_read(pcontext->connection.ssl, pbuff, len);
		} else {
			read_len = read(pcontext->connection.sockd, pbuff, len);
		}
		gettimeofday(&current_time, NULL);
		if (0 == read_len) {
			imap_reply_str = NULL;
			imap_parser_log_info(pcontext, 8, "connection lost");
			goto END_PROCESSING;
		} else if (read_len > 0) {
			pcontext->connection.last_timestamp = current_time;
			if (pcontext->literal_len <= pcontext->current_len + read_len) {
				temp_len = pcontext->current_len + read_len - pcontext->literal_len;
				memcpy(pcontext->read_buffer, pbuff + read_len - temp_len, temp_len);
				pcontext->read_offset = temp_len;
				stream_forward_writing_ptr(&pcontext->stream, read_len - temp_len);
				pcontext->current_len = pcontext->literal_len;
				pcontext->sched_stat = SCHED_STAT_APPENDED;
			} else {
				stream_forward_writing_ptr(&pcontext->stream, read_len);
				pcontext->current_len += read_len;
			}
			
			total_len = stream_get_total_length(&pcontext->stream);
		    if (total_len >= g_cache_size || 
				pcontext->literal_len == pcontext->current_len) {
				if (STREAM_DUMP_OK != stream_dump(&pcontext->stream, pcontext->message_fd)) {
					imap_parser_log_info(pcontext, 0, "fail to flush mail from memory into file");
					/* IMAP_CODE_2180010: BAD internal error: fail to dump stream object */
					imap_reply_str = resource_get_imap_code(IMAP_CODE_2180010, 1, &string_length);
					goto END_PROCESSING;
				}
				stream_clear(&pcontext->stream);
			}
			if (SCHED_STAT_APPENDED == pcontext->sched_stat) {
				pcontext->literal_ptr = NULL;
				pcontext->literal_len = 0;
				goto CMD_PROCESSING;
			} else {
				return PROCESS_CONTINUE;
			}
			
		} else {
			if (EAGAIN != errno) {
				imap_parser_log_info(pcontext, 8, "connection lost");
				imap_reply_str = NULL;
				goto END_PROCESSING;
			}
			/* check if context is timed out */
			if (CALCULATE_INTERVAL(current_time,
				pcontext->connection.last_timestamp) >= g_timeout) {
				/* IMAP_CODE_2180011: BAD time out */
				imap_reply_str = resource_get_imap_code(IMAP_CODE_2180011, 1, &string_length);
				goto END_PROCESSING;
			} else {
				return PROCESS_POLLING_RDONLY;
			}
		}
	
	} else if (SCHED_STAT_WRDAT == pcontext->sched_stat) {
		if (0 == pcontext->write_length) {
			imap_parser_wrdat_retrieve(pcontext);
		}
		if (NULL != pcontext->connection.ssl) {
			written_len = SSL_write(pcontext->connection.ssl,
				pcontext->write_buff + pcontext->write_offset,
				pcontext->write_length - pcontext->write_offset);
		} else {
			written_len = write(pcontext->connection.sockd,
				pcontext->write_buff + pcontext->write_offset,
				pcontext->write_length - pcontext->write_offset);
		}
			
		gettimeofday(&current_time, NULL);
			
		if (0 == written_len) {
			imap_reply_str = NULL;
			imap_parser_log_info(pcontext, 0, "connection lost");
			goto END_PROCESSING;
		} else if (written_len < 0) {
			if (EAGAIN != errno) {
				imap_reply_str = NULL;
				imap_parser_log_info(pcontext, 0, "connection lost");
				goto END_PROCESSING;
			}
			/* check if context is timed out */
			if (CALCULATE_INTERVAL(current_time,
				pcontext->connection.last_timestamp) >= g_timeout) {
				imap_parser_log_info(pcontext, 0, "time out");
				/* IMAP_CODE_2180011: BAD time out */
				imap_reply_str = resource_get_imap_code(IMAP_CODE_2180011, 1, &string_length);
				goto END_PROCESSING;
			} else {
				return PROCESS_POLLING_WRONLY;
			}
		}
		pcontext->connection.last_timestamp = current_time;	
		pcontext->write_offset += written_len;

		if (pcontext->write_offset < pcontext->write_length) {
			return PROCESS_CONTINUE;
		}
		
		if (-1 != pcontext->message_fd) {
			len = pcontext->literal_len - pcontext->current_len;
			if (len > 64*1024) {
				len = 64*1024;
			}
			read_len = read(pcontext->message_fd, pcontext->write_buff, len);
			if (read_len != len) {
				imap_parser_log_info(pcontext, 8, "fail to read message file");
				/* IMAP_CODE_2180012: * BAD internal error: fail to read file */
				imap_reply_str = resource_get_imap_code(IMAP_CODE_2180012, 1, &string_length);
				goto END_PROCESSING;
			}
			pcontext->current_len += len;
			pcontext->write_length = len;
			pcontext->write_offset = 0;
			if (pcontext->literal_len == pcontext->current_len) {
				close(pcontext->message_fd);
				pcontext->message_fd = -1;
				pcontext->literal_len = 0;
				pcontext->current_len = 0;
				if (IMAP_RETRIEVE_ERROR == imap_parser_wrdat_retrieve(pcontext)) {
					/* IMAP_CODE_2180008: internal error, fail to retrieve from stream object */
					imap_reply_str = resource_get_imap_code(IMAP_CODE_2180008, 1, &string_length);
					goto END_PROCESSING;
				}
			}
		} else {
			pcontext->write_offset = 0;
			pcontext->write_length = 0;
			switch (imap_parser_wrdat_retrieve(pcontext)) {
			case IMAP_RETRIEVE_TERM:
				stream_clear(&pcontext->stream);
				if (0 == pcontext->write_length) {
					pcontext->sched_stat = SCHED_STAT_RDCMD;
					goto LITERAL_CHECKING;
				}
				break;
			case IMAP_RETRIEVE_OK:
				break;
			case IMAP_RETRIEVE_ERROR:
				/* IMAP_CODE_2180008: internal error, fail to retrieve from stream object */
				imap_reply_str = resource_get_imap_code(IMAP_CODE_2180008, 1, &string_length);
				goto END_PROCESSING;
			}
		}
		return PROCESS_CONTINUE;
	} else if (SCHED_STAT_WRLST == pcontext->sched_stat) {
		if (0 == pcontext->write_length) {
			temp_len = MAX_LINE_LENGTH;
			pcontext->write_buff = stream_getbuffer_for_reading(&pcontext->stream,
									&temp_len);
			pcontext->write_length = temp_len;
		}
		if (NULL != pcontext->connection.ssl) {
			written_len = SSL_write(pcontext->connection.ssl,
				pcontext->write_buff + pcontext->write_offset,
				pcontext->write_length - pcontext->write_offset);
		} else {
			written_len = write(pcontext->connection.sockd,
				pcontext->write_buff + pcontext->write_offset,
				pcontext->write_length - pcontext->write_offset);
		}
			
		gettimeofday(&current_time, NULL);
		
		if (0 == written_len) {
			imap_reply_str = NULL;
			imap_parser_log_info(pcontext, 0, "connection lost");
			goto END_PROCESSING;
		} else if (written_len < 0) {
			if (EAGAIN != errno) {
				imap_reply_str = NULL;
				imap_parser_log_info(pcontext, 0, "connection lost");
				goto END_PROCESSING;
			}
			/* check if context is timed out */
			if (CALCULATE_INTERVAL(current_time,
				pcontext->connection.last_timestamp) >= g_timeout) {
				imap_parser_log_info(pcontext, 0, "time out");
				/* IMAP_CODE_2180011: BAD time out */
				imap_reply_str = resource_get_imap_code(IMAP_CODE_2180011, 1, &string_length);
				goto END_PROCESSING;
			} else {
				return PROCESS_POLLING_WRONLY;
			}
		}
		pcontext->connection.last_timestamp = current_time;	
		pcontext->write_offset += written_len;

		if (pcontext->write_offset < pcontext->write_length) {
			return PROCESS_CONTINUE;
		}

		pcontext->write_offset = 0;
		temp_len = MAX_LINE_LENGTH;
		pcontext->write_buff = stream_getbuffer_for_reading(
								&pcontext->stream, &temp_len);
		pcontext->write_length = temp_len;
		if (NULL == pcontext->write_buff) {
			stream_clear(&pcontext->stream);
			pcontext->write_length = 0;
			pcontext->write_offset = 0;
			pcontext->sched_stat = SCHED_STAT_RDCMD;
			goto LITERAL_CHECKING;
		}
		return PROCESS_CONTINUE;
	}


END_PROCESSING:
	
	if (NULL != imap_reply_str) {
		len = snprintf(reply_buff, 1024, "* %s", imap_reply_str);
		if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, reply_buff, len);
		} else {
			write(pcontext->connection.sockd, reply_buff, len);
		}
	}
	if (NULL != pcontext->connection.ssl) {
		SSL_shutdown(pcontext->connection.ssl);
		SSL_free(pcontext->connection.ssl);
		pcontext->connection.ssl = NULL;
	}
	SLEEP_BEFORE_CLOSE;
	close(pcontext->connection.sockd);
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_remove_select(pcontext);
		pcontext->proto_stat = PROTO_STAT_AUTH;
		pcontext->selected_folder[0] = '\0';
	}
	if (-1 != pcontext->message_fd) {
		close(pcontext->message_fd);
		pcontext->message_fd = -1;
	}
	if ('\0' != pcontext->file_path[0]) {
		remove(pcontext->file_path);
		pcontext->file_path[0] = '\0';
	}
	
	system_services_container_remove_ip(pcontext->connection.client_ip);
	imap_parser_context_clear(pcontext);
	return PROCESS_CLOSE;
}


int imap_parser_wrdat_retrieve(IMAP_CONTEXT *pcontext)
{
	int len;
	int read_len;
	int line_length;
	int copy_result;
	char *last_line;
	char *ptr, *ptr1;
	char temp_path[256];
	
	while (TRUE) {
		line_length = MAX_LINE_LENGTH - pcontext->write_length;
		if (line_length < 64) {
			return IMAP_RETRIEVE_OK;
		}
		/* make room for CRLF */
		line_length -= 2;
		copy_result = stream_copyline(&pcontext->stream, pcontext->write_buff +
						pcontext->write_length, &line_length);
		switch (copy_result) {
		case STREAM_COPY_END:
			return IMAP_RETRIEVE_TERM;
		case STREAM_COPY_TERM:
			return IMAP_RETRIEVE_ERROR;
		case STREAM_COPY_OK:
			last_line = pcontext->write_buff + pcontext->write_length;
			if (line_length > 8 && 0 == strncmp(last_line, "<<{file}", 8)) {
				last_line[line_length] = '\0';
				if (NULL == (ptr = strchr(last_line + 8, '|')) ||
					NULL == (ptr1 = strchr(ptr + 1, '|'))) {
					memcpy(pcontext->write_buff + pcontext->write_length , "NIL", 3);
					pcontext->write_length += 3;
				} else {
					*ptr = '\0';
					*ptr1 = '\0';
					snprintf(temp_path, 256, "%s/eml/%s", pcontext->maildir, last_line + 8);
					pcontext->message_fd = open(temp_path, O_RDONLY);
					if (-1 == pcontext->message_fd) {
						memcpy(pcontext->write_buff + pcontext->write_length, "NIL", 3);
						pcontext->write_length += 3;
					} else {
						lseek(pcontext->message_fd, atol(ptr + 1), SEEK_SET);
						pcontext->literal_len = atol(ptr1 + 1);
						pcontext->current_len = 0;
						len = MAX_LINE_LENGTH - pcontext->write_length;
						if (len > pcontext->literal_len) {
							len = pcontext->literal_len;
						}
						read_len = read(pcontext->message_fd, pcontext->write_buff +
									pcontext->write_length, len);
						if (read_len != len) {
							imap_parser_log_info(pcontext, 8, "fail to read message file");
							close(pcontext->message_fd);
							pcontext->message_fd = -1;
							return IMAP_RETRIEVE_ERROR;
						}
						pcontext->current_len += len;
						pcontext->write_length += len;
						if (pcontext->literal_len == len) {
							close(pcontext->message_fd);
							pcontext->message_fd = -1;
							pcontext->literal_len = 0;
							pcontext->current_len = 0;
						}
					}
				}
			} else if (line_length > 10 && 0 == strncmp(last_line, "<<{rfc822}", 10)) {
				last_line[line_length] = '\0';
				if (NULL == (ptr = strchr(last_line + 10, '|')) ||
					NULL == (ptr1 = strchr(ptr + 1, '|'))) {
					memcpy(pcontext->write_buff + pcontext->write_length , "NIL", 3);
					pcontext->write_length += 3;
				} else {
					*ptr = '\0';
					*ptr1 = '\0';
					snprintf(temp_path, 256, "%s/tmp/imap.rfc822/%s",
						pcontext->maildir, last_line + 10);
					
					pcontext->message_fd = open(temp_path, O_RDONLY);
					if (-1 == pcontext->message_fd) {
						memcpy(pcontext->write_buff + pcontext->write_length, "NIL", 3);
						pcontext->write_length += 3;
					} else {
						lseek(pcontext->message_fd, atol(ptr + 1), SEEK_SET);
						pcontext->literal_len = atol(ptr1 + 1);
						pcontext->current_len = 0;
						len = MAX_LINE_LENGTH - pcontext->write_length;
						if (len > pcontext->literal_len) {
							len = pcontext->literal_len;
						}
						read_len = read(pcontext->message_fd, pcontext->write_buff +
									pcontext->write_length, len);
						if (read_len != len) {
							imap_parser_log_info(pcontext, 8, "fail to read message file");
							close(pcontext->message_fd);
							pcontext->message_fd = -1;
							return IMAP_RETRIEVE_ERROR;
						}
						pcontext->current_len += len;
						pcontext->write_length += len;
						if (pcontext->literal_len == len) {
							close(pcontext->message_fd);
							pcontext->message_fd = -1;
							pcontext->literal_len = 0;
							pcontext->current_len = 0;
						}
					}
				}
			} else {
				pcontext->write_length += line_length;
				memcpy(pcontext->write_buff + pcontext->write_length, "\r\n", 2);
				pcontext->write_length += 2;
			}
			break;
		case STREAM_COPY_PART:
			pcontext->write_length += line_length;
			return IMAP_RETRIEVE_OK;
		}
	}
	
}

void imap_parser_touch_modify(IMAP_CONTEXT *pcontext, char *username, char *folder)
{
	char buff[1024];
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;
	IMAP_CONTEXT *pcontext1;
	
	
	strncpy(buff, username, 256);
	lower_string(buff);
	pthread_mutex_lock(&g_hash_lock);
	plist = str_hash_query(g_select_hash, buff);
	if (NULL == plist) {
		pthread_mutex_unlock(&g_hash_lock);
		return;
	}
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pcontext1 = (IMAP_CONTEXT*)(pnode->pdata);
		if (pcontext != pcontext1 && 0 == strcmp(folder, pcontext1->selected_folder)) {
			pcontext1->b_modify = TRUE;
		}
	}
	pthread_mutex_unlock(&g_hash_lock);
	
	snprintf(buff, 1024, "FOLDER-TOUCH %s %s", username, folder);
	system_services_broadcast_event(buff);
}

static void imap_parser_event_touch(char *username, char *folder)
{
	DOUBLE_LIST *plist;
	char temp_string[256];
	DOUBLE_LIST_NODE *pnode;
	IMAP_CONTEXT *pcontext;
	
	strncpy(temp_string, username, 256);
	lower_string(temp_string);
	pthread_mutex_lock(&g_hash_lock);
	plist = str_hash_query(g_select_hash, temp_string);
	if (NULL == plist) {
		pthread_mutex_unlock(&g_hash_lock);
		return;
	}
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pcontext = (IMAP_CONTEXT*)(pnode->pdata);
		if (0 == strcmp(folder, pcontext->selected_folder)) {
			pcontext->b_modify = TRUE;
		}
	}
	pthread_mutex_unlock(&g_hash_lock);
}

void imap_parser_modify_flags(IMAP_CONTEXT *pcontext, const char *mid_string)
{
	int len;
	char buff[1024];
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;
	IMAP_CONTEXT *pcontext1;
	
	strncpy(buff, pcontext->username, 256);
	lower_string(buff);
	pthread_mutex_lock(&g_hash_lock);
	plist = str_hash_query(g_select_hash, buff);
	if (NULL == plist) {
		pthread_mutex_unlock(&g_hash_lock);
		return;
	}
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pcontext1 = (IMAP_CONTEXT*)(pnode->pdata);
		if (pcontext != pcontext1 && 0 == strcmp(pcontext->selected_folder,
			pcontext1->selected_folder)) {
			mem_file_writeline(&pcontext1->f_flags, (char*)mid_string);
		}
	}
	pthread_mutex_unlock(&g_hash_lock);
	
	len = snprintf(buff, 1024, "MESSAGE-FLAG %s %s %s",
		pcontext->username, pcontext->selected_folder, mid_string);
	system_services_broadcast_event(buff);
}

static void imap_parser_event_flag(const char *username, const char *folder,
	const char *mid_string)
{
	DOUBLE_LIST *plist;
	char temp_string[256];
	DOUBLE_LIST_NODE *pnode;
	IMAP_CONTEXT *pcontext;
	
	strncpy(temp_string, username, 256);
	lower_string(temp_string);
	pthread_mutex_lock(&g_hash_lock);
	plist = str_hash_query(g_select_hash, temp_string);
	if (NULL == plist) {
		pthread_mutex_unlock(&g_hash_lock);
		return;
	}
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pcontext = (IMAP_CONTEXT*)(pnode->pdata);
		if (0 == strcmp(pcontext->selected_folder, folder)) {
			mem_file_writeline(&pcontext->f_flags, (char*)mid_string);
		}
	}
	pthread_mutex_unlock(&g_hash_lock);

}

void imap_parser_echo_modify(IMAP_CONTEXT *pcontext, STREAM *pstream)
{
	int id;
	int err;
	int recent;
	int exists;
	int tmp_len;
	int flag_bits;
	BOOL b_first;
	BOOL b_modify;
	char buff[1024];
	char estring[256];
	char mid_string[256];
	MEM_FILE temp_file;
	
	mem_file_init(&temp_file, g_alloc_file);
	
	pthread_mutex_lock(&g_hash_lock);
	b_modify = pcontext->b_modify;
	pcontext->b_modify = FALSE;
	mem_file_copy(&pcontext->f_flags, &temp_file);
	mem_file_clear(&pcontext->f_flags);
	pthread_mutex_unlock(&g_hash_lock);
	
	if (TRUE == b_modify && MIDB_RESULT_OK == system_services_summary_folder(
		pcontext->maildir, pcontext->selected_folder, &exists, &recent, 
		NULL, NULL, NULL, NULL, &err)) {
		tmp_len = snprintf(buff, 1024, "* %d RECENT\r\n"
									   "* %d EXISTS\r\n",
									   recent, exists);
		if (NULL == pstream) {
			if (NULL != pcontext->connection.ssl) {
				SSL_write(pcontext->connection.ssl, buff, tmp_len);
			} else {
				write(pcontext->connection.sockd, buff, tmp_len);
			}
		} else {
			stream_write(pstream, buff, tmp_len);
		}
	}
	
	if (0 == mem_file_get_total_length(&temp_file)) {
		mem_file_free(&temp_file);
		return;
	}
	
	while (MEM_END_OF_FILE != mem_file_readline(&temp_file, mid_string, sizeof(mid_string))) {
		if (MIDB_RESULT_OK == system_services_get_id(pcontext->maildir,
			pcontext->selected_folder, mid_string, &id) &&
			MIDB_RESULT_OK == system_services_get_flags(pcontext->maildir,
			pcontext->selected_folder, mid_string, &flag_bits, &err)) {
			tmp_len = snprintf(buff, 1024, "* %d FETCH (FLAGS (", id);
			b_first = FALSE;
			if (flag_bits & FLAG_RECENT) {
				tmp_len += snprintf(buff + tmp_len, 1024 - tmp_len, "\\Recent");
				b_first = TRUE;
			}
			if (flag_bits & FLAG_ANSWERED) {
				if (TRUE == b_first) {
					buff[tmp_len] = ' ';
					tmp_len ++;
				}
				tmp_len += snprintf(buff + tmp_len, 1024 - tmp_len, "\\Answered");
				b_first = TRUE;
			}
			if (flag_bits & FLAG_FLAGGED) {
				if (TRUE == b_first) {
					buff[tmp_len] = ' ';
					tmp_len ++;
				}
				tmp_len += snprintf(buff + tmp_len, 1024 - tmp_len, "\\Flagged");
				b_first = TRUE;
			}
			if (flag_bits & FLAG_DELETED) {
				if (TRUE == b_first) {
					buff[tmp_len] = ' ';
					tmp_len ++;
				}
				tmp_len += snprintf(buff + tmp_len, 1024 - tmp_len, "\\Deleted");
				b_first = TRUE;
			}
			if (flag_bits & FLAG_SEEN) {
				if (TRUE == b_first) {
					buff[tmp_len] = ' ';
					tmp_len ++;
				}
				tmp_len += snprintf(buff + tmp_len, 1024 - tmp_len, "\\Seen");
				b_first = TRUE;
			}
			if (flag_bits & FLAG_DRAFT) {
				if (TRUE == b_first) {
					buff[tmp_len] = ' ';
					tmp_len ++;
				}
				tmp_len += snprintf(buff + tmp_len, 1024 - tmp_len, "\\Draft");
			}
			tmp_len += snprintf(buff + tmp_len, 1024 - tmp_len, "))\r\n");
			if (NULL == pstream) {
				if (NULL != pcontext->connection.ssl) {
					SSL_write(pcontext->connection.ssl, buff, tmp_len);
				} else {
					write(pcontext->connection.sockd, buff, tmp_len);
				}
			} else {
				stream_write(pstream, buff, tmp_len);
			}
		}
	}
	mem_file_free(&temp_file);
}


/*
 *    get imap_parser's property
 *    @param
 *        param    indicate the parameter type
 *    @return
 *        value of property
 */
int imap_parser_get_param(int param)
{
    switch (param) {
    case MAX_AUTH_TIMES:
        return g_max_auth_times;
    case BLOCK_AUTH_FAIL:
        return g_block_auth_fail;
    case IMAP_SESSION_TIMEOUT:
        return g_timeout;
	case IMAP_AUTOLOGOUT_TIME:
		return g_autologout_time;
	case IMAP_SUPPORT_STARTTLS:
		return g_support_starttls;
	case IMAP_FORCE_STARTTLS:
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
IMAP_CONTEXT* imap_parser_get_contexts_list()
{
    return g_context_list;
}

/*
 *    set imap_parser's property
 *    @param
 *        param    indicate the pram type
 *    @return
 *         0        success
 *        <>0        fail
 */
int imap_parser_set_param(int param, int value)
{
    switch (param) {
    case MAX_AUTH_TIMES:
        g_max_auth_times = value;
        break;
    case IMAP_SESSION_TIMEOUT:
        g_timeout = value;
        break;
	case IMAP_AUTOLOGOUT_TIME:
		g_autologout_time = value;
		break;
	case BLOCK_AUTH_FAIL:
		g_block_auth_fail = value;
		break;
	case IMAP_FORCE_STARTTLS:
		if (TRUE == g_support_starttls) {
			g_force_starttls = value;
		}
		break;
    default:
        return -1;
    }
    return 0;
}


static int imap_parser_dispatch_cmd(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int string_length;
	char *imap_reply_str;
	char reply_buff[1024];
	
	
    /*========================================================================*/
    if (0 == strcasecmp(argv[1], "CAPABILITY")) {
        return imap_cmd_parser_capability(argc, argv, pcontext);
	/*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "ID")) {
        return imap_cmd_parser_id(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "NOOP")) {
        return imap_cmd_parser_noop(argc, argv, pcontext);
    /*========================================================================*/
    } else if (0 == strcasecmp(argv[1], "LOGOUT")) {
        return imap_cmd_parser_logout(argc, argv, pcontext);
    /*========================================================================*/
    } else if (0 == strcasecmp(argv[1], "STARTTLS")) {
        return imap_cmd_parser_starttls(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "AUTHENTICATE")) {
        return imap_cmd_parser_authenticate(argc, argv, pcontext);
    /*========================================================================*/
    } else if (0 == strcasecmp(argv[1], "LOGIN")) {
        return imap_cmd_parser_login(argc, argv, pcontext);
    /*========================================================================*/
    } else if (0 == strcasecmp(argv[1], "SELECT")) {
        return imap_cmd_parser_select(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "IDLE")) {
        return imap_cmd_parser_idle(argc, argv, pcontext);
    /*========================================================================*/
    } else if (0 == strcasecmp(argv[1], "EXAMINE")) {
        return imap_cmd_parser_examine(argc, argv, pcontext);
    /*========================================================================*/
    } else if (0 == strcasecmp(argv[1], "CREATE")) {
        return imap_cmd_parser_create(argc, argv, pcontext);
    /*========================================================================*/
    } else if (0 == strcasecmp(argv[1], "DELETE")) {
        return imap_cmd_parser_delete(argc, argv, pcontext);
    /*========================================================================*/
    } else if (0 == strcasecmp(argv[1], "RENAME")) {
        return imap_cmd_parser_rename(argc, argv, pcontext);
    /*========================================================================*/
    } else if (0 == strcasecmp(argv[1], "SUBSCRIBE")) {
        return imap_cmd_parser_subscribe(argc, argv, pcontext);
    /*========================================================================*/
    } else if (0 == strcasecmp(argv[1], "UNSUBSCRIBE")) {
        return imap_cmd_parser_unsubscribe(argc, argv, pcontext);
    /*========================================================================*/
    } else if (0 == strcasecmp(argv[1], "LIST")) {
        return imap_cmd_parser_list(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "XLIST")) {
        return imap_cmd_parser_xlist(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "LSUB")) {
        return imap_cmd_parser_lsub(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "STATUS")) {
        return imap_cmd_parser_status(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "APPEND")) {
        return imap_cmd_parser_append(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "CHECK")) {
        return imap_cmd_parser_check(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "CLOSE")) {
        return imap_cmd_parser_close(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "EXPUNGE")) {
        return imap_cmd_parser_expunge(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "UNSELECT")) {
        return imap_cmd_parser_unselect(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "SEARCH")) {
        return imap_cmd_parser_search(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "FETCH")) {
        return imap_cmd_parser_fetch(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "STORE")) {
        return imap_cmd_parser_store(argc, argv, pcontext);
    /*========================================================================*/
	} else if (0 == strcasecmp(argv[1], "COPY")) {
        return imap_cmd_parser_copy(argc, argv, pcontext);
    /*========================================================================*/
	} else if (argc > 2 && 0 == strcasecmp(argv[1], "UID") &&
		0 == strcasecmp(argv[2], "SEARCH")) {
        return imap_cmd_parser_uid_search(argc, argv, pcontext);
    /*========================================================================*/
	} else if (argc > 2 && 0 == strcasecmp(argv[1], "UID") &&
		0 == strcasecmp(argv[2], "FETCH")) {
        return imap_cmd_parser_uid_fetch(argc, argv, pcontext);
    /*========================================================================*/
	} else if (argc > 2 && 0 == strcasecmp(argv[1], "UID") &&
		0 == strcasecmp(argv[2], "STORE")) {
        return imap_cmd_parser_uid_store(argc, argv, pcontext);
    /*========================================================================*/
	} else if (argc > 2 && 0 == strcasecmp(argv[1], "UID") &&
		0 == strcasecmp(argv[2], "COPY")) {
        return imap_cmd_parser_uid_copy(argc, argv, pcontext);
    /*========================================================================*/
	} else if (argc > 2 && 0 == strcasecmp(argv[1], "UID") &&
		0 == strcasecmp(argv[2], "EXPUNGE")) {
        return imap_cmd_parser_uid_expunge(argc, argv, pcontext);
    /*========================================================================*/
    } else {
		/*IMAP_CODE_2180000: BAD command not support or parameter error */
		imap_reply_str = resource_get_imap_code(IMAP_CODE_2180000, 1, &string_length);
		string_length = snprintf(reply_buff, 1024, "%s %s", argv[0], imap_reply_str);
        if (NULL != pcontext->connection.ssl) {
			SSL_write(pcontext->connection.ssl, reply_buff, string_length);
		} else {
			write(pcontext->connection.sockd, reply_buff, string_length);
		}
		return DISPATCH_CONTINUE;
    }
}

/*
 *    imap context's construct function
 *    @param
 *        pcontext [in]    indicate the imap context object
 */
static void imap_parser_context_init(IMAP_CONTEXT *pcontext)
{
    LIB_BUFFER *palloc_stream;
    
    if (NULL == pcontext) {
        return;
    }
    palloc_stream = blocks_allocator_get_allocator();
    memset(pcontext, 0, sizeof(IMAP_CONTEXT));
	pcontext->hash_node.pdata = pcontext;
	pcontext->sleeping_node.pdata = pcontext;
    pcontext->connection.sockd = -1;
	pcontext->message_fd = -1;
    stream_init(&pcontext->stream, palloc_stream);
	mem_file_init(&pcontext->f_flags, g_alloc_file);
}

/*
 *    clear the imap context object
 *    @param
 *        pcontext [in]    indicate the imap context object
 */
static void imap_parser_context_clear(IMAP_CONTEXT *pcontext)
{
    if (NULL == pcontext) {
        return;
    }
    memset(&pcontext->connection, 0, sizeof(CONNECTION));
    pcontext->connection.sockd = -1;
	pcontext->proto_stat = 0;
	pcontext->sched_stat = 0;
	pcontext->mid[0] = '\0';
	pcontext->file_path[0] = '\0';
	pcontext->message_fd = -1;
	pcontext->write_buff = NULL;
	pcontext->write_length = 0;
	pcontext->write_offset = 0;
	pcontext->selected_time = 0;
	pcontext->selected_folder[0] = '\0';
	pcontext->b_readonly = FALSE;
	pcontext->tag_string[0] = '\0';
	pcontext->command_len = 0;
	pcontext->command_buffer[0] = '\0';
	pcontext->read_offset = 0;
	pcontext->read_buffer[0] = '\0';
	pcontext->literal_ptr = NULL;
	pcontext->literal_len = 0;
	pcontext->current_len = 0;
	stream_clear(&pcontext->stream);
	mem_file_clear(&pcontext->f_flags);
	pcontext->auth_times = 0;
	pcontext->username[0] = '\0';
	pcontext->maildir[0] = '\0';
}

static void imap_parser_context_free(IMAP_CONTEXT *pcontext)
{
	if (NULL == pcontext) {
		return;
	}
	stream_free(&pcontext->stream);
	mem_file_free(&pcontext->f_flags);
	if (NULL != pcontext->connection.ssl) {
		SSL_shutdown(pcontext->connection.ssl);
		SSL_free(pcontext->connection.ssl);
		pcontext->connection.ssl = NULL;
	}
	if (-1 != pcontext->connection.sockd) {
		close(pcontext->connection.sockd);
	}
	if (-1 != pcontext->message_fd) {
		close(pcontext->message_fd);
	}
	if ('\0' != pcontext->file_path) {
		remove(pcontext->file_path);
	}
}

static void* thread_work_func(void *argp)
{
	int peek_len;
	char tmp_buff;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	IMAP_CONTEXT *pcontext;
	struct timeval current_time;
	
	while (FALSE == g_notify_stop) {
		pthread_mutex_lock(&g_list_lock);
		ptail = double_list_get_tail(&g_sleeping_list);
		pthread_mutex_unlock(&g_list_lock);
		if (NULL == ptail) {
			usleep(100000);
			continue;
		}
		
		do {
			pthread_mutex_lock(&g_list_lock);
			pnode=double_list_get_from_head(&g_sleeping_list);
			pthread_mutex_unlock(&g_list_lock);
			pcontext = (IMAP_CONTEXT*)pnode->pdata;
			if (SCHED_STAT_IDLING == pcontext->sched_stat) {
				pthread_mutex_lock(&g_hash_lock);
				if (TRUE == pcontext->b_modify) {
					pcontext->b_modify = FALSE;
					pthread_mutex_unlock(&g_hash_lock);
					pcontext->sched_stat = SCHED_STAT_NOTIFYING;
					contexts_pool_wakeup_context(
						(SCHEDULE_CONTEXT*)pcontext, CONTEXT_TURNING);
					if (pnode == ptail) {
						break;
					} else {
						continue;
					}
				} else {
					pthread_mutex_unlock(&g_hash_lock);
				}
			}
			peek_len = recv(pcontext->connection.sockd, &tmp_buff, 1, MSG_PEEK);
			if (1 == peek_len) {
				contexts_pool_wakeup_context(
					(SCHEDULE_CONTEXT*)pcontext, CONTEXT_TURNING);
			} else if (peek_len < 0) {
				gettimeofday(&current_time, NULL);
				if (CALCULATE_INTERVAL(current_time,
					pcontext->connection.last_timestamp) >= g_autologout_time) {
					pcontext->sched_stat = SCHED_STAT_AUTOLOGOUT;
					contexts_pool_wakeup_context(
						(SCHEDULE_CONTEXT*)pcontext, CONTEXT_TURNING);
				} else {
					pthread_mutex_lock(&g_list_lock);
					double_list_append_as_tail(&g_sleeping_list, pnode);
					pthread_mutex_unlock(&g_list_lock);
				}
			} else {
				pcontext->sched_stat = SCHED_STAT_DISCINNECTED;
				contexts_pool_wakeup_context(
					(SCHEDULE_CONTEXT*)pcontext, CONTEXT_TURNING);
			}
		} while (pnode != ptail);
		usleep(100000);
	}
	pthread_exit(0);

}

void imap_parser_log_info(IMAP_CONTEXT *pcontext, int level, char *format, ...)
{
	char log_buf[2048];
	va_list ap;

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	log_buf[sizeof(log_buf) - 1] = '\0';
	
	system_services_log_info(level, "user: %s, IP: %s  %s",
		pcontext->username, pcontext->connection.client_ip, log_buf);

}

static void imap_parser_event_proc(char *event)
{
	char *pspace, *pspace1;
	
	if (0 == strncasecmp(event, "FOLDER-TOUCH ", 13)) {
		pspace = strchr(event + 13, ' ');
		if (NULL != pspace) {
			*pspace = '\0';
			imap_parser_event_touch(event + 13, pspace + 1);
		}
	} else if (0 == strncasecmp(event, "MESSAGE-FLAG ", 13)) {
		pspace = strchr(event + 13, ' ');
		if (NULL != pspace) {
			*pspace = '\0';
			pspace1 = strchr(pspace + 1, ' ');
			if (NULL != pspace1) {
				*pspace1 = '\0';
				imap_parser_event_flag(event + 13, pspace + 1, pspace1 + 1);
			}
		}
	}
}


void imap_parser_add_select(IMAP_CONTEXT *pcontext)
{
	char temp_string[256];
	DOUBLE_LIST *plist, temp_list;
	
	strncpy(temp_string, pcontext->username, 256);
	lower_string(temp_string);
	time(&pcontext->selected_time);
	pthread_mutex_lock(&g_hash_lock);
	plist = (DOUBLE_LIST*)str_hash_query(g_select_hash, temp_string);
	if (NULL == plist) {
		double_list_init(&temp_list);
		if (1 == str_hash_add(g_select_hash, temp_string, &temp_list)) {
			plist = (DOUBLE_LIST*)str_hash_query(g_select_hash, temp_string);
			if (NULL != plist) {
				double_list_append_as_tail(plist, &pcontext->hash_node);
			}
		}
	} else {
		double_list_append_as_tail(plist, &pcontext->hash_node);
	}
	pthread_mutex_unlock(&g_hash_lock);
	
	system_services_broadcast_select(pcontext->username, pcontext->selected_folder);
}

void imap_parser_remove_select(IMAP_CONTEXT *pcontext)
{
	BOOL should_remove;
	DOUBLE_LIST *plist;
	char temp_string[256];
	DOUBLE_LIST_NODE *pnode;
	IMAP_CONTEXT *pcontext1;
	
	should_remove = TRUE;
	pcontext->selected_time = 0;
	strncpy(temp_string, pcontext->username, 256);
	lower_string(temp_string);
	pthread_mutex_lock(&g_hash_lock);
	plist = (DOUBLE_LIST*)str_hash_query(g_select_hash, temp_string);
	if (NULL != plist) {
		double_list_remove(plist, &pcontext->hash_node);
		if (0 == double_list_get_nodes_num(plist)) {
			str_hash_remove(g_select_hash, temp_string);
		}
		pcontext->b_modify = FALSE;
		mem_file_clear(&pcontext->f_flags);
		for (pnode=double_list_get_head(plist); NULL!=pnode;
			pnode=double_list_get_after(plist, pnode)) {
			pcontext1 = (IMAP_CONTEXT*)pnode->pdata;
			if (0 == strcmp(pcontext->selected_folder, pcontext1->selected_folder)) {
				should_remove = FALSE;
				break;
			}
		}
	}
	pthread_mutex_unlock(&g_hash_lock);
	
	if (TRUE == should_remove) {
		system_services_broadcast_unselect(pcontext->username, pcontext->selected_folder);
	}
}

static void* scan_work_func(void *argp)
{
	int i = 0;
	int err_num;
	time_t cur_time;
	char folder[128];
	char maildir[256];
	char username[256];
	MEM_FILE temp_file;
	DOUBLE_LIST *plist;
	STR_HASH_ITER *iter;
	IMAP_CONTEXT *pcontext;
	DOUBLE_LIST_NODE *pnode;
	
	
	
	while (FALSE == g_notify_stop) {
		i ++;
		sleep(1);
		if (i < SCAN_INTERVAL) {
			continue;
		}
		
		i = 0;
		
		mem_file_init(&temp_file, g_alloc_file);
		pthread_mutex_lock(&g_hash_lock);
		time(&cur_time);
		iter = str_hash_iter_init(g_select_hash);
		for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			plist = (DOUBLE_LIST*)str_hash_iter_get_value(iter, username);
			for (pnode=double_list_get_head(plist); NULL!=pnode;
				pnode=double_list_get_after(plist, pnode)) {
				pcontext = (IMAP_CONTEXT*)pnode->pdata;
				if (cur_time - pcontext->selected_time > SELECT_INTERVAL) {
					mem_file_writeline(&temp_file, pcontext->username);
					mem_file_writeline(&temp_file, pcontext->maildir);
					mem_file_writeline(&temp_file, pcontext->selected_folder);
					pcontext->selected_time = cur_time;
				}
			}
		}
		str_hash_iter_free(iter);
		pthread_mutex_unlock(&g_hash_lock);
		
		while (MEM_END_OF_FILE != mem_file_readline(&temp_file, username, 256)) {
			mem_file_readline(&temp_file, maildir, 256);
			mem_file_readline(&temp_file, folder, 128);
			system_services_broadcast_select(username, folder);
			system_services_ping_mailbox(maildir, &err_num);
		}
		mem_file_free(&temp_file);
	}
	
	pthread_exit(0);
	
}

LIB_BUFFER* imap_parser_get_allocator()
{
	return g_alloc_file;
}

MIME_POOL* imap_parser_get_mpool()
{
	return g_mime_pool;
}

LIB_BUFFER* imap_parser_get_jpool()
{
	return g_alloc_mjson;
}

static void imap_parser_ssl_locking(int mode,
	int n, const char *file, int line)
{
	if (mode&CRYPTO_LOCK) {
		pthread_mutex_lock(&g_ssl_mutex_buf[n]);
	} else {
		pthread_mutex_unlock(&g_ssl_mutex_buf[n]);
	}
}

static void imap_parser_ssl_id(CRYPTO_THREADID* id)
{
	CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
}

int imap_parser_get_squence_ID()
{
	int temp_id;
	
	pthread_mutex_lock(&g_squence_lock);
	if (g_squence_ID > 0x7FFFFFFF) {
		g_squence_ID = 0;
	}
	g_squence_ID ++;
	temp_id = g_squence_ID;
	pthread_mutex_unlock(&g_squence_lock);

	return g_squence_ID;
}

void imap_parser_safe_write(IMAP_CONTEXT *pcontext, const void *pbuff, size_t count)
{
	int opt;
	
	/* set socket to block mode */
	opt = fcntl(pcontext->connection.sockd, F_GETFL, 0);
	opt &= (~O_NONBLOCK);
	fcntl(pcontext->connection.sockd, F_SETFL, opt);
	/* end of set mode */
	if (NULL != pcontext->connection.ssl) {
		SSL_write(pcontext->connection.ssl, pbuff, count);
	} else {
		write(pcontext->connection.sockd, pbuff, count);
	}
	/* set the socket back to non-block mode */
	opt |= O_NONBLOCK;
	fcntl(pcontext->connection.sockd, F_SETFL, opt);
	/* end of set mode */
}
