#include <ctype.h>
#include <string.h>
#include "files_allocator.h"
#include "sender_routing.h"
#include "smtp_deliverer.h"
#include "vstack.h"
#include "util.h"
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SOCKET_TIMEOUT			180

typedef struct _CONNECTION {
	int sockd;
	SSL *ssl;
} CONNECTION;

typedef BOOL (*DESTINATION_FORBIDDEN)(const char*);
typedef BOOL (*DESTINATION_AUDIT)(const char*);
typedef BOOL (*DESTINATION_QUERY)(const char*);
typedef BOOL (*HELLO_MX_QUERY)(const char*);
typedef BOOL (*DNS_QUERY)(const char*, VSTACK*);

static DESTINATION_FORBIDDEN smtp_deliverer_destination_forbidden;
static DESTINATION_AUDIT smtp_deliverer_destination_audit;
static DESTINATION_QUERY smtp_deliverer_destination_query;
static HELLO_MX_QUERY smtp_deliverer_hello_mx_query;
static DNS_QUERY smtp_deliverer_dns_query_A;
static DNS_QUERY smtp_deliverer_dns_query_MX;

static BOOL g_tls_switch;
static int g_trying_times;
static SSL_CTX *g_ssl_ctx;
static LIB_BUFFER *g_stack_allocator;
static pthread_mutex_t *g_ssl_mutex_buf;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void smtp_deliverer_ssl_locking(int mode,
	int n, const char *file, int line)
{
	if (mode&CRYPTO_LOCK) {
		pthread_mutex_lock(&g_ssl_mutex_buf[n]);
	} else {
		pthread_mutex_unlock(&g_ssl_mutex_buf[n]);
	}
}
 
static void smtp_deliverer_ssl_id(CRYPTO_THREADID* id)
{
	CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
}
#endif

/*
 *	smtp deliverer's construct function
 *	@param
 *		trying_times			trying when temporary fail or time out
 */
void smtp_deliverer_init(int trying_times, BOOL tls_switch)
{
	g_trying_times = trying_times;
	g_tls_switch = tls_switch;
}

/*
 *	run the smtp module
 *	@return
 *		 0			OK
 *		<>0			fail
 */
int smtp_deliverer_run()
{
	int i;
	
	smtp_deliverer_destination_forbidden =
		(DESTINATION_FORBIDDEN)query_service("destination_forbidden");
	smtp_deliverer_destination_audit = 
		(DESTINATION_AUDIT)query_service("destination_audit");
	if (NULL == smtp_deliverer_destination_audit) {
		printf("[remote_postman]: fail to get"
			" \"destination_audit\" service\n");
		return -1;
	}
	smtp_deliverer_destination_query =
		(DESTINATION_QUERY)query_service("destination_query");
	if (NULL == smtp_deliverer_destination_query) {
		printf("[remote_postman]: fail to get "
			"\"destination_query\" service\n");
		return -2;
	}
	smtp_deliverer_hello_mx_query =
		(HELLO_MX_QUERY)query_service("hello_mx_query");
	if (NULL == smtp_deliverer_hello_mx_query) {
		printf("[remote_postman]: fail to get"
			" \"hello_mx_query\" service\n");
		return -3;
	}
	smtp_deliverer_dns_query_A =
		(DNS_QUERY)query_service("dns_query_A");
	if (NULL == smtp_deliverer_dns_query_A) {
		printf("[remote_postman]: fail to "
			"get \"dns_query_A\"service\n");
		return -4;
	}
	smtp_deliverer_dns_query_MX =
		(DNS_QUERY)query_service("dns_query_MX");
	if (NULL == smtp_deliverer_dns_query_MX) {
		printf("[remote_postman]: fail to "
			"get \"dns_query_MX\" service\n");
		return -5;
	}
	
	SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    g_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (NULL == g_ssl_ctx) {
        printf("[remote_postman]: fail to init ssl context\n");
        return -6;
    }
	
	g_ssl_mutex_buf = malloc(CRYPTO_num_locks()*sizeof(pthread_mutex_t));
	if (NULL == g_ssl_mutex_buf) {
		printf("[remote_postman]: fail to allocate ssl locking buffer\n");
		return -7;
	}
	for (i=0; i<CRYPTO_num_locks(); i++) {
		pthread_mutex_init(&g_ssl_mutex_buf[i], NULL);
	}
	CRYPTO_THREADID_set_callback(smtp_deliverer_ssl_id);
	CRYPTO_set_locking_callback(smtp_deliverer_ssl_locking);
	
	g_stack_allocator = vstack_allocator_init(
			16, 1024*get_context_num(), TRUE);
	if (NULL == g_stack_allocator) {
		printf("[remote_postman]: fail to init stack allocator\n");
		return -8;
	}
	return 0;
}

/*
 *	stop the module
 *	@return
 *		 0			OK
 *		<>0			fail
 */
int smtp_deliverer_stop()
{
	int i;
	
	if (NULL != g_ssl_ctx) {
		SSL_CTX_free(g_ssl_ctx);
		g_ssl_ctx = NULL;
	}
	if (NULL != g_ssl_mutex_buf) {
		CRYPTO_set_id_callback(NULL);
		CRYPTO_set_locking_callback(NULL);
		for (i=0; i<CRYPTO_num_locks(); i++) {
			pthread_mutex_destroy(&g_ssl_mutex_buf[i]);
		}
		free(g_ssl_mutex_buf);
		g_ssl_mutex_buf = NULL;
	}
	if (NULL != g_stack_allocator) {
		vstack_allocator_free(g_stack_allocator);
		g_stack_allocator = NULL;
	}
	return 0;
}

/*
 *	module's destruct function
 */
void smtp_deliverer_free()
{
	/* do nothing */
}

/*
 *	send a command string to destination
 *	@param
 *		pconnection			smtp connection
 *		command [in]		command string to be sent
 *		command_len			command string length
 *	@return
 *		TRUE				OK
 *		FALSE				time out
 */
static BOOL smtp_deliverer_send_command(CONNECTION *pconnection,
	const char *command, int command_len)
{
	int written_len;
	
	if (NULL != pconnection->ssl) {
		written_len = SSL_write(pconnection->ssl, command, command_len);
	} else {	
		written_len = write(pconnection->sockd, command, command_len);
	}
    if (written_len != command_len) {
		return FALSE;
	}
	return TRUE;
}

/*
 *	get response from server
 *	@param
 *		pconnection				smtp connection
 *		response [out]			buffer for save response
 *		response_len			response buffer length
 *		preason [out]			fail reason
 *		expect_3xx				expect smtp return code 3XX
 *	@retrun
 *		TRUE					OK
 *		FALSE					fail
 */
static BOOL smtp_deliverer_get_response(CONNECTION *pconnection,
	char *response, int response_len, int *preason, BOOL expect_3xx)
{
	char *pline;
	fd_set myset;
	struct timeval tv;
	int read_len, offset;

	offset = 0;
	memset(response, 0, response_len);
	while (offset < response_len - 1) {
		/* wait the socket data to be available */ 
		tv.tv_sec = SOCKET_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&myset);
		FD_SET(pconnection->sockd, &myset);
		if (select(pconnection->sockd + 1,
			&myset, NULL, NULL, &tv) <= 0) {
			*preason = SMTP_DELIVERER_TIME_OUT;
			return FALSE;
		}
		if (NULL != pconnection->ssl) {
			read_len = SSL_read(pconnection->ssl, response
					+ offset, response_len - 1 - offset);
		} else {
			read_len = read(pconnection->sockd, response
					+ offset, response_len - 1 - offset);
		}
		if (-1 == read_len || 0 == read_len) {
			*preason = SMTP_DELIVERER_TIME_OUT;
			return FALSE;
		}
		offset += read_len;
		if ('\r' != response[offset - 2] ||
			'\n' != response[offset - 1]) {
			continue;
		}
		if (' ' == response[3]) {
			offset -= 2;
			break;
		}
		pline = response;
		while ((pline = strstr(pline, "\r\n")) != NULL) {
			pline += 2;
			if (' ' == pline[3]) {
				break;
			}
		}
		if (NULL != pline && ' ' == pline[3]) {
			offset -= 2;
			break;
		}
	}
	if (offset >= response_len - 1) {
		response[response_len - 1] = '\0';
		*preason = SMTP_DELIVERER_UNKOWN_RESPONSE;
		return FALSE;
	}
	response[offset] = '\0';
	if (FALSE == expect_3xx && '2' == response[0] &&
		0 != isdigit(response[1]) && 0 != isdigit(response[2])) {
		return TRUE;
	} else if (TRUE == expect_3xx && '3' == response[0] &&
		0 != isdigit(response[1]) && 0 != isdigit(response[2])) {
		return TRUE;
	} else {
		if ('4' == response[0]) {
           	*preason = SMTP_DELIVERER_TEMP_ERROR;	
		} else if ('5' == response[0]) {
			*preason = SMTP_DELIVERER_PERMANENT_ERROR;
		} else {
			*preason = SMTP_DELIVERER_UNKOWN_RESPONSE;
		}
		return FALSE;
	}
}

static void smtp_deliverer_close_connection(CONNECTION *pconnection)
{
	if (NULL != pconnection->ssl) {
		SSL_free(pconnection->ssl);
	}
	close(pconnection->sockd);
}

static int smtp_deliverer_send_mail(
	MESSAGE_CONTEXT *pcontext, const char *pdomain,
	const char* destination_ip, char *response_line,
	int length)
{
	long size;
	BOOL b_data;
	fd_set myset;
	struct timeval tv;
	char rcpt_to[256];
	char ehlo_size[32];
	MEM_FILE f_fail_rcpt;
	CONNECTION connection;
	char command_line[1024];
	char *ptr, *pbegin, *pend;
	int	opt, val_opt, opt_len;
	struct sockaddr_in servaddr;
	BOOL b_connected, rcpt_success;
	int command_len, mail_len, reason;
	
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	/* try to connect to the destination MTA */
	b_connected = FALSE;
	connection.sockd = socket(AF_INET, SOCK_STREAM, 0);
	connection.ssl = NULL;
	/* set the socket to non-block mode */
	opt = fcntl(connection.sockd, F_GETFL, 0);
	opt |= O_NONBLOCK;
	fcntl(connection.sockd, F_SETFL, opt);
	/* end of set mode */
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(25);
	inet_pton(AF_INET, destination_ip, &servaddr.sin_addr);
	if (0 == connect(connection.sockd,
		(struct sockaddr*)&servaddr, sizeof(servaddr))) {
		b_connected = TRUE;
		smtp_deliverer_destination_audit(destination_ip);
		/* set socket back to block mode */
		opt = fcntl(connection.sockd, F_GETFL, 0);
		opt &= (~O_NONBLOCK);
		fcntl(connection.sockd, F_SETFL, opt);
		/* end of set mode */
	} else {
		if (EINPROGRESS == errno) {
			tv.tv_sec = SOCKET_TIMEOUT;
			tv.tv_usec = 0;
			FD_ZERO(&myset);
			FD_SET(connection.sockd, &myset);
			if (select(connection.sockd + 1,
				NULL, &myset, NULL, &tv) > 0) {
				opt_len = sizeof(int);
				if (getsockopt(connection.sockd, SOL_SOCKET,
					SO_ERROR, &val_opt, &opt_len) >= 0) {
					if (0 == val_opt) {
						b_connected = TRUE;
						smtp_deliverer_destination_audit(destination_ip);
						/* set socket back to block mode */
						opt = fcntl(connection.sockd, F_GETFL, 0);
						opt &= (~O_NONBLOCK);
						fcntl(connection.sockd, F_SETFL, opt);
						/* end of set mode */
					}
				}
			}
		} 
	}
	if (FALSE == b_connected) {
		close(connection.sockd);
		smtp_deliverer_log_info(pcontext, 8, "cannot connect"
				" to destination server %s", destination_ip);
        return SMTP_DELIVERER_CANNOT_CONNECT;
	}
	/* read welcome information of MTA */
	if (FALSE == smtp_deliverer_get_response(&connection,
		response_line, length, &reason, FALSE)) {
		if (SMTP_DELIVERER_TIME_OUT == reason) {
			smtp_deliverer_log_info(pcontext, 8, "time out");
		} else {
			smtp_deliverer_log_info(pcontext, 8, "remote MTA "
				"answer \"%s\" after connection", response_line);
			/* change reason to connection refused */
			if (SMTP_DELIVERER_PERMANENT_ERROR == reason) {
				reason = SMTP_DELIVERER_CONNECTION_REFUSED;
			}
			strcpy(command_line, "quit\r\n");
           	/* send quit command to server */
           	smtp_deliverer_send_command(&connection, command_line, 6);
		}
		close(connection.sockd);
		return reason;
	}
SESSION_BEGIN:
	/* send ehlo xxx to server */
	if (TRUE == smtp_deliverer_hello_mx_query(pdomain)) {
		command_len = sprintf(command_line, "ehlo %s\r\n",
				strchr(pcontext->pcontrol->from, '@') + 1);
	} else {
		command_len = sprintf(command_line,
			"ehlo %s\r\n", get_host_ID());
	}
	if (FALSE == smtp_deliverer_send_command(
		&connection, command_line, command_len)) {
		smtp_deliverer_log_info(pcontext, 8, "time out");
		smtp_deliverer_close_connection(&connection);
		return SMTP_DELIVERER_TIME_OUT;
	}
	/* read helo response information */
	if (FALSE == smtp_deliverer_get_response(&connection,
		response_line, length, &reason, FALSE)) {
		if (SMTP_DELIVERER_TIME_OUT == reason) {
			smtp_deliverer_log_info(pcontext, 8, "time out");
			smtp_deliverer_close_connection(&connection);
			return SMTP_DELIVERER_TIME_OUT;
		} else {
			/* send helo xxx to server */
			if (TRUE == smtp_deliverer_hello_mx_query(pdomain)) {
				command_len = sprintf(command_line, "helo %s\r\n",
						strchr(pcontext->pcontrol->from, '@') + 1);
			} else {
				command_len = sprintf(command_line,
					"helo %s\r\n", get_host_ID());
			}
			if (FALSE == smtp_deliverer_send_command(
				&connection, command_line, command_len)) {
				smtp_deliverer_log_info(pcontext, 8, "time out");
				smtp_deliverer_close_connection(&connection);
				return SMTP_DELIVERER_TIME_OUT;
			}
			if (FALSE == smtp_deliverer_get_response(&connection,
				response_line, length, &reason, FALSE)) {
				if (SMTP_DELIVERER_TIME_OUT == reason) {
					smtp_deliverer_log_info(pcontext, 8, "time out");
				} else {
					smtp_deliverer_log_info(pcontext, 8,
						"remote MTA answer \"%s\" after "
						"\"helo\" command", response_line);
					strcpy(command_line, "quit\r\n");
					/* send quit command to server */
					smtp_deliverer_send_command(
						&connection, command_line, 6);
				}
				smtp_deliverer_close_connection(&connection);
				return reason;
			}
		}
	} else {
		if (TRUE == g_tls_switch && NULL == connection.ssl) {
			if (NULL != search_string(response_line,
				"250-STARTTLS", 1024) ||
				NULL != search_string(response_line,
				"250 STARTTLS", 1024)) {
				strcpy(command_line, "starttls\r\n");
				/* send starttls command to server */
				if (FALSE == smtp_deliverer_send_command(
					&connection, command_line, 10)) {
					smtp_deliverer_log_info(pcontext, 8, "time out");
					close(connection.sockd);
					return SMTP_DELIVERER_TIME_OUT;	
				}
				if (FALSE == smtp_deliverer_get_response(&connection,
					response_line, length, &reason, FALSE)) {
					if (SMTP_DELIVERER_TIME_OUT == reason) {
						smtp_deliverer_log_info(pcontext, 8, "time out");
					} else {
						smtp_deliverer_log_info(pcontext, 8,
							"remote MTA answer \"%s\" after "
							"\"starttls\" command", response_line);
					}
					close(connection.sockd);
					return SMTP_DELIVERER_CANNOT_CONNECT;
				}
				connection.ssl = SSL_new(g_ssl_ctx);	
				if (NULL == connection.ssl) {
					smtp_deliverer_log_info(pcontext, 8,
						"fail to init ssl connection");
					close(connection.sockd);
					return SMTP_DELIVERER_CANNOT_CONNECT;
				}
				SSL_set_fd(connection.ssl, connection.sockd);
				if (1 != SSL_connect(connection.ssl)) {
					smtp_deliverer_log_info(pcontext, 8,
						"cannot establish TLS connection to "
						"destination server %s", destination_ip);
					smtp_deliverer_close_connection(&connection);
					return SMTP_DELIVERER_CANNOT_CONNECT;
				}
				goto SESSION_BEGIN;
			}
		}
		/* try to get the size information after ehlo command */
		ptr = search_string(response_line, "size", 1024);
		if (NULL != ptr) {
			ptr += 4;
			/* 250-AUTH LOGIN
			 * 250-SIZE       //no size number after size
			 * 250 8BITMIME
			 * program should be aware of this situation 
			 */
			while (ptr < response_line + 1024) {
				if (0 != isdigit(*ptr) || '\r' == *ptr) {
					break;
				}
				ptr ++;
			}
			pbegin = ptr;
			while (ptr < response_line + 1024) {
				if (0 == isdigit(*ptr)) {
					break;
				}
				ptr ++;
			}
			pend = ptr;
			if (pbegin == pend) {
				size = 0;
			}
			if (pend - pbegin <= 31) {
				memcpy(ehlo_size, pbegin, pend - pbegin);
				ehlo_size[pend - pbegin] = '\0';
				size = atol(ehlo_size);
			} else {
				size = 0;
			}
			/* check if the size allowed is larger than mail itself */
			mail_len = mail_get_length(pcontext->pmail);
			if (-1 == mail_len) {
				printf("[remote_postman]: fail to get mail length\n");
			} else {
				if (0 != size && size < mail_len) {
					bytetoa(size, response_line);
					smtp_deliverer_log_info(pcontext, 8,
						"remote MTA can only accept mails whose"
						" size are less than %s", response_line);
					strcpy(command_line, "quit\r\n");
					/* send quit command to server */
					smtp_deliverer_send_command(
						&connection, command_line, 6);
					smtp_deliverer_close_connection(&connection);
					return SMTP_DELIVERER_EXCEED_SIZE;
				}
			}
		}
	}
	/* send mail from:<...> */
	if (0 == strcmp(pcontext->pcontrol->from, "none@none")) {
		command_len = 14;
		strcpy(command_line, "mail from:<>\r\n");
	} else {
		command_len = sprintf(command_line,
					"mail from:<%s>\r\n",
					pcontext->pcontrol->from);
	}
	if (FALSE == smtp_deliverer_send_command(
		&connection, command_line, command_len)) {
		smtp_deliverer_log_info(pcontext, 8, "time out");
		smtp_deliverer_close_connection(&connection);
		return SMTP_DELIVERER_TIME_OUT;
	}
	/* read mail from response information */
    if (FALSE == smtp_deliverer_get_response(&connection,
		response_line, length, &reason, FALSE)) {
        if (SMTP_DELIVERER_TIME_OUT == reason) {
            smtp_deliverer_log_info(pcontext, 8, "time out");
        } else {
            smtp_deliverer_log_info(pcontext, 8,
				"remote MTA answer \"%s\" after"
				" \"mail from\"", response_line);
			strcpy(command_line, "quit\r\n");
            /* send quit command to server */
            smtp_deliverer_send_command(
				&connection, command_line, 6);
        }
		smtp_deliverer_close_connection(&connection);
        return reason;
    }
	/* send rcpt to:<...> */
	mem_file_init(&f_fail_rcpt, files_allocator_get_allocator());
	rcpt_success = FALSE;
	while (MEM_END_OF_FILE != mem_file_readline(
		&pcontext->pcontrol->f_rcpt_to, rcpt_to, 256)) {
		command_len = sprintf(command_line, "rcpt to:<%s>\r\n", rcpt_to);
		if (FALSE == smtp_deliverer_send_command(
			&connection, command_line, command_len)) {
			smtp_deliverer_log_info(pcontext, 8, "time out");
			mem_file_free(&f_fail_rcpt);
			smtp_deliverer_close_connection(&connection);
            return SMTP_DELIVERER_TIME_OUT;
		}

		/* read rcpt to response information */
        if (FALSE == smtp_deliverer_get_response(&connection,
			response_line, length, &reason, FALSE)) {
            if (SMTP_DELIVERER_TIME_OUT == reason) {
                smtp_deliverer_log_info(pcontext, 8, "time out");
				mem_file_free(&f_fail_rcpt);
				smtp_deliverer_close_connection(&connection);
				return SMTP_DELIVERER_TIME_OUT;
            } else if (SMTP_DELIVERER_PERMANENT_ERROR == reason) {
				if (BOUND_IN == pcontext->pcontrol->bound_type ||
					BOUND_OUT == pcontext->pcontrol->bound_type ||
					BOUND_RELAY == pcontext->pcontrol->bound_type) {
					log_info(8, "SMTP message queue-ID: %d, FROM: %s, "
						"TO: ... seems there's no user %s in remote system,"
						" response: \"%s\"", pcontext->pcontrol->queue_ID,
						pcontext->pcontrol->from, rcpt_to, response_line);
				} else {
					log_info(8, "APP created message FROM: %s, TO: ..."
						" seems there's no user %s in remote system, "
						"response: \"%s\"", pcontext->pcontrol->from,
						rcpt_to, response_line);
				}
				mem_file_writeline(&f_fail_rcpt, rcpt_to);
            } else {
				smtp_deliverer_log_info(pcontext, 8, "remote MTA answer "
					"\"%s\" after \"rcpt to <%s>\"", response_line, rcpt_to);
				strcpy(command_line, "quit\r\n");
				/* send quit command to server */
				smtp_deliverer_send_command(&connection, command_line, 6);
				mem_file_free(&f_fail_rcpt);
				smtp_deliverer_close_connection(&connection);
				return reason;
			}
        } else {
			rcpt_success = TRUE;
		}
	}
	if (FALSE == rcpt_success) {
		smtp_deliverer_log_info(pcontext, 8,
			"all recipients fail, stop delivering");
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		smtp_deliverer_send_command(&connection, command_line, 6);
		mem_file_free(&f_fail_rcpt);
		smtp_deliverer_close_connection(&connection);
		return SMTP_DELIVERER_NO_USER;
	}
	/* send data */
	strcpy(command_line, "data\r\n");
	if (FALSE == smtp_deliverer_send_command(
		&connection, command_line, 6)) {
		smtp_deliverer_log_info(pcontext, 8, "time out");
		mem_file_free(&f_fail_rcpt);
		smtp_deliverer_close_connection(&connection);
        return SMTP_DELIVERER_TIME_OUT;
	}
	/* read data response information */
    if (FALSE == smtp_deliverer_get_response(&connection,
		response_line, length, &reason, TRUE)) {
        if (SMTP_DELIVERER_TIME_OUT == reason) {
            smtp_deliverer_log_info(pcontext, 8, "time out");
        } else {
            smtp_deliverer_log_info(pcontext, 8, "remote MTA "
				"answer \"%s\" after \"data\" command", response_line);
			strcpy(command_line, "quit\r\n");
            /* send quit command to server */
            smtp_deliverer_send_command(&connection, command_line, 6);
        }
		mem_file_free(&f_fail_rcpt);
		smtp_deliverer_close_connection(&connection);
		return reason;
    }
	if (NULL != connection.ssl) {
		b_data = mail_to_ssl(pcontext->pmail, connection.ssl);
	} else {
		b_data = mail_to_file(pcontext->pmail, connection.sockd);
	}
	if (FALSE == b_data) {
		reason = SMTP_DELIVERER_UNKOWN_RESPONSE;
		smtp_deliverer_get_response(&connection,
			response_line, length, &reason, FALSE);
		if (SMTP_DELIVERER_TIME_OUT == reason) {
            smtp_deliverer_log_info(pcontext, 8, "time out");
		} else {
			smtp_deliverer_log_info(pcontext, 8, "remote MTA "
				"answer \"%s\" when sending mail content", response_line);
			strcpy(command_line, "quit\r\n");
            /* send quit command to server */
            smtp_deliverer_send_command(&connection, command_line, 6);
		}
		mem_file_free(&f_fail_rcpt);
		smtp_deliverer_close_connection(&connection);
		return reason;
	}
	/* send .\r\n */
	strcpy(command_line, ".\r\n");
	if (FALSE == smtp_deliverer_send_command(
		&connection, command_line, 3)) {
		smtp_deliverer_log_info(pcontext, 8, "time out");
		mem_file_free(&f_fail_rcpt);
		smtp_deliverer_close_connection(&connection);
		return SMTP_DELIVERER_TIME_OUT;
	}
	if (FALSE == smtp_deliverer_get_response(&connection,
		response_line, length, &reason, FALSE)) {
		if (SMTP_DELIVERER_TIME_OUT == reason) {
			smtp_deliverer_log_info(pcontext, 8, "time out");
		} else {
			smtp_deliverer_log_info(pcontext, 8,
				"remote MTA answer \"%s\" when "
				"finishing delivery", response_line);
			strcpy(command_line, "quit\r\n");
            /* send quit command to server */
            smtp_deliverer_send_command(&connection, command_line, 6);
		}
		mem_file_free(&f_fail_rcpt);
		smtp_deliverer_close_connection(&connection);
		return reason;
	} else {
		if (NULL != connection.ssl) {
			smtp_deliverer_log_info(pcontext, 8, "remote "
				"MTA %s return OK via TLS", destination_ip);
		} else {
			smtp_deliverer_log_info(pcontext, 8, "remote"
					" MTA %s return OK", destination_ip);
		}
	}
	strcpy(command_line, "quit\r\n");
	/* send quit command to server */
	smtp_deliverer_send_command(&connection, command_line, 6);
	smtp_deliverer_close_connection(&connection);
	if (0 != mem_file_get_total_length(&f_fail_rcpt)) {
		mem_file_copy(&f_fail_rcpt, &pcontext->pcontrol->f_rcpt_to);
		mem_file_free(&f_fail_rcpt);
		smtp_deliverer_log_info(pcontext, 8,
			"remote MTA hasn't these users");
		return SMTP_DELIVERER_NO_USER;
	}
	mem_file_free(&f_fail_rcpt);
	return SMTP_DELIVERER_OK;
}

/*
 *	try to send mail(s) to destination(s)
 *	@param
 *		pcontext [in]		sending context
 *		response_line [out]	buffer for saving response of remote MTA
 *		length				buffer length
 *	@return
 *		result of delivery
 */
int smtp_deliverer_process(MESSAGE_CONTEXT *pcontext,
	char *ip_addr, char *response_line, int length)
{
	BOOL b_tried;
	char rcpt_to[256];
	char *destination_ip;
	char *pdomain;
	int result, i;
	VSTACK stack;
	
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
			MEM_FILE_SEEK_BEGIN);
	mem_file_readline(&pcontext->pcontrol->f_rcpt_to, rcpt_to, 256);
	pdomain = strchr(rcpt_to, '@');
	if (NULL == pdomain) {
		return SMTP_DELIVERER_DNS_ERROR;
	}
	pdomain ++;
	/* try to find domain's corresponding IP */
	vstack_init(&stack, g_stack_allocator, 16, 1024);
	if (FALSE == sender_routing_check(pcontext->pcontrol->from, &stack)) {
		if (FALSE == smtp_deliverer_dns_query_MX(pdomain, &stack)) {
			if (FALSE == smtp_deliverer_dns_query_A(pdomain, &stack)) {
				smtp_deliverer_log_info(pcontext, 8, "cannot "
					"find any IP corresponding to %s", pdomain);
				vstack_free(&stack);
				return SMTP_DELIVERER_DNS_ERROR;
			}
		}
	}
	b_tried = FALSE;
	result = SMTP_DELIVERER_CANNOT_CONNECT;
	/* try to connect to the destination MTA */
	while (FALSE == vstack_is_empty(&stack)) {
		destination_ip = vstack_get_top(&stack);
		strncpy(ip_addr, destination_ip, 16);
		if (0 == strncmp(destination_ip, "0.", 2) ||
			0 == strncmp(destination_ip, "127.", 4) ||
			(NULL != smtp_deliverer_destination_forbidden &&
			TRUE == smtp_deliverer_destination_forbidden(destination_ip))) {
			b_tried = TRUE;
			result = SMTP_DELIVERER_CANNOT_CONNECT;
			vstack_pop(&stack);
			continue;
		}
		if (TRUE == smtp_deliverer_destination_query(destination_ip)) {
			vstack_pop(&stack);
			continue;
		}
		for (i=0; i<g_trying_times; i++) {
			result = smtp_deliverer_send_mail(pcontext, pdomain,
						destination_ip, response_line, length);
			b_tried = TRUE;
			if (SMTP_DELIVERER_OK == result ||
				SMTP_DELIVERER_CANNOT_CONNECT == result ||
				SMTP_DELIVERER_CONNECTION_REFUSED == result ||
				SMTP_DELIVERER_EXCEED_SIZE == result ||
				SMTP_DELIVERER_NO_USER == result ||
				SMTP_DELIVERER_PERMANENT_ERROR == result) {
				break;
			}
		}
		if (SMTP_DELIVERER_OK == result ||
			SMTP_DELIVERER_EXCEED_SIZE == result ||
			SMTP_DELIVERER_NO_USER == result ||
			SMTP_DELIVERER_PERMANENT_ERROR == result) {
			break;
		}
		vstack_pop(&stack);
	}
	vstack_free(&stack);
	if (FALSE == b_tried) {
		return SMTP_DELIVERER_GIVE_UP;
	} else {
		return result;
	}
}

/*
 *	log message into log file
 *	@param
 *		pcontext [in]		sending context
 *		level				log level
 *		format [in]			control string
 *		...
 */
void smtp_deliverer_log_info(MESSAGE_CONTEXT *pcontext,
	int level, char *format, ...)
{
	char log_buf[2048], rcpt_buff[2048];
	size_t size_read = 0, rcpt_len = 0, i;
	va_list ap;

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	log_buf[sizeof(log_buf) - 1] = '\0';

	/* maximum record 8 rcpt to address */
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
					MEM_FILE_SEEK_BEGIN);
	for (i=0; i<8; i++) {
		size_read = mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
					                  rcpt_buff + rcpt_len, 256);
		if (size_read == MEM_END_OF_FILE) {
			break;
		}
		rcpt_len += size_read;
		rcpt_buff[rcpt_len] = ' ';
		rcpt_len ++;
	}
	rcpt_buff[rcpt_len] = '\0';

	switch (pcontext->pcontrol->bound_type) {
	case BOUND_IN:
	case BOUND_OUT:
	case BOUND_RELAY:
		log_info(level, "SMTP message queue-ID: %d, FROM: %s, TO: %s %s",
			pcontext->pcontrol->queue_ID, pcontext->pcontrol->from,
			rcpt_buff, log_buf);
		break;
	default:
		log_info(level, "APP created message FROM: %s, TO: %s %s",
			pcontext->pcontrol->from, rcpt_buff, log_buf);
		break;
	}
}

void smtp_deliverer_set_param(int param, int val)
{
	switch (param) {
	case SMTP_DELIVERER_TRYING_TIMES:
		g_trying_times = val;
		break;
	case SMTP_DELIVERER_SSL_SWITCH:
		g_tls_switch = val;
		break;
	}
}

int smtp_deliverer_get_param(int param)
{
	switch (param) {
	case SMTP_DELIVERER_TRYING_TIMES:
		return g_trying_times;
	case SMTP_DELIVERER_SSL_SWITCH:
		return g_tls_switch;
	}
	return -1;
}
