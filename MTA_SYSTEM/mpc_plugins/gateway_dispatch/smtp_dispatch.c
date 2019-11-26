#include <ctype.h>
#include "smtp_dispatch.h"
#include "files_allocator.h"
#include "backend_list.h"
#include "util.h"
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>

#define SOCKET_TIMEOUT			30

enum {
	SMTP_DISPATCH_RESPONSE_TIMEOUT,
	SMTP_DISPATCH_RESPONSE_OK,
	SMTP_DISPATCH_RESPONSE_TMPFAIL,
	SMTP_DISPATCH_RESPONSE_PMTFAIL
};

static char g_mask_string[1024];

static BOOL smtp_dispatch_send_command(int sockd, const char *command,
	int command_len);

static int smtp_dispatch_get_response(int sockd, char *response,
	int response_len, BOOL expect_3xx);

static BOOL smtp_dispatch_check_maskstring(const char *string);

/*
 *	smtp deliverer's construct function
 *	@param
 *		mask_string	[in]		mask string for checking user's exsitence
 */
void smtp_dispatch_init(const char *mask_string)
{
	char *ptr;

	if (NULL == mask_string) {
		g_mask_string[0] = '\0';
	} else {
		memset(g_mask_string, 0, 1024);
		strcpy(g_mask_string, mask_string);
		ptr = g_mask_string;
		while (ptr = strchr(ptr, '|')) {
			*ptr = '\0';
			ptr ++;
		}
	}
}

/*
 *	run the smtp module
 *	@return
 *		 0			OK
 *		<>0			fail
 */
int smtp_dispatch_run()
{
	return 0;
}

/*
 *	stop the module
 *	@return
 *		 0			OK
 *		<>0			fail
 */
int smtp_dispatch_stop()
{
	return 0;
}

/*
 *	module's destruct function
 */
void smtp_dispatch_free()
{
	g_mask_string[0] = '\0';
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
int smtp_dispatch_process(MESSAGE_CONTEXT *pcontext,
	char *dest_ip, char *response_line, int length)
{
	char rcpt_to[256];
	char command_line[512];
	int sockd, port;
	int command_len;
	BOOL rcpt_success;
	MEM_FILE f_fail_rcpt;
	struct sockaddr_in servaddr;
	
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
			MEM_FILE_SEEK_BEGIN);
	mem_file_readline(&pcontext->pcontrol->f_rcpt_to, rcpt_to, 256);
	/* try to find domain's corresponding IP */
	if (FALSE == backend_list_get_unit(dest_ip, &port)) {
		smtp_dispatch_log_info(pcontext, 8, "cannot get one back-end server "
			"to send the message");
		strncpy(response_line, "no back-end server alive", length);
		return SMTP_DISPATCH_TEMP_ERROR;
	}
	
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
			MEM_FILE_SEEK_BEGIN);
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, dest_ip, &servaddr.sin_addr);
	if (0 != connect(sockd, (struct sockaddr*)&servaddr,sizeof(servaddr))) {
		close(sockd);
		smtp_dispatch_log_info(pcontext, 8, "cannot connect to back-end server"
			" %s:%d", dest_ip, port);
		strncpy(response_line, "no back-end server alive", length);
		backend_list_invalid_unit(dest_ip, port);
		return SMTP_DISPATCH_TEMP_ERROR;
	}
	/* read welcome information of MTA */
	switch (smtp_dispatch_get_response(sockd, response_line, length, FALSE)) {
	case SMTP_DISPATCH_RESPONSE_TIMEOUT:
		snprintf(response_line, length, "time out to back-end server %s:%d",
			dest_ip, port);
		smtp_dispatch_log_info(pcontext, 8, "time out");
		close(sockd);
		return SMTP_DISPATCH_TEMP_ERROR;
	case SMTP_DISPATCH_RESPONSE_TMPFAIL:
	case SMTP_DISPATCH_RESPONSE_PMTFAIL:
		smtp_dispatch_log_info(pcontext, 8, "back-end server %s:%d answer "
			"\"%s\" after connection", dest_ip, port, response_line);
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_dispatch_send_command(sockd, command_line, 6);
		close(sockd);
		return SMTP_DISPATCH_TEMP_ERROR;
	}

	command_len = sprintf(command_line, "helo %s\r\n", get_host_ID());
	if (FALSE == smtp_dispatch_send_command(sockd, command_line, command_len)) {
		snprintf(response_line, length, "time out to back-end server %s:%d",
			dest_ip, port);
		smtp_dispatch_log_info(pcontext, 8, "time out");
		close(sockd);
		return SMTP_DISPATCH_TEMP_ERROR;
	}
	switch (smtp_dispatch_get_response(sockd, response_line, length, FALSE)) {
	case SMTP_DISPATCH_RESPONSE_TIMEOUT:
		snprintf(response_line, length, "time out to back-end server %s:%d",
			dest_ip, port);
		smtp_dispatch_log_info(pcontext, 8, "time out");
		close(sockd);
		return SMTP_DISPATCH_TEMP_ERROR;
	case SMTP_DISPATCH_RESPONSE_TMPFAIL:
	case SMTP_DISPATCH_RESPONSE_PMTFAIL:
		smtp_dispatch_log_info(pcontext, 8, "back-end server %s:%d answer "
			"\"%s\" after \"helo\" command", dest_ip, port, response_line);
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		smtp_dispatch_send_command(sockd, command_line, 6);
		close(sockd);
		return SMTP_DISPATCH_TEMP_ERROR;
	}

	/* send mail from:<...> */
	command_len = sprintf(command_line, "mail from:<%s>\r\n",
					pcontext->pcontrol->from);
	if (FALSE == smtp_dispatch_send_command(sockd, command_line, command_len)) {
		snprintf(response_line, length, "time out to back-end server %s:%d",
			dest_ip, port);
		smtp_dispatch_log_info(pcontext, 8, "time out");
		close(sockd);
		return SMTP_DISPATCH_TEMP_ERROR;
	}
	/* read mail from response information */
    switch (smtp_dispatch_get_response(sockd, response_line, length, FALSE)) {
    case SMTP_DISPATCH_RESPONSE_TIMEOUT:
		snprintf(response_line, length, "time out to back-end server %s:%d",
			dest_ip, port);
        smtp_dispatch_log_info(pcontext, 8, "time out");
		close(sockd);
		return SMTP_DISPATCH_TEMP_ERROR;
	case SMTP_DISPATCH_RESPONSE_TMPFAIL:
        smtp_dispatch_log_info(pcontext, 8, "back-end server %s:%d answer "
			"\"%s\" after \"mail from\"", dest_ip, port, response_line);
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_dispatch_send_command(sockd, command_line, 6);
		close(sockd);
		return SMTP_DISPATCH_TEMP_ERROR;
	case SMTP_DISPATCH_RESPONSE_PMTFAIL:
        smtp_dispatch_log_info(pcontext, 8, "back-end server %s:%d answer "
			"\"%s\" after \"mail from\"", dest_ip, port, response_line);
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_dispatch_send_command(sockd, command_line, 6);
		close(sockd);
		return SMTP_DISPATCH_PERMANENT_ERROR;
    }

	/* send rcpt to:<...> */
	mem_file_init(&f_fail_rcpt, files_allocator_get_allocator());
	rcpt_success = FALSE;
	while (MEM_END_OF_FILE != mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
		rcpt_to, 256)) {
		command_len = sprintf(command_line, "rcpt to:<%s>\r\n", rcpt_to);
		if (FALSE == smtp_dispatch_send_command(sockd, command_line,
			command_len)) {
			snprintf(response_line, length, "time out to back-end server %s:%d",
				dest_ip, port);
			smtp_dispatch_log_info(pcontext, 8, "time out");
			mem_file_free(&f_fail_rcpt);
			close(sockd);
            return SMTP_DISPATCH_TEMP_ERROR;
		}

		/* read rcpt to response information */
        switch (smtp_dispatch_get_response(sockd, response_line, length, 
			FALSE)) {
		case SMTP_DISPATCH_RESPONSE_TIMEOUT:
			snprintf(response_line, length, "time out to back-end server %s:%d",
				dest_ip, port);
            smtp_dispatch_log_info(pcontext, 8, "time out");
			mem_file_free(&f_fail_rcpt);
			close(sockd);
			return SMTP_DISPATCH_TEMP_ERROR;
        case SMTP_DISPATCH_RESPONSE_PMTFAIL:
			if (BOUND_IN == pcontext->pcontrol->bound_type ||
				BOUND_OUT == pcontext->pcontrol->bound_type ||
				BOUND_RELAY == pcontext->pcontrol->bound_type) {
				log_info(8, "SMTP message queue-ID: %d, FROM: %s, TO: ... "
					"seems there's no user %s in mail system, response: "
					"\"%s\"", pcontext->pcontrol->queue_ID,
					pcontext->pcontrol->from, rcpt_to, response_line);
			} else {
				log_info(8, "APP created message FROM: %s, TO: ... "
					"seems there's no user %s in mail system, response: "
					"\"%s\"", pcontext->pcontrol->from, rcpt_to, response_line);
			}
			mem_file_writeline(&f_fail_rcpt, rcpt_to);
			break;
        case SMTP_DISPATCH_RESPONSE_TMPFAIL:
			if (TRUE == smtp_dispatch_check_maskstring(response_line)) {
				if (BOUND_IN == pcontext->pcontrol->bound_type ||
					BOUND_OUT == pcontext->pcontrol->bound_type ||
					BOUND_RELAY == pcontext->pcontrol->bound_type) {
					log_info(8, "SMTP message queue-ID: %d, FROM: %s, "
						"TO: ... seems there's no user %s in mail system, "
						"response: \"%s\"", pcontext->pcontrol->queue_ID,
						pcontext->pcontrol->from, rcpt_to, response_line);
				} else {
					log_info(8, "APP created message FROM: %s, TO: ... "
						"seems there's no user %s in mail system, response: "
						"\"%s\"", pcontext->pcontrol->from, rcpt_to,
						response_line);
				}
				mem_file_writeline(&f_fail_rcpt, rcpt_to);
			} else {
				smtp_dispatch_log_info(pcontext, 8, "back-end server %s:%d"
					" answer \"%s\" after \"rcpt to <%s>\"", dest_ip, port,
					response_line, rcpt_to);
				strcpy(command_line, "quit\r\n");
				/* send quit command to server */
				smtp_dispatch_send_command(sockd, command_line, 6);
				mem_file_free(&f_fail_rcpt);
				close(sockd);
				return SMTP_DISPATCH_TEMP_ERROR;
			}
			break;
		case SMTP_DISPATCH_RESPONSE_OK:
			rcpt_success = TRUE;
			break;
		}
	}
	if (FALSE == rcpt_success) {
		smtp_dispatch_log_info(pcontext, 8, "all recipients fail, stop "
			"delivering");
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_dispatch_send_command(sockd, command_line, 6);
		mem_file_free(&f_fail_rcpt);
		close(sockd);
		return SMTP_DISPATCH_NO_USER;
	}
	
	/* send data */
	strcpy(command_line, "data\r\n");
	if (FALSE == smtp_dispatch_send_command(sockd, command_line, 6)) {
		snprintf(response_line, length, "time out to back-end server %s:%d",
			dest_ip, port);
		smtp_dispatch_log_info(pcontext, 8, "time out");
		mem_file_free(&f_fail_rcpt);
		close(sockd);
        return SMTP_DISPATCH_TEMP_ERROR;
	}

	/* read data response information */
    switch (smtp_dispatch_get_response(sockd, response_line, length, TRUE)) {
    case SMTP_DISPATCH_RESPONSE_TIMEOUT:
		snprintf(response_line, length, "time out to back-end server %s:%d",
			dest_ip, port);
        smtp_dispatch_log_info(pcontext, 8, "time out");
		mem_file_free(&f_fail_rcpt);
		close(sockd);
		return SMTP_DISPATCH_TEMP_ERROR;
    case SMTP_DISPATCH_RESPONSE_TMPFAIL:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_dispatch_send_command(sockd, command_line, 6);
		mem_file_free(&f_fail_rcpt);
		close(sockd);
		smtp_dispatch_log_info(pcontext, 8, "back-end server %s:%d answer "
			"\"%s\" after \"data\" command", dest_ip, port, response_line);
		if (TRUE == smtp_dispatch_check_maskstring(response_line)) {
			return SMTP_DISPATCH_NO_USER;
		} else {
			return SMTP_DISPATCH_TEMP_ERROR;
		}
	case SMTP_DISPATCH_RESPONSE_PMTFAIL:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_dispatch_send_command(sockd, command_line, 6);
		mem_file_free(&f_fail_rcpt);
		close(sockd);
		smtp_dispatch_log_info(pcontext, 8, "back-end server %s:%d answer "
			"\"%s\" after \"data\" command", dest_ip, port, response_line);
		if (TRUE == smtp_dispatch_check_maskstring(response_line)) {
			return SMTP_DISPATCH_NO_USER;
		} else {
			return SMTP_DISPATCH_PERMANENT_ERROR;
		}
    }

	if (FALSE == mail_to_file(pcontext->pmail, sockd)) {
		switch (smtp_dispatch_get_response(sockd, response_line, length,
			FALSE)) {
		case SMTP_DISPATCH_RESPONSE_TIMEOUT:
			snprintf(response_line, length, "time out to back-end server %s:%d",
				dest_ip, port);
            smtp_dispatch_log_info(pcontext, 8, "time out");
			mem_file_free(&f_fail_rcpt);
			close(sockd);
			return SMTP_DISPATCH_TEMP_ERROR;
		case SMTP_DISPATCH_RESPONSE_TMPFAIL:
			strcpy(command_line, "quit\r\n");
            /* send quit command to server */
            smtp_dispatch_send_command(sockd, command_line, 6);
			mem_file_free(&f_fail_rcpt);
			close(sockd);
			smtp_dispatch_log_info(pcontext, 8, "back-end server %s:%d answer "
				"\"%s\" when sending mail content", dest_ip, port,
				response_line);
			if (TRUE == smtp_dispatch_check_maskstring(response_line)) {
				return SMTP_DISPATCH_NO_USER;
			} else {
				return SMTP_DISPATCH_TEMP_ERROR;
			}
		case SMTP_DISPATCH_RESPONSE_PMTFAIL:
			strcpy(command_line, "quit\r\n");
            /* send quit command to server */
            smtp_dispatch_send_command(sockd, command_line, 6);
			mem_file_free(&f_fail_rcpt);
			close(sockd);
			smtp_dispatch_log_info(pcontext, 8, "back-end server %s:%d answer "
				"\"%s\" when sending mail content", dest_ip, port,
				response_line);
			if (TRUE == smtp_dispatch_check_maskstring(response_line)) {
				return SMTP_DISPATCH_NO_USER;
			} else {
				return SMTP_DISPATCH_PERMANENT_ERROR;
			}
		}
	}
	/* send .\r\n */
	strcpy(command_line, ".\r\n");
	if (FALSE == smtp_dispatch_send_command(sockd, command_line, 3)) {
		snprintf(response_line, length, "time out to back-end server %s:%d",
			dest_ip, port);
		smtp_dispatch_log_info(pcontext, 8, "time out");
		mem_file_free(&f_fail_rcpt);
		close(sockd);
		return SMTP_DISPATCH_TEMP_ERROR;
	}
	switch (smtp_dispatch_get_response(sockd, response_line, length, FALSE)) {
	case SMTP_DISPATCH_RESPONSE_TIMEOUT:
		snprintf(response_line, length, "time out to back-end server %s:%d",
			dest_ip, port);
		smtp_dispatch_log_info(pcontext, 8, "time out");
		mem_file_free(&f_fail_rcpt);
		close(sockd);
		return SMTP_DISPATCH_TEMP_ERROR;
	case SMTP_DISPATCH_RESPONSE_TMPFAIL:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_dispatch_send_command(sockd, command_line, 6);
		mem_file_free(&f_fail_rcpt);
		close(sockd);
		smtp_dispatch_log_info(pcontext, 8, "back-end server %s:%d answer "
			"\"%s\" when finishing delivery", dest_ip, port, response_line);
		if (TRUE == smtp_dispatch_check_maskstring(response_line)) {
			return SMTP_DISPATCH_NO_USER;
		} else {
			return SMTP_DISPATCH_TEMP_ERROR;
		}
	case SMTP_DISPATCH_RESPONSE_PMTFAIL:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_dispatch_send_command(sockd, command_line, 6);
		mem_file_free(&f_fail_rcpt);
		close(sockd);
		smtp_dispatch_log_info(pcontext, 8, "back-end server %s:%d answer "
			"\"%s\" when finishing delivery", dest_ip, port, response_line);
		if (TRUE == smtp_dispatch_check_maskstring(response_line)) {
			return SMTP_DISPATCH_NO_USER;
		} else {
			return SMTP_DISPATCH_PERMANENT_ERROR;
		}
	case SMTP_DISPATCH_RESPONSE_OK:
		smtp_dispatch_log_info(pcontext, 8, "back-end server %s:%d return OK",
			dest_ip, port);
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		smtp_dispatch_send_command(sockd, command_line, 6);
		close(sockd);
		if (0 != mem_file_get_total_length(&f_fail_rcpt)) {
			mem_file_copy(&f_fail_rcpt, &pcontext->pcontrol->f_rcpt_to);
			mem_file_free(&f_fail_rcpt);
			smtp_dispatch_log_info(pcontext, 8, "mail system hasn't these "
				"users");
			return SMTP_DISPATCH_NO_USER;
		} else {
			mem_file_free(&f_fail_rcpt);
			return SMTP_DISPATCH_OK;
		}
	}
	return SMTP_DISPATCH_PERMANENT_ERROR;
}


/*
 *	send a command string to destination
 *	@param
 *		sockd				socket fd
 *		command [in]		command string to be sent
 *		command_len			command string length
 *	@return
 *		TRUE				OK
 *		FALSE				time out
 */
static BOOL smtp_dispatch_send_command(int sockd, const char *command,
	int command_len)
{
	int write_len;

	write_len = write(sockd, command, command_len);
    if (write_len != command_len) {
		return FALSE;
	}
	return TRUE;
}

/*
 *	get response from server
 *	@param
 *		sockd					socket fd
 *		response [out]			buffer for save response
 *		response_len			response buffer length
 *		expect_3xx				expect smtp return code 3XX
 *	@retrun
 *		SMTP_DISPATCH_RESPONSE_TIMEOUT
 *		SMTP_DISPATCH_RESPONSE_OK
 *		SMTP_DISPATCH_RESPONSE_TMPFAIL
 *		SMTP_DISPATCH_RESPONSE_PMTFAIL
 */
static int smtp_dispatch_get_response(int sockd, char *response,
	int response_len, BOOL expect_3xx)
{
	int read_len;
	fd_set myset;
	struct timeval tv;

	/* wait the socket data to be available */ 
	tv.tv_sec = SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&myset);
	FD_SET(sockd, &myset);
	if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
		return SMTP_DISPATCH_RESPONSE_TIMEOUT;
	}
	memset(response, 0, response_len);
	read_len = read(sockd, response, response_len);
	if (-1 == read_len || 0 == read_len) {
		return SMTP_DISPATCH_RESPONSE_TIMEOUT;
	}
	if ('\n' == response[read_len - 1] && '\r' == response[read_len - 2]){
		/* remove /r/n at the end of response */
		read_len -= 2;
	}
	response[read_len] = '\0';
	if (FALSE == expect_3xx && '2' == response[0] &&
		0 != isdigit(response[1]) && 0 != isdigit(response[2])) {
		return SMTP_DISPATCH_RESPONSE_OK;
	} else if (TRUE == expect_3xx && '3' == response[0] &&
		0 != isdigit(response[1]) && 0 != isdigit(response[2])) {
		return SMTP_DISPATCH_RESPONSE_OK;
	} else {
		if ('5' == response[0]) {
           	return SMTP_DISPATCH_RESPONSE_PMTFAIL;	
		} else {
			return SMTP_DISPATCH_RESPONSE_TMPFAIL;
		}
	}
}

static BOOL smtp_dispatch_check_maskstring(const char *string)
{
	int offset, len;

	if ('\0' == g_mask_string[0]) {
		return FALSE;
	}
	offset = 0;
	while (TRUE) {
		if (NULL != strcasestr(string, g_mask_string + offset)) {
			return TRUE;
		}
		len = strlen(g_mask_string + offset);
		if (0 == len) {
			return FALSE;
		}
		offset += len + 1;
	};
}

BOOL smtp_dispatch_has_maskstring()
{
	if ('\0' == g_mask_string[0]) {
		return FALSE;
	} else {
		return TRUE;
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
void smtp_dispatch_log_info(MESSAGE_CONTEXT *pcontext, int level,
	char *format, ...)
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

