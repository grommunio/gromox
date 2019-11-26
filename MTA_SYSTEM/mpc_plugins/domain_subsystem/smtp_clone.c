#include <ctype.h>
#include <string.h>
#include "smtp_clone.h"
#include "util.h"
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>

#define SOCKET_TIMEOUT			180

enum {
	SMTP_CLONE_RESPONSE_TIMEOUT,
	SMTP_CLONE_RESPONSE_OK,
	SMTP_CLONE_RESPONSE_TMPFAIL,
	SMTP_CLONE_RESPONSE_PMTFAIL
};


static BOOL smtp_clone_send_command(int sockd, const char *command,
	int command_len);

static int smtp_clone_get_response(int sockd, char *response,
	int response_len, BOOL expect_3xx);

void smtp_clone_init()
{
	/* do nothing */
}

int smtp_clone_run()
{
	return 0;
}

int smtp_clone_stop()
{
	return 0;
}

void smtp_clone_free()
{
	/* do nothing */
}


int smtp_clone_process(MESSAGE_CONTEXT *pcontext, const char *ip, int port)
{
	char rcpt_to[256];
	char command_line[512];
	char response_line[1024];
	int command_len;
	int sockd, opt;
	int val_opt, opt_len;
	BOOL rcpt_success;
	BOOL b_connected;
	struct sockaddr_in servaddr;
	struct timeval tv;
	fd_set myset;
	
	
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
			MEM_FILE_SEEK_BEGIN);
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	/* set the socket to block mode */
	opt = fcntl(sockd, F_GETFL, 0);
	opt |= O_NONBLOCK;
	fcntl(sockd, F_SETFL, opt);
	/* end of set mode */
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);
	b_connected = FALSE;
	if (0 == connect(sockd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
		b_connected = TRUE;
		/* set socket back to block mode */
		opt = fcntl(sockd, F_GETFL, 0);
		opt &= (~O_NONBLOCK);
		fcntl(sockd, F_SETFL, opt);
		/* end of set mode */
	} else {
		if (EINPROGRESS == errno) {
			tv.tv_sec = SOCKET_TIMEOUT;
			tv.tv_usec = 0;
			FD_ZERO(&myset);
			FD_SET(sockd, &myset);
			if (select(sockd + 1, NULL, &myset, NULL, &tv) > 0) {
				opt_len = sizeof(int);
				if (getsockopt(sockd, SOL_SOCKET, SO_ERROR, &val_opt,
					&opt_len) >= 0) {
					if (0 == val_opt) {
						b_connected = TRUE;
						/* set socket back to block mode */
						opt = fcntl(sockd, F_GETFL, 0);
						opt &= (~O_NONBLOCK);
						fcntl(sockd, F_SETFL, opt);
						/* end of set mode */
					}
				}
			}
		}
	}
	if (FALSE == b_connected) {
		close(sockd);
		smtp_clone_log_info(pcontext, 8, "cannot connect to sub-system %s:%d",
			ip, port);
		return SMTP_CLONE_TEMP_ERROR;
	}
	/* read welcome information of MTA */
	switch (smtp_clone_get_response(sockd, response_line, 1024, FALSE)) {
	case SMTP_CLONE_RESPONSE_TIMEOUT:
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d time out", ip, port);
		close(sockd);
		return SMTP_CLONE_TEMP_ERROR;
	case SMTP_CLONE_RESPONSE_TMPFAIL:
	case SMTP_CLONE_RESPONSE_PMTFAIL:
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d answer \"%s\" "
			"after connection", ip, port, response_line);
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_clone_send_command(sockd, command_line, 6);
		close(sockd);
		return SMTP_CLONE_TEMP_ERROR;
	}

	command_len = sprintf(command_line, "helo %s\r\n", get_host_ID());
	if (FALSE == smtp_clone_send_command(sockd, command_line, command_len)) {
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d time out", ip, port);
		close(sockd);
		return SMTP_CLONE_TEMP_ERROR;
	}
	switch (smtp_clone_get_response(sockd, response_line, 1024, FALSE)) {
	case SMTP_CLONE_RESPONSE_TIMEOUT:
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d time out", ip, port);
		close(sockd);
		return SMTP_CLONE_TEMP_ERROR;
	case SMTP_CLONE_RESPONSE_TMPFAIL:
	case SMTP_CLONE_RESPONSE_PMTFAIL:
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d answer \"%s\" "
			"after \"helo\" command", ip, port, response_line);
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		smtp_clone_send_command(sockd, command_line, 6);
		close(sockd);
		return SMTP_CLONE_TEMP_ERROR;
	}

	/* send mail from:<...> */
	command_len = sprintf(command_line, "mail from:<%s>\r\n",
					pcontext->pcontrol->from);
	if (FALSE == smtp_clone_send_command(sockd, command_line, command_len)) {
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d time out", ip, port);
		close(sockd);
		return SMTP_CLONE_TEMP_ERROR;
	}
	/* read mail from response information */
    switch (smtp_clone_get_response(sockd, response_line, 1024, FALSE)) {
    case SMTP_CLONE_RESPONSE_TIMEOUT:
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d time out", ip, port);
		close(sockd);
		return SMTP_CLONE_PERMANENT_ERROR;
	case SMTP_CLONE_RESPONSE_TMPFAIL:
        smtp_clone_log_info(pcontext, 8, "sub-system %s:%d answer \"%s\" "
			"after \"mail from\"", ip, port, response_line);
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_clone_send_command(sockd, command_line, 6);
		close(sockd);
		return SMTP_CLONE_TEMP_ERROR;
	case SMTP_CLONE_RESPONSE_PMTFAIL:
        smtp_clone_log_info(pcontext, 8, "sub-system %s:%d answer "
			"\"%s\" after \"mail from\"", ip, port, response_line);
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_clone_send_command(sockd, command_line, 6);
		close(sockd);
		return SMTP_CLONE_PERMANENT_ERROR;
    }

	/* send rcpt to:<...> */
	rcpt_success = FALSE;
	while (MEM_END_OF_FILE != mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
		rcpt_to, 256)) {
		command_len = sprintf(command_line, "rcpt to:<%s>\r\n", rcpt_to);
		if (FALSE == smtp_clone_send_command(sockd, command_line,
			command_len)) {
			smtp_clone_log_info(pcontext, 8, "sub-system %s:%d time out",
				ip, port);
			close(sockd);
            return SMTP_CLONE_TEMP_ERROR;
		}

		/* read rcpt to response information */
        switch (smtp_clone_get_response(sockd, response_line, 1024, FALSE)) {
		case SMTP_CLONE_RESPONSE_TIMEOUT:
			smtp_clone_log_info(pcontext, 8, "sub-system %s:%d time out",
				ip, port);
			close(sockd);
			return SMTP_CLONE_TEMP_ERROR;
        case SMTP_CLONE_RESPONSE_PMTFAIL:
			if (BOUND_IN == pcontext->pcontrol->bound_type ||
				BOUND_OUT == pcontext->pcontrol->bound_type ||
				BOUND_RELAY == pcontext->pcontrol->bound_type) {
				log_info(8, "SMTP message queue-ID: %d, FROM: %s, TO: ... "
					"seems there's no user %s in sub-system %s:%d, response: "
					"\"%s\"", pcontext->pcontrol->queue_ID,
					pcontext->pcontrol->from, rcpt_to, ip, port, response_line);
			} else {
				log_info(8, "APP created message FROM: %s, TO: ... "
					"seems there's no user %s in sub-system %s:%d, response: "
					"\"%s\"", pcontext->pcontrol->from, rcpt_to, ip, port,
					response_line);
			}
			break;
        case SMTP_CLONE_RESPONSE_TMPFAIL:
			smtp_clone_log_info(pcontext, 8, "sub-system %s:%d"
				" answer \"%s\" after \"rcpt to <%s>\"", ip, port,
				response_line, rcpt_to);
			strcpy(command_line, "quit\r\n");
			/* send quit command to server */
			smtp_clone_send_command(sockd, command_line, 6);
			close(sockd);
			return SMTP_CLONE_TEMP_ERROR;
		case SMTP_CLONE_RESPONSE_OK:
			rcpt_success = TRUE;
			break;
		}
	}
	if (FALSE == rcpt_success) {
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_clone_send_command(sockd, command_line, 6);
		close(sockd);
		return SMTP_CLONE_PERMANENT_ERROR;
	}
	
	/* send data */
	strcpy(command_line, "data\r\n");
	if (FALSE == smtp_clone_send_command(sockd, command_line, 6)) {
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d time out", ip, port);
		close(sockd);
        return SMTP_CLONE_TEMP_ERROR;
	}

	/* read data response information */
    switch (smtp_clone_get_response(sockd, response_line, 1024, TRUE)) {
    case SMTP_CLONE_RESPONSE_TIMEOUT:
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d time out", ip, port);
		close(sockd);
		return SMTP_CLONE_TEMP_ERROR;
    case SMTP_CLONE_RESPONSE_TMPFAIL:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_clone_send_command(sockd, command_line, 6);
		close(sockd);
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d answer "
			"\"%s\" after \"data\" command", ip, port, response_line);
		return SMTP_CLONE_TEMP_ERROR;
	case SMTP_CLONE_RESPONSE_PMTFAIL:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_clone_send_command(sockd, command_line, 6);
		close(sockd);
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d answer "
			"\"%s\" after \"data\" command", ip, port, response_line);
		return SMTP_CLONE_PERMANENT_ERROR;
    }

	if (FALSE == mail_to_file(pcontext->pmail, sockd)) {
		switch (smtp_clone_get_response(sockd, response_line, 1024, FALSE)) {
		case SMTP_CLONE_RESPONSE_TIMEOUT:
			smtp_clone_log_info(pcontext, 8, "sub-system %s:%d time out",
				ip, port);
			close(sockd);
			return SMTP_CLONE_TEMP_ERROR;
		case SMTP_CLONE_RESPONSE_TMPFAIL:
			strcpy(command_line, "quit\r\n");
            /* send quit command to server */
            smtp_clone_send_command(sockd, command_line, 6);
			close(sockd);
			smtp_clone_log_info(pcontext, 8, "sub-system %s:%d answer "
				"\"%s\" when sending mail content", ip, port, response_line);
			return SMTP_CLONE_TEMP_ERROR;
		case SMTP_CLONE_RESPONSE_PMTFAIL:
			strcpy(command_line, "quit\r\n");
            /* send quit command to server */
            smtp_clone_send_command(sockd, command_line, 6);
			close(sockd);
			smtp_clone_log_info(pcontext, 8, "sub-system %s:%d answer "
				"\"%s\" when sending mail content", ip, port, response_line);
			return SMTP_CLONE_PERMANENT_ERROR;
		}
	}
	/* send .\r\n */
	strcpy(command_line, ".\r\n");
	if (FALSE == smtp_clone_send_command(sockd, command_line, 3)) {
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d time out", ip, port);
		close(sockd);
		return SMTP_CLONE_TEMP_ERROR;
	}
	switch (smtp_clone_get_response(sockd, response_line, 1024, FALSE)) {
	case SMTP_CLONE_RESPONSE_TIMEOUT:
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d time out", ip, port);
		close(sockd);
		return SMTP_CLONE_TEMP_ERROR;
	case SMTP_CLONE_RESPONSE_TMPFAIL:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_clone_send_command(sockd, command_line, 6);
		close(sockd);
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d answer "
			"\"%s\" when finishing delivery", ip, port, response_line);
		return SMTP_CLONE_TEMP_ERROR;
	case SMTP_CLONE_RESPONSE_PMTFAIL:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_clone_send_command(sockd, command_line, 6);
		close(sockd);
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d answer "
			"\"%s\" when finishing delivery", ip, port, response_line);
		return SMTP_CLONE_PERMANENT_ERROR;
	case SMTP_CLONE_RESPONSE_OK:
		smtp_clone_log_info(pcontext, 8, "sub-system %s:%d return OK",ip, port);
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		smtp_clone_send_command(sockd, command_line, 6);
		close(sockd);
		return SMTP_CLONE_OK;
	}
	return SMTP_CLONE_PERMANENT_ERROR;
}


static BOOL smtp_clone_send_command(int sockd, const char *command,
	int command_len)
{
	int write_len;

	write_len = write(sockd, command, command_len);
    if (write_len != command_len) {
		return FALSE;
	}
	return TRUE;
}


static int smtp_clone_get_response(int sockd, char *response, int response_len,
	BOOL expect_3xx)
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
		return SMTP_CLONE_RESPONSE_TIMEOUT;
	}
	memset(response, 0, response_len);
	read_len = read(sockd, response, response_len);
	if (-1 == read_len || 0 == read_len) {
		return SMTP_CLONE_RESPONSE_TIMEOUT;
	}
	if ('\n' == response[read_len - 1] && '\r' == response[read_len - 2]){
		/* remove /r/n at the end of response */
		read_len -= 2;
	}
	response[read_len] = '\0';
	if (FALSE == expect_3xx && '2' == response[0] &&
		0 != isdigit(response[1]) && 0 != isdigit(response[2])) {
		return SMTP_CLONE_RESPONSE_OK;
	} else if (TRUE == expect_3xx && '3' == response[0] &&
		0 != isdigit(response[1]) && 0 != isdigit(response[2])) {
		return SMTP_CLONE_RESPONSE_OK;
	} else {
		if ('5' == response[0]) {
           	return SMTP_CLONE_RESPONSE_PMTFAIL;	
		} else {
			return SMTP_CLONE_RESPONSE_TMPFAIL;
		}
	}
}

void smtp_clone_log_info(MESSAGE_CONTEXT *pcontext, int level,
    const char *format, ...)
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

