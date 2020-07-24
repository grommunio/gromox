#include <stdbool.h>
#include <libHX/ctype_helper.h>
#include <gromox/socket.h>
#include "smtp.h"
#include "util.h"
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define SOCKET_TIMEOUT		180
#define RETRYING_INTERVAL   180

enum {
	SMTP_SEND_OK = 0,
	SMTP_TIME_OUT,
	SMTP_TEMP_ERROR,
	SMTP_UNKOWN_RESPONSE,
	SMTP_PERMANENT_ERROR,
};


void smtp_init(SMTP_SESSION *psession, const char *ip, int port)
{
	strcpy(psession->ip, ip);
	psession->port = port;
}

void smtp_free(SMTP_SESSION *psession)
{
	psession->ip[0] = '\0';
	psession->port = 0;
}


static BOOL smtp_send_command(int sockd, const char *command,
	int command_len);

static int smtp_get_response(int sockd, char *response, 
	int response_len, BOOL expect_3xx);

BOOL smtp_send(SMTP_SESSION *psession, const char *from, const char *rcpt,
	const char *message)
{
	char command_line[1024];
	char response_line[1024];
	int size = strlen(message), times = 0, command_len, sockd;

SENDING_RETRY:
	if (0 != times) {
		sleep(RETRYING_INTERVAL);
	}
	/* try to connect to the destination MTA */
	sockd = gx_inet_connect(psession->ip, psession->port, 0);
	if (sockd < 0) {
		times ++;
		if (3 == times) {
			return FALSE;
		} else {
			goto SENDING_RETRY;
		}
	}
	/* read welcome information of MTA */
	switch (smtp_get_response(sockd, response_line, 1024, FALSE)) {
	case SMTP_TIME_OUT:
		close(sockd);
		times ++;
		if (3 == times) {
			return FALSE;
		} else {
			goto SENDING_RETRY;
		}
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_send_command(sockd, command_line, 6);
		close(sockd);
		return FALSE;
	}

	/* send helo xxx to server */
	if (FALSE == smtp_send_command(sockd, "helo system.mail\r\n", 18)) {
		close(sockd);
		times ++;
		if (3 == times) {
			return FALSE;
		} else {
			goto SENDING_RETRY;
		}
	}
	switch (smtp_get_response(sockd, response_line, 1024, FALSE)) {
	case SMTP_TIME_OUT:
	case SMTP_TEMP_ERROR:
		close(sockd);
		times ++;
		if (3 == times) {
			return FALSE;
		} else {
			goto SENDING_RETRY;
		}
	case SMTP_PERMANENT_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		smtp_send_command(sockd, command_line, 6);
		close(sockd);
		return FALSE;
	}

	/* send mail from:<...> */
	command_len = sprintf(command_line, "mail from:<%s>\r\n", from);
	if (FALSE == smtp_send_command(sockd, command_line, command_len)) {
		close(sockd);
		times ++;
		if (3 == times) {
			return FALSE;
		} else {
			goto SENDING_RETRY;
		}
	}
	/* read mail from response information */
    switch (smtp_get_response(sockd, response_line, 1024, FALSE)) {
    case SMTP_TIME_OUT:
	case SMTP_TEMP_ERROR:
		close(sockd);
		times ++;
		if (3 == times) {
			return FALSE;
		} else {
			goto SENDING_RETRY;
		}
	case SMTP_PERMANENT_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_send_command(sockd, command_line, 6);
		close(sockd);
        return FALSE;
    }

	/* send rcpt to:<...> */
	
	command_len = sprintf(command_line, "rcpt to:<%s>\r\n", rcpt);
	if (FALSE == smtp_send_command(sockd, command_line, command_len)) {
		close(sockd);
		times ++;
		if (3 == times) {
			return FALSE;
		} else {
			goto SENDING_RETRY;
		}
	}
	/* read rcpt to response information */
    switch (smtp_get_response(sockd, response_line, 1024, FALSE)) {
    case SMTP_TIME_OUT:
	case SMTP_TEMP_ERROR:
		close(sockd);
		times ++;
		if (3 == times) {
			return FALSE;
		} else {
			goto SENDING_RETRY;
		}
	case SMTP_PERMANENT_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		smtp_send_command(sockd, command_line, 6);
		close(sockd);
		return FALSE;
	}
	
	/* send data */
	strcpy(command_line, "data\r\n");
	if (FALSE == smtp_send_command(sockd, command_line, 6)) {
		close(sockd);
		times ++;
		if (3 == times) {
			return FALSE;
		} else {
			goto SENDING_RETRY;
		}
	}

	/* read data response information */
    switch (smtp_get_response(sockd, response_line, 1024, TRUE)) {
    case SMTP_TIME_OUT:
	case SMTP_TEMP_ERROR:
		close(sockd);
		times ++;
		if (3 == times) {
			return FALSE;
		} else {
			goto SENDING_RETRY;
		}
	case SMTP_PERMANENT_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_send_command(sockd, command_line, 6);
		close(sockd);
		return FALSE;
    }

	if (FALSE == smtp_send_command(sockd, message, size)) {
		close(sockd);
		times ++;
		if (3 == times) {
			return FALSE;
		} else {
			goto SENDING_RETRY;
		}
	}
	if (FALSE == smtp_send_command(sockd, "\r\n.\r\n", 5)) {
		close(sockd);
		times ++;
		if (3 == times) {
			return FALSE;
		} else {
			goto SENDING_RETRY;
		}
	}
	switch (smtp_get_response(sockd, response_line, 1024, FALSE)) {
	case SMTP_TIME_OUT:
	case SMTP_TEMP_ERROR:
		close(sockd);
		times ++;
		if (3 == times) {
			return false;
		} else {
			goto SENDING_RETRY;
		}
	case SMTP_PERMANENT_ERROR:
	case SMTP_UNKOWN_RESPONSE:	
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
        smtp_send_command(sockd, command_line, 6);
		close(sockd);
		return FALSE;
	case SMTP_SEND_OK:
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		smtp_send_command(sockd, command_line, 6);
		close(sockd);
		return TRUE;
	}
	return false;
}

static BOOL smtp_send_command(int sockd, const char *command, int command_len)
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
 *		reason [out]			fail reason
 *	@retrun
 *		SMTP_TIME_OUT			time out
 *		SMTP_TEMP_ERROR		temporary failure
 *		SMTP_UNKOWN_RESPONSE	unknown failure
 *		SMTP_PERMANENT_ERROR	permanent failure
 *		SMTP_SEND_OK		OK
 */
static int smtp_get_response(int sockd, char *response, int response_len,
	BOOL expect_3xx)
{
	int read_len;

	memset(response, 0, response_len);
	read_len = read(sockd, response, response_len);
	if (-1 == read_len || 0 == read_len) {
		return SMTP_TIME_OUT;
	}
	if ('\n' == response[read_len - 1] && '\r' == response[read_len - 2]){
		/* remove /r/n at the end of response */
		read_len -= 2;
	}
	response[read_len] = '\0';
	if (FALSE == expect_3xx && '2' == response[0] &&
	    HX_isdigit(response[1]) && HX_isdigit(response[2])) {
		return SMTP_SEND_OK;
	} else if(TRUE == expect_3xx && '3' == response[0] &&
	    HX_isdigit(response[1]) && HX_isdigit(response[2])) {
		return SMTP_SEND_OK;
	} else {
		if ('4' == response[0]) {
           	return SMTP_TEMP_ERROR;	
		} else if ('5' == response[0]) {
			return SMTP_PERMANENT_ERROR;
		} else {
			return SMTP_UNKOWN_RESPONSE;
		}
	}
}


