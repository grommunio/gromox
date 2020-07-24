#include <stdlib.h>
#include <gromox/socket.h>
#include "common_types.h"
#include "pop3.h"
#include "message.h"
#undef NOERROR                  /* in <sys/streams.h> on solaris 2.x */
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define SOCKET_TIMEOUT		180
#define RETRIEVE_BUFSIZE	60*1024

void pop3_init()
{
	/* do nothing */
}

int pop3_run()
{
	return 0;
	/* do nothing */
}

int pop3_stop()
{
	return 0;
	/* do nothing */
}

void pop3_free()
{
	/* do nothing */
}


static BOOL pop3_send_command(int sockd, const char *command, int command_len);

static int pop3_get_response(int sockd, char *response, int response_len);

static int pop3_read_list(int sockd, char *response, int response_len);

static int pop3_match_id(int sockd, int type, int check_id);

int pop3_retrieve_message(const char *ip, int port, const char *username,
	const char *password, int message_type, int check_id, char *last_command,
	char *last_response)
{
	char *pcrlf, *plast, *pspace;
	char list_buff[RETRIEVE_BUFSIZE];
	int id, size, command_len;
	
	/* try to connect to the destination MTA */
	int sockd = gx_inet_connect(ip, port, 0);
	if (sockd < 0)
		return POP3_CANNOT_CONNECT;
	/* read welcome information of MTA */
	switch (pop3_get_response(sockd, last_response, 1024)) {
	case POP3_TIME_OUT:
		close(sockd);
		return POP3_TIME_OUT;
	case POP3_RESPONSE_ERROR:
        /* send quit command to server */
        pop3_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return POP3_CONNECT_ERROR;
	}

	/* send helo xxx to server */
	command_len = sprintf(last_command, "user %s\r\n", username);
	if (FALSE == pop3_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return POP3_TIME_OUT;
	}
	switch (pop3_get_response(sockd, last_response, 1024)) {
	case POP3_TIME_OUT:
		close(sockd);
		return POP3_TIME_OUT;
	case POP3_RESPONSE_ERROR:
		/* send quit command to server */
		pop3_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return POP3_RESPONSE_ERROR;
	}

	command_len = sprintf(last_command, "pass %s\r\n", password);
	if (FALSE == pop3_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return POP3_TIME_OUT;
	}
	switch (pop3_get_response(sockd, last_response, 1024)) {
    case POP3_TIME_OUT:
		close(sockd);
		return POP3_TIME_OUT;
	case POP3_RESPONSE_ERROR:
        /* send quit command to server */
        pop3_send_command(sockd, "quit\r\n", 6);
		close(sockd);
        return POP3_AUTH_FAIL;
    }

	strcpy(last_command, "list\r\n");
	command_len = strlen(last_command);
	if (FALSE == pop3_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return POP3_TIME_OUT;
	}
	switch (pop3_read_list(sockd, list_buff, RETRIEVE_BUFSIZE)) {
    case POP3_TIME_OUT:
		close(sockd);
		return POP3_TIME_OUT;
	case POP3_RESPONSE_ERROR:
		pop3_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		strncpy(last_response, list_buff, 1023);
		last_response[1023] = '\0';
		return POP3_RESPONSE_ERROR;
	}

	pcrlf = list_buff;
	plast = pcrlf;
	while (TRUE) {
		pcrlf = strstr(plast, "\r\n");
		if (NULL == pcrlf) {
			break;
		}
		*pcrlf = '\0';
		pspace = strchr(plast, ' ');
		if (NULL == pspace) {
			plast = pcrlf + 2;
			continue;
		}
		*pspace = '\0';
		id = atoi(plast);
		size = atoi(pspace + 1);
		if (size <= 0 || size >= RETRIEVE_BUFSIZE) {
			plast = pcrlf + 2;
			continue;
		}
		command_len = sprintf(last_command, "retr %d\r\n", id);
		if (FALSE == pop3_send_command(sockd, last_command, command_len)) {
			close(sockd);
			return POP3_TIME_OUT;
		}
		switch (pop3_match_id(sockd, message_type, check_id)) {
		case POP3_RETRIEVE_OK:
			command_len = sprintf(last_command, "dele %d\r\n", id);
			if (FALSE == pop3_send_command(sockd, last_command, command_len)) {
				close(sockd);
				return POP3_TIME_OUT;
			}
			switch (pop3_get_response(sockd, last_response, 1024)) {
			case POP3_TIME_OUT:
				close(sockd);
				return POP3_TIME_OUT;
			case POP3_RESPONSE_ERROR:
				pop3_send_command(sockd, "quit\r\n", 6);
				close(sockd);
				return POP3_RESPONSE_ERROR;
			}
			if (FALSE == pop3_send_command(sockd, "quit\r\n", 6)) {
				close(sockd);
				return POP3_TIME_OUT;
			}
			switch (pop3_get_response(sockd, last_response, 1024)) {
			case POP3_TIME_OUT:
				close(sockd);
				return POP3_TIME_OUT;
			case POP3_RESPONSE_ERROR:
				close(sockd);
				return POP3_UPDATE_FAIL;
			}
			close(sockd);
			return POP3_RETRIEVE_OK;
		case POP3_TIME_OUT:
			close(sockd);
			return POP3_TIME_OUT;
		case POP3_RESPONSE_ERROR:
		case POP3_RETRIEVE_NONE:
			plast = pcrlf + 2;
			continue;
		}
	}
	pop3_send_command(sockd, "quit\r\n", 6);
	close(sockd);
	return POP3_RETRIEVE_NONE;
}

static int pop3_match_id(int sockd, int type, int check_id)
{
	int offset, read_len;
	char temp_field[64];
	char msg_buff[RETRIEVE_BUFSIZE];

	if (MESSAGE_SUPERVISING_SMTP ==  type) {
		sprintf(temp_field, "X-SMTP-ID: <%d>", check_id);
	} else if (MESSAGE_SUPERVISING_POP3 == type) {
		sprintf(temp_field, "X-POP3-ID: <%d>", check_id);
	} else {
		return POP3_RETRIEVE_NONE;
	}
	offset = 0;
	while (RETRIEVE_BUFSIZE - offset > 0) {
		read_len = read(sockd, msg_buff + offset, RETRIEVE_BUFSIZE - offset);
		if (0 == read_len || -1 == read_len) {
			return POP3_TIME_OUT;
		}
		offset += read_len;
		msg_buff[offset] = '\0';
		if (NULL != strstr(msg_buff, "\r\n.\r\n")) {
			if (NULL != strstr(msg_buff, temp_field)) {
				return POP3_RETRIEVE_OK;
			} else {
				return POP3_RETRIEVE_NONE;
			}
		}
	}
	return POP3_RESPONSE_ERROR;
}


static int pop3_read_list(int sockd, char *response, int response_len)
{
	int read_len, offset;
	char *pbegin, *pend;
	 
	offset = 0;
	while (response_len - offset > 0) {
		read_len = read(sockd, response + offset, response_len - offset);
		if (0 == read_len || -1 == read_len) {
			return POP3_TIME_OUT;
		}
		offset += read_len;
		response[offset] = '\0';
		if (offset > 3 && 0 != strncmp(response, "+OK", 3)) {
			return POP3_RESPONSE_ERROR;
		}
		if ((pend = strstr(response, "\r\n.\r\n")) != NULL) {
			pend += 2;
			pbegin = strstr(response, "\r\n");
			pbegin += 2;
			memmove(response, pbegin, pend - pbegin);
			response[pend - pbegin] = '\0';
			return POP3_RETRIEVE_OK;
		}
	}
	response[response_len - 1] = '\0';
	return POP3_RESPONSE_ERROR;
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
static BOOL pop3_send_command(int sockd, const char *command, int command_len)
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
 *		POP3_TIME_OUT			time out
 *		POP3_RESPONSE_ERROR		temporary failure
 *		POP3_RETRIEVE_OK		OK
 */
static int pop3_get_response(int sockd, char *response, int response_len)
{
	int read_len;

	memset(response, 0, response_len);
	read_len = read(sockd, response, response_len);
	if (-1 == read_len || 0 == read_len) {
		return POP3_TIME_OUT;
	}
	if ('\n' == response[read_len - 1] && '\r' == response[read_len - 2]){
		/* remove /r/n at the end of response */
		read_len -= 2;
	}
	response[read_len] = '\0';
	if (0 == strncmp(response, "+OK", 3)) {
		return POP3_RETRIEVE_OK;
	} else {
		return POP3_RESPONSE_ERROR;
	}
}

