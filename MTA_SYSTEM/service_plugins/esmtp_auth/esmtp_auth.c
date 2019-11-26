#include <ctype.h>
#include "esmtp_auth.h"
#include "util.h"
#include "mail_func.h"
#include "host_list.h"
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

#define EHLO_AUTH_LOGIN				1
#define EHLO_AUTH_PLAIN				2
#define SOCKET_TIMEOUT				10

enum {
	SMTP_TIME_OUT,
	SMTP_TEMP_ERROR,
	SMTP_UNKOWN_RESPONSE,
	SMTP_PERMANENT_ERROR,
	SMTP_RESPONSE_OK
};

static int g_retrying_times;

static BOOL esmtp_auth_send_command(int sockd, const char *command,
	int command_len);

static int esmtp_auth_get_response(int sockd, char *response, int response_len,
	BOOL expect_3xx);

static BOOL esmtp_auth_read_ehlo(int sockd, char *response,
	int response_len, int *preason, int *auth_type);

void esmtp_auth_init(int retrying_times)
{
	g_retrying_times = retrying_times;
}

int esmtp_auth_run()
{
	/* do nothing */
	return 0;
}

int esmtp_auth_stop()
{
	/* do nothing */
	return 0;

}

void esmtp_auth_free()
{
	/* do nothing */
}


BOOL esmtp_auth_login(const char *username, const char *password, char *reason,
	int reason_len)
{
	BOOL b_connected;
	char host_ip[16];
	char temp_line[1024];
	char command_line[1024];
	char response_line[1024];
	int user_len, pass_len;
	size_t encode_len;
	size_t command_len;
	int	times, port;
	int sockd, opt, auth_type, ireason;
	int val_opt, opt_len;
	struct sockaddr_in servaddr;
	struct in_addr ip_addr;
	struct timeval tv;
	fd_set myset;

	times = 0;	
RECONNECT:
	if (times >= g_retrying_times) {
		return FALSE;
	}
	/* when auth host list is empty, esmtp auth will be turned off */
	if (FALSE == host_list_get_unit(host_ip, &port)) {
		return TRUE;
	}
	
	b_connected = FALSE;
	/* try to connect to the destination MTA */
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	opt = fcntl(sockd, F_GETFL, 0);
	opt |= O_NONBLOCK;
	fcntl(sockd, F_SETFL, opt);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, host_ip, &servaddr.sin_addr);
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
		host_list_invalid_unit(host_ip, port);
		snprintf(reason, reason_len, "cannot connect to auth host %s:%d",
			host_ip, port);
		times ++;
		goto RECONNECT;
	}
	/* read welcome information of MTA */
	switch (esmtp_auth_get_response(sockd, response_line, 1024, FALSE)) {
	case SMTP_TIME_OUT:
		close(sockd);
		snprintf(reason, reason_len, "connect to auth host %s:%d time out",
			host_ip, port);
		times ++;
		goto RECONNECT;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        esmtp_auth_send_command(sockd, command_line, 6);
		close(sockd);
		snprintf(reason, reason_len, "auth host %s:%d answer \"%s\" after "
			"connected", host_ip, port, response_line);
		times ++;
		goto RECONNECT;
	}

	/* send ehlo xxx to server */
	if (FALSE == esmtp_auth_send_command(sockd, "ehlo athena\r\n", 13)) {
		close(sockd);
		snprintf(reason, reason_len, "connect to auth host %s:%d time out",
			host_ip, port);
		times ++;
		goto RECONNECT;
	}
	
	/* read mail from response information */
    if (FALSE == esmtp_auth_read_ehlo(sockd, response_line, 1024, &ireason,
		&auth_type)) {
		switch (ireason) {
	    case SMTP_TIME_OUT:
			close(sockd);
			snprintf(reason, reason_len, "connect to auth host %s:%d time out",
				host_ip, port);
			times ++;
			goto RECONNECT;
		case SMTP_PERMANENT_ERROR:
		case SMTP_TEMP_ERROR:
		case SMTP_UNKOWN_RESPONSE:
			strcpy(command_line, "quit\r\n");
	        /* send quit command to server */
		    esmtp_auth_send_command(sockd, command_line, 6);
			close(sockd);
			snprintf(reason, reason_len, "auth host %s:%d answer \"%s\" after "
				"ehlo command", host_ip, port, response_line);
			times ++;
			goto RECONNECT;
		}
	}
	if (auth_type&EHLO_AUTH_LOGIN) {
		/* send auth login */
		if (FALSE == esmtp_auth_send_command(sockd, "auth login\r\n", 12)) {
			close(sockd);
			snprintf(reason, reason_len, "connect to auth host %s:%d "
				"time out", host_ip, port);
			times ++;
			goto RECONNECT;
		}
		/* read auth login response information */
		switch (esmtp_auth_get_response(sockd, response_line, 1024, TRUE)) {
		case SMTP_TIME_OUT:
			close(sockd);
			snprintf(reason, reason_len, "connect to auth host %s:%d "
				"time out", host_ip, port);
			times ++;
			goto RECONNECT;
		case SMTP_PERMANENT_ERROR:
		case SMTP_TEMP_ERROR:
		case SMTP_UNKOWN_RESPONSE:
			strcpy(command_line, "quit\r\n");
			/* send quit command to server */
			esmtp_auth_send_command(sockd, command_line, 6);
			close(sockd);
			snprintf(reason, reason_len, "auth host %s:%d answer \"%s\" "
				"after auth login command", host_ip, port, response_line);
			times ++;
			goto RECONNECT;
		}
		encode64(username, strlen(username), command_line, 1024, &command_len);
		command_line[command_len] = '\r';
		command_len ++;
		command_line[command_len] = '\n';
		command_len ++;
		/* send encoded username */
		if (FALSE == esmtp_auth_send_command(sockd, command_line,
			command_len)) {
			close(sockd);
			snprintf(reason, reason_len, "connect to auth host %s:%d "
				"time out", host_ip, port);
			times ++;
			goto RECONNECT;
		}
		/* read username response information */
		switch (esmtp_auth_get_response(sockd, response_line, 1024, TRUE)) {
		case SMTP_TIME_OUT:
			close(sockd);
			snprintf(reason, reason_len, "connect to auth host %s:%d "
				"time out", host_ip, port);
			times ++;
			goto RECONNECT;
		case SMTP_PERMANENT_ERROR:
		case SMTP_TEMP_ERROR:
		case SMTP_UNKOWN_RESPONSE:
			strcpy(command_line, "quit\r\n");
			/* send quit command to server */
			esmtp_auth_send_command(sockd, command_line, 6);
			close(sockd);
			snprintf(reason, reason_len, "auth host %s:%d answer \"%s\" after "
				"username has been sent", host_ip, port, response_line);
			times ++;
			goto RECONNECT;
		}
		encode64(password, strlen(password), command_line, 1024, &command_len);
		command_line[command_len] = '\r';
		command_len ++;
		command_line[command_len] = '\n';
		command_len ++;
		/* send encoded password */
		if (FALSE == esmtp_auth_send_command(sockd, command_line,
			command_len)) {
			close(sockd);
			snprintf(reason, reason_len, "connect to auth host %s:%d "
				"time out", host_ip, port);
			times ++;
			goto RECONNECT;
		}
		/* read password response information */
		switch (esmtp_auth_get_response(sockd, response_line, 1024, FALSE)) {
		case SMTP_TIME_OUT:
			close(sockd);
			snprintf(reason, reason_len, "connect to auth host %s:%d "
				"time out", host_ip, port);
			times ++;
			goto RECONNECT;
		case SMTP_PERMANENT_ERROR:
		case SMTP_TEMP_ERROR:
		case SMTP_UNKOWN_RESPONSE:
			strcpy(command_line, "quit\r\n");
			/* send quit command to server */
			esmtp_auth_send_command(sockd, command_line, 6);
			close(sockd);
			if (0 != isdigit(response_line[0]) &&
				0 != isdigit(response_line[1]) &&
				0 != isdigit(response_line[2]) &&
				' ' == response_line[3]) {
				strncpy(reason, response_line + 4, reason_len);
			} else {
				strncpy(reason, response_line, reason_len);
			}
			return FALSE;
		}
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		esmtp_auth_send_command(sockd, command_line, 6);
		close(sockd);
		return TRUE;
	}
	if (auth_type&EHLO_AUTH_PLAIN) {
		strcpy(command_line, "auth plain ");
		command_len = 11;
		user_len = strlen(username);
		pass_len = strlen(password);
		if (user_len + pass_len > 512) {
			close(sockd);
			strncpy(reason, "username or password too long", reason_len);
			return FALSE;
		}
		temp_line[0] = '\0';
		memcpy(temp_line + 1, username, user_len);
		temp_line[user_len + 1] = '\0';
		memcpy(temp_line + user_len + 2, password, pass_len);
		
		encode64(temp_line, user_len + pass_len + 2, command_line + command_len,
			1000, &encode_len);
		command_len += encode_len;
		command_line[command_len] = '\r';
		command_len ++;
		command_line[command_len] = '\n';
		command_len ++;
		/* send auth plain command */
		if (FALSE == esmtp_auth_send_command(sockd, command_line,
			command_len)) {
			close(sockd);
			snprintf(reason, reason_len, "connect to auth host %s:%d "
				"time out", host_ip, port);
			times ++;
			goto RECONNECT;
		}
		/* read auth plain response information */
		switch (esmtp_auth_get_response(sockd, response_line, 1024, FALSE)) {
		case SMTP_TIME_OUT:
			close(sockd);
			snprintf(reason, reason_len, "connect to auth host %s:%d "
				"time out", host_ip, port);
			times ++;
			goto RECONNECT;
		case SMTP_PERMANENT_ERROR:
		case SMTP_TEMP_ERROR:
		case SMTP_UNKOWN_RESPONSE:
			strcpy(command_line, "quit\r\n");
			/* send quit command to server */
			esmtp_auth_send_command(sockd, command_line, 6);
			close(sockd);
			if (0 != isdigit(response_line[0]) &&
				0 != isdigit(response_line[1]) &&
				0 != isdigit(response_line[2]) &&
				' ' == response_line[3]) {
				strncpy(reason, response_line + 4, reason_len);
			} else {
				strncpy(reason, response_line, reason_len);
			}
			return FALSE;
		}
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		esmtp_auth_send_command(sockd, command_line, 6);
		close(sockd);
		return TRUE;
	}
	snprintf(reason, reason_len, "cannot find proper auth type in "
		"auth host %s:%d", host_ip, port);
	times ++;
	goto RECONNECT;
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
static BOOL esmtp_auth_send_command(int sockd, const char *command,
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
 *		reason [out]			fail reason
 *	@retrun
 *		SMTP_TIME_OUT			time out
 *		SMTP_TEMP_ERROR			temp fail
 *		SMTP_UNKOWN_RESPONSE	unkown fail
 *		SMTP_PERMANENT_ERROR	permanent fail
 *		SMTP_RESPONSE_OK		OK
 */
static int esmtp_auth_get_response(int sockd, char *response, int response_len,
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
		0 != isdigit(response[1]) && 0 != isdigit(response[2])) {
		return SMTP_RESPONSE_OK;
	} else if(TRUE == expect_3xx && '3' == response[0] &&
		0 != isdigit(response[1]) && 0 != isdigit(response[2])) {
		return SMTP_RESPONSE_OK;
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

static BOOL esmtp_auth_read_ehlo(int sockd, char *response,
	int response_len, int *preason, int *auth_type)
{
	int read_len, offset;

	offset = 0;
	*auth_type = 0;
	memset(response, 0, response_len);
	while (offset < response_len - 1) {
		read_len = read(sockd, response + offset, response_len - 1 - offset);
		if (-1 == read_len || 0 == read_len) {
			*preason = SMTP_TIME_OUT;
			return FALSE;
		}
		offset += read_len;
		if (NULL != search_string(response, "PLAIN", offset)) {
			*auth_type |= EHLO_AUTH_PLAIN;
		}
		if (NULL != search_string(response, "LOGIN", offset)) {
			*auth_type |= EHLO_AUTH_LOGIN;
		}
		if (NULL != strstr(response, "250 ")) {
			return TRUE;
		}
		if ('4' == response[0]) {
           	*preason = SMTP_TEMP_ERROR;	
			return FALSE;
		} else if ('5' == response[0]) {
			*preason = SMTP_PERMANENT_ERROR;
			return FALSE;
		}
	}
	*preason = SMTP_UNKOWN_RESPONSE;
	return FALSE;
}

int esmtp_auth_get_param(int param)
{
	if (ESMTP_AUTH_RETRYING_TIMES == param) {
		return g_retrying_times;
	}
	return 0;
}

void esmtp_auth_set_param(int param, int value)
{
	if (ESMTP_AUTH_RETRYING_TIMES == param) {
		g_retrying_times = value;
	}
}

