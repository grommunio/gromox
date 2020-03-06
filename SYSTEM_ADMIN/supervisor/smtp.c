#include <string.h>
#include <libHX/ctype_helper.h>
#include <libHX/misc.h>
#include <gromox/resolv.h>
#include "smtp.h"
#include "mail_func.h"
#include "util.h"
#undef NOERROR                  /* in <sys/streams.h> on solaris 2.x */
#include <arpa/nameser.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <netdb.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#define MAXPACKET			8192 /* max size of packet */
#define MAXBUF				256          
#define MAXMXHOSTS			32   /* max num of mx records we want to see */
#define MAXMXBUFSIZ			(MAXMXHOSTS * (MAXBUF+1)) 
#define SOCKET_TIMEOUT		180
#define RETRYING_INTERVAL	180
#define EHLO_AUTH_LOGIN     1
#define EHLO_AUTH_PLAIN     2


void smtp_init()
{
	/* do nothing */
}

int smtp_run()
{
	return 0;
	/* do nothing */
}

int smtp_stop()
{
	return 0;
	/* do nothing */
}

void smtp_free()
{
	/* do nothing */
}

static int smtp_read_ehlo(int sockd, char *response, int response_len,
	int *auth_type);

static BOOL smtp_send_command(int sockd, const char *command,
	int command_len);

static int smtp_get_response(int sockd, char *response, 
	int response_len, BOOL expect_3xx);

void smtp_send_message(const char *from, const char *rcpt, const char *message)
{
	BOOL b_connected;
	char **p_addr;
	char *pdomain, ip[16];
	char command_line[1024];
	char response_line[1024];
	int size, i, times, num;
	int command_len, sockd, opt;
	int port, val_opt;
	struct sockaddr_in servaddr;
	struct in_addr ip_addr;
	char **mx_buff = NULL;
	struct hostent *phost;
	struct timeval tv;
	fd_set myset;
	
	b_connected = FALSE;
	pdomain = strchr(rcpt, '@');
	if (NULL == pdomain) {
		return;
	}
	pdomain ++;
	size = strlen(message);
	num = gx_getmxbyname(pdomain, &mx_buff);
	if (num <= 0) {
		if (mx_buff != NULL)
			HX_zvecfree(mx_buff);
		return;
	}
	memset(ip, 0, 16);
	for (i = 0; i < num && i < MAXMXHOSTS; ++i) {
		if (NULL == extract_ip(mx_buff[i], ip)) {
			if (NULL == (phost = gethostbyname(mx_buff[i]))) {
				continue;
			}
			p_addr = phost->h_addr_list;
			for (; NULL != (*p_addr); p_addr++) {
				ip_addr.s_addr = *((unsigned int *)*p_addr);
				strcpy(ip, inet_ntoa(ip_addr));
				break;
			}
			if ('\0' != ip[0]) {
				break;
			}
		} else {
			break;
		}
	}
	if (mx_buff != NULL)
		HX_zvecfree(mx_buff);
	if ('\0' == ip[0]) {
		return;
	}
	port = 25;
	times = 0;
SENDING_RETRY:
	if (0 != times) {
		sleep(RETRYING_INTERVAL);
	}
	/* try to connect to the destination MTA */
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	opt = fcntl(sockd, F_GETFL, 0);
	opt |= O_NONBLOCK;
	fcntl(sockd, F_SETFL, opt);
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);
	if (0 == connect(sockd, (struct sockaddr*)&servaddr,sizeof(servaddr))) {
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
				socklen_t opt_len = sizeof(int);
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
		times ++;
		if (3 == times) {
			return;
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
			return;
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
		return;
	}

	/* send helo xxx to server */
	if (FALSE == smtp_send_command(sockd, "helo system.mail\r\n", 18)) {
		close(sockd);
		times ++;
		if (3 == times) {
			return;
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
			return;
		} else {
			goto SENDING_RETRY;
		}
	case SMTP_PERMANENT_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		smtp_send_command(sockd, command_line, 6);
		close(sockd);
		return;
	}

	/* send mail from:<...> */
	command_len = sprintf(command_line, "mail from:<%s>\r\n", from);
	if (FALSE == smtp_send_command(sockd, command_line, command_len)) {
		close(sockd);
		times ++;
		if (3 == times) {
			return;
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
			return;
		} else {
			goto SENDING_RETRY;
		}
	case SMTP_PERMANENT_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_send_command(sockd, command_line, 6);
		close(sockd);
        return;
    }

	/* send rcpt to:<...> */
	
	command_len = sprintf(command_line, "rcpt to:<%s>\r\n", rcpt);
	if (FALSE == smtp_send_command(sockd, command_line, command_len)) {
		close(sockd);
		times ++;
		if (3 == times) {
			return;
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
			return;
		} else {
			goto SENDING_RETRY;
		}
	case SMTP_PERMANENT_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		smtp_send_command(sockd, command_line, 6);
		close(sockd);
		return;
	}
	
	/* send data */
	strcpy(command_line, "data\r\n");
	if (FALSE == smtp_send_command(sockd, command_line, 6)) {
		close(sockd);
		times ++;
		if (3 == times) {
			return;
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
			return;
		} else {
			goto SENDING_RETRY;
		}
	case SMTP_PERMANENT_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		strcpy(command_line, "quit\r\n");
        /* send quit command to server */
        smtp_send_command(sockd, command_line, 6);
		close(sockd);
		return;
    }

	if (FALSE == smtp_send_command(sockd, message, size)) {
		close(sockd);
		times ++;
		if (3 == times) {
			return;
		} else {
			goto SENDING_RETRY;
		}
	}
	if (FALSE == smtp_send_command(sockd, "\r\n.\r\n", 5)) {
		close(sockd);
		times ++;
		if (3 == times) {
			return;
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
			return;
		} else {
			goto SENDING_RETRY;
		}
	case SMTP_PERMANENT_ERROR:
	case SMTP_UNKOWN_RESPONSE:	
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
        smtp_send_command(sockd, command_line, 6);
		close(sockd);
		return;
	case SMTP_SEND_OK:
		strcpy(command_line, "quit\r\n");
		/* send quit command to server */
		smtp_send_command(sockd, command_line, 6);
		close(sockd);
		return;
	}
}

int smtp_send_inbound(const char *ip, int port, const char *rcpt,
	const char *message, char *last_command, char *last_response)
{
	BOOL b_connected;
	int size, res_val, command_len;
	int sockd, opt, val_opt;
	struct sockaddr_in servaddr;
	struct timeval tv;
	fd_set myset;
	
	b_connected = FALSE;
	size = strlen(message);
	/* try to connect to the destination MTA */
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	opt = fcntl(sockd, F_GETFL, 0);
	opt |= O_NONBLOCK;
	fcntl(sockd, F_SETFL, opt);
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);
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
				socklen_t opt_len = sizeof(int);
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
		return SMTP_CANNOT_CONNECT;
	}
	/* read welcome information of MTA */
	res_val = smtp_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		return SMTP_TIME_OUT;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
        /* send quit command to server */
        smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return SMTP_CONNECT_ERROR;
	}

	/* send helo xxx to server */
	strcpy(last_command, "helo system.mail\r\n");
	command_len = strlen(last_command);
	if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return SMTP_TIME_OUT;
	}
	res_val = smtp_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		return SMTP_TIME_OUT;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		/* send quit command to server */
		smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return res_val;
	}

	/* send mail from:<...> */
	strcpy(last_command, "mail from:<system-supervise@system.mail>\r\n");
	command_len = strlen(last_command);
	if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return SMTP_TIME_OUT;
	}
	/* read mail from response information */
	res_val = smtp_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
    case SMTP_TIME_OUT:
		close(sockd);
		return SMTP_TIME_OUT;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
        /* send quit command to server */
        smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
        return res_val;
    }

	/* send rcpt to:<...> */
	command_len = sprintf(last_command, "rcpt to:<%s>\r\n", rcpt);
	if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return SMTP_TIME_OUT;
	}
	/* read rcpt to response information */
	res_val = smtp_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
    case SMTP_TIME_OUT:
		close(sockd);
		return SMTP_TIME_OUT;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return res_val;
	}
	
	/* send data */
	strcpy(last_command, "data\r\n");
	command_len = strlen(last_command);
	if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return SMTP_TIME_OUT;
	}

	/* read data response information */
    res_val = smtp_get_response(sockd, last_response, 1024, TRUE);
	switch (res_val) {
    case SMTP_TIME_OUT:
		close(sockd);
		return SMTP_TIME_OUT;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
        smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return res_val;
    }

	if (FALSE == smtp_send_command(sockd, message, size)) {
		close(sockd);
		return SMTP_TIME_OUT;
	}
	strcpy(last_command, "\r\n.\r\n");
	command_len = strlen(last_command);
	if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return SMTP_TIME_OUT;
	}
	res_val = smtp_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		return SMTP_TIME_OUT;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:	
        smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return res_val;
	case SMTP_SEND_OK:
		smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return SMTP_SEND_OK;
	}
	return SMTP_SEND_OK;

}

int smtp_send_outbound(const char *ip, int port, const char *username,
	const char *password, const char *rcpt, const char *message,
	char *last_command, char *last_response)
{
	BOOL b_connected;
	char temp_line[1024];
	int user_len, pass_len;
	int size, res_val;
	int auth_type;
	size_t encode_len;
	size_t command_len;
	int sockd, opt, val_opt;
	struct sockaddr_in servaddr;
	struct timeval tv;
	fd_set myset;
	
	b_connected = FALSE;
	size = strlen(message);
	/* try to connect to the destination MTA */
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	opt = fcntl(sockd, F_GETFL, 0);
	opt |= O_NONBLOCK;
	fcntl(sockd, F_SETFL, opt);
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);
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
				socklen_t opt_len = sizeof(int);
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
		return SMTP_CANNOT_CONNECT;
	}
	/* read welcome information of MTA */
	res_val = smtp_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		return SMTP_TIME_OUT;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
        /* send quit command to server */
        smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return SMTP_CONNECT_ERROR;
	}


	/* send ehlo xxx to server */
	strcpy(last_command, "ehlo athena\r\n");
	command_len = strlen(last_command);
	if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return SMTP_TIME_OUT;
	}
	
	/* read mail from response information */
    res_val = smtp_read_ehlo(sockd, last_response, 1024, &auth_type);
	switch (res_val) {
    case SMTP_TIME_OUT:
		close(sockd);
		return SMTP_TIME_OUT;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
        /* send quit command to server */
        smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
        return res_val;
    }
	if (auth_type&EHLO_AUTH_LOGIN) {
		/* send auth login */
		strcpy(last_command, "auth login\r\n");
		command_len = strlen(last_command);
		if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
			close(sockd);
			return SMTP_TIME_OUT;
		}
		/* read auth login response information */
		res_val = smtp_get_response(sockd, last_response, 1024, TRUE);
		switch (res_val) {
		case SMTP_TIME_OUT:
			close(sockd);
			return SMTP_TIME_OUT;
		case SMTP_PERMANENT_ERROR:
		case SMTP_TEMP_ERROR:
		case SMTP_UNKOWN_RESPONSE:
			smtp_send_command(sockd, "quit\r\n", 6);
			close(sockd);
			return res_val;
		}
		encode64(username, strlen(username), last_command, 1024, &command_len);
		last_command[command_len] = '\r';
		command_len ++;
		last_command[command_len] = '\n';
		command_len ++;
		/* send encoded username */
		if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
			close(sockd);
			return SMTP_TIME_OUT;
		}
		/* read username response information */
		res_val = smtp_get_response(sockd, last_response, 1024, TRUE);
		switch (res_val) {
		case SMTP_TIME_OUT:
			close(sockd);
			return SMTP_TIME_OUT;
		case SMTP_PERMANENT_ERROR:
		case SMTP_TEMP_ERROR:
		case SMTP_UNKOWN_RESPONSE:
			smtp_send_command(sockd, "quit\r\n", 6);
			close(sockd);
			return res_val;
		}
		encode64(password, strlen(password), last_command, 1024, &command_len);
		last_command[command_len] = '\r';
		command_len ++;
		last_command[command_len] = '\n';
		command_len ++;
		/* send encoded password */
		if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
			close(sockd);
			return SMTP_TIME_OUT;
		}
		/* read password response information */
		res_val = smtp_get_response(sockd, last_response, 1024, FALSE);
		switch (res_val) {
		case SMTP_TIME_OUT:
			close(sockd);
			return SMTP_TIME_OUT;
		case SMTP_PERMANENT_ERROR:
		case SMTP_TEMP_ERROR:
		case SMTP_UNKOWN_RESPONSE:
			smtp_send_command(sockd, "quit\r\n", 6);
			close(sockd);
			return SMTP_AUTH_FAIL;
		}
	} else if (auth_type&EHLO_AUTH_PLAIN) {
		strcpy(last_command, "auth plain ");
		command_len = 11;
		user_len = strlen(username);
		pass_len = strlen(password);
			
		temp_line[0] = '\0';
		memcpy(temp_line + 1, username, user_len);
		temp_line[user_len + 1] = '\0';
		memcpy(temp_line + user_len + 2, password, pass_len);		
		encode64(temp_line, user_len + pass_len + 2, last_command + command_len,
			1000, &encode_len);
		command_len += encode_len;
		last_command[command_len] = '\r';
		command_len ++;
		last_command[command_len] = '\n';
		command_len ++;
			
		/* send auth plain command */
		if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
			close(sockd);
			return SMTP_TIME_OUT;
		}
		/* read auth plain response information */
		switch (smtp_get_response(sockd, last_response, 1024, FALSE)) {
		case SMTP_TIME_OUT:
			close(sockd);
			return SMTP_TIME_OUT;
		case SMTP_PERMANENT_ERROR:
		case SMTP_TEMP_ERROR:
		case SMTP_UNKOWN_RESPONSE:
			/* send quit command to server */
			smtp_send_command(sockd, "quit\r\n", 6);
			close(sockd);
			return SMTP_AUTH_FAIL;
		}
	}

	/* send mail from:<...> */
	command_len= sprintf(last_command, "mail from:<%s>\r\n", rcpt);
	if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return SMTP_TIME_OUT;
	}
	/* read mail from response information */
	res_val = smtp_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
    case SMTP_TIME_OUT:
		close(sockd);
		return SMTP_TIME_OUT;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
        /* send quit command to server */
        smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
        return res_val;
    }

	/* send rcpt to:<...> */
	command_len = sprintf(last_command, "rcpt to:<%s>\r\n", rcpt);
	if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return SMTP_TIME_OUT;
	}
	/* read rcpt to response information */
	res_val = smtp_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
    case SMTP_TIME_OUT:
		close(sockd);
		return SMTP_TIME_OUT;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
		smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return res_val;
	}
	
	/* send data */
	strcpy(last_command, "data\r\n");
	command_len = strlen(last_command);
	if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return SMTP_TIME_OUT;
	}

	/* read data response information */
    res_val = smtp_get_response(sockd, last_response, 1024, TRUE);
	switch (res_val) {
    case SMTP_TIME_OUT:
		close(sockd);
		return SMTP_TIME_OUT;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:
        smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return res_val;
    }

	if (FALSE == smtp_send_command(sockd, message, size)) {
		close(sockd);
		return SMTP_TIME_OUT;
	}
	strcpy(last_command, "\r\n.\r\n");
	command_len = strlen(last_command);
	if (FALSE == smtp_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return SMTP_TIME_OUT;
	}
	res_val = smtp_get_response(sockd, last_response, 1024, FALSE);
	switch (res_val) {
	case SMTP_TIME_OUT:
		close(sockd);
		return SMTP_TIME_OUT;
	case SMTP_PERMANENT_ERROR:
	case SMTP_TEMP_ERROR:
	case SMTP_UNKOWN_RESPONSE:	
        smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return res_val;
	case SMTP_SEND_OK:
		smtp_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return SMTP_SEND_OK;
	}
	return SMTP_SEND_OK;

}


static int smtp_read_ehlo(int sockd, char *response, int response_len,
	int *auth_type)
{
	int read_len, offset;

	offset = 0;
	*auth_type = 0;
	memset(response, 0, response_len);
	while (offset < response_len - 1) {
		read_len = read(sockd, response + offset, response_len - 1 - offset);
		if (-1 == read_len || 0 == read_len) {
			return SMTP_TIME_OUT;
		}
		offset += read_len;
		if (NULL != search_string(response, "PLAIN", offset)) {
			*auth_type |= EHLO_AUTH_PLAIN;
		}
		if (NULL != search_string(response, "LOGIN", offset)) {
			*auth_type |= EHLO_AUTH_LOGIN;
		}
		if (NULL != strstr(response, "250 ")) {
			return SMTP_SEND_OK;
		}
		if ('4' == response[0]) {
           	return SMTP_TEMP_ERROR;	
		} else if ('5' == response[0]) {
			return SMTP_PERMANENT_ERROR;
		}
	}
	return SMTP_UNKOWN_RESPONSE;
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
 *		SMTP_TEMP_ERROR		temp fail
 *		SMTP_UNKOWN_RESPONSE	unkown fail
 *		SMTP_PERMANENT_ERROR	permanent fail
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
