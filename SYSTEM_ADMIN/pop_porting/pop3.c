#include "common_types.h"
#include "mail_func.h"
#include "pop3.h"
#include "util.h"
#undef NOERROR                  /* in <sys/streams.h> on solaris 2.x */
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define SOCKET_TIMEOUT		180
#define RETRIEVE_BUFSIZE	256*1024


static BOOL pop3_send_command(int sockd, const char *command, int command_len);

static BOOL pop3_get_response(int sockd, char *response, int response_len);

static BOOL pop3_read_list(int sockd, char *response, int response_len);

void pop3_init(POP3_SESSION *psession, const char *ip, int port,
	const char *username, const char *password)
{
	strcpy(psession->server_ip, ip);
	psession->port = port;
	strcpy(psession->username, username);
	strcpy(psession->password, password);
	psession->sockd = -1;
}


BOOL pop3_login(POP3_SESSION *psession)
{
	BOOL b_connected;
	int sockd, opt;
	int command_len;
	int val_opt, opt_len;
	struct sockaddr_in servaddr;
	struct timeval tv;
	fd_set myset;
	char last_command[1024];
	char last_response[1024];

	b_connected = FALSE;
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	opt = fcntl(sockd, F_GETFL, 0);
	opt |= O_NONBLOCK;
	fcntl(sockd, F_SETFL, 0);
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(psession->port);
	inet_pton(AF_INET, psession->server_ip, &servaddr.sin_addr);
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
		return FALSE;
	}
	
	/* read welcome information of MTA */
	if (FALSE == pop3_get_response(sockd, last_response, 1024)) {
        /* send quit command to server */
        pop3_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return FALSE;
	}

	/* send user xxx to server */
	command_len = sprintf(last_command, "user %s\r\n", psession->username);
	if (FALSE == pop3_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return FALSE;
	}
	if (FALSE == pop3_get_response(sockd, last_response, 1024)) {
		/* send quit command to server */
		pop3_send_command(sockd, "quit\r\n", 6);
		close(sockd);
		return FALSE;
	}

	command_len = sprintf(last_command, "pass %s\r\n", psession->password);
	if (FALSE == pop3_send_command(sockd, last_command, command_len)) {
		close(sockd);
		return FALSE;
	}
	if (FALSE == pop3_get_response(sockd, last_response, 1024)) {
        /* send quit command to server */
        pop3_send_command(sockd, "quit\r\n", 6);
		close(sockd);
        return FALSE;
    }

	psession->sockd = sockd;
	return TRUE;
}


BOOL pop3_list(POP3_SESSION *psession, int *pnum)
{
	char last_command[1024];
	char *pcrlf, *plast, *pspace;
	char list_buff[RETRIEVE_BUFSIZE];
	int command_len, i;

	strcpy(last_command, "list\r\n");
	command_len = strlen(last_command);
	if (FALSE == pop3_send_command(psession->sockd, last_command, command_len)) {
		return FALSE;
	}
	if (FALSE == pop3_read_list(psession->sockd, list_buff, RETRIEVE_BUFSIZE)) {
		return FALSE;
	}
	
	pcrlf = list_buff;
	plast = pcrlf;
	i = 0;
	while (i < 16*1024 - 1) {
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
		pnum[i] = atoi(plast);
		plast = pcrlf + 2;
		i ++;
	}
	pnum[i] = -1;
	return TRUE;
}

	
BOOL pop3_retr(POP3_SESSION *psession, int n, char *pbuff, int size)
{
	int command_len;
	char last_command[1024];

	if (-1 == psession->sockd) {
		return FALSE;
	}
	command_len = sprintf(last_command, "retr %d\r\n", n);
	
	if (FALSE == pop3_send_command(psession->sockd, last_command, command_len)) {
		return FALSE;
	}
	return pop3_read_list(psession->sockd, pbuff, size);
}


void pop3_free(POP3_SESSION *psession)
{
	if (-1 != psession->sockd) {
		close(psession->sockd);
		psession->sockd = -1;
	}
	psession->server_ip[0] = '\0';
	psession->port = 0;
	psession->username[0] = '\0';
	psession->password[0] = '\0';
}

static BOOL pop3_read_list(int sockd, char *response, int response_len)
{
	int read_len, offset;
	char *pbegin, *pend;
	fd_set myset;
	struct timeval tv;
	 
	offset = 0;
	while (response_len - offset > 0) {
		tv.tv_sec = SOCKET_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return FALSE;
		}
		read_len = read(sockd, response + offset, response_len - offset);
		if (0 == read_len || -1 == read_len) {
			return FALSE;
		}
		offset += read_len;
		response[offset] = '\0';
		if (offset > 3 && 0 != strncmp(response, "+OK", 3)) {
			return FALSE;
		}
		if ((pend = strstr(response, "\r\n.\r\n")) != NULL) {
			pend += 2;
			pbegin = strstr(response, "\r\n");
			pbegin += 2;
			memmove(response, pbegin, pend - pbegin);
			response[pend - pbegin] = '\0';
			return TRUE;
		}
	}
	response[response_len - 1] = '\0';
	return FALSE;
}

static BOOL pop3_send_command(int sockd, const char *command, int command_len)
{
	int write_len;

	write_len = write(sockd, command, command_len);
    if (write_len != command_len) {
		return FALSE;
	}
	return TRUE;
}

static BOOL pop3_get_response(int sockd, char *response, int response_len)
{
	int read_len;
	fd_set myset;
	struct timeval tv;

	memset(response, 0, response_len);
	tv.tv_sec = SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&myset);
	FD_SET(sockd, &myset);
	if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
		return FALSE;
	}
	read_len = read(sockd, response, response_len);
	if (-1 == read_len || 0 == read_len) {
		return FALSE;
	}
	if ('\n' == response[read_len - 1] && '\r' == response[read_len - 2]) {
		/* remove /r/n at the end of response */
		read_len -= 2;
	}
	response[read_len] = '\0';
	if (0 == strncmp(response, "+OK", 3)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

