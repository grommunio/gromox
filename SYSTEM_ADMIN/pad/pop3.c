#include <gromox/socket.h>
#include "common_types.h"
#include "mail_func.h"
#include "pop3.h"
#include "util.h"
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
#include <stdlib.h>
#include <string.h>

#define SOCKET_TIMEOUT		180
#define MAX_FILE_SIZE		(1024*1024*1024)


static BOOL pop3_send_command(int sockd, const char *command, int command_len);

static BOOL pop3_get_response(int sockd, char *response, int response_len);

static BOOL pop3_read_save(int sockd, const char *path);

static BOOL pop3_read_list(int sockd, char *response, int response_len);

void pop3_init(POP3_SESSION *psession, const char *ip, int port,
	const char *username, const char *password)
{
	strcpy(psession->server_ip, ip);
	psession->port = port;
	strcpy(psession->username, username);
	strcpy(psession->password, password);
	psession->sockd = -1;
	double_list_init(&psession->uid_list);
	double_list_init(&psession->del_list);
	psession->pnode_iter = NULL;
}


BOOL pop3_login(POP3_SESSION *psession)
{
	int command_len;
	char last_command[1024];
	char last_response[1024];

	if (-1 != psession->sockd) {
		return FALSE;
	}
	int sockd = gx_inet_connect(psession->server_ip, psession->port, 0);
	if (sockd < 0)
		return FALSE;
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
	psession->b_touch = FALSE;
	return TRUE;
}


BOOL pop3_uidl(POP3_SESSION *psession)
{
	UID_ITEM *puid;
	char last_command[1024];
	char *pcrlf, *plast, *pspace;
	char list_buff[1024*1024];
	int command_len;

	strcpy(last_command, "uidl\r\n");
	command_len = strlen(last_command);

	if (-1 == psession->sockd) {
		return FALSE;
	}

	if (0 != double_list_get_nodes_num(&psession->uid_list) ||
		0 != double_list_get_nodes_num(&psession->del_list)) {
		return FALSE;
	}

	if (FALSE == pop3_send_command(psession->sockd, last_command, command_len)) {
		return FALSE;
	}
	if (FALSE == pop3_read_list(psession->sockd, list_buff, 1024*1024)) {
		return FALSE;
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
		puid = malloc(sizeof(UID_ITEM));
		if (NULL != puid) {
			puid->node.pdata = puid;
			puid->id = atoi(plast);
			strcpy(puid->uid, pspace + 1);
			puid->b_done = FALSE;
			double_list_append_as_tail(&psession->uid_list, &puid->node);
		}
		plast = pcrlf + 2;
	}
	return TRUE;
}


BOOL pop3_retr(POP3_SESSION *psession, UID_ITEM *puid, char *path)
{
	int command_len;
	char last_command[1024];

	if (-1 == psession->sockd) {
		return FALSE;
	}
	command_len = sprintf(last_command, "retr %d\r\n", puid->id);
	
	if (FALSE == pop3_send_command(psession->sockd, last_command, command_len)) {
		return FALSE;
	}
	return pop3_read_save(psession->sockd, path);
}

BOOL pop3_delete(POP3_SESSION *psession, UID_ITEM *puid)
{
	int command_len;
	char last_command[1024];
	char last_response[1024];

	if (-1 == psession->sockd) {
		return FALSE;
	}
	puid->b_done = TRUE;
	psession->b_touch = TRUE;

	command_len = sprintf(last_command, "dele %d\r\n", puid->id);
	
	if (FALSE == pop3_send_command(psession->sockd, last_command, command_len)) {
		return FALSE;
	}
	if (FALSE == pop3_get_response(psession->sockd, last_response, 1024)) {
		return FALSE;
	}
	double_list_remove(&psession->uid_list, &puid->node);
	double_list_append_as_tail(&psession->del_list, &puid->node);
	return TRUE;
}

void pop3_mark(POP3_SESSION *psession, UID_ITEM *puid)
{
	puid->b_done = TRUE;
	psession->b_touch = TRUE;
}

BOOL pop3_update(POP3_SESSION *psession)
{
	char last_response[1024];

	if (-1 == psession->sockd) {
		return FALSE;
	}
	
	if (FALSE == pop3_send_command(psession->sockd, "quit\r\n", 6)) {
		double_list_append_list(&psession->uid_list, &psession->del_list);
		double_list_init(&psession->del_list);
		return FALSE;
	}
	if (FALSE == pop3_get_response(psession->sockd, last_response, 1024)) {
		double_list_append_list(&psession->uid_list, &psession->del_list);
		double_list_init(&psession->del_list);
		return FALSE;
	}
	return TRUE;
}

void pop3_free(POP3_SESSION *psession)
{
	DOUBLE_LIST_NODE *pnode;

	if (-1 != psession->sockd) {
		close(psession->sockd);
		psession->sockd = -1;
	}
	while ((pnode = double_list_get_from_head(&psession->uid_list)) != NULL)
		free(pnode->pdata);
	double_list_free(&psession->uid_list);
	while ((pnode = double_list_get_from_head(&psession->del_list)) != NULL)
		free(pnode->pdata);
	double_list_free(&psession->del_list);


	psession->server_ip[0] = '\0';
	psession->port = 0;
	psession->username[0] = '\0';
	psession->password[0] = '\0';
	psession->b_touch = FALSE;
}

static BOOL pop3_read_save(int sockd, const char *path)
{
	int fd;
	BOOL b_first;
	BOOL b_result;
	int total_length;
	char buff[64*1024 + 1];
	int read_len, offset;
	char *pbegin, *pend;
	fd_set myset;
	struct timeval tv;

	fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd) {
		return FALSE;
	}

	offset = 0;
	b_first = TRUE;
	b_result = FALSE;
	total_length = 0;
	while (total_length < MAX_FILE_SIZE) {
		tv.tv_sec = SOCKET_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			close(fd);
			remove(path);
			return FALSE;
		}
		read_len = read(sockd, buff + offset, 64*1024 - offset);
		if (0 == read_len || -1 == read_len) {
			close(fd);
			remove(path);
			return FALSE;
		}
		offset += read_len;
		buff[offset] = '\0';
		total_length += read_len;
		if (FALSE == b_result && offset > 3) {
			if (0 != strncmp(buff, "+OK", 3)) {
				close(fd);
				remove(path);
				return FALSE;
			} else {
				b_result = TRUE;
			}
		}

		if ((pend = strstr(buff, "\r\n.\r\n")) != NULL) {
			pend += 2;
			if (TRUE == b_first) {
				pbegin = strstr(buff, "\r\n");
				pbegin += 2;
			} else {
				pbegin = buff;
			}
			write(fd, pbegin, pend - pbegin);
			close(fd);
			return TRUE;
		}

		if (offset >= 64*1024) {
			if (TRUE == b_first) {
				pbegin = strstr(buff, "\r\n");
				if (NULL == pbegin) {
					close(fd);
					remove(path);
					return FALSE;
				}
				pbegin += 2;
				write(fd, pbegin, offset - 4 - (pbegin - buff));
				b_first = FALSE;
			} else {
				write(fd, buff, offset - 4);
			}
			memmove(buff, buff + offset - 4, 4);
			offset = 4;
		}
		
	}

	close(fd);
	remove(path);
	return FALSE;
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

UID_ITEM *pop3_uidl_head(POP3_SESSION *psession)
{
	UID_ITEM *puid;
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(&psession->uid_list); NULL!=pnode;
		pnode=double_list_get_after(&psession->uid_list, pnode)) {
		puid = (UID_ITEM*)pnode->pdata;
		if (FALSE == puid->b_done) {
			psession->pnode_iter = double_list_get_after(
									&psession->uid_list, pnode);
			return puid;
		}
	}
	psession->pnode_iter = NULL;
	return NULL;
}

UID_ITEM *pop3_uidl_next(POP3_SESSION *psession)
{
	UID_ITEM *puid;
	DOUBLE_LIST_NODE *pnode;

	if (NULL == psession->pnode_iter) {
		return NULL;
	}
	
	for (pnode=psession->pnode_iter; NULL!=pnode;
		pnode=double_list_get_after(&psession->uid_list, pnode)) {
		puid = (UID_ITEM*)pnode->pdata;
		if (FALSE == puid->b_done) {
			psession->pnode_iter = double_list_get_after(
									&psession->uid_list, pnode);
			return puid;
		}
	}
	psession->pnode_iter = NULL;
	return NULL;
}



