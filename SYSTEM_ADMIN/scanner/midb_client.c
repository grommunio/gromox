#include "midb_client.h"
#include "double_list.h"
#include "single_list.h"
#include "list_file.h"
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define SOCKET_TIMEOUT		60

typedef struct _MIDB_ITEM {
	char prefix[256];
	char ip_addr[16];
	int port;
} MIDB_ITEM;

typedef struct _BACK_SVR {
	DOUBLE_LIST_NODE node;
	char prefix[256];
	int prefix_len;
	char ip_addr[16];
	int port;
} BACK_SVR;

static char g_list_path[256];

static DOUBLE_LIST g_server_list;

static int midb_client_connect(const char *ip_addr, int port);

static BOOL midb_client_readline(int sockd, char *buff, int length);

void midb_client_init(const char *list_path)
{
	strcpy(g_list_path, list_path);
	double_list_init(&g_server_list);
}

int midb_client_run()
{
	int i;
	int list_num;
	MIDB_ITEM *pitem;
	LIST_FILE *plist;
	BACK_SVR *pserver;
	
	plist = list_file_init(g_list_path, "%s:256%s:16%d");
	if (NULL == plist) {
		return -1;
	}

	list_num = list_file_get_item_num(plist);
	pitem = (MIDB_ITEM*)list_file_get_list(plist);
	for (i=0; i<list_num; i++) {
		pserver = (BACK_SVR*)malloc(sizeof(BACK_SVR));
		if (NULL == pserver) {
			list_file_free(plist);
			return -2;
		}
		pserver->node.pdata = pserver;
		strcpy(pserver->prefix, pitem[i].prefix);
		pserver->prefix_len = strlen(pserver->prefix);
		strcpy(pserver->ip_addr, pitem[i].ip_addr);
		pserver->port = pitem[i].port;
		double_list_append_as_tail(&g_server_list, &pserver->node);
	}
	list_file_free(plist);
	return 0;
}

int midb_client_stop()
{
	BACK_SVR *pserver;
	DOUBLE_LIST_NODE *pnode;
	
	while (pnode=double_list_get_from_head(&g_server_list)) {
		pserver = (BACK_SVR*)pnode->pdata;
		free(pserver);
	}
	return 0;
}

static BOOL midb_client_list_mail(int sockd,
	const char *maildir, char *folder, sqlite3_stmt *pstmt)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	fd_set myset;
	char *pspace;
	struct timeval tv;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	
	length = snprintf(buff, 1024, "M-UIDL %s %s\r\n", maildir, folder);
	if (length != write(sockd, buff, length)) {
		return FALSE;
	}
	count = 0;
	offset = 0;
	lines = -1;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return FALSE;
		}
		read_len = read(sockd, buff + offset, 256*1024 - offset);
		if (read_len <= 0) {
			return FALSE;
		}
		offset += read_len;
		buff[offset] = '\0';
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					if (0 == strncmp(buff, "TRUE ", 5)) {
						memcpy(num_buff, buff + 5, i - 5);
						num_buff[i - 5] = '\0';
						lines = atoi(num_buff);
						if (lines < 0) {
							return FALSE;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						return FALSE;
					}
				}
			}
			if (-1 == lines) {
				if (offset > 1024) {
					return FALSE;
				}
				continue;
			}
		}
		for (i=last_pos; i<offset; i++) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				pspace = memchr(temp_line, ' ', line_pos);
				if (NULL == pspace) {
					return FALSE;
				}
				*pspace = '\0';
				if (strlen(temp_line) > 127) {
					return FALSE;
				}
				pspace ++;
				temp_line[line_pos] = '\0';
				sqlite3_reset(pstmt);
				sqlite3_bind_text(pstmt, 1, temp_line, -1, SQLITE_STATIC);
				if (SQLITE_DONE != sqlite3_step(pstmt)) {
					return FALSE;
				}
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 256) {
						return FALSE;
					}
				}
			}
		}
		if (count >= lines) {
			return TRUE;
		}
		if ('\r' == buff[offset - 1]) {
			last_pos = offset - 1;
		} else {
			last_pos = offset;
		}
		if (256*1024 == offset) {
			if ('\r' != buff[offset - 1]) {
				offset = 0;
			} else {
				buff[0] = '\r';
				offset = 1;
			}
			last_pos = 0;
		}
	}
}

static BOOL midb_client_enum_folders(int sockd,
	const char *maildir, SINGLE_LIST *plist)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	fd_set myset;
	struct timeval tv;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	SINGLE_LIST_NODE *pnode;

	length = snprintf(buff, 1024, "M-ENUM %s\r\n", maildir);
	if (length != write(sockd, buff, length)) {
		return FALSE;
	}
	count = 0;
	offset = 0;
	lines = -1;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			goto RDWR_ERROR;
		}
		read_len = read(sockd, buff + offset, 256*1024 - offset);
		if (read_len <= 0) {
			goto RDWR_ERROR;
		}
		offset += read_len;
		buff[offset] = '\0';
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					if (0 == strncmp(buff, "TRUE ", 5)) {
						memcpy(num_buff, buff + 5, i - 5);
						num_buff[i - 5] = '\0';
						lines = atoi(num_buff);
						if (lines < 0) {
							goto RDWR_ERROR;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						return FALSE;
					} else {
						goto RDWR_ERROR;
					}
				}
			}
			if (-1 == lines) {
				if (offset > 1024) {
					goto RDWR_ERROR;
				}
				continue;
			}
		}
		for (i=last_pos; i<offset; i++) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				temp_line[line_pos] = '\0';
				pnode = malloc(sizeof(SINGLE_LIST_NODE));
				if (NULL == pnode) {
					goto RDWR_ERROR;
				}
				pnode->pdata = strdup(temp_line);
				if (NULL == pnode->pdata) {
					free(pnode);
					goto RDWR_ERROR;
				}
				single_list_append_as_tail(plist, pnode);
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 512) {
						goto RDWR_ERROR;
					}
				}
			}
		}
		if (count >= lines) {
			return TRUE;
		}
		if ('\r' == buff[offset - 1]) {
			last_pos = offset - 1;
		} else {
			last_pos = offset;
		}
		if (256*1024 == offset) {
			if ('\r' != buff[offset - 1]) {
				offset = 0;
			} else {
				buff[0] = '\r';
				offset = 1;
			}
			last_pos = 0;
		}
	}
	
RDWR_ERROR:
	while (pnode=single_list_get_from_head(plist)) {
		free(pnode->pdata);
		free(pnode);
	}
	return FALSE;
}

BOOL midb_client_rewrite_eml(const char *maildir, const char *mid_string)
{
	int len;
	int sockd;
	BACK_SVR *pserver;
	char temp_buff[256];
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
		pnode=double_list_get_after(&g_server_list, pnode)) {
		pserver = (BACK_SVR*)pnode->pdata;
		if (0 == strncmp(maildir, pserver->prefix, pserver->prefix_len)) {
			break;
		}
	}
	if (NULL == pnode) {
		return FALSE;
	}
	sockd = midb_client_connect(pserver->ip_addr, pserver->port);
	if (-1 == sockd) {
		return FALSE;
	}
	len = snprintf(temp_buff, 256, "M-WEML %s %s\r\n", maildir, mid_string);
	if (len != write(sockd, temp_buff, len)) {
		close(sockd);
		return FALSE;
	}

	if (FALSE == midb_client_readline(sockd, temp_buff, 256)) {
		close(sockd);
		return FALSE;
	}
	write(sockd, "QUIT\r\n", 6);
	close(sockd);
	return TRUE;
}

BOOL midb_client_all_mid_strings(const char *maildir, sqlite3_stmt *pstmt)
{
	int len;
	int sockd;
	BACK_SVR *pserver;
	char temp_buff[1024];
	DOUBLE_LIST_NODE *pnode;
	SINGLE_LIST_NODE *psnode;
	SINGLE_LIST folders_list;
	
	for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
		pnode=double_list_get_after(&g_server_list, pnode)) {
		pserver = (BACK_SVR*)pnode->pdata;
		if (0 == strncmp(maildir, pserver->prefix, pserver->prefix_len)) {
			break;
		}
	}
	if (NULL == pnode) {
		return FALSE;
	}
	sockd = midb_client_connect(pserver->ip_addr, pserver->port);
	if (-1 == sockd) {
		return FALSE;
	}
	single_list_init(&folders_list);
	if (FALSE == midb_client_enum_folders(sockd, maildir, &folders_list)) {
		single_list_free(&folders_list);
		close(sockd);
		return FALSE;
	}
	if (FALSE == midb_client_list_mail(sockd, maildir, "inbox", pstmt) ||
		FALSE == midb_client_list_mail(sockd, maildir, "draft", pstmt) ||
		FALSE == midb_client_list_mail(sockd, maildir, "sent", pstmt) ||
		FALSE == midb_client_list_mail(sockd, maildir, "trash", pstmt) ||
		FALSE == midb_client_list_mail(sockd, maildir, "junk", pstmt)) {
		goto LIST_ERROR;
	}
	while (psnode=single_list_get_from_head(&folders_list)) {
		if (FALSE == midb_client_list_mail(sockd,
			maildir, psnode->pdata, pstmt)) {
			free(psnode->pdata);
			free(psnode);
			goto LIST_ERROR;
		}
		free(psnode->pdata);
		free(psnode);
	}
	single_list_free(&folders_list);
	write(sockd, "QUIT\r\n", 6);
	close(sockd);
	return TRUE;

LIST_ERROR:
	while (psnode=single_list_get_from_head(&folders_list)) {
		free(psnode->pdata);
		free(psnode);
	}
	single_list_free(&folders_list);
	close(sockd);
	return FALSE;
}

BOOL midb_client_unload_db(const char *maildir)
{
	int len;
	int sockd;
	BACK_SVR *pserver;
	char temp_buff[256];
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
		pnode=double_list_get_after(&g_server_list, pnode)) {
		pserver = (BACK_SVR*)pnode->pdata;
		if (0 == strncmp(maildir, pserver->prefix, pserver->prefix_len)) {
			break;
		}
	}
	if (NULL == pnode) {
		return FALSE;
	}
	sockd = midb_client_connect(pserver->ip_addr, pserver->port);
	if (-1 == sockd) {
		return FALSE;
	}
	len = snprintf(temp_buff, 256, "M-FREE %s\r\n", maildir);
	if (len != write(sockd, temp_buff, len)) {
		close(sockd);
		return FALSE;
	}

	if (FALSE == midb_client_readline(sockd, temp_buff, 256)) {
		close(sockd);
		return FALSE;
	}
	write(sockd, "QUIT\r\n", 6);
	close(sockd);
	return TRUE;
}

void midb_client_free()
{
	double_list_free(&g_server_list);

}

static int midb_client_connect(const char *ip_addr, int port)
{
	int sockd;
	int offset;
	int read_len;
	char temp_buff[1024];
	struct sockaddr_in servaddr;


	sockd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip_addr, &servaddr.sin_addr);
	if (0 != connect(sockd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
		close(sockd);
		return -1;
	}
	read_len = read(sockd, temp_buff, 1024);
	if (read_len <= 0) {
		close(sockd);
		return -1;
	}
	temp_buff[read_len] = '\0';
	if (0 != strcasecmp(temp_buff, "OK\r\n")) {
		close(sockd);
		return -1;
	}
	return sockd;
}

static BOOL midb_client_readline(int sockd, char *buff, int length)
{
	int offset;
	int read_len;
	fd_set myset;
	struct timeval tv;

	offset = 0;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return FALSE;
		}
		read_len = read(sockd, buff + offset, length - offset);
		if (read_len <= 0) {
			return FALSE;
		}
		offset += read_len;
		if (offset >= 2 && '\r' == buff[offset - 2] &&
			'\n' == buff[offset - 1]) {
			buff[offset - 2] = '\0';
			return TRUE;
		}
		if (length == offset) {
			return FALSE;
		}	
	}
}
