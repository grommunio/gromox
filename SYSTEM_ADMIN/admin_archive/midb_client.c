#include <gromox/socket.h>
#include "midb_client.h"
#include "double_list.h"
#include "list_file.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>

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
	
	while ((pnode = double_list_get_from_head(&g_server_list)) != NULL) {
		pserver = (BACK_SVR*)pnode->pdata;
		free(pserver);
	}
	return 0;
}

BOOL midb_client_insert(const char *maildir, const char *folder,
	const char *mid_string, const char *flag_strings, long rcv_time)
{
	int len;
	int sockd;
	BACK_SVR *pserver;
	char temp_buff[1024];
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

	len = snprintf(temp_buff, 1024, "M-INST %s %s %s %s %ld\r\n",
			maildir, folder, mid_string, flag_strings, rcv_time);
	if (len != write(sockd, temp_buff, len)) {
		close(sockd);
	}
	
	if (FALSE == midb_client_readline(sockd, temp_buff, 1024)) {
		close(sockd);
		return FALSE;
	}
	write(sockd, "QUIT\r\n", 6);
	close(sockd);
	if (0 == strcasecmp(temp_buff, "TRUE")) {
		return TRUE;
	} else {
		return FALSE;
	}
}

void midb_client_free()
{
	double_list_free(&g_server_list);

}


static int midb_client_connect(const char *ip_addr, int port)
{
	int read_len;
	char temp_buff[1024];
	int sockd = gx_inet_connect(ip_addr, port, 0);
	if (sockd < 0)
		return -1;
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

