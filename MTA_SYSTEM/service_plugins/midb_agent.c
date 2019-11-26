#include <stdbool.h>
#include "service_common.h"
#include "util.h"
#include "list_file.h"
#include "config_file.h"
#include "double_list.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>

#define SOCKET_TIMEOUT			60

#define MIDB_RESULT_OK			0

#define MIDB_NO_SERVER			1

#define MIDB_RDWR_ERROR			2

#define MIDB_RESULT_ERROR		3

#define MIDB_MAILBOX_FULL		4


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
	DOUBLE_LIST conn_list;
} BACK_SVR;

typedef struct _BACK_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
	time_t last_time;
	BACK_SVR *psvr;
} BACK_CONN;

static void* scan_work_func(void *param);

static int connect_midb(const char *ip_addr, int port);

static BOOL check_full(char *path);

static void console_talk(int argc, char **argv, char *result, int length);

static int g_conn_num;
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static DOUBLE_LIST g_lost_list;
static DOUBLE_LIST g_server_list;
static pthread_mutex_t g_server_lock;

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	int i, j;
	int list_num;
	char *psearch;
	char *str_value;
	char file_name[256];
	char list_path[256];
	char config_path[256];
    BACK_CONN *pback;
	BACK_SVR *pserver;
	LIST_FILE *plist;
	MIDB_ITEM *pitem;
	CONFIG_FILE *pconfig;
    DOUBLE_LIST_NODE *pnode;

	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		
		g_notify_stop = TRUE;

		double_list_init(&g_server_list);
		double_list_init(&g_lost_list);
		pthread_mutex_init(&g_server_lock, NULL);

		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(config_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig = config_file_init(config_path);
		if (NULL == pconfig) {
			printf("[midb_agent]: fail to open config file!!!\n");
			return FALSE;
		}
		
		sprintf(list_path, "%s/midb_list.txt", get_data_path());
		str_value = config_file_get_value(pconfig, "CONNECTION_NUM");
		if (NULL == str_value) {
			g_conn_num = 5;
			config_file_set_value(pconfig, "CONNECTION_NUM", "5");
		} else {
			g_conn_num = atoi(str_value);
			if (g_conn_num < 2 || g_conn_num > 100) {
				g_conn_num = 5;
				config_file_set_value(pconfig, "CONNECTION_NUM", "5");
			}
		}

		printf("[midb_agent]: midb connection number is %d\n", g_conn_num);

		config_file_save(pconfig);
		config_file_free(pconfig);

		plist = list_file_init(list_path, "%s:256%s:16%d");
		if (NULL == plist) {
			printf("[midb_agent]: fail to open midb list file\n");
			return FALSE;
		}


		list_num = list_file_get_item_num(plist);
		pitem = (MIDB_ITEM*)list_file_get_list(plist);
		for (i=0; i<list_num; i++) {
			pserver = (BACK_SVR*)malloc(sizeof(BACK_SVR));
			if (NULL == pserver) {
				printf("[midb_agent]: fail to allocate memory for midb\n");
				list_file_free(plist);
				return FALSE;
			}
			pserver->node.pdata = pserver;
			strcpy(pserver->prefix, pitem[i].prefix);
			pserver->prefix_len = strlen(pserver->prefix);
			strcpy(pserver->ip_addr, pitem[i].ip_addr);
			pserver->port = pitem[i].port;
			double_list_init(&pserver->conn_list);
			double_list_append_as_tail(&g_server_list, &pserver->node);
			for (j=0; j<g_conn_num; j++) {
			   pback = (BACK_CONN*)malloc(sizeof(BACK_CONN));
				if (NULL != pback) {
					pback->node.pdata = pback;
					pback->sockd = -1;
					pback->psvr = pserver;
			        double_list_append_as_tail(&g_lost_list, &pback->node);
				}
			}
		}
		list_file_free(plist);

		g_notify_stop = FALSE;
		if (0 != pthread_create(&g_scan_id, NULL, scan_work_func, NULL)) {
			printf("[midb_agent]: fail to create scan thread\n");
			return FALSE;
		}

		if (FALSE == register_service("check_full", check_full)) {
			printf("[midb_agent]: fail to register services\n");
			return FALSE;
		}

		if (FALSE == register_talk(console_talk)) {
			printf("[midb_agent]: fail to register console talk\n");
			return FALSE;
		}

		return TRUE;
	case PLUGIN_FREE:
		if (FALSE == g_notify_stop) {
			g_notify_stop = TRUE;
			pthread_join(g_scan_id, NULL);
		}

		while ((pnode = double_list_get_from_head(&g_lost_list)) != NULL)
			free(pnode->pdata);

		while ((pnode = double_list_get_from_head(&g_server_list)) != NULL) {
			pserver = (BACK_SVR*)pnode->pdata;
			while ((pnode = double_list_get_from_head(&pserver->conn_list)) != NULL) {
				pback = (BACK_CONN*)pnode->pdata;
				write(pback->sockd, "QUIT\r\n", 6);
				close(pback->sockd);
				free(pback);
			}
			free(pserver);
		}

		double_list_free(&g_lost_list);
		double_list_free(&g_server_list);

		pthread_mutex_destroy(&g_server_lock);

		return TRUE;
	}
	return false;
}


static void *scan_work_func(void *param)
{
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	DOUBLE_LIST_NODE *pnode1;
	BACK_SVR *pserver;
	BACK_CONN *pback;
	time_t now_time;
	char temp_buff[1024];
	fd_set myset;
	struct timeval tv;


	double_list_init(&temp_list);

	while (FALSE == g_notify_stop) {
		pthread_mutex_lock(&g_server_lock);
		time(&now_time);
		for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
			pnode=double_list_get_after(&g_server_list, pnode)) {
			pserver = (BACK_SVR*)pnode->pdata;
			ptail = double_list_get_tail(&pserver->conn_list);
			while ((pnode1 = double_list_get_from_head(&pserver->conn_list)) != NULL) {
				pback = (BACK_CONN*)pnode1->pdata;
				if (now_time - pback->last_time >= SOCKET_TIMEOUT - 3) {
					double_list_append_as_tail(&temp_list, &pback->node);
				} else {
					double_list_append_as_tail(&pserver->conn_list,
						&pback->node);
				}

				if (pnode1 == ptail) {
					break;
				}
			}
		}
		pthread_mutex_unlock(&g_server_lock);

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			write(pback->sockd, "PING\r\n", 6);
			tv.tv_usec = 0;
			tv.tv_sec = SOCKET_TIMEOUT;
			FD_ZERO(&myset);
			FD_SET(pback->sockd, &myset);
			if (select(pback->sockd + 1, &myset, NULL, NULL, &tv) <= 0 ||
				read(pback->sockd, temp_buff, 1024) <= 0) {
				close(pback->sockd);
				pback->sockd = -1;
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&g_lost_list, &pback->node);
				pthread_mutex_unlock(&g_server_lock);
			} else {
				time(&pback->last_time);
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				pthread_mutex_unlock(&g_server_lock);
			}
		}

		pthread_mutex_lock(&g_server_lock);
		while ((pnode = double_list_get_from_head(&g_lost_list)) != NULL)
			double_list_append_as_tail(&temp_list, pnode);
		pthread_mutex_unlock(&g_server_lock);

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			pback->sockd = connect_midb(pback->psvr->ip_addr,
							pback->psvr->port);
			if (-1 != pback->sockd) {
				time(&pback->last_time);
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				pthread_mutex_unlock(&g_server_lock);
			} else {
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&g_lost_list, &pback->node);
				pthread_mutex_unlock(&g_server_lock);
			}
		}
		sleep(1);
	}
	return NULL;
}

static BACK_CONN *get_connection(const char *prefix)
{
	int i;
	BACK_SVR *pserver;
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
		pnode=double_list_get_after(&g_server_list, pnode)) {
		pserver = (BACK_SVR*)pnode->pdata;
		if (0 == strncmp(pserver->prefix, prefix, pserver->prefix_len)) {
			break;
		}
	}
	
	if (NULL == pnode) {
		return NULL;
	}

	pthread_mutex_lock(&g_server_lock);
	pnode = double_list_get_from_head(&pserver->conn_list);
	pthread_mutex_unlock(&g_server_lock);
	if (NULL == pnode) {
		for (i=0; i<SOCKET_TIMEOUT; i++) {
			sleep(1);
			pthread_mutex_lock(&g_server_lock);
			pnode = double_list_get_from_head(&pserver->conn_list);
			pthread_mutex_unlock(&g_server_lock);
			if (NULL != pnode) {
				break;
			}
		}
		if (NULL == pnode) {
			return NULL;
		}
	}
	return (BACK_CONN*)pnode->pdata;
}

static BOOL check_full(char *path)
{
	int length;
	int offset;
	int read_len;
	fd_set myset;
	BACK_CONN *pback;
	struct timeval tv;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return TRUE;
	}

	length = snprintf(buff, 1024, "M-CKFL %s\r\n", path);
	if (length != write(pback->sockd, buff, length)) {
		goto CHECK_ERROR;
	}

	offset = 0;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(pback->sockd, &myset);
		if (select(pback->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			goto CHECK_ERROR;
		}
		read_len = read(pback->sockd, buff + offset, 1024 - offset);
		if (read_len <= 0) {
			goto CHECK_ERROR;
		}
		offset += read_len;
		if (offset >= 2 && '\r' == buff[offset - 2] &&
			'\n' == buff[offset - 1]) {
			if (8 == offset && 0 == strncasecmp("TRUE ", buff, 5)) {
				time(&pback->last_time);
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				pthread_mutex_unlock(&g_server_lock);
				if ('1' == buff[5]) {
					return FALSE;
				} else {
					return TRUE;
				}
			} else if (offset > 8 && 0 == strncasecmp("FALSE ", buff, 6)) {
				time(&pback->last_time);
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				pthread_mutex_unlock(&g_server_lock);
				return TRUE;
			} else {
				goto CHECK_ERROR;
			}
		}
		if (1024 == offset) {
			goto CHECK_ERROR;
		}
	}

CHECK_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return TRUE;
}

static int connect_midb(const char *ip_addr, int port)
{
    int sockd;
    int read_len;
	fd_set myset;
	struct timeval tv;
    char temp_buff[1024];
    struct sockaddr_in servaddr;


    sockd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    inet_pton(AF_INET, ip_addr, &servaddr.sin_addr);
    if (0 != connect(sockd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
        close(sockd);
        return -1;
    }
	tv.tv_usec = 0;
	tv.tv_sec = SOCKET_TIMEOUT;
	FD_ZERO(&myset);
	FD_SET(sockd, &myset);
	if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
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

static void console_talk(int argc, char **argv, char *result, int length)
{
	BACK_SVR *pserver;
	DOUBLE_LIST_NODE *pnode;
	char help_string[] = "250 midb agent help information:\r\n"
						 "\t%s echo mp-path\r\n"
						 "\t    --print the midb server information";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0]);
		result[length - 1] = '\0';
		return;
	}
	
	if (3 == argc && 0 == strcmp("echo", argv[1])) {
		for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
			pnode=double_list_get_after(&g_server_list, pnode)) {
			pserver = (BACK_SVR*)pnode->pdata;
			if (0 == strcmp(argv[2], pserver->prefix)) {
				snprintf(result, length,
				"250 agent information of midb(mp:%s ip:%s port:%d):\r\n"
				"\ttotal connections       %d\r\n"
				"\tavailable connections   %d",
				pserver->prefix, pserver->ip_addr, pserver->port,
				g_conn_num, double_list_get_nodes_num(&pserver->conn_list));
				result[length - 1] = '\0';
				return;
			}
		}
		snprintf(result, length, "250 no agent inforamtion of midb(mp:%s)", 
			argv[2]);
		return;
	}
	
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

