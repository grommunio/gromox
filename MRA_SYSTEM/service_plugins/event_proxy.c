#include <stdbool.h>
#include <gromox/mrasvc_common.h>
#include "double_list.h"
#include "config_file.h"
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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>


#define SOCKET_TIMEOUT          60

#define MAX_CMD_LENGTH			64*1024

typedef struct _BACK_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
	time_t last_time;
} BACK_CONN;


static BOOL g_notify_stop;
static char g_event_ip[16];
static int g_event_port;
static pthread_t g_scan_id;
static pthread_mutex_t g_back_lock;
static DOUBLE_LIST g_back_list;
static DOUBLE_LIST g_lost_list;



static void* scan_work_func(void *param);

static int read_line(int sockd, char *buff, int length);
static int connect_event(void);
static void console_talk(int argc, char **argv, char *result, int length);

static void broadcast_event(const char *event);

static void broadcast_select(const char *username, const char *folder);

static void broadcast_unselect(const char *username, const char *folder);

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	int i, conn_num;
    BACK_CONN *pback;
    DOUBLE_LIST_NODE *pnode;
	CONFIG_FILE  *pfile;
	char file_name[256];
	char config_path[256];
	char *str_value, *psearch;
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);

		g_notify_stop = TRUE;

		double_list_init(&g_back_list);
		double_list_init(&g_lost_list);

		pthread_mutex_init(&g_back_lock, NULL);

		
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(config_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init2(NULL, config_path);
		if (NULL == pfile) {
			printf("[event_proxy]: config_file_init %s: %s\n", config_path, strerror(errno));
			return FALSE;
		}

		str_value = config_file_get_value(pfile, "CONNECTION_NUM");
		if (NULL == str_value) {
			conn_num = 8;
			config_file_set_value(pfile, "CONNECTION_NUM", "8");
		} else {
			conn_num = atoi(str_value);
			if (conn_num < 0) {
				conn_num = 8;
				config_file_set_value(pfile, "CONNECTION_NUM", "8");
			}
		}
		printf("[event_proxy]: event connection number is %d\n", conn_num);

		str_value = config_file_get_value(pfile, "EVENT_HOST");
		if (NULL == str_value) {
			strcpy(g_event_ip, "127.0.0.1");
			config_file_set_value(pfile, "EVENT_HOST", "127.0.0.1");
		} else {
			strcpy(g_event_ip, str_value);
		}
		printf("[event_proxy]: event host is %s\n", g_event_ip);

		str_value = config_file_get_value(pfile, "EVENT_PORT");
		if (NULL == str_value) {
			g_event_port = 33333;
			config_file_set_value(pfile, "EVENT_PORT", "33333");
		} else {
			g_event_port = atoi(str_value);
			if (g_event_port <= 0) {
				g_event_port = 33333;
				config_file_set_value(pfile, "EVENT_PORT", "33333");
			}
		}
		printf("[event_proxy]: event port is %d\n", g_event_port);
		config_file_free(pfile);

		for (i=0; i<conn_num; i++) {
			pback = (BACK_CONN*)malloc(sizeof(BACK_CONN));
			if (NULL != pback) {
		        pback->node.pdata = pback;
				pback->sockd = -1;
				double_list_append_as_tail(&g_lost_list, &pback->node);
			}
		}

		g_notify_stop = FALSE;
		if (0 != pthread_create(&g_scan_id, NULL, scan_work_func, NULL)) {
			g_notify_stop = TRUE;
			while ((pnode = double_list_get_from_head(&g_back_list)) != NULL)
				free(pnode->pdata);
			printf("[event_proxy]: fail to create scan thread\n");
			return FALSE;
		}

		if (FALSE == register_service("broadcast_event", broadcast_event)) {
			printf("[event_proxy]: fail to register broadcast_event\n");
		}
		
		if (FALSE == register_service("broadcast_select", broadcast_select)) {
			printf("[event_proxy]: fail to register broadcast_select\n");
		}
		
		if (FALSE == register_service("broadcast_unselect", broadcast_unselect)) {
			printf("[event_proxy]: fail to register broadcast_unselect\n");
		}
		
        if (FALSE == register_talk(console_talk)) {
			printf("[event_proxy]: fail to register console talk\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:

		if (FALSE == g_notify_stop) {
			g_notify_stop = TRUE;
			pthread_join(g_scan_id, NULL);

			while ((pnode = double_list_get_from_head(&g_lost_list)) != NULL)
				free(pnode->pdata);

			while ((pnode = double_list_get_from_head(&g_back_list)) != NULL) {
				pback = (BACK_CONN*)pnode->pdata;
				write(pback->sockd, "QUIT\r\n", 6);
				close(pback->sockd);
				free(pback);
			}
		}

		pthread_mutex_destroy(&g_back_lock);

		double_list_free(&g_lost_list);
		double_list_free(&g_back_list);

		return TRUE;
	}
	return false;
}


static void console_talk(int argc, char **argv, char *result, int length)
{

	char help_string[] = "250 event agent help information:\r\n"
		                 "\t%s info\r\n"
						 "\t    --print the module information";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0]);
		result[length - 1] = '\0';
		return;
	}

	if (2 == argc && 0 == strcmp("info", argv[1])) {
		snprintf(result, length,
			"250 event agent information:\r\n"
			"\ttotal event connections    %d\r\n"
			"\talive event connections    %d",
			double_list_get_nodes_num(&g_back_list) +
			double_list_get_nodes_num(&g_lost_list),
			double_list_get_nodes_num(&g_back_list));
		result[length - 1] = '\0';
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


static void *scan_work_func(void *param)
{
	int tv_msec;
	time_t now_time;
	BACK_CONN *pback;
	char temp_buff[1024];
	struct pollfd pfd_read;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;

	double_list_init(&temp_list);
	
	while (FALSE == g_notify_stop) {
		pthread_mutex_lock(&g_back_lock);
		time(&now_time);
		ptail = double_list_get_tail(&g_back_list);
		while ((pnode = double_list_get_from_head(&g_back_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			if (now_time - pback->last_time >= SOCKET_TIMEOUT - 3) {
				double_list_append_as_tail(&temp_list, &pback->node);
			} else {
				double_list_append_as_tail(&g_back_list, &pback->node);
			}

			if (pnode == ptail) {
				break;
			}
		}
		pthread_mutex_unlock(&g_back_lock);

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			write(pback->sockd, "PING\r\n", 6);
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec) ||
				read(pback->sockd, temp_buff, 1024) <= 0) {
				close(pback->sockd);
				pback->sockd = -1;
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_lost_list, &pback->node);
				pthread_mutex_unlock(&g_back_lock);
			} else {
				time(&pback->last_time);
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_back_list, &pback->node);
				pthread_mutex_unlock(&g_back_lock);
			}
		}

		pthread_mutex_lock(&g_back_lock);
		while ((pnode = double_list_get_from_head(&g_lost_list)) != NULL)
			double_list_append_as_tail(&temp_list, pnode);
		pthread_mutex_unlock(&g_back_lock);

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			pback->sockd = connect_event();
			if (-1 != pback->sockd) {
				time(&pback->last_time);
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_back_list, &pback->node);
				pthread_mutex_unlock(&g_back_lock);
			} else {
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_lost_list, &pback->node);
				pthread_mutex_unlock(&g_back_lock);
			}
		}
		sleep(1);
	}
	return NULL;
}

static void broadcast_select(const char *username, const char *folder)
{
	char buff[512];
	
	snprintf(buff, 512, "SELECT %s %s", username, folder);
	broadcast_event(buff);
}

static void broadcast_unselect(const char *username, const char *folder)
{
	char buff[512];
	
	snprintf(buff, 512, "UNSELECT %s %s", username, folder);
	broadcast_event(buff);
}

static void broadcast_event(const char *event)
{
	int len;
	BACK_CONN *pback;
	DOUBLE_LIST_NODE *pnode;
	char temp_buff[MAX_CMD_LENGTH];

	
	pthread_mutex_lock(&g_back_lock);
	pnode = double_list_get_from_head(&g_back_list);
	pthread_mutex_unlock(&g_back_lock);

	if (NULL == pnode) {
		return;
	}

	pback = (BACK_CONN*)pnode->pdata;

	len = snprintf(temp_buff, MAX_CMD_LENGTH, "%s\r\n", event);
	write(pback->sockd, temp_buff, len);
	if (0 != read_line(pback->sockd, temp_buff, 1024)) {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return;
	}
	time(&pback->last_time);
	pthread_mutex_lock(&g_back_lock);
	double_list_append_as_tail(&g_back_list, &pback->node);
	pthread_mutex_unlock(&g_back_lock);
}

static int read_line(int sockd, char *buff, int length)
{
	int offset;
	int tv_msec;
	int read_len;
	struct pollfd pfd_read;

	offset = 0;
	while (1) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			return -1;
		}
		read_len = read(sockd, buff + offset, length - offset);
		if (read_len <= 0) {
			return -1;
		}
		offset += read_len;
		if (offset >= 2 &&
			'\r' == buff[offset - 2] && '\n' == buff[offset - 1]) {
			buff[offset - 2] = '\0';
			return 0;
		}
		if (length == offset) {
			return -1;
		}
	}
}


static int connect_event()
{
    int sockd;
	int temp_len;
    char temp_buff[1024];
    struct sockaddr_in servaddr;


    sockd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(g_event_port);
    inet_pton(AF_INET, g_event_ip, &servaddr.sin_addr);
    if (0 != connect(sockd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
        close(sockd);
        return -1;
    }
	if (-1 == read_line(sockd, temp_buff, 1024) ||
		0 != strcasecmp(temp_buff, "OK")) {
		close(sockd);
		return -1;
	}
	temp_len = snprintf(temp_buff, 1024, "ID %s:%d\r\n",
				get_host_ID(), getpid());
	if (temp_len != write(sockd, temp_buff, temp_len)) {
		close(sockd);
		return -1;
	}

	if (-1 == read_line(sockd, temp_buff, 1024) ||
		0 != strcasecmp(temp_buff, "TRUE")) {
		close(sockd);
		return -1;
	}

	return sockd;
}



