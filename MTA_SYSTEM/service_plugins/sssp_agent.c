#include <stdbool.h>
#include <gromox/mtasvc_common.h>
#include "util.h"
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


typedef struct _BACK_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
	time_t last_time;
} BACK_CONN;

static void* scan_work_func(void *param);

static int connect_sssp(const char *ip_addr, int port);

static BOOL check_virus(int buflen, void *pbuff, char *virusname);

static void console_talk(int argc, char **argv, char *result, int length);

static int g_conn_num;
static int g_sssp_port;
static char g_sssp_ip[16];
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static DOUBLE_LIST g_lost_list;
static DOUBLE_LIST g_connection_list;
static pthread_mutex_t g_connection_lock;

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	int i;
	char *psearch;
	char *str_value;
	char file_name[256];
	char config_path[256];
    BACK_CONN *pback;
	CONFIG_FILE *pconfig;
    DOUBLE_LIST_NODE *pnode;

	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		
		g_notify_stop = TRUE;

		double_list_init(&g_lost_list);
		double_list_init(&g_connection_list);
		pthread_mutex_init(&g_connection_lock, NULL);

		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(config_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig = config_file_init(config_path);
		if (NULL == pconfig) {
			printf("[sssp_agent]: fail to open config file!!!\n");
			return FALSE;
		}
		
		str_value = config_file_get_value(pconfig, "CONNECTION_NUM");
		if (NULL == str_value) {
			g_conn_num = 10;
			config_file_set_value(pconfig, "CONNECTION_NUM", "10");
		} else {
			g_conn_num = atoi(str_value);
			if (g_conn_num < 2 || g_conn_num > 100) {
				g_conn_num = 10;
				config_file_set_value(pconfig, "CONNECTION_NUM", "10");
			}
		}

		printf("[sssp_agent]: sssp connection number is %d\n", g_conn_num);

		str_value = config_file_get_value(pconfig, "SSSP_LISTEN_IP");
		if (NULL == str_value) {
			strcpy(g_sssp_ip, "127.0.0.1");
		} else {
			strcpy(g_sssp_ip, str_value);
		}
		printf("[sssp_agent]: sssp server listen ip is %s\n", g_sssp_ip);

		str_value = config_file_get_value(pconfig, "SSSP_LISTEN_PORT");
		if (NULL == str_value) {
			g_sssp_port = 4010;
		} else {
			g_sssp_port = atoi(str_value);
			if (g_sssp_port <= 0) {
				g_sssp_port = 4010;
			}
		}
		printf("[sssp_agent]: sssp server listen port is %d\n", g_sssp_port);

		config_file_save(pconfig);
		config_file_free(pconfig);

		for (i=0; i<g_conn_num; i++) {
			pback = (BACK_CONN*)malloc(sizeof(BACK_CONN));
			if (NULL != pback) {
				pback->node.pdata = pback;
				pback->sockd = -1;
				double_list_append_as_tail(&g_lost_list, &pback->node);
			}
		}

		g_notify_stop = FALSE;
		if (0 != pthread_create(&g_scan_id, NULL, scan_work_func, NULL)) {
			printf("[sssp_agent]: fail to create scan thread\n");
			return FALSE;
		}

		if (FALSE == register_service("check_virus", check_virus)) {
			printf("[sssp_agent]: fail to register services\n");
			return FALSE;
		}

		if (FALSE == register_talk(console_talk)) {
			printf("[sssp_agent]: fail to register console talk\n");
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

		while ((pnode = double_list_get_from_head(&g_connection_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			write(pback->sockd, "BYE\r\n", 5);
			close(pback->sockd);
			free(pback);
		}

		double_list_free(&g_lost_list);
		double_list_free(&g_connection_list);

		pthread_mutex_destroy(&g_connection_lock);

		return TRUE;
	}
	return false;
}


static int read_line(int sockd, char *buff, int length)
{
    int offset;
    int read_len;
    fd_set myset;
    struct timeval tv;

    offset = 0;
    while (1) {
        tv.tv_usec = 0;
        tv.tv_sec = SOCKET_TIMEOUT;
        FD_ZERO(&myset);
        FD_SET(sockd, &myset);
        if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
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


static int read_message(int sockd, char *buff, int length)
{
    int offset;
    int read_len;
    fd_set myset;
    struct timeval tv;

    offset = 0;
    while (1) {
        tv.tv_usec = 0;
        tv.tv_sec = SOCKET_TIMEOUT;
        FD_ZERO(&myset);
        FD_SET(sockd, &myset);
        if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
            return -1;
        }
        read_len = read(sockd, buff + offset, length - offset);
        if (read_len <= 0) {
            return -1;
        }
        offset += read_len;
        if (offset >= 4 && 0 == memcmp(buff + offset - 4, "\r\n\r\n", 4)) {
            buff[offset - 2] = '\0';
            return 0;
        }
        if (length == offset) {
            return -1;
        }
    }

}


static void *scan_work_func(void *param)
{
	time_t now_time;
	BACK_CONN *pback;
	char temp_buff[4096];
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;


	double_list_init(&temp_list);

	while (FALSE == g_notify_stop) {
		pthread_mutex_lock(&g_connection_lock);
		time(&now_time);
		ptail = double_list_get_tail(&g_connection_list);
		while ((pnode = double_list_get_from_head(&g_connection_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			if (now_time - pback->last_time >= SOCKET_TIMEOUT - 3) {
				double_list_append_as_tail(&temp_list, &pback->node);
			} else {
				double_list_append_as_tail(&g_connection_list,
					&pback->node);
			}

			if (pnode == ptail) {
				break;
			}
		}
		pthread_mutex_unlock(&g_connection_lock);

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			if (16 != write(pback->sockd, "SSSP/1.0 QUERY\r\n", 16) ||
				-1 == read_message(pback->sockd, temp_buff, 4096)) {
				close(pback->sockd);
				pback->sockd = -1;
				pthread_mutex_lock(&g_connection_lock);
				double_list_append_as_tail(&g_lost_list, &pback->node);
				pthread_mutex_unlock(&g_connection_lock);
			} else {
				time(&pback->last_time);
				pthread_mutex_lock(&g_connection_lock);
				double_list_append_as_tail(&g_connection_list, &pback->node);
				pthread_mutex_unlock(&g_connection_lock);
			}
		}

		pthread_mutex_lock(&g_connection_lock);
		while ((pnode = double_list_get_from_head(&g_lost_list)) != NULL)
			double_list_append_as_tail(&temp_list, pnode);
		pthread_mutex_unlock(&g_connection_lock);

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			pback->sockd = connect_sssp(g_sssp_ip, g_sssp_port);
			if (-1 != pback->sockd) {
				time(&pback->last_time);
				pthread_mutex_lock(&g_connection_lock);
				double_list_append_as_tail(&g_connection_list,
					&pback->node);
				pthread_mutex_unlock(&g_connection_lock);
			} else {
				pthread_mutex_lock(&g_connection_lock);
				double_list_append_as_tail(&g_lost_list, &pback->node);
				pthread_mutex_unlock(&g_connection_lock);
			}
		}
		sleep(1);
	}
	return NULL;
}


static BOOL check_virus(int buflen, void *pbuff, char *virusname)
{
	int length;
	char *ptoken;
	int writie_len;
	BACK_CONN *pback;
	char buff[4096];
	DOUBLE_LIST_NODE *pnode;


	pthread_mutex_lock(&g_connection_lock);
	pnode = double_list_get_from_head(&g_connection_list);
	pthread_mutex_unlock(&g_connection_lock);

	if (NULL == pnode) {
		return TRUE;
	}

	pback = (BACK_CONN*)pnode->pdata;

	length = snprintf(buff, 1024, "SSSP/1.0 SCANDATA %d\r\n", buflen);
	if (length != write(pback->sockd, buff, length)) {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_connection_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_connection_lock);
		return TRUE;
	}

	if (-1 == read_line(pback->sockd, buff, sizeof(buff))) {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_connection_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_connection_lock);
		return TRUE;
	}

	if (0 != strncasecmp(buff, "ACC ", 4)) {
		pthread_mutex_lock(&g_connection_lock);
		double_list_append_as_tail(&g_connection_list, &pback->node);
		pthread_mutex_unlock(&g_connection_lock);
		return TRUE;
	}

	writie_len = write(pback->sockd, pbuff, buflen);
	if (writie_len != buflen || 2 != write(pback->sockd, "\r\n", 2)) {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_connection_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_connection_lock);
		return TRUE;
	}

	if (-1 == read_message(pback->sockd, buff, sizeof(buff))) {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_connection_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_connection_lock);
		return TRUE;
	}

	pthread_mutex_lock(&g_connection_lock);
	double_list_append_as_tail(&g_connection_list, &pback->node);
	pthread_mutex_unlock(&g_connection_lock);

	if (0 == strncasecmp(buff, "VIRUS ", 6)) {
		ptoken = strchr(buff, '\r');
		if (NULL != ptoken) {
			length = ptoken - (buff + 6);
			if (length >= 256) {
				length = 255;
			}
			memcpy(virusname, buff + 6, length);
			virusname[length] = '\0';
			rtrim_string(virusname);
		} else {
			strcpy(virusname, "unknown virus");
		}
		return FALSE;
	}
	return TRUE;
}


static int connect_sssp(const char *ip_addr, int port)
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
	if (0 != strcasecmp(temp_buff, "OK SSSP/1.0\r\n")) {
		close(sockd);
		return -1;
	}
	return sockd;
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	char help_string[] = "250 sssp agent help information:\r\n"
						 "\t%s echo\r\n"
						 "\t    --print the sssp server information";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0]);
		result[length - 1] = '\0';
		return;
	}
	
	if (2 == argc && 0 == strcmp("echo", argv[1])) {
		snprintf(result, length,
		"250 agent information of sssp:\r\n"
		"\ttotal connections       %d\r\n"
		"\tavailable connections   %d",
		g_conn_num, double_list_get_nodes_num(&g_connection_list));
		result[length - 1] = '\0';
		return;
	}
	
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

