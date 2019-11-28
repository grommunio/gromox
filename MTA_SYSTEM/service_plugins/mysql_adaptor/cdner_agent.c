#include <gromox/mtasvc_common.h>
#include "util.h"
#include "double_list.h"
#include "cdner_agent.h"
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
#include <sys/select.h>
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

static BOOL cdner_agent_read_line(int sockd, char *buff, int length);

static int cdner_agent_connect_cdner(const char *ip_addr, int port);

static int g_conn_num;
static int g_host_port;
static char g_host_ip[16];
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static DOUBLE_LIST g_lost_list;
static DOUBLE_LIST g_back_list;
static pthread_mutex_t g_back_lock;
static pthread_mutex_t g_crypt_lock;



void cdner_agent_init(int conn_num, const char *host_ip, int host_port)
{
	g_notify_stop = TRUE;
	g_conn_num = conn_num;
	strcpy(g_host_ip, host_ip);
	g_host_port = host_port;
}



int cdner_agent_run()
{
	int i;
	BACK_CONN *pback;

	if (0 == g_conn_num) {
		return 0;
	}


	double_list_init(&g_back_list);
	double_list_init(&g_lost_list);
	pthread_mutex_init(&g_back_lock, NULL);
	pthread_mutex_init(&g_crypt_lock, NULL);

	for (i=0; i<g_conn_num; i++) {
		pback = (BACK_CONN*)malloc(sizeof(BACK_CONN));
		if (NULL != pback) {
			pback->node.pdata = pback;
			pback->sockd = -1;
			double_list_append_as_tail(&g_lost_list, &pback->node);
		}
	}

	g_notify_stop = FALSE;
	int ret = pthread_create(&g_scan_id, nullptr, scan_work_func, nullptr);
	if (ret != 0) {
		printf("[mysql_adaptor]: failed to create cdner scan thread: %s\n", strerror(ret));
		g_notify_stop = TRUE;
		return -1;
	}
	pthread_setname_np(g_scan_id, "sqladp/cdnagent");
	return 0;
}

int cdner_agent_stop()
{
	BACK_CONN *pback;
	DOUBLE_LIST_NODE *pnode;

	if (0 == g_conn_num) {
		return 0;
	}
	
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_scan_id, NULL);
	}

	while ((pnode = double_list_get_from_head(&g_lost_list)) != NULL)
		free(pnode->pdata);

	while ((pnode = double_list_get_from_head(&g_back_list)) != NULL) {
		pback = (BACK_CONN*)pnode->pdata;
		write(pback->sockd, "QUIT\r\n", 6);
		close(pback->sockd);
		free(pback);
	}

	double_list_free(&g_lost_list);
	double_list_free(&g_back_list);

	pthread_mutex_destroy(&g_back_lock);
	pthread_mutex_destroy(&g_crypt_lock);
		
	return 0;
}



static void *scan_work_func(void *param)
{
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	BACK_CONN *pback;
	time_t now_time;
	char temp_buff[1024];
	fd_set myset;
	struct timeval tv;


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
			tv.tv_usec = 0;
			tv.tv_sec = SOCKET_TIMEOUT;
			FD_ZERO(&myset);
			FD_SET(pback->sockd, &myset);
			if (select(pback->sockd + 1, &myset, NULL, NULL, &tv) <= 0 ||
				read(pback->sockd, temp_buff, 1024) <= 0) {
				close(pback->sockd);
				pback->sockd = -1;
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_lost_list, &pback->node);
				pthread_mutex_unlock(&g_back_lock);
			} else {
				time(&pback->last_time);
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_back_list,
					&pback->node);
				pthread_mutex_unlock(&g_back_lock);
			}
		}

		pthread_mutex_lock(&g_back_lock);
		while ((pnode = double_list_get_from_head(&g_lost_list)) != NULL)
			double_list_append_as_tail(&temp_list, pnode);
		pthread_mutex_unlock(&g_back_lock);

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			pback->sockd = cdner_agent_connect_cdner(g_host_ip, g_host_port);
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

static BACK_CONN *cdner_agent_get_connection()
{
	int i;
	DOUBLE_LIST_NODE *pnode;

	pthread_mutex_lock(&g_back_lock);
	pnode = double_list_get_from_head(&g_back_list);
	pthread_mutex_unlock(&g_back_lock);
	if (NULL == pnode) {
		for (i=0; i<SOCKET_TIMEOUT; i++) {
			sleep(1);
			pthread_mutex_lock(&g_back_lock);
			pnode = double_list_get_from_head(&g_back_list);
			pthread_mutex_unlock(&g_back_lock);
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

BOOL cdner_agent_check_user(const char *username)
{
	int length;
	char buff[1024];
	BACK_CONN *pback;

	if (0 == g_conn_num) {
		return FALSE;
	}

	pback = cdner_agent_get_connection();
	if (NULL == pback) {
		return FALSE;
	}

	length = snprintf(buff, 1024, "CHECK %s\r\n", username);
	if (length != write(pback->sockd, buff, length)) {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return FALSE;
	}

	if (FALSE == cdner_agent_read_line(pback->sockd, buff, sizeof(buff))) {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return FALSE;
	}

	if (0 == strcasecmp(buff, "TRUE")) {
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_back_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return TRUE;
	} else if (0 == strcasecmp(buff, "FALSE")) {
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_back_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return FALSE;	
	} else {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return FALSE;
	}

}

BOOL cdner_agent_login(const char *username, const char *password)
{
	int length;
	char buff[1024];
	BACK_CONN *pback;

	if (0 == g_conn_num) {
		return FALSE;
	}
	pback = cdner_agent_get_connection();
	if (NULL == pback) {
		return FALSE;
	}

	length = snprintf(buff, 1024, "INFO %s\r\n", username);
	if (length != write(pback->sockd, buff, length)) {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return FALSE;
	}

	if (FALSE == cdner_agent_read_line(pback->sockd, buff, sizeof(buff))) {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return FALSE;
	}

	if (0 == strncasecmp(buff, "TRUE ", 5)) {
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_back_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);

		pthread_mutex_lock(&g_crypt_lock);
		if (0 == strcmp(crypt(password, buff + 5), buff + 5)) {
			pthread_mutex_unlock(&g_crypt_lock);
			return TRUE;
		} else {
			pthread_mutex_unlock(&g_crypt_lock);
			return FALSE;
		}
	} else if (0 == strcasecmp(buff, "FALSE")) {
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_back_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return FALSE;	
	} else {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return FALSE;
	}

}

void cdner_agent_create_user(const char *username)
{
	int length;
	char buff[1024];
	BACK_CONN *pback;

	if (0 == g_conn_num) {
		return;
	}
	pback = cdner_agent_get_connection();
	if (NULL == pback) {
		return;
	}

	length = snprintf(buff, 1024, "CREATE %s\r\n", username);
	if (length != write(pback->sockd, buff, length)) {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return;
	}

	if (FALSE == cdner_agent_read_line(pback->sockd, buff, sizeof(buff))) {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return;
	}

	if (0 == strcasecmp(buff, "TRUE") ||
		0 == strcasecmp(buff, "FALSE")) {
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_back_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_back_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
	} else {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
	}

}

static BOOL cdner_agent_read_line(int sockd, char *buff, int length)
{
	int offset;
	fd_set myset;
	int read_len;
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
		
		read_len = read(sockd, buff + offset,  length - offset);
		if (read_len <= 0) {
			return FALSE;
		}
		offset += read_len;
		if (offset >= 2 && '\r' == buff[offset - 2] &&
			'\n' == buff[offset - 1]) {
			offset -= 2;
			buff[offset] = '\0';
			return TRUE;
		}
		if (length == offset) {
			return FALSE;
		}
	}
	
}

static int cdner_agent_connect_cdner(const char *ip_addr, int port)
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


void cdner_agent_free()
{
	g_conn_num = 0;
	g_host_ip[0] = '\0';
	g_host_port = 0;
}

int cdner_agent_get_param(int param)
{
	switch (param) {
	case CDNER_TOTAL_CONNECTION:
		return g_conn_num;
	case CDNER_ALIVE_CONNECTION:
		if (0 == g_conn_num) {
			return 0;
		} else {
			return double_list_get_nodes_num(&g_back_list);
		}
	}

	return 0;
}


