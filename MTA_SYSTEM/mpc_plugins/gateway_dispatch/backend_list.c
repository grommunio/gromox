#include "backend_list.h"
#include "double_list.h"
#include "list_file.h"
#include "mail_func.h"
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#define DEF_MODE	S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

typedef struct _BACKEND_UNIT {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST_NODE node_temp;
	char ip[16];
	int port;
} BACKEND_UNIT;

static void* thread_work_func(void *arg);

static char g_list_path[256];
static int g_scan_interval;
static pthread_t g_thread_id;
static DOUBLE_LIST g_units_list;
static DOUBLE_LIST g_invalid_list;
static pthread_mutex_t g_list_lock;
static BOOL g_notify_stop = TRUE;


void backend_list_init(const char *list_path, int scan_interval)
{
	g_notify_stop = TRUE;
	strcpy(g_list_path, list_path);
	g_scan_interval = scan_interval;
	double_list_init(&g_units_list);
	double_list_init(&g_invalid_list);
	pthread_mutex_init(&g_list_lock, NULL);
}

int backend_list_run()
{
	pthread_attr_t attr;
	
	if (FALSE == backend_list_refresh()) {
		return -1;
	}
	g_notify_stop = FALSE;
	pthread_attr_init(&attr);
	if (0 != pthread_create(&g_thread_id, &attr, thread_work_func, NULL)) {
		pthread_attr_destroy(&attr);
		g_notify_stop = TRUE;
		return -2;
	}
	pthread_attr_destroy(&attr);
	return 0;

}

int backend_list_stop()
{
	DOUBLE_LIST_NODE *pnode;

	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thread_id, NULL);
	}
	while (pnode=double_list_get_from_head(&g_units_list)) {
		free(pnode->pdata);
	}
	while (pnode=double_list_get_from_head(&g_invalid_list)) {
		free(pnode->pdata);
	}
	return 0;
}

void backend_list_free()
{
	g_list_path[0] = '\0';
	double_list_free(&g_units_list);
	double_list_free(&g_invalid_list);
	pthread_mutex_destroy(&g_list_lock);
}

BOOL backend_list_refresh()
{
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST temp_list;
	LIST_FILE *pfile;
	BACKEND_UNIT *punit;
	int i, list_len, temp_port;
	char *pitem, temp_ip[16], *pcolon;

	pfile = list_file_init(g_list_path, "%s:32");
	if (NULL == pfile) {
		return FALSE;
	}
	list_len = list_file_get_item_num(pfile);
	if (0 == list_len) {
		printf("[gateway_dispatch]: warning!!! backend list is empty!!!\n");
	}
	pitem = list_file_get_list(pfile);
	double_list_init(&temp_list);
	for (i=0; i<list_len; i++) {
		if (NULL == extract_ip(pitem + 32*i, temp_ip)) {
			printf("[gateway_dispatch]: line %d: ip address format error in "
				"backend list\n", i);
			continue;
		}
		pcolon = strchr(pitem + 32*i, ':');
		if (NULL == pcolon) {
			temp_port = 25;
		} else {
			temp_port = atoi(pcolon + 1);
			if (0 == temp_port) {
				printf("[gateway_dispatch]: line %d: port error in backend "
					"list\n", i);
				continue;
			}
		}
		punit = (BACKEND_UNIT*)malloc(sizeof(BACKEND_UNIT));
		if (NULL == punit) {
			debug_info("[gateway_dispatch]: fail to allocate memory");
			continue;
		}
		punit->node.pdata = punit;
		punit->node_temp.pdata = punit;
		strcpy(punit->ip, temp_ip);
		punit->port = temp_port;
		double_list_append_as_tail(&temp_list, &punit->node);
	}
	list_file_free(pfile);
	pthread_mutex_lock(&g_list_lock);
	while (pnode=double_list_get_from_head(&g_invalid_list)) {
		free(pnode->pdata);
	}
	while (pnode=double_list_get_from_head(&g_units_list)) {
		free(pnode->pdata);
	}
	while (pnode=double_list_get_from_head(&temp_list)) {
		double_list_append_as_tail(&g_units_list, pnode);
	}
	pthread_mutex_unlock(&g_list_lock);
	double_list_free(&temp_list);
	return TRUE;
}

BOOL backend_list_get_unit(char *ip, int *port)
{
	DOUBLE_LIST_NODE *pnode;

	pthread_mutex_lock(&g_list_lock);
	pnode = double_list_get_from_head(&g_units_list);
	if (NULL == pnode) {
		pthread_mutex_unlock(&g_list_lock);
		return FALSE;
	}
	strcpy(ip, ((BACKEND_UNIT*)(pnode->pdata))->ip);
	*port = ((BACKEND_UNIT*)(pnode->pdata))->port;
	double_list_append_as_tail(&g_units_list, pnode);
	pthread_mutex_unlock(&g_list_lock);
	return TRUE;
}

void backend_list_invalid_unit(const char *ip, int port)
{
	DOUBLE_LIST_NODE *pnode;
	BACKEND_UNIT *punit;

	pthread_mutex_lock(&g_list_lock);
	for (pnode=double_list_get_head(&g_units_list); NULL!=pnode;
		pnode=double_list_get_after(&g_units_list, pnode)) {
		punit = (BACKEND_UNIT*)pnode->pdata;
		if (0 == strcmp(punit->ip, ip) && port == punit->port) {
			double_list_remove(&g_units_list, pnode);
			double_list_append_as_tail(&g_invalid_list, pnode);
			break;
		}
	}
	pthread_mutex_unlock(&g_list_lock);
}


static void* thread_work_func(void *arg)
{
	int i, sockd, opt;
	int val_opt, opt_len;
	struct timeval tv;
	BOOL b_connected;
	fd_set myset;
	struct sockaddr_in servaddr;
	BACKEND_UNIT *punit;
	DOUBLE_LIST_NODE *phead, *ptail, *pnode;
	DOUBLE_LIST temp_list;
	
	i = 0;
	double_list_init(&temp_list);
	while (FALSE == g_notify_stop) {
		if (i < g_scan_interval) {
			sleep(1);
			i ++;
			continue;
		}
		pthread_mutex_lock(&g_list_lock);
		phead = double_list_get_head(&g_invalid_list);
		ptail = double_list_get_tail(&g_invalid_list);
		pthread_mutex_unlock(&g_list_lock);
		for (pnode=phead; NULL!=pnode; pnode=double_list_get_after(
			&g_invalid_list, pnode)) {
			punit = (BACKEND_UNIT*)pnode;
			sockd = socket(AF_INET, SOCK_STREAM, 0);
			/* set the socket to block mode */
			opt = fcntl(sockd, F_GETFL, 0);
			opt |= O_NONBLOCK;
			fcntl(sockd, F_SETFL, opt);
			/* end of set mode */
			bzero(&servaddr, sizeof(servaddr));
			servaddr.sin_family = AF_INET;
			servaddr.sin_port = htons(punit->port);
			inet_pton(AF_INET, punit->ip, &servaddr.sin_addr);
			b_connected = FALSE;
			if (0 == connect(sockd, (struct sockaddr*)&servaddr,
				sizeof(servaddr))) {
				b_connected = TRUE;
			} else {
				if (EINPROGRESS == errno) {
					tv.tv_sec = 10;
					tv.tv_usec = 0;
					FD_ZERO(&myset);
					FD_SET(sockd, &myset);
					if (select(sockd + 1, NULL, &myset, NULL, &tv) > 0) {
						opt_len = sizeof(int);
						if (getsockopt(sockd, SOL_SOCKET, SO_ERROR, &val_opt,
							&opt_len) >= 0 && 0 == val_opt) {
							b_connected = TRUE;
						}
					}
				}
			}
			if (FALSE == b_connected) {
				close(sockd);
			} else {
				write(sockd, "quit\r\n", 6);
				close(sockd);
				double_list_append_as_tail(&temp_list, &punit->node_temp);
			}
			if (pnode == ptail) {
				break;
			}
		}
		pthread_mutex_lock(&g_list_lock);
		while (pnode=double_list_get_from_head(&temp_list)) {
			punit = (BACKEND_UNIT*)pnode->pdata;
			double_list_remove(&g_invalid_list, &punit->node);
			double_list_append_as_tail(&g_units_list, &punit->node);
		}
		pthread_mutex_unlock(&g_list_lock);
		i = 0;
	}
	double_list_free(&temp_list);
	return NULL;
}

void backend_list_enum_invalid(BACKEND_LIST_ENUM_FUNC enum_func)
{
	DOUBLE_LIST_NODE *pnode;
	BACKEND_UNIT *punit;
	
	pthread_mutex_lock(&g_list_lock);
	for (pnode=double_list_get_head(&g_invalid_list); NULL!=pnode;
		pnode=double_list_get_after(&g_invalid_list, pnode)) {
		punit = (BACKEND_UNIT*)pnode->pdata;
		enum_func(punit->ip, punit->port);
	}
	pthread_mutex_unlock(&g_list_lock);
}

int backend_list_get_param(int param)
{
	if (BACKEND_LIST_SCAN_INTERVAL == param) {
		return g_scan_interval;
	}
	return 0;

}

void backend_list_set_param(int param, int value)
{
	if (BACKEND_LIST_SCAN_INTERVAL == param) {
		g_scan_interval = value;
		return;
	}
}

