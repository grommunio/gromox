#include "exec_sched.h"
#include "util.h"
#include "double_list.h"
#include "communicator.h"
#include "list_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>


#define SOCKET_TIMEOUT		60

#define COMMAND_LENGTH		512

#define MAXARGS				128

typedef struct _ACL_ITEM {
	DOUBLE_LIST_NODE node;
	char ip_addr[16];
} ACL_ITEM;


typedef struct _CONNECTION_NODE {
	DOUBLE_LIST_NODE node;
	int sockd;
	int offset;
	char buffer[1024];
	char line[1024];
} CONNECTION_NODE;


static int g_threads_num;
static int g_listen_port;
static int g_listen_sockd;
static char g_listen_ip[16];
static char g_list_path[256];
static BOOL g_notify_stop;
static pthread_t g_listen_tid;
static pthread_t *g_thr_ids;
static DOUBLE_LIST g_acl_list;
static DOUBLE_LIST g_connection_list;
static DOUBLE_LIST g_connection_list1;
static pthread_mutex_t g_connection_lock;
static pthread_mutex_t g_cond_mutex;
static pthread_cond_t g_waken_cond;



static void *accept_work_func(void *param);

static void *thread_work_func(void *param);

static BOOL read_mark(CONNECTION_NODE *pconnection);


void communicator_init(const char *listen_ip, int listen_port,
	const char *list_path, int threads_num)
{
	if ('\0' != listen_ip[0]) {
		strcpy(g_listen_ip, listen_ip);
		g_list_path[0]  = '\0';
	} else {
		g_listen_ip[0] = '\0';
		strcpy(g_list_path, list_path);
	}
	g_listen_port = listen_port;
	g_listen_sockd = -1;
	g_threads_num = threads_num;
	g_notify_stop = TRUE;

	pthread_mutex_init(&g_connection_lock, NULL);
	pthread_mutex_init(&g_cond_mutex, NULL);
	pthread_cond_init(&g_waken_cond, NULL);

	double_list_init(&g_acl_list);
	double_list_init(&g_connection_list);
	double_list_init(&g_connection_list1);

}

int communicator_run()
{
	int i, num;
	char *pitem;
	ACL_ITEM *pacl;
	LIST_FILE *plist;
	int optval, status;
	DOUBLE_LIST_NODE *pnode;
	struct sockaddr_in my_name;

	
	/* create a socket */
	g_listen_sockd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_listen_sockd == -1) {
        printf("[communicator]: fail to create socket for listening\n");
		return -1;
	}
	optval = -1;
	/* eliminates "Address already in use" error from bind */
	setsockopt(g_listen_sockd, SOL_SOCKET, SO_REUSEADDR,
		(const void *)&optval, sizeof(int));
	
	/* socket binding */
	memset(&my_name, 0, sizeof(my_name));
	my_name.sin_family = AF_INET;
	if ('\0' != g_listen_ip[0]) {
		my_name.sin_addr.s_addr = inet_addr(g_listen_ip);
	} else {
		my_name.sin_addr.s_addr = INADDR_ANY;	
	}
	my_name.sin_port = htons(g_listen_port);
	
	status = bind(g_listen_sockd, (struct sockaddr*)&my_name, sizeof(my_name));
	if (-1 == status) {
		printf("[communicator]: fail to bind socket\n");
        close(g_listen_sockd);
		return -2;
    }
	
	status = listen(g_listen_sockd, 5);

	if (-1 == status) {
		printf("[communicator]: fail to listen socket\n");
		close(g_listen_sockd);
		return -3;
	}

	if ('\0' != g_list_path[0]) {
		plist = list_file_init(g_list_path, "%s:16");
		if (NULL == plist) {
			printf("[communicator]: fail to load acl from %s\n", g_list_path);
			close(g_listen_sockd);
			return -4;
		}
		num = list_file_get_item_num(plist);
		pitem = list_file_get_list(plist);
		for (i=0; i<num; i++) {
			pacl = (ACL_ITEM*)malloc(sizeof(ACL_ITEM));
			if (NULL == pacl) {
				continue;
			}
			pacl->node.pdata = pacl;
			strcpy(pacl->ip_addr, pitem + 16*i);
			double_list_append_as_tail(&g_acl_list, &pacl->node);
		}
		list_file_free(plist);

	}

	g_notify_stop = FALSE;

	if (0 != pthread_create(&g_listen_tid, NULL,
		accept_work_func, NULL)) {
		close(g_listen_sockd);
		while (pnode=double_list_get_from_head(&g_acl_list)) {
			free(pnode->pdata);
		}
		printf("[communicator]: fail to create accept thread\n");
		return -5;
	}

	g_thr_ids = (pthread_t*)malloc(g_threads_num*sizeof(pthread_t));

	for (i=0; i<g_threads_num; i++) {
		pthread_create(&g_thr_ids[i], NULL, thread_work_func, NULL);
	}


	return 0;
}

int communicator_stop()
{
	int i;
	DOUBLE_LIST_NODE *pnode;

	g_notify_stop = TRUE;
	if (g_listen_sockd > 0) {
		close(g_listen_sockd);
		g_listen_sockd = -1;
	}

	for (i=0; i<g_threads_num; i++) {
		pthread_cancel(g_thr_ids[i]);
	}

	free(g_thr_ids);
	g_thr_ids = NULL;

	close(g_listen_sockd);

	while (pnode=double_list_get_from_head(&g_acl_list)) {
		free(pnode->pdata);
	}

	return 0;
}

void communicator_free()
{
	double_list_free(&g_acl_list);
	double_list_free(&g_connection_list);
	double_list_free(&g_connection_list1);

	pthread_mutex_destroy(&g_connection_lock);
	pthread_mutex_destroy(&g_cond_mutex);
	pthread_cond_destroy(&g_waken_cond);
}


static void *accept_work_func(void *param)
{
	int sockd;
	ACL_ITEM *pacl;
	socklen_t addrlen;
	char client_hostip[16];
	DOUBLE_LIST_NODE *pnode;
	struct sockaddr_in peer_name;
	CONNECTION_NODE *pconnection;	

    while (FALSE == g_notify_stop) {
		/* wait for an incoming connection */
        addrlen = sizeof(peer_name);
        sockd = accept(g_listen_sockd, (struct sockaddr*)&peer_name, &addrlen);
		if (-1 == sockd) {
			continue;
		}
		strcpy(client_hostip, inet_ntoa(peer_name.sin_addr));
		if ('\0' != g_list_path[0]) {
			for (pnode=double_list_get_head(&g_acl_list); NULL!=pnode;
				pnode=double_list_get_after(&g_acl_list, pnode)) {
				pacl = (ACL_ITEM*)pnode->pdata;
				if (0 == strcmp(client_hostip, pacl->ip_addr)) {
					break;
				}
			}
			
			if (NULL == pnode) {
				write(sockd, "Access Deny\r\n", 13);
				close(sockd);
				continue;
			}

		}

		pconnection = (CONNECTION_NODE*)malloc(sizeof(CONNECTION_NODE));
		if (NULL == pconnection) {
			write(sockd, "Internal Error!\r\n", 17);
			close(sockd);
			continue;
		}
		pthread_mutex_lock(&g_connection_lock);
		if (double_list_get_nodes_num(&g_connection_list) + 1 +
			double_list_get_nodes_num(&g_connection_list1) >= g_threads_num) {
			pthread_mutex_unlock(&g_connection_lock);
			free(pconnection);
			write(sockd, "Maximum Connection Reached!\r\n", 29);
			close(sockd);
			continue;
		}

		pconnection->node.pdata = pconnection;
		pconnection->sockd = sockd;
		pconnection->offset = 0;
		double_list_append_as_tail(&g_connection_list1, &pconnection->node);
		pthread_mutex_unlock(&g_connection_lock);
		write(sockd, "OK\r\n", 4);
		pthread_cond_signal(&g_waken_cond);
	}
	
	pthread_exit(0);

}

static void *thread_work_func(void *param)
{
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;	

NEXT_LOOP:
	pthread_mutex_lock(&g_cond_mutex);
	pthread_cond_wait(&g_waken_cond, &g_cond_mutex);
	pthread_mutex_unlock(&g_cond_mutex);

	pthread_mutex_lock(&g_connection_lock);
	pnode = double_list_get_from_head(&g_connection_list1);
	if (NULL != pnode) {
		double_list_append_as_tail(&g_connection_list, pnode);
	}
	pthread_mutex_unlock(&g_connection_lock);

	if (NULL == pnode) {
		goto NEXT_LOOP;
	}

	pconnection = (CONNECTION_NODE*)pnode->pdata;

	while (TRUE) {
		if (FALSE == read_mark(pconnection)) {
			close(pconnection->sockd);
			pthread_mutex_lock(&g_connection_lock);
			double_list_remove(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_connection_lock);
			free(pconnection);
			goto NEXT_LOOP;
		}

		if (0 == strncasecmp(pconnection->line, "REMOVE ", 7)) {
			ltrim_string(pconnection->line + 7);
			rtrim_string(pconnection->line + 7);
			if (TRUE == exec_sched_remove(pconnection->line + 7)) {
				write(pconnection->sockd, "TRUE\r\n", 6);	
			} else {
				write(pconnection->sockd, "FALSE\r\n", 7);
			}
		} else if (0 == strncasecmp(pconnection->line, "ADD ", 4)) {
			ltrim_string(pconnection->line + 4);
			rtrim_string(pconnection->line + 4);
			if (TRUE == exec_sched_add(pconnection->line + 4)) {
				write(pconnection->sockd, "TRUE\r\n", 6);	
			} else {
				write(pconnection->sockd, "FALSE\r\n", 7);
			}
		} else if (0 == strcasecmp(pconnection->line, "QUIT")) {
			write(pconnection->sockd, "BYE\r\n", 5);
			close(pconnection->sockd);
			pthread_mutex_lock(&g_connection_lock);
			double_list_remove(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_connection_lock);
			free(pconnection);
			goto NEXT_LOOP;
		} else if (0 == strcasecmp(pconnection->line, "PING")) {
			write(pconnection->sockd, "TRUE\r\n", 6);	
		} else {
			write(pconnection->sockd, "FALSE\r\n", 7);
		}
	}
	return NULL;
}

static BOOL read_mark(CONNECTION_NODE *pconnection)
{
	fd_set myset;
	int i, read_len;
	struct timeval tv;

	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(pconnection->sockd, &myset);
		if (select(pconnection->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return FALSE;
		}
		read_len = read(pconnection->sockd, pconnection->buffer +
		pconnection->offset, 1024 - pconnection->offset);
		if (read_len <= 0) {
			return FALSE;
		}
		pconnection->offset += read_len;
		for (i=0; i<pconnection->offset-1; i++) {
			if ('\r' == pconnection->buffer[i] &&
				'\n' == pconnection->buffer[i + 1]) {
				memcpy(pconnection->line, pconnection->buffer, i);
				pconnection->line[i] = '\0';
				pconnection->offset -= i + 2;
				memmove(pconnection->buffer, pconnection->buffer + i + 2,
					pconnection->offset);
				return TRUE;
			}
		}
		if (1024 == pconnection->offset) {
			return FALSE;
		}
	}
}

