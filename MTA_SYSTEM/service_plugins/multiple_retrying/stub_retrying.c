#include <errno.h>
#include <string.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "list_file.h"
#include "double_list.h"
#include "retrying_table.h"
#include "multiple_retrying.h"
#include "stub_retrying.h"
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

typedef struct _CONNECTION_THR {
	DOUBLE_LIST_NODE node;
	int sockd;
	pthread_t tid;
} CONNECTION_THR;

typedef struct _UNIT_ADDR {
	DOUBLE_LIST_NODE node;
	char ip_addr[16];
} UNIT_ADDR;

static int g_port;
static int g_time_out;
static int g_channel_num;
static int g_wait_interval;
static int g_listen_sockd;
static pthread_t g_thr_id;
static char g_list_path[256];
static DOUBLE_LIST g_unit_list;
static DOUBLE_LIST g_connection_list;
static pthread_mutex_t g_connection_lock;

static BOOL stub_retrying_check_allowing(const char *client_ip);

static void *accept_work_func(void *param);

static void *connection_work_func(void *param);

void stub_retrying_init(const char *list_path, int port, int time_out,
	int channel_num)
{
	g_listen_sockd = -1;
	g_port = port;
	g_time_out = time_out;
	g_channel_num = channel_num;
	strcpy(g_list_path, list_path);
	double_list_init(&g_unit_list);
	double_list_init(&g_connection_list);
	pthread_mutex_init(&g_connection_lock, NULL);
}

int stub_retrying_run()
{
	int optval;
	int i, item_num;
	int sockd, status;
	LIST_FILE *plist;
	UNIT_ADDR *punit;
	struct sockaddr_in my_name;
	struct ipitem { char ip_addr[16]; };
	
	plist = list_file_init(g_list_path, "%s:16");
	if (NULL == plist) {
		printf("[multiple_retrying]: list_file_init %s: %s\n",
			g_list_path, strerror(errno));
		return -1;
	}
	const struct ipitem *pitem = reinterpret_cast(struct ipitem *, list_file_get_list(plist));
	item_num = list_file_get_item_num(plist);
	for (i=0; i<item_num; i++) {
		punit = (UNIT_ADDR*)malloc(sizeof(UNIT_ADDR));
		if (NULL == punit) {
			printf("[multiple_retrying]: Failed to allocate memory for unit\n");
			continue;
		}
		punit->node.pdata = punit;
		HX_strlcpy(punit->ip_addr, pitem[i].ip_addr, sizeof(punit->ip_addr));
		double_list_append_as_tail(&g_unit_list, &punit->node);
	}
	list_file_free(plist);

	if (g_time_out > double_list_get_nodes_num(&g_unit_list)*g_channel_num) {
		g_wait_interval = g_time_out;
	} else {
		g_wait_interval = double_list_get_nodes_num(&g_unit_list)*g_channel_num;
	}
	
	/* create a socket */
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockd == -1) {
		printf("[multiple_retrying]: failed to create listen socket: %s\n", strerror(errno));
		return -2;
	}
	optval = -1;
	/* eliminates "Address already in use" error from bind */
	setsockopt(sockd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
		sizeof(int));
	
	/* socket binding */
	memset(&my_name, 0, sizeof(my_name));
	my_name.sin_family = AF_INET;
	my_name.sin_addr.s_addr = INADDR_ANY;
	my_name.sin_port = htons(g_port);
	
	status = bind(sockd, (struct sockaddr*)&my_name, sizeof(my_name));
	if (-1 == status) {
		printf("[multiple_retrying]: bind *:%u: %s\n", g_port, strerror(errno));
        close(sockd);
		return -3;
    }
	status = listen(sockd, 5);

	if (-1 == status) {
		printf("[multiple_retrying]: fail to listen socket\n");
		close(sockd);
		return -4;
	}
	int ret = pthread_create(&g_thr_id, nullptr, accept_work_func,
	          reinterpret_cast(void *, static_cast(intptr_t, sockd)));
	if (ret != 0) {
		printf("[multiple_retrying]: failed to create accept thread: %s\n", strerror(ret));
		close(sockd);
		return -5;
	}
	pthread_setname_np(g_thr_id, "multiretr/accept");
	g_listen_sockd = sockd;
	return 0;
}

static void *accept_work_func(void *param)
{
	int sockd, sockd2;
	socklen_t addrlen;
	CONNECTION_THR *pconnection;	
	struct sockaddr_storage peer_name;
	
	sockd = (int)(long)param;
    for (;;) {
		/* wait for an incoming connection */
        addrlen = sizeof(peer_name);
        sockd2 = accept(sockd, (struct sockaddr*)&peer_name, &addrlen);
		if (-1 == sockd2){
			printf("[multiple_retrying]: fail to accept connection\n");
			continue;
        }
		fcntl(sockd2, F_SETFL, O_NONBLOCK);

		char client_hostip[16];
		int ret = getnameinfo(reinterpret_cast(struct sockaddr *, &peer_name),
		          addrlen, client_hostip, sizeof(client_hostip),
		          nullptr, 0, NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			printf("getnameinfo: %s\n", gai_strerror(ret));
			close(sockd2);
			continue;
		}
		if (!stub_retrying_check_allowing(client_hostip)) {
			multiple_retrying_writeline_timeout(sockd2, "Access Deny!", 1);
			close(sockd2);
			continue;
		}
		pconnection = (CONNECTION_THR*)malloc(sizeof(CONNECTION_THR));
		if (NULL == pconnection) {
			multiple_retrying_writeline_timeout(sockd2, "Internal Error!", 1);
			close(sockd2);
			continue;
		}
		pconnection->node.pdata = pconnection;
		pconnection->sockd = sockd2;
		if (0 != pthread_create(&pconnection->tid, NULL, connection_work_func,
			pconnection)) {
			multiple_retrying_writeline_timeout(sockd2, "Internal Error!", 1);
			close(sockd2);
			free(pconnection);
			continue;
		}
		pthread_setname_np(pconnection->tid, "multiretr/conn");
	}
	return NULL;
}

int stub_retrying_stop()
{
	UNIT_ADDR *punit;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_THR *pconnection;
	
	if (-1 != g_listen_sockd) {
		pthread_cancel(g_thr_id);
		close(g_listen_sockd);
		g_listen_sockd = -1;
	}
	pthread_mutex_lock(&g_connection_lock);
	while ((pnode = double_list_get_from_head(&g_connection_list)) != NULL) {
		pconnection = (CONNECTION_THR*)pnode->pdata;
		pthread_cancel(pconnection->tid);
		close(pconnection->sockd);
		free(pconnection);
	}
	while ((pnode = double_list_get_from_head(&g_unit_list)) != NULL) {
		punit = (UNIT_ADDR*)pnode->pdata;
		free(punit);
	}
	return 0;
}

void stub_retrying_free()
{
	double_list_free(&g_connection_list);
	double_list_free(&g_unit_list);
	pthread_mutex_destroy(&g_connection_lock);
}

static BOOL stub_retrying_check_allowing(const char *client_ip)
{
	UNIT_ADDR *punit;
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(&g_unit_list); pnode!=NULL;
		pnode=double_list_get_after(&g_unit_list, pnode)) {
		punit = (UNIT_ADDR*)pnode->pdata;
		if (0 == strcmp(punit->ip_addr, client_ip)) {
			return TRUE;
		}
	}
	return FALSE;
}

static void *connection_work_func(void *param)
{
	BOOL b_result;
	char temp_line[256];
	CONNECTION_THR *pconnection;

	pconnection = (CONNECTION_THR*)param;
	if (FALSE == multiple_retrying_writeline_timeout(pconnection->sockd,
		"OK", 1)) {
		close(pconnection->sockd);
		free(pconnection);
		pthread_detach(pthread_self());
		pthread_exit(0);
	}
	pthread_mutex_lock(&g_connection_lock);
	double_list_append_as_tail(&g_connection_list, &pconnection->node);
	pthread_mutex_unlock(&g_connection_lock);
	while (TRUE) {
		if (FALSE == multiple_retrying_readline_timeout(pconnection->sockd,
			temp_line, 256, g_wait_interval)) {
			goto EXIT_THEARD;
		}
		if (0 == strcmp(temp_line, "PING")) {
			if (FALSE == multiple_retrying_writeline_timeout(
				pconnection->sockd, "OK", 1)) {
				goto EXIT_THEARD;
			} else {
				continue;
			}
		}
		if (TRUE == retrying_table_check(temp_line)) {
			b_result = multiple_retrying_writeline_timeout(pconnection->sockd,
						"TRUE", 1);
		} else {
			b_result = multiple_retrying_writeline_timeout(pconnection->sockd,
						"FALSE", 1);
		}
		if (FALSE == b_result) {
			goto EXIT_THEARD;
		}
	}
EXIT_THEARD:
	pthread_mutex_lock(&g_connection_lock);
	double_list_remove(&g_connection_list, &pconnection->node);
	pthread_mutex_unlock(&g_connection_lock);
	close(pconnection->sockd);
	free(pconnection);
	pthread_detach(pthread_self());
	pthread_exit(0);
}

void stub_retrying_set_param(int param, int value)
{
	if (STUB_RETRYING_WAIT_INTERVAL == param) {
		g_wait_interval = value;
	}
}

