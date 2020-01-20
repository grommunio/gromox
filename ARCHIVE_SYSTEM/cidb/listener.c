#include <errno.h>
#include <gromox/defs.h>
#include "common_types.h"
#include "list_file.h"
#include "double_list.h"
#include "cmd_parser.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>
#include "listener.h"

typedef struct _ACL_ITEM {
	DOUBLE_LIST_NODE node;
	char ip_addr[16];
} ACL_ITEM;

static int g_listen_port;
static char g_listen_ip[16];
static char g_list_path[256];
static int g_listen_sockd;
static BOOL g_notify_stop;
static DOUBLE_LIST g_acl_list;

static void *thread_work_func(void *param);

void listener_init(const char *ip, int port, const char *list_path)
{
	if ('\0' != ip[0]) {
		strcpy(g_listen_ip, ip);
		g_list_path[0] = '\0';
	} else {
		g_listen_ip[0] = '\0';
		strcpy(g_list_path, list_path);
	}
	g_listen_port = port;
	g_listen_sockd = -1;
	g_notify_stop = TRUE;
	double_list_init(&g_acl_list);
}

int listener_run()
{
	int i, num;
	char *pitem;
	ACL_ITEM *pacl;
	LIST_FILE *plist;
	int status, optval;
	struct sockaddr_in my_name;

	/* create a socket */
	g_listen_sockd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_listen_sockd == -1) {
		printf("[listener]: failed to create socket: %s\n", strerror(errno));
		return -1;
	}
	optval = -1;
	/* eliminates "Address already in use" error from bind */
	if (setsockopt(g_listen_sockd, SOL_SOCKET, SO_REUSEADDR,
		(const void *)&optval, sizeof(int)) < 0) {
		return -2;
	}
	
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
		printf("[listener]: bind %s:%u: %s\n", g_listen_ip, g_listen_port, strerror(errno));
        close(g_listen_sockd);
		return -3;
    }
	
	status = listen(g_listen_sockd, 5);

	if (-1 == status) {
		printf("[listener]: fail to listen socket\n");
		close(g_listen_sockd);
		return -4;
	}

	if ('\0' != g_list_path[0]) {
		plist = list_file_init(g_list_path, "%s:16");
		if (NULL == plist) {
			printf("[listener]: Failed to read ACLs from %s: %s\n",
				g_list_path, strerror(errno));
			close(g_listen_sockd);
			return -5;
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
	return 0;
}

int listener_trigger_accept()
{
	pthread_t thr_id;

	g_notify_stop = FALSE;
	int ret = pthread_create(&thr_id, nullptr, thread_work_func, nullptr);
	if (ret != 0) {
		printf("[listener]: failed to create listener thread: %s\n", strerror(ret));
		return -1;
	}
	pthread_setname_np(thr_id, "accept");
	return 0;
}

int listener_stop() {
	g_notify_stop = TRUE;
	if (g_listen_sockd > 0) {
		close(g_listen_sockd);
		g_listen_sockd = -1;
	}
	return 0;
}

void listener_free(){
	g_listen_port = 0;
}


static void *thread_work_func(void *param)
{
	int sockd;
	ACL_ITEM *pacl;
	socklen_t addrlen;
	char client_hostip[16];
	CONNECTION *pconnection;
	DOUBLE_LIST_NODE *pnode;
	struct sockaddr_in peer_name;


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

		pconnection = cmd_parser_get_connection();
		if (NULL == pconnection) {
			write(sockd, "Maximum Connection Reached!\r\n", 29);
			close(sockd);
			continue;

		}
		pconnection->sockd = sockd;
		pconnection->is_selecting = FALSE;
		write(sockd, "OK\r\n", 4);
		cmd_parser_put_connection(pconnection);
	}
	
	pthread_exit(0);
}


