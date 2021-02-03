// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/socket.h>
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>
#include "cmd_parser.h"
#include <gromox/list_file.hpp>
#include "listener.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <cstdio>
#include "common_util.h"

struct ACL_ITEM {
	DOUBLE_LIST_NODE node;
	char ip_addr[32];
};

static int g_listen_port;
static char g_listen_ip[32];
static char g_list_path[256];
static int g_listen_sockd;
static BOOL g_notify_stop;
static DOUBLE_LIST g_acl_list;

static void *thread_work_func(void *param);

void listener_init(const char *ip, int port, const char *list_path)
{
	if ('\0' != ip[0]) {
		HX_strlcpy(g_listen_ip, ip, GX_ARRAY_SIZE(g_listen_ip));
		g_list_path[0] = '\0';
	} else {
		g_listen_ip[0] = '\0';
		HX_strlcpy(g_list_path, list_path, GX_ARRAY_SIZE(g_list_path));
	}
	g_listen_port = port;
	g_listen_sockd = -1;
	g_notify_stop = TRUE;
	double_list_init(&g_acl_list);
}

int listener_run()
{
	int i, num;
	ACL_ITEM *pacl;
	LIST_FILE *plist;

	g_listen_sockd = gx_inet_listen(g_listen_ip, g_listen_port);
	if (g_listen_sockd == -1) {
		printf("[listener]: failed to create listen socket: %s\n", strerror(errno));
		return -1;
	}
	
	if ('\0' != g_list_path[0]) {
		struct ipitem { char ip_addr[32]; };
		plist = list_file_init(g_list_path, "%s:32");
		if (NULL == plist) {
			printf("[listener]: Failed to read ACLs from %s: %s\n",
				g_list_path, strerror(errno));
			close(g_listen_sockd);
			return -5;
		}
		num = list_file_get_item_num(plist);
		auto pitem = reinterpret_cast<ipitem *>(list_file_get_list(plist));
		for (i=0; i<num; i++) {
			pacl = me_alloc<ACL_ITEM>();
			if (NULL == pacl) {
				continue;
			}
			pacl->node.pdata = pacl;
			HX_strlcpy(pacl->ip_addr, pitem[i].ip_addr, sizeof(pacl->ip_addr));
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
	pthread_setname_np(thr_id, "listener");
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
	char client_hostip[32];
	CONNECTION *pconnection;
	DOUBLE_LIST_NODE *pnode;
	struct sockaddr_storage peer_name;

	while (FALSE == g_notify_stop) {
		/* wait for an incoming connection */
        addrlen = sizeof(peer_name);
        sockd = accept(g_listen_sockd, (struct sockaddr*)&peer_name, &addrlen);
		if (-1 == sockd) {
			continue;
		}
		int ret = getnameinfo(reinterpret_cast<struct sockaddr *>(&peer_name),
		          addrlen, client_hostip, sizeof(client_hostip),
		          nullptr, 0, NI_NUMERICSERV | NI_NUMERICHOST);
		if (ret != 0) {
			printf("getnameinfo: %s\n", gai_strerror(ret));
			close(sockd);
			continue;
		}
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


