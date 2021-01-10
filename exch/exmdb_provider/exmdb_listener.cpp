// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/socket.h>
#include <gromox/list_file.hpp>
#include <gromox/double_list.hpp>
#include "common_util.h"
#include "exmdb_parser.h"
#include "exmdb_listener.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <netdb.h>

struct ACL_ITEM {
	DOUBLE_LIST_NODE node;
	char ip_addr[32];
};

static int g_listen_port;
static int g_listen_sockd;
static BOOL g_notify_stop;
static char g_listen_ip[32];
static char g_list_path[256];
static DOUBLE_LIST g_acl_list;
static pthread_t g_listener_id;

static void *thread_work_func(void *param)
{
	int sockd;
	ACL_ITEM *pacl;
	uint8_t tmp_byte;
	socklen_t addrlen;
	char client_hostip[32];
	DOUBLE_LIST_NODE *pnode;
	struct sockaddr_storage peer_name;
	EXMDB_CONNECTION *pconnection;
	
	while (NULL == common_util_lang_to_charset ||
		NULL == common_util_cpid_to_charset ||
		NULL == common_util_get_user_displayname ||
		NULL == common_util_check_mlist_include ||
		NULL == common_util_get_user_lang ||
		NULL == common_util_get_timezone ||
		NULL == common_util_get_maildir ||
		NULL == common_util_get_id_from_username ||
		NULL == common_util_get_domain_ids ||
		NULL == common_util_send_mail ||
		NULL == common_util_get_mime_pool ||
		NULL == common_util_log_info) {
		if (g_notify_stop)
			break;
		sleep(1);	
	}
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
				tmp_byte = exmdb_response::ACCESS_DENY;
				write(sockd, &tmp_byte, 1);
				close(sockd);
				continue;
			}
		}
		pconnection = exmdb_parser_get_connection();
		if (NULL == pconnection) {
			tmp_byte = exmdb_response::MAX_REACHED;
			write(sockd, &tmp_byte, 1);
			close(sockd);
			continue;

		}
		pconnection->sockd = sockd;
		exmdb_parser_put_connection(pconnection);
	}
	pthread_exit(0);
}

void exmdb_listener_init(const char *ip,
	int port, const char *list_path)
{
	if ('\0' != ip[0]) {
		HX_strlcpy(g_listen_ip, ip, GX_ARRAY_SIZE(g_listen_ip));
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

int exmdb_listener_run()
{
	int i, num;
	ACL_ITEM *pacl;
	LIST_FILE *plist;
	
	if (0 == g_listen_port) {
		return 0;
	}
	g_listen_sockd = gx_inet_listen(g_listen_ip, g_listen_port);
	if (g_listen_sockd == -1) {
		printf("[exmdb_provider]: failed to create listen socket: %s\n", strerror(errno));
		return -1;
	}

	if ('\0' != g_list_path[0]) {
		struct ipitem { char ip_addr[32]; };
		plist = list_file_init(g_list_path, "%s:32");
		if (NULL == plist) {
			printf("[exmdb_provider]: Failed to read ACLs from %s: %s\n",
				g_list_path, strerror(errno));
			close(g_listen_sockd);
			return -5;
		}
		num = list_file_get_item_num(plist);
		auto pitem = reinterpret_cast<struct ipitem *>(list_file_get_list(plist));
		for (i=0; i<num; i++) {
			pacl = (ACL_ITEM*)malloc(sizeof(ACL_ITEM));
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

int exmdb_listener_trigger_accept()
{
	if (0 == g_listen_port) {
		return 0;
	}
	g_notify_stop = FALSE;
	int ret = pthread_create(&g_listener_id, nullptr, thread_work_func, nullptr);
	if (ret != 0) {
		printf("[exmdb_provider]: failed to create exmdb listener thread: %s\n", strerror(ret));
		return -1;
	}
	pthread_setname_np(g_listener_id, "exmdb_listener");
	return 0;
}

int exmdb_listener_stop()
{
	DOUBLE_LIST_NODE *pnode;
	
	if (0 == g_listen_port) {
		return 0;
	}
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		shutdown(g_listen_sockd, SHUT_RDWR);
		pthread_join(g_listener_id, NULL);
	}
	if (-1 != g_listen_sockd) {
		close(g_listen_sockd);
		g_listen_sockd = -1;
	}
	while ((pnode = double_list_get_from_head(&g_acl_list)) != NULL)
		free(pnode->pdata);
	return 0;
}
