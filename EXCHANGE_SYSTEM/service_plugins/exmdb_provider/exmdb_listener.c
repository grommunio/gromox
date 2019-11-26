#include <errno.h>
#include "list_file.h"
#include "double_list.h"
#include "common_util.h"
#include "exmdb_parser.h"
#include "exmdb_listener.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>


typedef struct _ACL_ITEM {
	DOUBLE_LIST_NODE node;
	char ip_addr[16];
} ACL_ITEM;

static int g_listen_port;
static int g_listen_sockd;
static BOOL g_notify_stop;
static char g_listen_ip[16];
static char g_list_path[256];
static DOUBLE_LIST g_acl_list;
static pthread_t g_listener_id;

static void *thread_work_func(void *param)
{
	int sockd;
	ACL_ITEM *pacl;
	uint8_t tmp_byte;
	socklen_t addrlen;
	char client_hostip[16];
	DOUBLE_LIST_NODE *pnode;
	struct sockaddr_in peer_name;
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
		sleep(1);	
	}
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
				tmp_byte = RESPONSE_CODE_ACCESS_DENY;
				write(sockd, &tmp_byte, 1);
				close(sockd);
				continue;
			}
		}
		pconnection = exmdb_parser_get_connection();
		if (NULL == pconnection) {
			tmp_byte = RESPONSE_CODE_MAX_REACHED;
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

int exmdb_listener_run()
{
	int i, num;
	char *pitem;
	ACL_ITEM *pacl;
	LIST_FILE *plist;
	int status, optval;
	struct sockaddr_in my_name;
	
	
	if (0 == g_listen_port) {
		return 0;
	}
	/* create a socket */
	g_listen_sockd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_listen_sockd == -1) {
        printf("[exmdb_provider]: fail to create socket for listening\n");
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
		printf("[exmdb_provider]: bind %s:%u: %s\n", g_listen_ip, g_listen_port, strerror(errno));
        close(g_listen_sockd);
		return -3;
    }
	
	status = listen(g_listen_sockd, 5);

	if (-1 == status) {
		printf("[exmdb_provider]: fail to listen socket\n");
		close(g_listen_sockd);
		return -4;
	}

	if ('\0' != g_list_path[0]) {
		plist = list_file_init(g_list_path, "%s:16");
		if (NULL == plist) {
			printf("[exmdb_provider]: Failed to read ACLs from %s: %s\n",
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

int exmdb_listener_trigger_accept()
{
	if (0 == g_listen_port) {
		return 0;
	}
	g_notify_stop = FALSE;
	if(0 != pthread_create(&g_listener_id,
		NULL, thread_work_func, NULL)) {
		printf("[exmdb_provider]: fail to create exmdb listener thread\n");
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

void exmdb_listener_free()
{
	/* do nothing */
}
