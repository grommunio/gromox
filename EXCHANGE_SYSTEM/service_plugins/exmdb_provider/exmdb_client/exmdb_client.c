#include "service_common.h"
#include "exmdb_client.h"
#include "exmdb_server.h"
#include "common_util.h"
#include "double_list.h"
#include "list_file.h"
#include "exmdb_ext.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>
#include <poll.h>


typedef struct _REMOTE_SVR {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST conn_list;
	char ip_addr[16];
	char prefix[256];
	int prefix_len;
	BOOL b_private;
	int port;
} REMOTE_SVR;

typedef struct _REMOTE_CONN {
    DOUBLE_LIST_NODE node;
	time_t last_time;
	REMOTE_SVR *psvr;
	int sockd;
} REMOTE_CONN;

typedef struct _AGENT_THREAD {
	DOUBLE_LIST_NODE node;
	REMOTE_SVR *pserver;
	pthread_t thr_id;
	int sockd;
} AGENT_THREAD;

static int g_conn_num;
static int g_threads_num;
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static char g_list_path[256];
static DOUBLE_LIST g_lost_list;
static DOUBLE_LIST g_agent_list;
static DOUBLE_LIST g_local_list;
static DOUBLE_LIST g_server_list;
static pthread_mutex_t g_server_lock;


int exmdb_client_get_param(int param)
{
	int total_num;
	DOUBLE_LIST_NODE *pnode;
	
	switch (param) {
	case ALIVE_PROXY_CONNECTIONS:
		total_num = 0;
		for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
			pnode=double_list_get_after(&g_server_list, pnode)) {
			total_num += double_list_get_nodes_num(
				&((REMOTE_SVR*)pnode->pdata)->conn_list);
		}
		return total_num;
	case LOST_PROXY_CONNECTIONS:
		return double_list_get_nodes_num(&g_lost_list);
	}
	return -1;
}

static BOOL exmdb_client_read_socket(int sockd, BINARY *pbin)
{
	int tv_msec;
	int read_len;
	uint32_t offset;
	uint8_t resp_buff[5];
	struct pollfd pfd_read;
	
	pbin->pb = NULL;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			return FALSE;
		}
		if (NULL == pbin->pb) {
			read_len = read(sockd, resp_buff, 5);
			if (1 == read_len) {
				pbin->cb = 1;
				pbin->pb = common_util_alloc(1);
				if (NULL == pbin->pb) {
					return FALSE;
				}
				*(uint8_t*)pbin->pb = resp_buff[0];
				return TRUE;
			} else if (5 == read_len) {
				pbin->cb = *(uint32_t*)(resp_buff + 1) + 5;
				pbin->pb = common_util_alloc(pbin->cb);
				if (NULL == pbin->pb) {
					return FALSE;
				}
				memcpy(pbin->pb, resp_buff, 5);
				offset = 5;
				if (offset == pbin->cb) {
					return TRUE;
				}
				continue;
			} else {
				return FALSE;
			}
		}
		read_len = read(sockd, pbin->pb + offset, pbin->cb - offset);
		if (read_len <= 0) {
			return FALSE;
		}
		offset += read_len;
		if (offset == pbin->cb) {
			return TRUE;
		}
	}
}

static BOOL exmdb_client_write_socket(int sockd, const BINARY *pbin)
{
	int tv_msec;
	int written_len;
	uint32_t offset;
	struct pollfd pfd_write;
	
	offset = 0;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_write.fd = sockd;
		pfd_write.events = POLLOUT|POLLWRBAND;
		if (1 != poll(&pfd_write, 1, tv_msec)) {
			return FALSE;
		}
		written_len = write(sockd, pbin->pb + offset, pbin->cb - offset);
		if (written_len <= 0) {
			return FALSE;
		}
		offset += written_len;
		if (offset == pbin->cb) {
			return TRUE;
		}
	}
}

static int exmdb_client_connect_exmdb(REMOTE_SVR *pserver, BOOL b_listen)
{
	int sockd;
	int process_id;
	BINARY tmp_bin;
	struct timeval tv;
	char remote_id[128];
	const char *str_host;
	EXMDB_REQUEST request;
	uint8_t response_code;
	struct sockaddr_in servaddr;
	
    sockd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(pserver->port);
    inet_pton(AF_INET, pserver->ip_addr, &servaddr.sin_addr);
    if (0 != connect(sockd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
        close(sockd);
        return -1;
    }
	str_host = get_host_ID();
	process_id = getpid();
	sprintf(remote_id, "%s:%d", str_host, process_id);
	if (FALSE == b_listen) {
		request.call_id = CALL_ID_CONNECT;
		request.payload.connect.prefix = pserver->prefix;
		request.payload.connect.remote_id = remote_id;
		request.payload.connect.b_private = pserver->b_private;
	} else {
		request.call_id = CALL_ID_LISTEN_NOTIFICATION;
		request.payload.listen_notification.remote_id = remote_id;
	}
	if (EXT_ERR_SUCCESS != exmdb_ext_push_request(&request, &tmp_bin)) {
		close(sockd);
		return -1;
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		close(sockd);
		return -1;
	}
	free(tmp_bin.pb);
	exmdb_server_build_environment(FALSE, pserver->b_private, NULL);
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		exmdb_server_free_environment();
		close(sockd);
		return -1;
	}
	response_code = tmp_bin.pb[0];
	if (RESPONSE_CODE_SUCCESS == response_code) {
		if (5 != tmp_bin.cb || 0 != *(uint32_t*)(tmp_bin.pb + 1)) {
			exmdb_server_free_environment();
			printf("[exmdb_provider]: response format error "
				"when connect to %s:%d for prefix \"%s\"\n",
				pserver->ip_addr, pserver->port, pserver->prefix);
			close(sockd);
			return -1;
		}
		exmdb_server_free_environment();
		return sockd;
	}
	exmdb_server_free_environment();
	switch (response_code) {
	case RESPONSE_CODE_ACCESS_DENY:
		printf("[exmdb_provider]: fail to connect to "
			"%s:%d for prefix \"%s\", access deny!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_MAX_REACHED:
		printf("[exmdb_provider]: fail to connect to %s:%d for "
			"prefix \"%s\", maximum connections reached in server!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_LACK_MEMORY:
		printf("[exmdb_provider]: fail to connect to %s:%d "
			"for prefix \"%s\", server out of memory!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_MISCONFIG_PREFIX:
		printf("[exmdb_provider]: fail to connect to %s:%d for "
			"prefix \"%s\", server does not serve the prefix, "
			"configuation file of client or server may be incorrect!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_MISCONFIG_MODE:
		printf("[exmdb_provider]: fail to connect to %s:%d for "
			"prefix \"%s\", work mode with the prefix in server is"
			" different from the mode in client, configuation file"
			" of client or server may be incorrect!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	default:
		printf("[exmdb_provider]: fail to connect to "
			"%s:%d for prefix \"%s\", error code %d!\n",
			pserver->ip_addr, pserver->port,
			pserver->prefix, (int)response_code);
		break;
	}
	close(sockd);
	return -1;
}

static void *scan_work_func(void *pparam)
{
	int tv_msec;
	time_t now_time;
	uint8_t resp_buff;
	uint32_t ping_buff;
	REMOTE_CONN *pconn;
	REMOTE_SVR *pserver;
	DOUBLE_LIST temp_list;
	struct pollfd pfd_read;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	DOUBLE_LIST_NODE *pnode1;
	
	
	ping_buff = 0;
	double_list_init(&temp_list);

	while (FALSE == g_notify_stop) {
		pthread_mutex_lock(&g_server_lock);
		time(&now_time);
		for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
			pnode=double_list_get_after(&g_server_list, pnode)) {
			pserver = (REMOTE_SVR*)pnode->pdata;
			ptail = double_list_get_tail(&pserver->conn_list);
			while (pnode1=double_list_get_from_head(&pserver->conn_list)) {
				pconn = (REMOTE_CONN*)pnode1->pdata;
				if (now_time - pconn->last_time >= SOCKET_TIMEOUT - 3) {
					double_list_append_as_tail(&temp_list, &pconn->node);
				} else {
					double_list_append_as_tail(&pserver->conn_list,
						&pconn->node);
				}

				if (pnode1 == ptail) {
					break;
				}
			}
		}
		pthread_mutex_unlock(&g_server_lock);

		while (pnode=double_list_get_from_head(&temp_list)) {
			pconn = (REMOTE_CONN*)pnode->pdata;
			if (TRUE == g_notify_stop) {
				close(pconn->sockd);
				free(pconn);
				continue;
			}
			if (sizeof(uint32_t) != write(pconn->sockd,
				&ping_buff, sizeof(uint32_t))) {
				close(pconn->sockd);
				pconn->sockd = -1;
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&g_lost_list, &pconn->node);
				pthread_mutex_unlock(&g_server_lock);
				continue;
			}
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pconn->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec) ||
				1 != read(pconn->sockd, &resp_buff, 1) ||
				RESPONSE_CODE_SUCCESS != resp_buff) {
				close(pconn->sockd);
				pconn->sockd = -1;
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&g_lost_list, &pconn->node);
				pthread_mutex_unlock(&g_server_lock);
			} else {
				time(&pconn->last_time);
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pconn->psvr->conn_list,
					&pconn->node);
				pthread_mutex_unlock(&g_server_lock);
			}
		}

		pthread_mutex_lock(&g_server_lock);
		while (pnode=double_list_get_from_head(&g_lost_list)) {
			double_list_append_as_tail(&temp_list, pnode);
		}
		pthread_mutex_unlock(&g_server_lock);

		while (pnode=double_list_get_from_head(&temp_list)) {
			pconn = (REMOTE_CONN*)pnode->pdata;
			if (TRUE == g_notify_stop) {
				close(pconn->sockd);
				free(pconn);
				continue;
			}
			pconn->sockd = exmdb_client_connect_exmdb(pconn->psvr, FALSE);
			if (-1 != pconn->sockd) {
				time(&pconn->last_time);
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pconn->psvr->conn_list,
					&pconn->node);
				pthread_mutex_unlock(&g_server_lock);
			} else {
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&g_lost_list, &pconn->node);
				pthread_mutex_unlock(&g_server_lock);
			}
		}
		sleep(1);
	}
}

static void *thread_work_func(void *pparam)
{
	int i;
	int tv_msec;
	int read_len;
	BINARY tmp_bin;
	uint32_t offset;
	uint8_t resp_code;
	uint32_t buff_len;
	uint8_t buff[0x8000];
	AGENT_THREAD *pagent;
	struct pollfd pfd_read;
	DB_NOTIFY_DATAGRAM notify;
	
	pagent = (AGENT_THREAD*)pparam;
	while (FALSE == g_notify_stop) {
		pagent->sockd = exmdb_client_connect_exmdb(
							pagent->pserver, TRUE);
		if (-1 == pagent->sockd) {
			sleep(1);
			continue;
		}
		buff_len = 0;
		while (TRUE) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pagent->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				close(pagent->sockd);
				pagent->sockd = -1;
				break;
			}
			if (0 == buff_len) {
				if (sizeof(uint32_t) != read(pagent->sockd,
					&buff_len, sizeof(uint32_t))) {
					close(pagent->sockd);
					pagent->sockd = -1;
					break;
				}
				/* ping packet */
				if (0 == buff_len) {
					resp_code = RESPONSE_CODE_SUCCESS;
					if (1 != write(pagent->sockd, &resp_code, 1)) {
						close(pagent->sockd);
						pagent->sockd = -1;
						break;
					}
				}
				offset = 0;
				continue;
			}
			read_len = read(pagent->sockd, buff + offset, buff_len - offset);
			if (read_len <= 0) {
				close(pagent->sockd);
				pagent->sockd = -1;
				break;
			}
			offset += read_len;
			if (offset == buff_len) {
				tmp_bin.cb = buff_len;
				tmp_bin.pb = buff;
				exmdb_server_build_environment(FALSE,
					pagent->pserver->b_private, NULL);
				if (EXT_ERR_SUCCESS == exmdb_ext_pull_db_notify(
					&tmp_bin, &notify)) {
					resp_code = RESPONSE_CODE_SUCCESS;
				} else {
					resp_code = RESPONSE_CODE_PULL_ERROR;
				}
				if (1 != write(pagent->sockd, &resp_code, 1)) {
					close(pagent->sockd);
					pagent->sockd = -1;
					exmdb_server_free_environment();
					break;
				}
				if (RESPONSE_CODE_SUCCESS == resp_code) {
					for (i=0; i<notify.id_array.count; i++) {
						exmdb_server_event_proc(notify.dir,
							notify.b_table, notify.id_array.pl[i],
							&notify.db_notify);
					}
				}
				exmdb_server_free_environment();
				buff_len = 0;
			}
		}
	}
	pthread_exit(0);
}

static REMOTE_CONN *exmdb_client_get_connection(const char *dir)
{
	REMOTE_SVR *pserver;
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
		pnode=double_list_get_after(&g_server_list, pnode)) {
		pserver = (REMOTE_SVR*)pnode->pdata;
		if (0 == strncmp(dir, pserver->prefix, pserver->prefix_len)) {
			break;
		}
	}
	if (NULL == pnode) {
		printf("[exmdb_provider]: cannot find remote server for %s\n", dir);
		return NULL;
	}
	pthread_mutex_lock(&g_server_lock);
	pnode = double_list_get_from_head(&pserver->conn_list);
	pthread_mutex_unlock(&g_server_lock);
	if (NULL == pnode) {
		printf("[exmdb_provider]: no alive connection for"
			" remote server for %s\n", pserver->prefix);
		return NULL;
	}
	return (REMOTE_CONN*)pnode->pdata;
}

static void exmdb_client_put_connection(REMOTE_CONN *pconn, BOOL b_lost)
{
	if (FALSE == b_lost) {
		pthread_mutex_lock(&g_server_lock);
		double_list_append_as_tail(&pconn->psvr->conn_list, &pconn->node);
		pthread_mutex_unlock(&g_server_lock);
	} else {
		close(pconn->sockd);
		pconn->sockd = -1;
		pthread_mutex_lock(&g_server_lock);
		double_list_append_as_tail(&g_lost_list, &pconn->node);
		pthread_mutex_unlock(&g_server_lock);
	}
}

void exmdb_client_init(int conn_num,
	int threads_num, const char *list_path)
{
	g_notify_stop = TRUE;
	g_conn_num = conn_num;
	g_threads_num = threads_num;
	strcpy(g_list_path, list_path);
	double_list_init(&g_local_list);
	double_list_init(&g_server_list);
	double_list_init(&g_lost_list);
	double_list_init(&g_agent_list);
	pthread_mutex_init(&g_server_lock, NULL);
}

int exmdb_client_run()
{
	int i, j;
	int list_num;
	BOOL b_private;
	LIST_FILE *plist;
	LOCAL_SVR *plocal;
	EXMDB_ITEM *pitem;
	REMOTE_CONN *pconn;
	REMOTE_SVR *pserver;
	AGENT_THREAD *pagent;
	
	plist = list_file_init(g_list_path, "%s:256%s:16%s:16%d");
	if (NULL == plist) {
		printf("[exmdb_provider]: fail to open exmdb list file\n");
		return 1;
	}
	g_notify_stop = FALSE;
	list_num = list_file_get_item_num(plist);
	pitem = (EXMDB_ITEM*)list_file_get_list(plist);
	for (i=0; i<list_num; i++) {
		if (0 == strcasecmp(pitem[i].type, "private")) {
			b_private = TRUE;
		} else if (0 == strcasecmp(pitem[i].type, "public")) {
			b_private = FALSE;
		} else {
			printf("[exmdb_provider]: unknown type \"%s\", only"
				"can be \"private\" or \"public\"!");
			list_file_free(plist);
			g_notify_stop = TRUE;
			return 2;
		}
		if (TRUE == common_util_check_local_ip(pitem[i].ip_addr)) {
			plocal = malloc(sizeof(LOCAL_SVR));
			if (NULL == plocal) {
				printf("[exmdb_provider]: fail to allocate memory\n");
				list_file_free(plist);
				g_notify_stop = TRUE;
				return 3;
			}
			plocal->node.pdata = plocal;
			strcpy(plocal->prefix, pitem[i].prefix);
			plocal->prefix_len = strlen(plocal->prefix);
			plocal->b_private = b_private;
			double_list_append_as_tail(&g_local_list, &plocal->node);
			continue;
		}
		if (0 == g_conn_num) {
			printf("[exmdb_provider]: there's remote store media "
				"in exmdb list, but rpc proxy connection number is 0\n");
			list_file_free(plist);
			g_notify_stop = TRUE;
			return 4;
		}
		pserver = malloc(sizeof(REMOTE_SVR));
		if (NULL == pserver) {
			printf("[exmdb_provider]: fail to allocate memory for exmdb\n");
			list_file_free(plist);
			g_notify_stop = TRUE;
			return 5;
		}
		pserver->node.pdata = pserver;
		strcpy(pserver->prefix, pitem[i].prefix);
		pserver->prefix_len = strlen(pserver->prefix);
		pserver->b_private = b_private;
		strcpy(pserver->ip_addr, pitem[i].ip_addr);
		pserver->port = pitem[i].port;
		double_list_init(&pserver->conn_list);
		double_list_append_as_tail(&g_server_list, &pserver->node);
		for (j=0; j<g_conn_num; j++) {
		   pconn = malloc(sizeof(REMOTE_CONN));
			if (NULL == pconn) {
				printf("[exmdb_provider]: fail to "
					"allocate memory for exmdb\n");
				list_file_free(plist);
				g_notify_stop = TRUE;
				return 6;
			}
			pconn->node.pdata = pconn;
			pconn->sockd = -1;
			pconn->psvr = pserver;
			double_list_append_as_tail(&g_lost_list, &pconn->node);
		}
		for (j=0; j<g_threads_num; j++) {
			pagent = malloc(sizeof(AGENT_THREAD));
			if (NULL == pagent) {
				printf("[exmdb_provider]: fail to "
					"allocate memory for exmdb\n");
				list_file_free(plist);
				g_notify_stop = TRUE;
				return 7;
			}
			pagent->node.pdata = pagent;
			pagent->pserver = pserver;
			pagent->sockd = -1;
			if (0 != pthread_create(&pagent->thr_id,
				NULL, thread_work_func, pagent)) {
				printf("[exmdb_provider]: fail to "
					"create agent thread for exmdb\n");
				list_file_free(plist);
				g_notify_stop = TRUE;
				return 8;
			}
			double_list_append_as_tail(&g_agent_list, &pagent->node);
		}
	}
	list_file_free(plist);
	if (0 == g_conn_num) {
		return 0;
	}
	if (0 != pthread_create(&g_scan_id, NULL, scan_work_func, NULL)) {
		printf("[exmdb_provider]: fail to create proxy scan thread\n");
		g_notify_stop = TRUE;
		return 9;
	}
	return 0;
}

int exmdb_client_stop()
{
	REMOTE_CONN *pconn;
	REMOTE_SVR *pserver;
	AGENT_THREAD *pagent;
	DOUBLE_LIST_NODE *pnode;
	
	if (0 != g_conn_num) {
		if (FALSE == g_notify_stop) {
			g_notify_stop = TRUE;
			pthread_join(g_scan_id, NULL);
		}
	}
	g_notify_stop = TRUE;
	while (pnode=double_list_get_from_head(&g_agent_list)) {
		pagent = (AGENT_THREAD*)pnode->pdata;
		pthread_cancel(pagent->thr_id);
		if (-1 != pagent->sockd) {
			close(pagent->sockd);
		}
		free(pagent);
	}
	while (pnode=double_list_get_from_head(&g_local_list)) {
		free(pnode->pdata);
	}
	while (pnode=double_list_get_from_head(&g_lost_list)) {
		free(pnode->pdata);
	}
	while (pnode=double_list_get_from_head(&g_server_list)) {
		pserver = (REMOTE_SVR*)pnode->pdata;
		while (pnode=double_list_get_from_head(&pserver->conn_list)) {
			pconn = (REMOTE_CONN*)pnode->pdata;
			close(pconn->sockd);
			free(pconn);
		}
		free(pserver);
	}
	return 0;
}

void exmdb_client_free()
{
	double_list_free(&g_local_list);
	double_list_free(&g_lost_list);
	double_list_free(&g_server_list);
	double_list_free(&g_agent_list);
	pthread_mutex_destroy(&g_server_lock);
}

static BOOL exmdb_client_check_local(const char *prefix, BOOL *pb_private)
{
	LOCAL_SVR *plocal;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&g_local_list); NULL!=pnode;
		pnode=double_list_get_after(&g_local_list, pnode)) {
		plocal = (LOCAL_SVR*)pnode->pdata;
		if (0 == strncmp(plocal->prefix, prefix, plocal->prefix_len)) {
			*pb_private = ((LOCAL_SVR*)pnode->pdata)->b_private;
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL exmdb_client_do_rpc(const char *dir,
	const EXMDB_REQUEST *prequest, EXMDB_RESPONSE *presponse)
{
	BINARY tmp_bin;
	REMOTE_CONN *pconn;
	
	if (EXT_ERR_SUCCESS != exmdb_ext_push_request(prequest, &tmp_bin)) {
		return FALSE;
	}
	pconn = exmdb_client_get_connection(dir);
	if (NULL == pconn) {
		free(tmp_bin.pb);
		return FALSE;
	}
	if (FALSE == exmdb_client_write_socket(pconn->sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		exmdb_client_put_connection(pconn, TRUE);
		return FALSE;
	}
	free(tmp_bin.pb);
	if (FALSE == exmdb_client_read_socket(pconn->sockd, &tmp_bin)) {
		exmdb_client_put_connection(pconn, TRUE);
		return FALSE;
	}
	time(&pconn->last_time);
	exmdb_client_put_connection(pconn, FALSE);
	if (tmp_bin.cb < 5 || RESPONSE_CODE_SUCCESS != tmp_bin.pb[0]) {
		return FALSE;
	}
	presponse->call_id = prequest->call_id;
	tmp_bin.cb -= 5;
	tmp_bin.pb += 5;
	if (EXT_ERR_SUCCESS != exmdb_ext_pull_response(&tmp_bin, presponse)) {	
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_ping_store(const char *dir)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_ping_store(dir);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_PING_STORE;
	request.dir = (void*)dir;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_get_all_named_propids(
	const char *dir, PROPID_ARRAY *ppropids)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_all_named_propids(
										dir, ppropids);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_ALL_NAMED_PROPIDS;
	request.dir = (void*)dir;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppropids = response.payload.get_all_named_propids.propids;
	return TRUE;
}

BOOL exmdb_client_get_named_propids(const char *dir,
	BOOL b_create, const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_named_propids(dir,
					b_create, ppropnames, ppropids);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_NAMED_PROPIDS;
	request.dir = (void*)dir;
	request.payload.get_named_propids.b_create = b_create;
	request.payload.get_named_propids.ppropnames = (void*)ppropnames;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppropids = response.payload.get_named_propids.propids;
	return TRUE;
}

BOOL exmdb_client_get_named_propnames(const char *dir,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_named_propnames(
						dir, ppropids, ppropnames);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_NAMED_PROPNAMES;
	request.dir = (void*)dir;
	request.payload.get_named_propnames.ppropids = (void*)ppropids;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppropnames = response.payload.get_named_propnames.propnames;
	return TRUE;
}

BOOL exmdb_client_get_mapping_guid(const char *dir,
	uint16_t replid, BOOL *pb_found, GUID *pguid)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_mapping_guid(
					dir, replid, pb_found, pguid);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_MAPPING_GUID;
	request.dir = (void*)dir;
	request.payload.get_mapping_guid.replid = replid;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_found = response.payload.get_mapping_guid.b_found;
	*pguid = response.payload.get_mapping_guid.guid;
	return TRUE;
}

BOOL exmdb_client_get_mapping_replid(const char *dir,
	GUID guid, BOOL *pb_found, uint16_t *preplid)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_mapping_replid(
					dir, guid, pb_found, preplid);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_MAPPING_REPLID;
	request.dir = (void*)dir;
	request.payload.get_mapping_replid.guid = guid;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_found = response.payload.get_mapping_replid.b_found;
	*preplid = response.payload.get_mapping_replid.replid;
	return TRUE;
}

BOOL exmdb_client_get_store_all_proptags(
	const char *dir, PROPTAG_ARRAY *pproptags)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_store_all_proptags(dir, pproptags);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_STORE_ALL_PROPTAGS;
	request.dir = (void*)dir;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pproptags = response.payload.get_store_all_proptags.proptags;
	return TRUE;
}

BOOL exmdb_client_get_store_properties(const char *dir,
	uint32_t cpid, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_store_properties(
					dir, cpid, pproptags, ppropvals);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_STORE_PROPERTIES;
	request.dir = (void*)dir;
	request.payload.get_store_properties.cpid = cpid;
	request.payload.get_store_properties.pproptags = (void*)pproptags;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppropvals = response.payload.get_store_properties.propvals;
	return TRUE;
}

BOOL exmdb_client_set_store_properties(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *ppropvals,
	PROBLEM_ARRAY *pproblems)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_set_store_properties(
					dir, cpid, ppropvals, pproblems);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SET_STORE_PROPERTIES;
	request.dir = (void*)dir;
	request.payload.set_store_properties.cpid = cpid;
	request.payload.set_store_properties.ppropvals = (void*)ppropvals;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pproblems = response.payload.set_store_properties.problems;
	return TRUE;
}

BOOL exmdb_client_remove_store_properties(
	const char *dir, const PROPTAG_ARRAY *pproptags)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_remove_store_properties(
										dir, pproptags);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_REMOVE_STORE_PROPERTIES;
	request.dir = (void*)dir;
	request.payload.remove_store_properties.pproptags = (void*)pproptags;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_check_mailbox_permission(const char *dir,
	const char *username, uint32_t *ppermission)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_check_mailbox_permission(
							dir, username, ppermission);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_CHECK_MAILBOX_PERMISSION;
	request.dir = (void*)dir;
	request.payload.check_mailbox_permission.username = (void*)username;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppermission = response.payload.check_mailbox_permission.permission;
	return TRUE;
}

BOOL exmdb_client_get_folder_by_class(const char *dir,
	const char *str_class, uint64_t *pid, char *str_explicit)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_folder_by_class(
					dir, str_class, pid, str_explicit);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_FOLDER_BY_CLASS;
	request.dir = (void*)dir;
	request.payload.get_folder_by_class.str_class = (void*)str_class;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pid = response.payload.get_folder_by_class.id;
	strcpy(str_explicit, response.payload.get_folder_by_class.str_explicit);
	return TRUE;
}

BOOL exmdb_client_set_folder_by_class(const char *dir,
	uint64_t folder_id, const char *str_class, BOOL *pb_result)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_set_folder_by_class(
				dir, folder_id, str_class, pb_result);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SET_FOLDER_BY_CLASS;
	request.dir = (void*)dir;
	request.payload.set_folder_by_class.folder_id;
	request.payload.set_folder_by_class.str_class = (void*)str_class;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_result = response.payload.set_folder_by_class.b_result;
	return TRUE;
}

BOOL exmdb_client_get_folder_class_table(
	const char *dir, TARRAY_SET *ptable)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_folder_class_table(dir, ptable);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_FOLDER_CLASS_TABLE;
	request.dir = (void*)dir;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ptable = response.payload.get_folder_class_table.table;
	return TRUE;
}

BOOL exmdb_client_check_folder_id(const char *dir,
	uint64_t folder_id, BOOL *pb_exist)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_check_folder_id(
					dir, folder_id, pb_exist);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_CHECK_FOLDER_ID;
	request.dir = (void*)dir;
	request.payload.check_folder_id.folder_id = folder_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_exist = response.payload.check_folder_id.b_exist;
	return TRUE;
}

BOOL exmdb_client_query_folder_messages(const char *dir,
	uint64_t folder_id, TARRAY_SET *pset)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_query_folder_messages(
								dir, folder_id, pset);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_QUERY_FOLDER_MESSAGES;
	request.dir = (void*)dir;
	request.payload.query_folder_messages.folder_id = folder_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pset = response.payload.query_folder_messages.set;
	return TRUE;
}

BOOL exmdb_client_check_folder_deleted(const char *dir,
	uint64_t folder_id, BOOL *pb_del)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_check_folder_deleted(
							dir, folder_id, pb_del);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_CHECK_FOLDER_DELETED;
	request.dir = (void*)dir;
	request.payload.check_folder_deleted.folder_id = folder_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_del = response.payload.check_folder_deleted.b_del;
	return TRUE;
}

BOOL exmdb_client_get_folder_by_name(const char *dir,
	uint64_t parent_id, const char *str_name,
	uint64_t *pfolder_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_folder_by_name(dir,
					parent_id, str_name, pfolder_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_FOLDER_BY_NAME;
	request.dir = (void*)dir;
	request.payload.get_folder_by_name.parent_id = parent_id;
	request.payload.get_folder_by_name.str_name = (void*)str_name;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pfolder_id = response.payload.get_folder_by_name.folder_id;
	return TRUE;
}

BOOL exmdb_client_check_folder_permission(const char *dir,
	uint64_t folder_id, const char *username,
	uint32_t *ppermission)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_check_folder_permission(
					dir, folder_id, username, ppermission);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_CHECK_FOLDER_PERMISSION;
	request.dir = (void*)dir;
	request.payload.check_folder_permission.folder_id = folder_id;
	request.payload.check_folder_permission.username = (void*)username;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppermission = response.payload.check_folder_permission.permission;
	return TRUE;
}

BOOL exmdb_client_create_folder_by_properties(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *pproperties,
	uint64_t *pfolder_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_create_folder_by_properties(
						dir, cpid, pproperties, pfolder_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_CREATE_FOLDER_BY_PROPERTIES;
	request.dir = (void*)dir;
	request.payload.create_folder_by_properties.cpid = cpid;
	request.payload.create_folder_by_properties.pproperties =
											(void*)pproperties;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pfolder_id = response.payload.create_folder_by_properties.folder_id;
	return TRUE;
}

BOOL exmdb_client_get_folder_all_proptags(const char *dir,
	uint64_t folder_id, PROPTAG_ARRAY *pproptags)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_folder_all_proptags(
							dir, folder_id, pproptags);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_FOLDER_ALL_PROPTAGS;
	request.dir = (void*)dir;
	request.payload.get_folder_all_proptags.folder_id = folder_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pproptags = response.payload.get_folder_all_proptags.proptags;
	return TRUE;
}

BOOL exmdb_client_get_folder_properties(
	const char *dir, uint32_t cpid, uint64_t folder_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_folder_properties(dir,
					cpid, folder_id, pproptags, ppropvals);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_FOLDER_PROPERTIES;
	request.dir = (void*)dir;
	request.payload.get_folder_properties.cpid = cpid;
	request.payload.get_folder_properties.folder_id = folder_id;
	request.payload.get_folder_properties.pproptags = (void*)pproptags;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppropvals = response.payload.get_folder_properties.propvals;
	return TRUE;
}

BOOL exmdb_client_set_folder_properties(
	const char *dir, uint32_t cpid, uint64_t folder_id,
	const TPROPVAL_ARRAY *pproperties,
	PROBLEM_ARRAY *pproblems)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_set_folder_properties(dir,
					cpid, folder_id, pproperties, pproblems);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SET_FOLDER_PROPERTIES;
	request.dir = (void*)dir;
	request.payload.set_folder_properties.cpid = cpid;
	request.payload.set_folder_properties.folder_id = folder_id;
	request.payload.set_folder_properties.pproperties = (void*)pproperties;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pproblems = response.payload.set_folder_properties.problems;
	return TRUE;
}

BOOL exmdb_client_remove_folder_properties(const char *dir,
	uint64_t folder_id, const PROPTAG_ARRAY *pproptags)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_remove_folder_properties(
								dir, folder_id, pproptags);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_REMOVE_FOLDER_PROPERTIES;
	request.dir = (void*)dir;
	request.payload.remove_folder_properties.folder_id = folder_id;
	request.payload.remove_folder_properties.pproptags = (void*)pproptags;
	return exmdb_client_do_rpc(dir, &request, &response);
}

BOOL exmdb_client_delete_folder(const char *dir, uint32_t cpid,
	uint64_t folder_id, BOOL b_hard, BOOL *pb_result)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_delete_folder(dir,
				cpid, folder_id, b_hard, pb_result);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_DELETE_FOLDER;
	request.dir = (void*)dir;
	request.payload.delete_folder.cpid = cpid;
	request.payload.delete_folder.folder_id = folder_id;
	request.payload.delete_folder.b_hard = b_hard;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_result = response.payload.delete_folder.b_result;
	return TRUE;
}

BOOL exmdb_client_empty_folder(const char *dir, uint32_t cpid,
	const char *username, uint64_t folder_id, BOOL b_hard,
	BOOL b_normal, BOOL b_fai, BOOL b_sub, BOOL *pb_partial)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_empty_folder(dir, cpid,
				username, folder_id, b_hard, b_normal,
				b_fai, b_sub, pb_partial);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_EMPTY_FOLDER;
	request.dir = (void*)dir;
	request.payload.empty_folder.cpid = cpid;
	request.payload.empty_folder.username = (void*)username;
	request.payload.empty_folder.folder_id = folder_id;
	request.payload.empty_folder.b_hard = b_hard;
	request.payload.empty_folder.b_normal = b_normal;
	request.payload.empty_folder.b_fai = b_fai;
	request.payload.empty_folder.b_sub = b_sub;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_partial = response.payload.empty_folder.b_partial;
	return TRUE;
}

BOOL exmdb_client_check_folder_cycle(const char *dir,
	uint64_t src_fid, uint64_t dst_fid, BOOL *pb_cycle)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_check_folder_cycle(
					dir, src_fid, dst_fid, pb_cycle);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_CHECK_FOLDER_CYCLE;
	request.dir = (void*)dir;
	request.payload.check_folder_cycle.src_fid;
	request.payload.check_folder_cycle.dst_fid;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_cycle = response.payload.check_folder_cycle.b_cycle;
	return TRUE;
}

BOOL exmdb_client_copy_folder_internal(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest, const char *username,
	uint64_t src_fid, BOOL b_normal, BOOL b_fai, BOOL b_sub,
	uint64_t dst_fid, BOOL *pb_collid, BOOL *pb_partial)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_copy_folder_internal(dir,
			account_id, cpid, b_guest, username, src_fid, b_normal,
			b_fai, b_sub, dst_fid, pb_collid, pb_partial);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_COPY_FOLDER_INTERNAL;
	request.dir = (void*)dir;
	request.payload.copy_folder_internal.account_id = account_id;
	request.payload.copy_folder_internal.cpid = cpid;
	request.payload.copy_folder_internal.b_guest = b_guest;
	request.payload.copy_folder_internal.username = (void*)username;
	request.payload.copy_folder_internal.src_fid = src_fid;
	request.payload.copy_folder_internal.b_normal = b_normal;
	request.payload.copy_folder_internal.b_fai = b_fai;
	request.payload.copy_folder_internal.b_sub = b_sub;
	request.payload.copy_folder_internal.dst_fid = dst_fid;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_collid = response.payload.copy_folder_internal.b_collid;
	*pb_partial = response.payload.copy_folder_internal.b_partial;
	return TRUE;
}

BOOL exmdb_client_get_search_criteria(
	const char *dir, uint64_t folder_id, uint32_t *psearch_status,
	RESTRICTION **pprestriction, LONGLONG_ARRAY *pfolder_ids)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_search_criteria(dir, folder_id,
					psearch_status, pprestriction, pfolder_ids);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_SEARCH_CRITERIA;
	request.dir = (void*)dir;
	request.payload.get_search_criteria.folder_id = folder_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*psearch_status = response.payload.get_search_criteria.search_status;
	*pprestriction = response.payload.get_search_criteria.prestriction;
	*pfolder_ids = response.payload.get_search_criteria.folder_ids;
	return TRUE;
}

BOOL exmdb_client_set_search_criteria(const char *dir,
	uint32_t cpid, uint64_t folder_id, uint32_t search_flags,
	const RESTRICTION *prestriction, const LONGLONG_ARRAY *pfolder_ids,
	BOOL *pb_result)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_set_search_criteria(dir,
			cpid, folder_id, search_flags, prestriction,
			pfolder_ids, pb_result);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SET_SEARCH_CRITERIA;
	request.dir = (void*)dir;
	request.payload.set_search_criteria.cpid = cpid;
	request.payload.set_search_criteria.folder_id = folder_id;
	request.payload.set_search_criteria.search_flags = search_flags;
	request.payload.set_search_criteria.prestriction = (void*)prestriction;
	request.payload.set_search_criteria.pfolder_ids = (void*)pfolder_ids;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_result = response.payload.set_search_criteria.b_result;
	return TRUE;
}

BOOL exmdb_client_movecopy_message(const char *dir,
	int account_id, uint32_t cpid, uint64_t message_id,
	uint64_t dst_fid, uint64_t dst_id, BOOL b_move,
	BOOL *pb_result)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_movecopy_message(dir, account_id,
			cpid, message_id, dst_fid, dst_id, b_move, pb_result);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_MOVECOPY_MESSAGE;
	request.dir = (void*)dir;
	request.payload.movecopy_message.account_id = account_id;
	request.payload.movecopy_message.cpid = cpid;
	request.payload.movecopy_message.message_id = message_id;
	request.payload.movecopy_message.dst_fid = dst_fid;
	request.payload.movecopy_message.dst_id = dst_id;
	request.payload.movecopy_message.b_move = b_move;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_result = response.payload.movecopy_message.b_result;
	return TRUE;
}

BOOL exmdb_client_movecopy_messages(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest,
	const char *username, uint64_t src_fid, uint64_t dst_fid,
	BOOL b_copy, const EID_ARRAY *pmessage_ids, BOOL *pb_partial)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_movecopy_messages(dir,
			account_id, cpid, b_guest, username, src_fid,
			dst_fid, b_copy, pmessage_ids, pb_partial);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_MOVECOPY_MESSAGES;
	request.dir = (void*)dir;
	request.payload.movecopy_messages.account_id = account_id;
	request.payload.movecopy_messages.cpid = cpid;
	request.payload.movecopy_messages.b_guest = b_guest;
	request.payload.movecopy_messages.username = (void*)username;
	request.payload.movecopy_messages.src_fid = src_fid;
	request.payload.movecopy_messages.dst_fid = dst_fid;
	request.payload.movecopy_messages.b_copy = b_copy;
	request.payload.movecopy_messages.pmessage_ids = (void*)pmessage_ids;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_partial = response.payload.movecopy_messages.b_partial;
	return TRUE;
}

BOOL exmdb_client_movecopy_folder(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest, const char *username,
	uint64_t src_pid, uint64_t src_fid, uint64_t dst_fid,
	const char *str_new, BOOL b_copy, BOOL *pb_exist,
	BOOL *pb_partial)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_movecopy_folder(dir, account_id,
			cpid, b_guest, username, src_pid, src_fid, dst_fid,
			str_new, b_copy, pb_exist,pb_partial);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_MOVECOPY_FOLDER;
	request.dir = (void*)dir;
	request.payload.movecopy_folder.account_id = account_id;
	request.payload.movecopy_folder.cpid = cpid;
	request.payload.movecopy_folder.b_guest = b_guest;
	request.payload.movecopy_folder.username = (void*)username;
	request.payload.movecopy_folder.src_pid = src_pid;
	request.payload.movecopy_folder.src_fid = src_fid;
	request.payload.movecopy_folder.dst_fid = dst_fid;
	request.payload.movecopy_folder.str_new = (void*)str_new;
	request.payload.movecopy_folder.b_copy = b_copy;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_exist = response.payload.movecopy_folder.b_exist;
	*pb_partial = response.payload.movecopy_folder.b_partial;
	return TRUE;
}

BOOL exmdb_client_delete_messages(const char *dir,
	int account_id, uint32_t cpid, const char *username,
	uint64_t folder_id, const EID_ARRAY *pmessage_ids,
	BOOL b_hard, BOOL *pb_partial)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_delete_messages(dir,
			account_id, cpid, username, folder_id,
			pmessage_ids, b_hard, pb_partial);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_DELETE_MESSAGES;
	request.dir = (void*)dir;
	request.payload.delete_messages.account_id = account_id;
	request.payload.delete_messages.cpid = cpid;
	request.payload.delete_messages.username = (void*)username;
	request.payload.delete_messages.folder_id = folder_id;
	request.payload.delete_messages.pmessage_ids = (void*)pmessage_ids;
	request.payload.delete_messages.b_hard = b_hard;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_partial = response.payload.delete_messages.b_partial;
	return TRUE;
}

BOOL exmdb_client_get_message_brief(const char *dir, uint32_t cpid,
	uint64_t message_id, MESSAGE_CONTENT **ppbrief)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_message_brief(
					dir, cpid, message_id, ppbrief);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_MESSAGE_BRIEF;
	request.dir = (void*)dir;
	request.payload.get_message_brief.cpid = cpid;
	request.payload.get_message_brief.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppbrief = response.payload.get_message_brief.pbrief;
	return TRUE;
}

BOOL exmdb_client_sum_hierarchy(const char *dir,
	uint64_t folder_id, const char *username,
	BOOL b_depth, uint32_t *pcount)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_sum_hierarchy(dir,
			folder_id, username, b_depth, pcount);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SUM_HIERARCHY;
	request.dir = (void*)dir;
	request.payload.sum_hierarchy.folder_id = folder_id;
	request.payload.sum_hierarchy.username = (void*)username;
	request.payload.sum_hierarchy.b_depth = b_depth;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pcount = response.payload.sum_hierarchy.count;
	return TRUE;
}
	
BOOL exmdb_client_load_hierarchy_table(const char *dir,
	uint64_t folder_id, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, uint32_t *ptable_id,
	uint32_t *prow_count)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_load_hierarchy_table(
					dir, folder_id, username, table_flags,
					prestriction, ptable_id, prow_count);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_LOAD_HIERARCHY_TABLE;
	request.dir = (void*)dir;
	request.payload.load_hierarchy_table.folder_id = folder_id;
	request.payload.load_hierarchy_table.username = (void*)username;
	request.payload.load_hierarchy_table.table_flags = table_flags;
	request.payload.load_hierarchy_table.prestriction = (void*)prestriction;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ptable_id = response.payload.load_hierarchy_table.table_id;
	*prow_count = response.payload.load_hierarchy_table.row_count;
	return TRUE;
}

BOOL exmdb_client_sum_content(const char *dir, uint64_t folder_id,
	BOOL b_fai, BOOL b_deleted, uint32_t *pcount)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_sum_content(dir,
			folder_id, b_fai, b_deleted, pcount);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SUM_CONTENT;
	request.dir = (void*)dir;
	request.payload.sum_content.folder_id = folder_id;
	request.payload.sum_content.b_fai = b_fai;
	request.payload.sum_content.b_deleted = b_deleted;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pcount = response.payload.sum_content.count;
	return TRUE;
}

BOOL exmdb_client_load_content_table(const char *dir, uint32_t cpid,
	uint64_t folder_id, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, const SORTORDER_SET *psorts,
	uint32_t *ptable_id, uint32_t *prow_count)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_load_content_table(
			dir, cpid, folder_id, username, table_flags,
			prestriction, psorts, ptable_id, prow_count);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_LOAD_CONTENT_TABLE;
	request.dir = (void*)dir;
	request.payload.load_content_table.cpid = cpid;
	request.payload.load_content_table.folder_id = folder_id;
	request.payload.load_content_table.username = (void*)username;
	request.payload.load_content_table.table_flags = table_flags;
	request.payload.load_content_table.prestriction = (void*)prestriction;
	request.payload.load_content_table.psorts = (void*)psorts;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ptable_id = response.payload.load_content_table.table_id;
	*prow_count = response.payload.load_content_table.row_count;
	return TRUE;
}

BOOL exmdb_client_reload_content_table(const char *dir, uint32_t table_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_reload_content_table(dir, table_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_RELOAD_CONTENT_TABLE;
	request.dir = (void*)dir;
	request.payload.reload_content_table.table_id = table_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_load_permission_table(const char *dir,
	uint64_t folder_id, uint8_t table_flags,
	uint32_t *ptable_id, uint32_t *prow_count)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_load_permission_table(
						dir, folder_id, table_flags,
						ptable_id, prow_count);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_LOAD_PERMISSION_TABLE;
	request.dir = (void*)dir;
	request.payload.load_permission_table.folder_id = folder_id;
	request.payload.load_permission_table.table_flags = table_flags;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ptable_id = response.payload.load_permission_table.table_id;
	*prow_count = response.payload.load_permission_table.row_count;
	return TRUE;
}

BOOL exmdb_client_load_rule_table(const char *dir,
	uint64_t folder_id, uint8_t table_flags,
	const RESTRICTION *prestriction,
	uint32_t *ptable_id, uint32_t *prow_count)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_load_rule_table(
					dir, folder_id, table_flags,
					prestriction, ptable_id, prow_count);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_LOAD_RULE_TABLE;
	request.dir = (void*)dir;
	request.payload.load_rule_table.folder_id = folder_id;
	request.payload.load_rule_table.table_flags = table_flags;
	request.payload.load_rule_table.prestriction = (void*)prestriction;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ptable_id = response.payload.load_rule_table.table_id;
	*prow_count = response.payload.load_rule_table.row_count;
	return TRUE;
}

BOOL exmdb_client_unload_table(const char *dir, uint32_t table_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_unload_table(dir, table_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_UNLOAD_TABLE;
	request.dir = (void*)dir;
	request.payload.unload_table.table_id = table_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_sum_table(const char *dir,
	uint32_t table_id, uint32_t *prows)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_sum_table(dir, table_id, prows);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SUM_TABLE;
	request.dir = (void*)dir;
	request.payload.sum_table.table_id = table_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*prows = response.payload.sum_table.rows;
	return TRUE;
}

BOOL exmdb_client_query_table(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_query_table(dir, username, cpid,
			table_id, pproptags, start_pos, row_needed, pset);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_QUERY_TABLE;
	request.dir = (void*)dir;
	request.payload.query_table.username = (void*)username;
	request.payload.query_table.cpid = cpid;
	request.payload.query_table.table_id = table_id;
	request.payload.query_table.pproptags = (void*)pproptags;
	request.payload.query_table.start_pos = start_pos;
	request.payload.query_table.row_needed = row_needed;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pset = response.payload.query_table.set;
	return TRUE;
}

BOOL exmdb_client_match_table(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, BOOL b_forward, uint32_t start_pos,
	const RESTRICTION *pres, const PROPTAG_ARRAY *pproptags,
	int32_t *pposition, TPROPVAL_ARRAY *ppropvals)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_match_table(dir, username, cpid, table_id,
			b_forward, start_pos, pres, pproptags, pposition, ppropvals);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_MATCH_TABLE;
	request.dir = (void*)dir;
	request.payload.match_table.username = (void*)username;
	request.payload.match_table.cpid = cpid;
	request.payload.match_table.table_id = table_id;
	request.payload.match_table.b_forward = b_forward;
	request.payload.match_table.start_pos = start_pos;
	request.payload.match_table.pres = (void*)pres;
	request.payload.match_table.pproptags = (void*)pproptags;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pposition = response.payload.match_table.position;
	*ppropvals = response.payload.match_table.propvals;
	return TRUE;
}

BOOL exmdb_client_locate_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, uint32_t inst_num,
	int32_t *pposition, uint32_t *prow_type)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_locate_table(dir, table_id,
					inst_id, inst_num, pposition, prow_type);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_LOCATE_TABLE;
	request.dir = (void*)dir;
	request.payload.locate_table.table_id = table_id;
	request.payload.locate_table.inst_id = inst_id;
	request.payload.locate_table.inst_num = inst_num;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pposition = response.payload.locate_table.position;
	*prow_type = response.payload.locate_table.row_type;
	return TRUE;
}

BOOL exmdb_client_read_table_row(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, const PROPTAG_ARRAY *pproptags,
	uint64_t inst_id, uint32_t inst_num, TPROPVAL_ARRAY *ppropvals)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_read_table_row(dir,
				username, cpid, table_id, pproptags,
				inst_id, inst_num, ppropvals);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_READ_TABLE_ROW;
	request.dir = (void*)dir;
	request.payload.read_table_row.username = (void*)username;
	request.payload.read_table_row.cpid = cpid;
	request.payload.read_table_row.table_id = table_id;
	request.payload.read_table_row.pproptags = (void*)pproptags;
	request.payload.read_table_row.inst_id = inst_id;
	request.payload.read_table_row.inst_num = inst_num;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppropvals = response.payload.read_table_row.propvals;
	return TRUE;
}
	
BOOL exmdb_client_mark_table(const char *dir,
	uint32_t table_id, uint32_t position, uint64_t *pinst_id,
	uint32_t *pinst_num, uint32_t *prow_type)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_mark_table(dir, table_id,
				position, pinst_id, pinst_num, prow_type);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_MARK_TABLE;
	request.dir = (void*)dir;
	request.payload.mark_table.table_id = table_id;
	request.payload.mark_table.position = position;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pinst_id = response.payload.mark_table.inst_id;
	*pinst_num = response.payload.mark_table.inst_num;
	*prow_type = response.payload.mark_table.row_type;
	return TRUE;
}

BOOL exmdb_client_get_table_all_proptags(const char *dir,
	uint32_t table_id, PROPTAG_ARRAY *pproptags)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_table_all_proptags(
							dir, table_id, pproptags);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_TABLE_ALL_PROPTAGS;
	request.dir = (void*)dir;
	request.payload.get_table_all_proptags.table_id = table_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pproptags = response.payload.get_table_all_proptags.proptags;
	return TRUE;
}

BOOL exmdb_client_expand_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, BOOL *pb_found,
	int32_t *pposition, uint32_t *prow_count)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_expand_table(dir, table_id,
				inst_id, pb_found, pposition, prow_count);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_EXPAND_TABLE;
	request.dir = (void*)dir;
	request.payload.expand_table.table_id = table_id;
	request.payload.expand_table.inst_id = inst_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_found = response.payload.expand_table.b_found;
	*pposition = response.payload.expand_table.position;
	*prow_count = response.payload.expand_table.row_count;
	return TRUE;
}

BOOL exmdb_client_collapse_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, BOOL *pb_found,
	int32_t *pposition, uint32_t *prow_count)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_collapse_table(dir, table_id,
					inst_id, pb_found, pposition, prow_count);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_COLLAPSE_TABLE;
	request.dir = (void*)dir;
	request.payload.collapse_table.table_id = table_id;
	request.payload.collapse_table.inst_id = inst_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_found = response.payload.collapse_table.b_found;
	*pposition = response.payload.collapse_table.position;
	*prow_count = response.payload.collapse_table.row_count;
	return TRUE;
}

BOOL exmdb_client_store_table_state(const char *dir,
	uint32_t table_id, uint64_t inst_id, uint32_t inst_num,
	uint32_t *pstate_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_store_table_state(dir,
				table_id, inst_id, inst_num, pstate_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_STORE_TABLE_STATE;
	request.dir = (void*)dir;
	request.payload.store_table_state.table_id = table_id;
	request.payload.store_table_state.table_id = inst_id;
	request.payload.store_table_state.table_id = inst_num;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pstate_id = response.payload.store_table_state.state_id;
	return TRUE;
}

BOOL exmdb_client_restore_table_state(const char *dir,
	uint32_t table_id, uint32_t state_id, int32_t *pposition)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_restore_table_state(
				dir, table_id, state_id, pposition);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_RESTORE_TABLE_STATE;
	request.dir = (void*)dir;
	request.payload.restore_table_state.table_id = table_id;
	request.payload.restore_table_state.state_id = state_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pposition = response.payload.restore_table_state.position;
	return TRUE;
}

BOOL exmdb_client_check_message(const char *dir,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_exist)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_check_message(dir,
				folder_id, message_id, pb_exist);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_CHECK_MESSAGE;
	request.dir = (void*)dir;
	request.payload.check_message.folder_id = folder_id;
	request.payload.check_message.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_exist = response.payload.check_message.b_exist;
	return TRUE;
}

BOOL exmdb_client_check_message_deleted(const char *dir,
	uint64_t message_id, BOOL *pb_del)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_check_message_deleted(
							dir, message_id, pb_del);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_CHECK_MESSAGE_DELETED;
	request.dir = (void*)dir;
	request.payload.check_message_deleted.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_del = response.payload.check_message_deleted.b_del;
	return TRUE;
}

BOOL exmdb_client_load_message_instance(const char *dir,
	const char *username, uint32_t cpid, BOOL b_new,
	uint64_t folder_id, uint64_t message_id,
	uint32_t *pinstance_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_load_message_instance(
				dir, username, cpid, b_new, folder_id,
				message_id, pinstance_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_LOAD_MESSAGE_INSTANCE;
	request.dir = (void*)dir;
	request.payload.load_message_instance.username = (void*)username;
	request.payload.load_message_instance.cpid = cpid;
	request.payload.load_message_instance.b_new = b_new;
	request.payload.load_message_instance.folder_id = folder_id;
	request.payload.load_message_instance.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pinstance_id = response.payload.load_message_instance.instance_id;
	return TRUE;
}

BOOL exmdb_client_load_embedded_instance(
	const char *dir, BOOL b_new, uint32_t attachment_instance_id,
	uint32_t *pinstance_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_load_embedded_instance(dir,
				b_new, attachment_instance_id, pinstance_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_LOAD_EMBEDDED_INSTANCE;
	request.dir = (void*)dir;
	request.payload.load_embedded_instance.b_new = b_new;
	request.payload.load_embedded_instance.attachment_instance_id =
											attachment_instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pinstance_id = response.payload.load_embedded_instance.instance_id;
	return TRUE;
}

BOOL exmdb_client_get_embeded_cn(const char *dir,
	uint32_t instance_id, uint64_t **ppcn)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_embeded_cn(dir, instance_id, ppcn);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_EMBEDED_CN;
	request.dir = (void*)dir;
	request.payload.get_embeded_cn.instance_id = instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppcn = response.payload.get_embeded_cn.pcn;
	return TRUE;
}

BOOL exmdb_client_reload_message_instance(
	const char *dir, uint32_t instance_id, BOOL *pb_result)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_reload_message_instance(
							dir, instance_id, pb_result);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_RELOAD_MESSAGE_INSTANCE;
	request.dir = (void*)dir;
	request.payload.reload_message_instance.instance_id = instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_result = response.payload.reload_message_instance.b_result;
	return TRUE;
}

BOOL exmdb_client_clear_message_instance(
	const char *dir, uint32_t instance_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_clear_message_instance(
									dir, instance_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_CLEAR_MESSAGE_INSTANCE;
	request.dir = (void*)dir;
	request.payload.clear_message_instance.instance_id = instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_read_message_instance(const char *dir,
	uint32_t instance_id, MESSAGE_CONTENT *pmsgctnt)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_read_message_instance(
							dir, instance_id, pmsgctnt);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_READ_MESSAGE_INSTANCE;
	request.dir = (void*)dir;
	request.payload.read_message_instance.instance_id = instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pmsgctnt = response.payload.read_message_instance.msgctnt;
	return TRUE;
}

BOOL exmdb_client_write_message_instance(const char *dir,
	uint32_t instance_id, const MESSAGE_CONTENT *pmsgctnt,
	BOOL b_force, PROPTAG_ARRAY *pproptags,
	PROBLEM_ARRAY *pproblems)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_write_message_instance(
					dir, instance_id, pmsgctnt, b_force,
					pproptags, pproblems);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_WRITE_MESSAGE_INSTANCE;
	request.dir = (void*)dir;
	request.payload.write_message_instance.instance_id = instance_id;
	request.payload.write_message_instance.pmsgctnt = (void*)pmsgctnt;
	request.payload.write_message_instance.b_force = b_force;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pproptags = response.payload.write_message_instance.proptags;
	*pproblems = response.payload.write_message_instance.problems;
	return TRUE;
}

BOOL exmdb_client_load_attachment_instance(const char *dir,
	uint32_t message_instance_id, uint32_t attachment_num,
	uint32_t *pinstance_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_load_attachment_instance(dir,
			message_instance_id, attachment_num, pinstance_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_LOAD_ATTACHMENT_INSTANCE;
	request.dir = (void*)dir;
	request.payload.load_attachment_instance.message_instance_id =
												message_instance_id;
	request.payload.load_attachment_instance.attachment_num =
												attachment_num;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pinstance_id = response.payload.load_attachment_instance.instance_id;
	return TRUE;
}

BOOL exmdb_client_create_attachment_instance(const char *dir,
	uint32_t message_instance_id, uint32_t *pinstance_id,
	uint32_t *pattachment_num)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_create_attachment_instance(dir,
			message_instance_id, pinstance_id, pattachment_num);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_CREATE_ATTACHMENT_INSTANCE;
	request.dir = (void*)dir;
	request.payload.create_attachment_instance.message_instance_id =
												message_instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pinstance_id =
		response.payload.create_attachment_instance.instance_id;
	*pattachment_num =
		response.payload.create_attachment_instance.attachment_num;
	return TRUE;
}

BOOL exmdb_client_read_attachment_instance(const char *dir,
	uint32_t instance_id, ATTACHMENT_CONTENT *pattctnt)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_read_attachment_instance(
							dir, instance_id, pattctnt);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_READ_ATTACHMENT_INSTANCE;
	request.dir = (void*)dir;
	request.payload.read_attachment_instance.instance_id = instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pattctnt = response.payload.read_attachment_instance.attctnt;
	return TRUE;
}

BOOL exmdb_client_write_attachment_instance(const char *dir,
	uint32_t instance_id, const ATTACHMENT_CONTENT *pattctnt,
	BOOL b_force, PROBLEM_ARRAY *pproblems)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_write_attachment_instance(dir,
					instance_id, pattctnt, b_force, pproblems);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_WRITE_ATTACHMENT_INSTANCE;
	request.dir = (void*)dir;
	request.payload.write_attachment_instance.instance_id = instance_id;
	request.payload.write_attachment_instance.pattctnt = (void*)pattctnt;
	request.payload.write_attachment_instance.b_force = b_force;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pproblems = response.payload.write_attachment_instance.problems;
	return TRUE;
}

BOOL exmdb_client_delete_message_instance_attachment(
	const char *dir, uint32_t message_instance_id,
	uint32_t attachment_num)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_delete_message_instance_attachment(
						dir, message_instance_id, attachment_num);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_DELETE_MESSAGE_INSTANCE_ATTACHMENT;
	request.dir = (void*)dir;
	request.payload.delete_message_instance_attachment.message_instance_id =
														message_instance_id;
	request.payload.delete_message_instance_attachment.attachment_num =
														attachment_num;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_flush_instance(const char *dir,
	uint32_t instance_id, const char *account, BOOL *pb_result)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_flush_instance(
			dir, instance_id, account, pb_result);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_FLUSH_INSTANCE;
	request.dir = (void*)dir;
	request.payload.flush_instance.instance_id = instance_id;
	request.payload.flush_instance.account = (void*)account;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_result = response.payload.flush_instance.b_result;
	return TRUE;
}
	
BOOL exmdb_client_unload_instance(
	const char *dir, uint32_t instance_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_unload_instance(dir, instance_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_UNLOAD_INSTANCE;
	request.dir = (void*)dir;
	request.payload.unload_instance.instance_id = instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_get_instance_all_proptags(
	const char *dir, uint32_t instance_id,
	PROPTAG_ARRAY *pproptags)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_instance_all_proptags(
							dir, instance_id, pproptags);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_INSTANCE_ALL_PROPTAGS;
	request.dir = (void*)dir;
	request.payload.get_instance_all_proptags.instance_id = instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pproptags = response.payload.get_instance_all_proptags.proptags;
	return TRUE;
}

BOOL exmdb_client_get_instance_properties(
	const char *dir, uint32_t size_limit, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_instance_properties(dir,
			size_limit, instance_id, pproptags, ppropvals);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_INSTANCE_PROPERTIES;
	request.dir = (void*)dir;
	request.payload.get_instance_properties.size_limit = size_limit;
	request.payload.get_instance_properties.instance_id = instance_id;
	request.payload.get_instance_properties.pproptags = (void*)pproptags;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppropvals = response.payload.get_instance_properties.propvals;
	return TRUE;
}

BOOL exmdb_client_set_instance_properties(const char *dir,
	uint32_t instance_id, const TPROPVAL_ARRAY *pproperties,
	PROBLEM_ARRAY *pproblems)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_set_instance_properties(
				dir, instance_id, pproperties, pproblems);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SET_INSTANCE_PROPERTIES;
	request.dir = (void*)dir;
	request.payload.set_instance_properties.instance_id = instance_id;
	request.payload.set_instance_properties.pproperties = (void*)pproperties;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pproblems = response.payload.set_instance_properties.problems;
	return TRUE;
}

BOOL exmdb_client_remove_instance_properties(
	const char *dir, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_remove_instance_properties(
					dir, instance_id, pproptags, pproblems);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_REMOVE_INSTANCE_PROPERTIES;
	request.dir = (void*)dir;
	request.payload.remove_instance_properties.instance_id = instance_id;
	request.payload.remove_instance_properties.pproptags = (void*)pproptags;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pproblems = response.payload.remove_instance_properties.problems;
	return TRUE;
}

BOOL exmdb_client_check_instance_cycle(const char *dir,
	uint32_t src_instance_id, uint32_t dst_instance_id, BOOL *pb_cycle)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_check_instance_cycle(dir,
			src_instance_id, dst_instance_id, pb_cycle);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_CHECK_INSTANCE_CYCLE;
	request.dir = (void*)dir;
	request.payload.check_instance_cycle.src_instance_id = src_instance_id;
	request.payload.check_instance_cycle.dst_instance_id = dst_instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_cycle = response.payload.check_instance_cycle.b_cycle;
	return TRUE;
}

BOOL exmdb_client_empty_message_instance_rcpts(
	const char *dir, uint32_t instance_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_empty_message_instance_rcpts(
											dir, instance_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_EMPTY_MESSAGE_INSTANCE_RCPTS;
	request.dir = (void*)dir;
	request.payload.empty_message_instance_rcpts.instance_id = instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_get_message_instance_rcpts_num(
	const char *dir, uint32_t instance_id, uint16_t *pnum)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_message_instance_rcpts_num(
										dir, instance_id, pnum);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_MESSAGE_INSTANCE_RCPTS_NUM;
	request.dir = (void*)dir;
	request.payload.get_message_instance_rcpts_num.instance_id = instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pnum = response.payload.get_message_instance_rcpts_num.num;
	return TRUE;
}

BOOL exmdb_client_get_message_instance_rcpts_all_proptags(
	const char *dir, uint32_t instance_id, PROPTAG_ARRAY *pproptags)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_message_instance_rcpts_all_proptags(
											dir, instance_id, pproptags);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS;
	request.dir = (void*)dir;
	request.payload.get_message_instance_rcpts_all_proptags.instance_id = instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pproptags = response.payload.get_message_instance_rcpts_all_proptags.proptags;
	return TRUE;
}

BOOL exmdb_client_get_message_instance_rcpts(
	const char *dir, uint32_t instance_id, uint32_t row_id,
	uint16_t need_count, TARRAY_SET *pset)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_message_instance_rcpts(
				dir, instance_id, row_id, need_count, pset);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_MESSAGE_INSTANCE_RCPTS;
	request.dir = (void*)dir;
	request.payload.get_message_instance_rcpts.instance_id = instance_id;
	request.payload.get_message_instance_rcpts.row_id = row_id;
	request.payload.get_message_instance_rcpts.need_count = need_count;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pset = response.payload.get_message_instance_rcpts.set;
	return TRUE;
}

BOOL exmdb_client_update_message_instance_rcpts(
	const char *dir, uint32_t instance_id, const TARRAY_SET *pset)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_update_message_instance_rcpts(
								dir, instance_id, pset);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_UPDATE_MESSAGE_INSTANCE_RCPTS;
	request.dir = (void*)dir;
	request.payload.update_message_instance_rcpts.instance_id = instance_id;
	request.payload.update_message_instance_rcpts.pset = (void*)pset;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_copy_instance_rcpts(
	const char *dir, BOOL b_force, uint32_t src_instance_id,
	uint32_t dst_instance_id, BOOL *pb_result)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_copy_instance_rcpts(dir, b_force,
					src_instance_id, dst_instance_id, pb_result);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_COPY_INSTANCE_RCPTS;
	request.dir = (void*)dir;
	request.payload.copy_instance_rcpts.b_force = b_force;
	request.payload.copy_instance_rcpts.src_instance_id = src_instance_id;
	request.payload.copy_instance_rcpts.dst_instance_id = dst_instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_result = response.payload.copy_instance_rcpts.b_result;
	return TRUE;
}

BOOL exmdb_client_empty_message_instance_attachments(
	const char *dir, uint32_t instance_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_empty_message_instance_attachments(
												dir, instance_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_EMPTY_MESSAGE_INSTANCE_ATTACHMENTS;
	request.dir = (void*)dir;
	request.payload.empty_message_instance_attachments.instance_id =
														instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_get_message_instance_attachments_num(
	const char *dir, uint32_t instance_id, uint16_t *pnum)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_message_instance_attachments_num(
											dir, instance_id, pnum);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM;
	request.dir = (void*)dir;
	request.payload.get_message_instance_attachments_num.instance_id =
															instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pnum = response.payload.get_message_instance_attachments_num.num;
	return TRUE;
}

BOOL exmdb_client_get_message_instance_attachment_table_all_proptags(
	const char *dir, uint32_t instance_id, PROPTAG_ARRAY *pproptags)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_message_instance_attachment_table_all_proptags(
														dir, instance_id, pproptags);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS;
	request.dir = (void*)dir;
	request.payload.get_message_instance_attachment_table_all_proptags.instance_id =
																		instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pproptags = response.payload.get_message_instance_attachment_table_all_proptags.proptags;
	return TRUE;
}

BOOL exmdb_client_query_message_instance_attachment_table(
	const char *dir, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, uint32_t start_pos,
	int32_t row_needed, TARRAY_SET *pset)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_query_message_instance_attachment_table(
				dir, instance_id, pproptags, start_pos, row_needed, pset);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE;
	request.dir = (void*)dir;
	request.payload.query_message_instance_attachment_table.instance_id =
															instance_id;
	request.payload.query_message_instance_attachment_table.pproptags =
														(void*)pproptags;
	request.payload.query_message_instance_attachment_table.start_pos =
															start_pos;
	request.payload.query_message_instance_attachment_table.row_needed =
															row_needed;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pset = response.payload.query_message_instance_attachment_table.set;
	return TRUE;
}

BOOL exmdb_client_copy_instance_attachments(
	const char *dir, BOOL b_force, uint32_t src_instance_id,
	uint32_t dst_instance_id, BOOL *pb_result)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_copy_instance_attachments(dir,
			b_force, src_instance_id, dst_instance_id, pb_result);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_COPY_INSTANCE_ATTACHMENTS;
	request.dir = (void*)dir;
	request.payload.copy_instance_attachments.b_force = b_force;
	request.payload.copy_instance_attachments.src_instance_id =
												src_instance_id;
	request.payload.copy_instance_attachments.dst_instance_id =
												dst_instance_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_result = response.payload.copy_instance_attachments.b_result;
	return TRUE;
}

BOOL exmdb_client_set_message_instance_conflict(const char *dir,
	uint32_t instance_id, const MESSAGE_CONTENT *pmsgctnt)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_set_message_instance_conflict(
									dir, instance_id, pmsgctnt);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SET_MESSAGE_INSTANCE_CONFLICT;
	request.dir = (void*)dir;
	request.payload.set_message_instance_conflict.instance_id = instance_id;
	request.payload.set_message_instance_conflict.pmsgctnt = (void*)pmsgctnt;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_get_message_rcpts(const char *dir,
	uint64_t message_id, TARRAY_SET *pset)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_message_rcpts(
							dir, message_id, pset);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_MESSAGE_RCPTS;
	request.dir = (void*)dir;
	request.payload.get_message_rcpts.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pset = response.payload.get_message_rcpts.set;
	return TRUE;
}

BOOL exmdb_client_get_message_properties(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_message_properties(dir,
			username, cpid, message_id, pproptags, ppropvals);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_MESSAGE_PROPERTIES;
	request.dir = (void*)dir;
	request.payload.get_message_properties.username = (void*)username;
	request.payload.get_message_properties.cpid = cpid;
	request.payload.get_message_properties.message_id = message_id;
	request.payload.get_message_properties.pproptags = (void*)pproptags;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppropvals = response.payload.get_message_properties.propvals;
	return TRUE;
}

BOOL exmdb_client_set_message_properties(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	const TPROPVAL_ARRAY *pproperties, PROBLEM_ARRAY *pproblems)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_set_message_properties(dir,
			username, cpid, message_id, pproperties, pproblems);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SET_MESSAGE_PROPERTIES;
	request.dir = (void*)dir;
	request.payload.set_message_properties.username = (void*)username;
	request.payload.set_message_properties.cpid = cpid;
	request.payload.set_message_properties.message_id = message_id;
	request.payload.set_message_properties.pproperties = (void*)pproperties;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pproblems = response.payload.set_message_properties.problems;
	return TRUE;
}

BOOL exmdb_client_set_message_read_state(const char *dir,
	const char *username, uint64_t message_id,
	uint8_t mark_as_read, uint64_t *pread_cn)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_set_message_read_state(dir,
			username, message_id, mark_as_read, pread_cn);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SET_MESSAGE_READ_STATE;
	request.dir = (void*)dir;
	request.payload.set_message_read_state.username = (void*)username;
	request.payload.set_message_read_state.message_id = message_id;
	request.payload.set_message_read_state.mark_as_read = mark_as_read;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pread_cn = response.payload.set_message_read_state.read_cn;
	return TRUE;
}

BOOL exmdb_client_remove_message_properties(
	const char *dir, uint32_t cpid, uint64_t message_id,
	const PROPTAG_ARRAY *pproptags)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_remove_message_properties(
						dir, cpid, message_id, pproptags);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_REMOVE_MESSAGE_PROPERTIES;
	request.dir = (void*)dir;
	request.payload.remove_message_properties.cpid = cpid;
	request.payload.remove_message_properties.message_id = message_id;
	request.payload.remove_message_properties.pproptags = (void*)pproptags;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_allocate_message_id(const char *dir,
	uint64_t folder_id, uint64_t *pmessage_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_allocate_message_id(
						dir, folder_id, pmessage_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_ALLOCATE_MESSAGE_ID;
	request.dir = (void*)dir;
	request.payload.allocate_message_id.folder_id = folder_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pmessage_id = response.payload.allocate_message_id.message_id;
	return TRUE;
}

BOOL exmdb_client_allocate_cn(const char *dir, uint64_t *pcn)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_allocate_cn(dir, pcn);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_ALLOCATE_CN;
	request.dir = (void*)dir;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pcn = response.payload.allocate_cn.cn;
	return TRUE;
}

BOOL exmdb_client_get_message_group_id(const char *dir,
	uint64_t message_id, uint32_t **ppgroup_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_message_group_id(
						dir, message_id, ppgroup_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_MESSAGE_GROUP_ID;
	request.dir = (void*)dir;
	request.payload.get_message_group_id.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppgroup_id = response.payload.get_message_group_id.pgroup_id;
	return TRUE;
}

BOOL exmdb_client_set_message_group_id(const char *dir,
	uint64_t message_id, uint32_t group_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_set_message_group_id(
							dir, message_id, group_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SET_MESSAGE_GROUP_ID;
	request.dir = (void*)dir;
	request.payload.set_message_group_id.message_id = message_id;
	request.payload.set_message_group_id.group_id = group_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_save_change_indices(const char *dir,
	uint64_t message_id, uint64_t cn, const INDEX_ARRAY *pindices,
	const PROPTAG_ARRAY *pungroup_proptags)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_save_change_indices(dir,
			message_id, cn, pindices, pungroup_proptags);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SAVE_CHANGE_INDICES;
	request.dir = (void*)dir;
	request.payload.save_change_indices.message_id = message_id;
	request.payload.save_change_indices.cn = cn;
	request.payload.save_change_indices.pindices = (void*)pindices;
	request.payload.save_change_indices.pungroup_proptags =
									(void*)pungroup_proptags;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_get_change_indices(const char *dir,
	uint64_t message_id, uint64_t cn, INDEX_ARRAY *pindices,
	PROPTAG_ARRAY *pungroup_proptags)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_change_indices(dir,
			message_id, cn, pindices, pungroup_proptags);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_CHANGE_INDICES;
	request.dir = (void*)dir;
	request.payload.get_change_indices.message_id = message_id;
	request.payload.get_change_indices.cn = cn;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pindices = response.payload.get_change_indices.indices;
	*pungroup_proptags = response.payload.get_change_indices.ungroup_proptags;
	return TRUE;
}

BOOL exmdb_client_mark_modified(const char *dir, uint64_t message_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_mark_modified(dir, message_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_MARK_MODIFIED;
	request.dir = (void*)dir;
	request.payload.mark_modified.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_try_mark_submit(const char *dir,
	uint64_t message_id, BOOL *pb_marked)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_try_mark_submit(
					dir, message_id, pb_marked);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_TRY_MARK_SUBMIT;
	request.dir = (void*)dir;
	request.payload.try_mark_submit.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_marked = response.payload.try_mark_submit.b_marked;
	return TRUE;
}

BOOL exmdb_client_clear_submit(const char *dir,
	uint64_t message_id, BOOL b_unsent)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_clear_submit(dir, message_id, b_unsent);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_CLEAR_SUBMIT;
	request.dir = (void*)dir;
	request.payload.clear_submit.message_id = message_id;
	request.payload.clear_submit.b_unsent = b_unsent;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_link_message(const char *dir, uint32_t cpid,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_result)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_link_message(dir,
			cpid, folder_id, message_id, pb_result);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_LINK_MESSAGE;
	request.dir = (void*)dir;
	request.payload.link_message.cpid = cpid;
	request.payload.link_message.folder_id = folder_id;
	request.payload.link_message.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_result = response.payload.link_message.b_result;
	return TRUE;
}

BOOL exmdb_client_unlink_message(const char *dir,
	uint32_t cpid, uint64_t folder_id, uint64_t message_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_unlink_message(
				dir, cpid, folder_id, message_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_UNLINK_MESSAGE;
	request.dir = (void*)dir;
	request.payload.unlink_message.cpid = cpid;
	request.payload.unlink_message.folder_id = folder_id;
	request.payload.unlink_message.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_rule_new_message(const char *dir,
	const char *username, const char *account, uint32_t cpid,
	uint64_t folder_id, uint64_t message_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_rule_new_message(dir,
			username, account, cpid, folder_id, message_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_RULE_NEW_MESSAGE;
	request.dir = (void*)dir;
	request.payload.rule_new_message.username = (void*)username;
	request.payload.rule_new_message.account = (void*)account;
	request.payload.rule_new_message.cpid = cpid;
	request.payload.rule_new_message.folder_id = folder_id;
	request.payload.rule_new_message.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_set_message_timer(const char *dir,
	uint64_t message_id, uint32_t timer_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_set_message_timer(
						dir, message_id, timer_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SET_MESSAGE_TIMER;
	request.dir = (void*)dir;
	request.payload.set_message_timer.message_id = message_id;
	request.payload.set_message_timer.timer_id = timer_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_get_message_timer(const char *dir,
	uint64_t message_id, uint32_t **pptimer_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_message_timer(
					dir, message_id, pptimer_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_MESSAGE_TIMER;
	request.dir = (void*)dir;
	request.payload.get_message_timer.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pptimer_id = response.payload.get_message_timer.ptimer_id;
	return TRUE;
}

BOOL exmdb_client_empty_folder_permission(
	const char *dir, uint64_t folder_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_empty_folder_permission(
										dir, folder_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_EMPTY_FOLDER_PERMISSION;
	request.dir = (void*)dir;
	request.payload.empty_folder_permission.folder_id = folder_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_update_folder_permission(const char *dir,
	uint64_t folder_id, BOOL b_freebusy,
	uint16_t count, const PERMISSION_DATA *prow)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_update_folder_permission(
				dir, folder_id, b_freebusy, count, prow);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_UPDATE_FOLDER_PERMISSION;
	request.dir = (void*)dir;
	request.payload.update_folder_permission.folder_id = folder_id;
	request.payload.update_folder_permission.b_freebusy = b_freebusy;
	request.payload.update_folder_permission.count = count;
	request.payload.update_folder_permission.prow = (void*)prow;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_empty_folder_rule(
	const char *dir, uint64_t folder_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_empty_folder_rule(dir, folder_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_EMPTY_FOLDER_RULE;
	request.dir = (void*)dir;
	request.payload.empty_folder_rule.folder_id = folder_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_update_folder_rule(const char *dir,
	uint64_t folder_id, uint16_t count,
	const RULE_DATA *prow, BOOL *pb_exceed)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_update_folder_rule(dir,
					folder_id, count, prow, pb_exceed);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_UPDATE_FOLDER_RULE;
	request.dir = (void*)dir;
	request.payload.update_folder_rule.folder_id = folder_id;
	request.payload.update_folder_rule.count = count;
	request.payload.update_folder_rule.prow = (void*)prow;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_exceed = response.payload.update_folder_rule.b_exceed;
	return TRUE;
}

/* CAUSION!!! this function is not a common exmdb service,
	it only can be called by message_rule_new_message to
	pass message to delegate's mailbox */
BOOL exmdb_client_relay_delivery(const char *dir,
	const char *from_address, const char *account,
	uint32_t cpid, const MESSAGE_CONTENT *pmsg,
	const char *pdigest, uint32_t *presult)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	const char *orignal_dir;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		orignal_dir = exmdb_server_get_dir();
		exmdb_server_set_dir(dir);
		b_result = exmdb_server_delivery_message(
					dir, from_address, account,
					cpid, pmsg, pdigest, presult);
		exmdb_server_set_dir(orignal_dir);
		return b_result;
	}
	request.call_id = CALL_ID_DELIVERY_MESSAGE;
	request.dir = (void*)dir;
	request.payload.delivery_message.from_address = (void*)from_address;
	request.payload.delivery_message.account = (void*)account;
	request.payload.delivery_message.cpid = cpid;
	request.payload.delivery_message.pmsg = (void*)pmsg;
	request.payload.delivery_message.pdigest = (void*)pdigest;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*presult = response.payload.delivery_message.result;
	return TRUE;
}

BOOL exmdb_client_delivery_message(const char *dir,
	const char *from_address, const char *account,
	uint32_t cpid, const MESSAGE_CONTENT *pmsg,
	const char *pdigest, uint32_t *presult)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_delivery_message(
					dir, from_address, account,
					cpid, pmsg, pdigest, presult);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_DELIVERY_MESSAGE;
		request.dir = (void*)dir;
	request.payload.delivery_message.from_address = (void*)from_address;
	request.payload.delivery_message.account = (void*)account;
	request.payload.delivery_message.cpid = cpid;
	request.payload.delivery_message.pmsg = (void*)pmsg;
	request.payload.delivery_message.pdigest = (void*)pdigest;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*presult = response.payload.delivery_message.result;
	return TRUE;
}

BOOL exmdb_client_write_message(const char *dir,
	const char *account, uint32_t cpid, uint64_t folder_id,
	const MESSAGE_CONTENT *pmsgctnt, BOOL *pb_result)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_write_message(dir,
			account, cpid, folder_id, pmsgctnt, pb_result);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_WRITE_MESSAGE;
	request.dir = (void*)dir;
	request.payload.write_message.account = (void*)account;
	request.payload.write_message.cpid = cpid;
	request.payload.write_message.folder_id = folder_id;
	request.payload.write_message.pmsgctnt = (void*)pmsgctnt;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_result = response.payload.write_message.b_result;
	return TRUE;
}

BOOL exmdb_client_read_message(const char *dir, const char *username,
	uint32_t cpid, uint64_t message_id, MESSAGE_CONTENT **ppmsgctnt)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_read_message(dir,
			username, cpid, message_id, ppmsgctnt);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_READ_MESSAGE;
	request.dir = (void*)dir;
	request.payload.read_message.username = (void*)username;
	request.payload.read_message.cpid = cpid;
	request.payload.read_message.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*ppmsgctnt = response.payload.read_message.pmsgctnt;
	return TRUE;
}

BOOL exmdb_client_get_content_sync(const char *dir,
	uint64_t folder_id, const char *username, const IDSET *pgiven,
	const IDSET *pseen, const IDSET *pseen_fai, const IDSET *pread,
	uint32_t cpid, const RESTRICTION *prestriction, BOOL b_ordered,
	uint32_t *pfai_count, uint64_t *pfai_total, uint32_t *pnormal_count,
	uint64_t *pnormal_total, EID_ARRAY *pupdated_mids, EID_ARRAY *pchg_mids,
	uint64_t *plast_cn, EID_ARRAY *pgiven_mids, EID_ARRAY *pdeleted_mids,
	EID_ARRAY *pnolonger_mids, EID_ARRAY *pread_mids,
	EID_ARRAY *punread_mids, uint64_t *plast_readcn)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_content_sync(dir, folder_id,
			username, pgiven, pseen, pseen_fai, pread, cpid,
			prestriction, b_ordered, pfai_count, pfai_total,
			pnormal_count, pnormal_total, pupdated_mids, pchg_mids,
			plast_cn, pgiven_mids, pdeleted_mids, pnolonger_mids,
			pread_mids, punread_mids, plast_readcn);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_CONTENT_SYNC;
	request.dir = (void*)dir;
	request.payload.get_content_sync.folder_id = folder_id;
	request.payload.get_content_sync.username = (void*)username;
	request.payload.get_content_sync.pgiven = (void*)pgiven;
	request.payload.get_content_sync.pseen = (void*)pseen;
	request.payload.get_content_sync.pseen_fai = (void*)pseen_fai;
	request.payload.get_content_sync.pread = (void*)pread;
	request.payload.get_content_sync.cpid = cpid;
	request.payload.get_content_sync.prestriction = (void*)prestriction;
	request.payload.get_content_sync.b_ordered = b_ordered;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pfai_count = response.payload.get_content_sync.fai_count;
	*pfai_total = response.payload.get_content_sync.fai_total;
	*pnormal_count = response.payload.get_content_sync.normal_count;
	*pnormal_total = response.payload.get_content_sync.normal_total;
	*pupdated_mids = response.payload.get_content_sync.updated_mids;
	*pchg_mids = response.payload.get_content_sync.chg_mids;
	*plast_cn = response.payload.get_content_sync.last_cn;
	*pgiven_mids = response.payload.get_content_sync.given_mids;
	*pdeleted_mids = response.payload.get_content_sync.deleted_mids;
	*pnolonger_mids = response.payload.get_content_sync.nolonger_mids;
	*pread_mids = response.payload.get_content_sync.read_mids;
	*punread_mids = response.payload.get_content_sync.unread_mids;
	*plast_readcn = response.payload.get_content_sync.last_readcn;
	return TRUE;
}

BOOL exmdb_client_get_hierarchy_sync(const char *dir,
	uint64_t folder_id, const char *username, const IDSET *pgiven,
	const IDSET *pseen, FOLDER_CHANGES *pfldchgs, uint64_t *plast_cn,
	EID_ARRAY *pgiven_fids, EID_ARRAY *pdeleted_fids)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_hierarchy_sync(
			dir, folder_id, username, pgiven, pseen,
			pfldchgs, plast_cn, pgiven_fids, pdeleted_fids);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_HIERARCHY_SYNC;
	request.dir = (void*)dir;
	request.payload.get_hierarchy_sync.folder_id = folder_id;
	request.payload.get_hierarchy_sync.username = (void*)username;
	request.payload.get_hierarchy_sync.pgiven = (void*)pgiven;
	request.payload.get_hierarchy_sync.pseen = (void*)pseen;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pfldchgs = response.payload.get_hierarchy_sync.fldchgs;
	*plast_cn = response.payload.get_hierarchy_sync.last_cn;
	*pgiven_fids = response.payload.get_hierarchy_sync.given_fids;
	*pdeleted_fids = response.payload.get_hierarchy_sync.deleted_fids;
	return TRUE;
}

BOOL exmdb_client_allocate_ids(const char *dir,
	uint32_t count, uint64_t *pbegin_eid)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_allocate_ids(dir, count, pbegin_eid);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_ALLOCATE_IDS;
	request.dir = (void*)dir;
	request.payload.allocate_ids.count = count;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pbegin_eid = response.payload.allocate_ids.begin_eid;
	return TRUE;
}

BOOL exmdb_client_subscribe_notification(const char *dir,
	uint16_t notificaton_type, BOOL b_whole, uint64_t folder_id,
	uint64_t message_id, uint32_t *psub_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_subscribe_notification(
						dir, notificaton_type, b_whole,
						folder_id, message_id, psub_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_SUBSCRIBE_NOTIFICATION;
	request.dir = (void*)dir;
	request.payload.subscribe_notification.notificaton_type = notificaton_type;
	request.payload.subscribe_notification.b_whole = b_whole;
	request.payload.subscribe_notification.folder_id = folder_id;
	request.payload.subscribe_notification.message_id = message_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*psub_id = response.payload.subscribe_notification.sub_id;
	return TRUE;
}

BOOL exmdb_client_unsubscribe_notification(
	const char *dir, uint32_t sub_id)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_unsubscribe_notification(dir, sub_id);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_UNSUBSCRIBE_NOTIFICATION;
	request.dir = (void*)dir;
	request.payload.unsubscribe_notification.sub_id = sub_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_transport_new_mail(const char *dir,
	uint64_t folder_id, uint64_t message_id, uint32_t message_flags,
	const char *pstr_class)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_transport_new_mail(dir,
			folder_id, message_id, message_flags, pstr_class);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_TRANSPORT_NEW_MAIL;
	request.dir = (void*)dir;
	request.payload.transport_new_mail.folder_id = folder_id;
	request.payload.transport_new_mail.message_id = message_id;
	request.payload.transport_new_mail.message_flags = message_flags;
	request.payload.transport_new_mail.pstr_class = (void*)pstr_class;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_check_contact_address(const char *dir,
	const char *paddress, BOOL *pb_found)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_check_contact_address(
							dir, paddress, pb_found);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_CHECK_CONTACT_ADDRESS;
	request.dir = (void*)dir;
	request.payload.check_contact_address.paddress = (void*)paddress;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pb_found = response.payload.check_contact_address.b_found;
	return TRUE;
}

BOOL exmdb_client_get_public_folder_unread_count(const char *dir,
	const char *username, uint64_t folder_id, uint32_t *pcount)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_get_public_folder_unread_count(
							dir, username, folder_id, pcount);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_GET_PUBLIC_FOLDER_UNREAD_COUNT;
	request.dir = (void*)dir;
	request.payload.get_public_folder_unread_count.username =
											(void*)username;
	request.payload.get_public_folder_unread_count.folder_id =
													folder_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*pcount = response.payload.get_public_folder_unread_count.count;
	return TRUE;
}

BOOL exmdb_client_unload_store(const char *dir)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	if (TRUE == exmdb_client_check_local(dir, &b_private)) {
		exmdb_server_build_environment(TRUE, b_private, dir);
		b_result = exmdb_server_unload_store(dir);
		exmdb_server_free_environment();
		return b_result;
	}
	request.call_id = CALL_ID_UNLOAD_STORE;
	request.dir = (void*)dir;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}
