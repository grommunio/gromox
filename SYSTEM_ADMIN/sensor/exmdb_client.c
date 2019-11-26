#include "alloc_context.h"
#include "exmdb_client.h"
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


#define SOCKET_TIMEOUT										60

typedef struct _EXMDB_ITEM {
	char prefix[256];
	char type[16];
	char ip_addr[16];
	int port;
} EXMDB_ITEM;

typedef struct _REMOTE_SVR {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST conn_list;
	char ip_addr[16];
	char prefix[256];
	int prefix_len;
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
static pthread_key_t g_ctx_key;
static DOUBLE_LIST g_lost_list;
static DOUBLE_LIST g_agent_list;
static DOUBLE_LIST g_server_list;
static pthread_mutex_t g_server_lock;

static void (*exmdb_client_event_proc)(const char *dir,
	BOOL b_table, uint32_t notify_id, const DB_NOTIFY *pdb_notify);
	
static BOOL exmdb_client_build_environment()
{
	ALLOC_CONTEXT *pctx;
	
	pctx = malloc(sizeof(ALLOC_CONTEXT));
	if (NULL == pctx) {
		return FALSE;
	}
	alloc_context_init(pctx);
	pthread_setspecific(g_ctx_key, pctx);
	return TRUE;
}

static void exmdb_client_free_environment()
{
	ALLOC_CONTEXT *pctx;
	
	pctx = pthread_getspecific(g_ctx_key);
	if (NULL == pctx) {
		return;
	}
	alloc_context_free(pctx);
	free(pctx);
	pthread_setspecific(g_ctx_key, NULL);
}

static void* exmdb_client_alloc(size_t size)
{
	ALLOC_CONTEXT *pctx;
	
	pctx = pthread_getspecific(g_ctx_key);
	if (NULL == pctx) {
		return NULL;
	}
	return alloc_context_alloc(pctx, size);
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
				pbin->pb = exmdb_client_alloc(1);
				if (NULL == pbin->pb) {
					return FALSE;
				}
				*(uint8_t*)pbin->pb = resp_buff[0];
				return TRUE;
			} else if (5 == read_len) {
				pbin->cb = *(uint32_t*)(resp_buff + 1) + 5;
				pbin->pb = exmdb_client_alloc(pbin->cb);
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
	int written_len;
	uint32_t offset;
	
	offset = 0;
	while (TRUE) {
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
	char remote_id[128];
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
	process_id = getpid();
	sprintf(remote_id, "sensor:%d", process_id);
	if (FALSE == b_listen) {
		request.call_id = CALL_ID_CONNECT;
		request.payload.connect.prefix = pserver->prefix;
		request.payload.connect.remote_id = remote_id;
		request.payload.connect.b_private = TRUE;
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
	exmdb_client_build_environment();
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		exmdb_client_free_environment();
		close(sockd);
		return -1;
	}
	response_code = tmp_bin.pb[0];
	if (RESPONSE_CODE_SUCCESS == response_code) {
		if (5 != tmp_bin.cb || 0 != *(uint32_t*)(tmp_bin.pb + 1)) {
			exmdb_client_free_environment();
			printf("[exmdb_client]: response format error "
				"when connect to %s:%d for prefix \"%s\"\n",
				pserver->ip_addr, pserver->port, pserver->prefix);
			close(sockd);
			return -1;
		}
		exmdb_client_free_environment();
		return sockd;
	}
	exmdb_client_free_environment();
	switch (response_code) {
	case RESPONSE_CODE_ACCESS_DENY:
		printf("[exmdb_client]: fail to connect to "
			"%s:%d for prefix \"%s\", access deny!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_MAX_REACHED:
		printf("[exmdb_client]: fail to connect to %s:%d for "
			"prefix \"%s\", maximum connections reached in server!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_LACK_MEMORY:
		printf("[exmdb_client]: fail to connect to %s:%d "
			"for prefix \"%s\", server out of memory!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_MISCONFIG_PREFIX:
		printf("[exmdb_client]: fail to connect to %s:%d for "
			"prefix \"%s\", server does not serve the prefix, "
			"configuation file of client or server may be incorrect!",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_MISCONFIG_MODE:
		printf("[exmdb_client]: fail to connect to %s:%d for "
			"prefix \"%s\", work mode with the prefix in server is"
			"different from the mode in client, configuation file "
			"of client or server may be incorrect!",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	default:
		printf("[exmdb_client]: fail to connect to "
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
	return NULL;
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
				exmdb_client_build_environment();
				if (EXT_ERR_SUCCESS == exmdb_ext_pull_db_notify(
					&tmp_bin, exmdb_client_alloc, &notify)) {
					resp_code = RESPONSE_CODE_SUCCESS;
				} else {
					resp_code = RESPONSE_CODE_PULL_ERROR;
				}
				if (1 != write(pagent->sockd, &resp_code, 1)) {
					close(pagent->sockd);
					pagent->sockd = -1;
					exmdb_client_free_environment();
					break;
				}
				if (RESPONSE_CODE_SUCCESS == resp_code) {
					for (i=0; i<notify.id_array.count; i++) {
						exmdb_client_event_proc(notify.dir,
							notify.b_table, notify.id_array.pl[i],
							&notify.db_notify);
					}
				}
				exmdb_client_free_environment();
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
		printf("[exmdb_client]: cannot find remote server for %s\n", dir);
		return NULL;
	}
	pthread_mutex_lock(&g_server_lock);
	pnode = double_list_get_from_head(&pserver->conn_list);
	pthread_mutex_unlock(&g_server_lock);
	if (NULL == pnode) {
		printf("[exmdb_client]: no alive connection for"
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
	double_list_init(&g_server_list);
	double_list_init(&g_lost_list);
	double_list_init(&g_agent_list);
	pthread_mutex_init(&g_server_lock, NULL);
	pthread_key_create(&g_ctx_key, NULL);
}

int exmdb_client_run()
{
	int i, j;
	int list_num;
	LIST_FILE *plist;
	EXMDB_ITEM *pitem;
	REMOTE_CONN *pconn;
	REMOTE_SVR *pserver;
	AGENT_THREAD *pagent;
	
	plist = list_file_init(g_list_path, "%s:256%s:16%s:16%d");
	if (NULL == plist) {
		printf("[exmdb_client]: fail to open exmdb list file\n");
		return 1;
	}
	g_notify_stop = FALSE;
	list_num = list_file_get_item_num(plist);
	pitem = (EXMDB_ITEM*)list_file_get_list(plist);
	for (i=0; i<list_num; i++) {
		if (0 != strcasecmp(pitem[i].type, "private")) {
			continue;	
		}
		pserver = malloc(sizeof(REMOTE_SVR));
		if (NULL == pserver) {
			printf("[exmdb_client]: fail to allocate memory for exmdb\n");
			list_file_free(plist);
			g_notify_stop = TRUE;
			return 5;
		}
		pserver->node.pdata = pserver;
		strcpy(pserver->prefix, pitem[i].prefix);
		pserver->prefix_len = strlen(pserver->prefix);
		strcpy(pserver->ip_addr, pitem[i].ip_addr);
		pserver->port = pitem[i].port;
		double_list_init(&pserver->conn_list);
		double_list_append_as_tail(&g_server_list, &pserver->node);
		for (j=0; j<g_conn_num; j++) {
		   pconn = malloc(sizeof(REMOTE_CONN));
			if (NULL == pconn) {
				printf("[exmdb_client]: fail to "
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
				printf("[exmdb_client]: fail to "
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
				printf("[exmdb_client]: fail to "
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
		printf("[exmdb_client]: fail to create proxy scan thread\n");
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
	double_list_free(&g_lost_list);
	double_list_free(&g_server_list);
	double_list_free(&g_agent_list);
	pthread_mutex_destroy(&g_server_lock);
	pthread_key_delete(g_ctx_key);
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
	exmdb_client_build_environment();
	if (FALSE == exmdb_client_read_socket(pconn->sockd, &tmp_bin)) {
		exmdb_client_free_environment();
		exmdb_client_put_connection(pconn, TRUE);
		return FALSE;
	}
	time(&pconn->last_time);
	exmdb_client_put_connection(pconn, FALSE);
	if (tmp_bin.cb < 5 || RESPONSE_CODE_SUCCESS != tmp_bin.pb[0]) {
		exmdb_client_free_environment();
		return FALSE;
	}
	presponse->call_id = prequest->call_id;
	tmp_bin.cb -= 5;
	tmp_bin.pb += 5;
	if (EXT_ERR_SUCCESS != exmdb_ext_pull_response(
		&tmp_bin, exmdb_client_alloc, presponse)) {
		exmdb_client_free_environment();
		return FALSE;
	}
	exmdb_client_free_environment();
	return TRUE;
}

BOOL exmdb_client_ping_store(const char *dir)
{
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	request.call_id = CALL_ID_PING_STORE;
	request.dir = (void*)dir;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_subscribe_notification(const char *dir,
	uint16_t notificaton_type, BOOL b_whole, uint64_t folder_id,
	uint64_t message_id, uint32_t *psub_id)
{
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
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
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	
	request.call_id = CALL_ID_UNSUBSCRIBE_NOTIFICATION;
	request.dir = (void*)dir;
	request.payload.unsubscribe_notification.sub_id = sub_id;
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	return TRUE;
}

void exmdb_client_register_proc(void *pproc)
{
	exmdb_client_event_proc = pproc;
}
