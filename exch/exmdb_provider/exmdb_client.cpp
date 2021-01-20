// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/socket.h>
#include <gromox/svc_common.h>
#include "exmdb_client.h"
#include "exmdb_server.h"
#include "common_util.h"
#include <gromox/double_list.hpp>
#include <gromox/list_file.hpp>
#include "exmdb_ext.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <csignal>
#include <cerrno>
#include <cstdio>
#include <ctime>
#include <poll.h>

struct REMOTE_SVR {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST conn_list;
	char ip_addr[32];
	char prefix[256];
	int prefix_len;
	BOOL b_private;
	int port;
};

struct REMOTE_CONN {
    DOUBLE_LIST_NODE node;
	time_t last_time;
	REMOTE_SVR *psvr;
	int sockd;
};

struct AGENT_THREAD {
	DOUBLE_LIST_NODE node;
	REMOTE_SVR *pserver;
	pthread_t thr_id;
	int sockd;
};

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
				pbin->pv = common_util_alloc(1);
				if (pbin->pv == nullptr)
					return FALSE;
				*(uint8_t*)pbin->pb = resp_buff[0];
				return TRUE;
			} else if (5 == read_len) {
				pbin->cb = *(uint32_t*)(resp_buff + 1) + 5;
				pbin->pv = common_util_alloc(pbin->cb);
				if (pbin->pv == nullptr)
					return FALSE;
				memcpy(pbin->pv, resp_buff, 5);
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
	int process_id;
	BINARY tmp_bin;
	char remote_id[128];
	const char *str_host;
	EXMDB_REQUEST request;
	uint8_t response_code;

	int sockd = gx_inet_connect(pserver->ip_addr, pserver->port, 0);
	if (sockd < 0)
	        return -1;
	str_host = get_host_ID();
	process_id = getpid();
	sprintf(remote_id, "%s:%d", str_host, process_id);
	if (FALSE == b_listen) {
		request.call_id = exmdb_callid::CONNECT;
		request.payload.connect.prefix = pserver->prefix;
		request.payload.connect.remote_id = remote_id;
		request.payload.connect.b_private = pserver->b_private;
	} else {
		request.call_id = exmdb_callid::LISTEN_NOTIFICATION;
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
	if (response_code == exmdb_response::SUCCESS) {
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
	case exmdb_response::ACCESS_DENY:
		printf("[exmdb_provider]: Failed to connect to "
			"%s:%d for prefix \"%s\", access denied.\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case exmdb_response::MAX_REACHED:
		printf("[exmdb_provider]: Failed to connect to %s:%d for "
			"prefix \"%s\", maximum connections reached in server!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case exmdb_response::LACK_MEMORY:
		printf("[exmdb_provider]: Failed to connect to %s:%d "
			"for prefix \"%s\", server out of memory!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case exmdb_response::MISCONFIG_PREFIX:
		printf("[exmdb_provider]: Failed to connect to %s:%d for "
			"prefix \"%s\", server does not serve the prefix, "
			"configuation file of client or server may be incorrect!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case exmdb_response::MISCONFIG_MODE:
		printf("[exmdb_provider]: Failed to connect to %s:%d for "
			"prefix \"%s\", work mode with the prefix in server is"
			" different from the mode in client, configuation file"
			" of client or server may be incorrect!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	default:
		printf("[exmdb_provider]: Failed to connect to "
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
			while ((pnode1 = double_list_pop_front(&pserver->conn_list)) != nullptr) {
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

		while ((pnode = double_list_pop_front(&temp_list)) != nullptr) {
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
			    resp_buff != exmdb_response::SUCCESS) {
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
		while ((pnode = double_list_pop_front(&g_lost_list)) != nullptr)
			double_list_append_as_tail(&temp_list, pnode);
		pthread_mutex_unlock(&g_server_lock);

		while ((pnode = double_list_pop_front(&temp_list)) != nullptr) {
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
					resp_code = exmdb_response::SUCCESS;
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
					resp_code = exmdb_response::SUCCESS;
				} else {
					resp_code = exmdb_response::PULL_ERROR;
				}
				if (1 != write(pagent->sockd, &resp_code, 1)) {
					close(pagent->sockd);
					pagent->sockd = -1;
					exmdb_server_free_environment();
					break;
				}
				if (resp_code == exmdb_response::SUCCESS) {
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
	pnode = double_list_pop_front(&pserver->conn_list);
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
	HX_strlcpy(g_list_path, list_path, GX_ARRAY_SIZE(g_list_path));
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
	LOCAL_SVR *plocal;
	EXMDB_ITEM *pitem;
	REMOTE_CONN *pconn;
	REMOTE_SVR *pserver;
	AGENT_THREAD *pagent;
	
	auto plist = list_file_init3(g_list_path, /* EXMDB_ITEM */ "%s:256%s:16%s:32%d", false);
	if (NULL == plist) {
		printf("[exmdb_provider]: Failed to read exmdb list from %s: %s\n",
			g_list_path, strerror(errno));
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
				"can be \"private\" or \"public\"!", pitem[i].type);
			list_file_free(plist);
			g_notify_stop = TRUE;
			return 2;
		}
		if (gx_peer_is_local(pitem[i].ip_addr)) {
			plocal = static_cast<LOCAL_SVR *>(malloc(sizeof(LOCAL_SVR)));
			if (NULL == plocal) {
				printf("[exmdb_provider]: Failed to allocate memory\n");
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
		pserver = static_cast<REMOTE_SVR *>(malloc(sizeof(REMOTE_SVR)));
		if (NULL == pserver) {
			printf("[exmdb_provider]: Failed to allocate memory for exmdb\n");
			list_file_free(plist);
			g_notify_stop = TRUE;
			return 5;
		}
		pserver->node.pdata = pserver;
		strcpy(pserver->prefix, pitem[i].prefix);
		pserver->prefix_len = strlen(pserver->prefix);
		pserver->b_private = b_private;
		HX_strlcpy(pserver->ip_addr, pitem[i].ip_addr, GX_ARRAY_SIZE(pserver->ip_addr));
		pserver->port = pitem[i].port;
		double_list_init(&pserver->conn_list);
		double_list_append_as_tail(&g_server_list, &pserver->node);
		for (j=0; j<g_conn_num; j++) {
			pconn = static_cast<REMOTE_CONN *>(malloc(sizeof(REMOTE_CONN)));
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
			pagent = static_cast<AGENT_THREAD *>(malloc(sizeof(AGENT_THREAD)));
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
			char buf[32];
			snprintf(buf, sizeof(buf), "exmdbcl/%u", i);
			pthread_setname_np(pagent->thr_id, buf);
			double_list_append_as_tail(&g_agent_list, &pagent->node);
		}
	}
	list_file_free(plist);
	if (0 == g_conn_num) {
		return 0;
	}
	int ret = pthread_create(&g_scan_id, nullptr, scan_work_func, nullptr);
	if (ret != 0) {
		printf("[exmdb_provider]: failed to create proxy scan thread: %s\n", strerror(ret));
		g_notify_stop = TRUE;
		return 9;
	}
	pthread_setname_np(g_scan_id, "exmdbcl/scan");
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
	while ((pnode = double_list_pop_front(&g_agent_list)) != nullptr) {
		pagent = (AGENT_THREAD*)pnode->pdata;
		pthread_cancel(pagent->thr_id);
		if (-1 != pagent->sockd) {
			close(pagent->sockd);
		}
		free(pagent);
	}
	while ((pnode = double_list_pop_front(&g_local_list)) != nullptr)
		free(pnode->pdata);
	while ((pnode = double_list_pop_front(&g_lost_list)) != nullptr)
		free(pnode->pdata);
	while ((pnode = double_list_pop_front(&g_server_list)) != nullptr) {
		pserver = (REMOTE_SVR*)pnode->pdata;
		while ((pnode = double_list_pop_front(&pserver->conn_list)) != nullptr) {
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

BOOL exmdb_client_check_local(const char *prefix, BOOL *pb_private)
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

BOOL exmdb_client_do_rpc(const char *dir,
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
	if (tmp_bin.cb < 5 || tmp_bin.pb[0] != exmdb_response::SUCCESS)
		return FALSE;
	presponse->call_id = prequest->call_id;
	tmp_bin.cb -= 5;
	tmp_bin.pb += 5;
	if (EXT_ERR_SUCCESS != exmdb_ext_pull_response(&tmp_bin, presponse)) {	
		return FALSE;
	}
	return TRUE;
}

/* Caution. This function is not a common exmdb service,
	it only can be called by message_rule_new_message to
	pass a message to the delegate's mailbox. */
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
	request.call_id = exmdb_callid::DELIVERY_MESSAGE;
	request.dir = deconst(dir);
	request.payload.delivery_message.from_address = deconst(from_address);
	request.payload.delivery_message.account = deconst(account);
	request.payload.delivery_message.cpid = cpid;
	request.payload.delivery_message.pmsg = deconst(pmsg);
	request.payload.delivery_message.pdigest = deconst(pdigest);
	if (FALSE == exmdb_client_do_rpc(dir, &request, &response)) {
		return FALSE;
	}
	*presult = response.payload.delivery_message.result;
	return TRUE;
}
