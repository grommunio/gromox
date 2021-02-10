// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <mutex>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/endian_macro.hpp>
#include "exmdb_client.h"
#include <gromox/double_list.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/hook_common.h>
#include <gromox/socket.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/list_file.hpp>
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

#define SOCKET_TIMEOUT								60

struct EXMDB_ITEM {
	char prefix[256];
	char type[16];
	char ip_addr[32];
	int port;
};

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

struct CONNECT_REQUEST {
	char *prefix;
	char *remote_id;
	BOOL b_private;
};

struct DELIVERY_MESSAGE_REQUEST {
	const char *dir;
	const char *from_address;
	const char *account;
	uint32_t cpid;
	const MESSAGE_CONTENT *pmsg;
	const char *pdigest;
};

struct CHECK_CONTACT_ADDRESS_REQUEST {
	const char *dir;
	const char *paddress;
};

static int g_conn_num;
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static char g_list_path[256];
static DOUBLE_LIST g_lost_list;
static DOUBLE_LIST g_server_list;
static std::mutex g_server_lock;

static int exmdb_client_push_connect_request(
	EXT_PUSH *pext, const CONNECT_REQUEST *r)
{
	int status;
	
	status = ext_buffer_push_string(pext, r->prefix);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_string(pext, r->remote_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext, r->b_private);
}

static int exmdb_client_push_delivery_message_request(
	EXT_PUSH *pext, const DELIVERY_MESSAGE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_push_string(pext, r->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_string(pext, r->from_address);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_string(pext, r->account);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_message_content(pext, r->pmsg);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_string(pext, r->pdigest);
}

static int exmdb_client_push_check_contact_address_request(
	EXT_PUSH *pext, const CHECK_CONTACT_ADDRESS_REQUEST *r)
{
	int status;
	
	status = ext_buffer_push_string(pext, r->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_string(pext, r->paddress);
}

static int exmdb_client_push_request(uint8_t call_id,
	void *prequest, BINARY *pbin_out)
{
	int status;
	EXT_PUSH ext_push;
	
	if (FALSE == ext_buffer_push_init(
		&ext_push, NULL, 0, EXT_FLAG_WCOUNT)) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_push_advance(&ext_push, sizeof(uint32_t));
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	status = ext_buffer_push_uint8(&ext_push, call_id);
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	switch (call_id) {
	case exmdb_callid::CONNECT:
		status = exmdb_client_push_connect_request(&ext_push, static_cast<CONNECT_REQUEST *>(prequest));
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case exmdb_callid::DELIVERY_MESSAGE:
		status = exmdb_client_push_delivery_message_request(&ext_push, static_cast<DELIVERY_MESSAGE_REQUEST *>(prequest));
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case exmdb_callid::CHECK_CONTACT_ADDRESS:
		status = exmdb_client_push_check_contact_address_request(&ext_push, static_cast<CHECK_CONTACT_ADDRESS_REQUEST *>(prequest));
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	default:
		ext_buffer_push_free(&ext_push);
		return EXT_ERR_BAD_SWITCH;
	}
	pbin_out->cb = ext_push.offset;
	ext_push.offset = 0;
	ext_buffer_push_uint32(&ext_push,
		pbin_out->cb - sizeof(uint32_t));
	/* memory referneced by ext_push.data will be freed outside */
	pbin_out->pb = ext_push.data;
	return EXT_ERR_SUCCESS;
}

static BOOL exmdb_client_read_socket(int sockd, BINARY *pbin)
{
	fd_set myset;
	int read_len;
	uint32_t offset;
	struct timeval tv;
	uint8_t resp_buff[5];
	
	pbin->cb = 0;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return FALSE;
		}
		if (0 == pbin->cb) {
			read_len = read(sockd, resp_buff, 5);
			if (1 == read_len) {
				pbin->cb = 1;
				*(uint8_t*)pbin->pb = resp_buff[0];
				return TRUE;
			} else if (5 == read_len) {
				pbin->cb = *(uint32_t*)(resp_buff + 1) + 5;
				if (pbin->cb >= 1024) {
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
		read_len = read(sockd,
			pbin->pb + offset,
			pbin->cb - offset);
		if (read_len <= 0) {
			return FALSE;
		}
		offset += read_len;
		if (offset == pbin->cb) {
			return TRUE;
		}
	}
}

static BOOL exmdb_client_write_socket(
	int sockd, const BINARY *pbin)
{
	fd_set myset;
	int written_len;
	uint32_t offset;
	struct timeval tv;
	
	offset = 0;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, NULL, &myset, NULL, &tv) <= 0) {
			return FALSE;
		}
		written_len = write(sockd,
				pbin->pb + offset,
				pbin->cb - offset);
		if (written_len <= 0) {
			return FALSE;
		}
		offset += written_len;
		if (offset == pbin->cb) {
			return TRUE;
		}
	}
}

static int exmdb_client_connect_exmdb(REMOTE_SVR *pserver)
{
	int process_id;
	BINARY tmp_bin;
	char remote_id[128];
	const char *str_host;
	uint8_t response_code, tmp_buff[1024];
	CONNECT_REQUEST request;

	int sockd = gx_inet_connect(pserver->ip_addr, pserver->port, 0);
	if (sockd < 0)
		return -1;
	str_host = get_host_ID();
	process_id = getpid();
	sprintf(remote_id, "%s:%d", str_host, process_id);
	request.prefix = pserver->prefix;
	request.remote_id = remote_id;
	request.b_private = pserver->b_private;
	if (exmdb_client_push_request(exmdb_callid::CONNECT, &request,
	    &tmp_bin) != EXT_ERR_SUCCESS) {
		close(sockd);
		return -1;
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		close(sockd);
		return -1;
	}
	free(tmp_bin.pb);
	tmp_bin.pb = tmp_buff;
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		close(sockd);
		return -1;
	}
	response_code = tmp_bin.pb[0];
	if (response_code == exmdb_response::SUCCESS) {
		if (5 != tmp_bin.cb || 0 != *(uint32_t*)(tmp_bin.pb + 1)) {
			printf("[exmdb_local]: response format error "
				"when connect to %s:%d for prefix \"%s\"\n",
				pserver->ip_addr, pserver->port, pserver->prefix);
			close(sockd);
			return -1;
		}
		return sockd;
	}
	switch (response_code) {
	case exmdb_response::ACCESS_DENY:
		printf("[exmdb_local]: Failed to connect to "
			"%s:%d for prefix \"%s\", access denied.\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case exmdb_response::MAX_REACHED:
		printf("[exmdb_local]: Failed to connect to %s:%d for "
			"prefix \"%s\",maximum connections reached in server!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case exmdb_response::LACK_MEMORY:
		printf("[exmdb_local]: Failed to connect to %s:%d "
			"for prefix \"%s\", server out of memory!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case exmdb_response::MISCONFIG_PREFIX:
		printf("[exmdb_local]: Failed to connect to %s:%d for "
			"prefix \"%s\", server does not serve the prefix, "
			"configuation file of client or server may be incorrect!",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case exmdb_response::MISCONFIG_MODE:
		printf("[exmdb_local]: Failed to connect to %s:%d for "
			"prefix \"%s\", work mode with the prefix in server is"
			"different from the mode in client, configuation file "
			"of client or server may be incorrect!",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	default:
		printf("[exmdb_local]: Failed to connect to "
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
	fd_set myset;
	time_t now_time;
	struct timeval tv;
	uint8_t resp_buff;
	uint32_t ping_buff;
	REMOTE_CONN *pconn;
	REMOTE_SVR *pserver;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	DOUBLE_LIST_NODE *pnode1;
	
	
	ping_buff = 0;
	double_list_init(&temp_list);

	while (FALSE == g_notify_stop) {
		std::unique_lock sv_hold(g_server_lock);
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
		sv_hold.unlock();

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
				sv_hold.lock();
				double_list_append_as_tail(&g_lost_list, &pconn->node);
				continue;
			}
			tv.tv_usec = 0;
			tv.tv_sec = SOCKET_TIMEOUT;
			FD_ZERO(&myset);
			FD_SET(pconn->sockd, &myset);
			if (select(pconn->sockd + 1, &myset, NULL, NULL, &tv) <= 0 ||
				1 != read(pconn->sockd, &resp_buff, 1) ||
			    resp_buff != exmdb_response::SUCCESS) {
				close(pconn->sockd);
				pconn->sockd = -1;
				sv_hold.lock();
				double_list_append_as_tail(&g_lost_list, &pconn->node);
				sv_hold.unlock();
			} else {
				time(&pconn->last_time);
				sv_hold.lock();
				double_list_append_as_tail(&pconn->psvr->conn_list,
					&pconn->node);
				sv_hold.unlock();
			}
		}

		sv_hold.lock();
		while ((pnode = double_list_pop_front(&g_lost_list)) != nullptr)
			double_list_append_as_tail(&temp_list, pnode);
		sv_hold.unlock();

		while ((pnode = double_list_pop_front(&temp_list)) != nullptr) {
			pconn = (REMOTE_CONN*)pnode->pdata;
			if (TRUE == g_notify_stop) {
				close(pconn->sockd);
				free(pconn);
				continue;
			}
			pconn->sockd = exmdb_client_connect_exmdb(pconn->psvr);
			if (-1 != pconn->sockd) {
				time(&pconn->last_time);
				sv_hold.lock();
				double_list_append_as_tail(&pconn->psvr->conn_list,
					&pconn->node);
				sv_hold.unlock();
			} else {
				sv_hold.lock();
				double_list_append_as_tail(&g_lost_list, &pconn->node);
				sv_hold.unlock();
			}
		}
		sleep(1);
	}
	return NULL;
}

static REMOTE_CONN* exmdb_client_get_connection(const char *dir)
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
		printf("[exmdb_local]: cannot find remote server for %s\n", dir);
		return NULL;
	}
	std::unique_lock sv_hold(g_server_lock);
	pnode = double_list_pop_front(&pserver->conn_list);
	sv_hold.unlock();
	if (NULL == pnode) {
		printf("[exmdb_local]: no alive connection for"
			" remote server for %s\n", pserver->prefix);
		return NULL;
	}
	return (REMOTE_CONN*)pnode->pdata;
}

BOOL exmdb_client_get_exmdb_information(
	const char *dir, char *ip_addr, int *pport,
	int *pconn_num, int *palive_conn)
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
		return FALSE;
	}
	strcpy(ip_addr, pserver->ip_addr);
	*pport = pserver->port;
	*palive_conn = double_list_get_nodes_num(&pserver->conn_list);
	*pconn_num = g_conn_num;
	return TRUE;
}

static void exmdb_client_put_connection(REMOTE_CONN *pconn, BOOL b_lost)
{
	if (FALSE == b_lost) {
		std::unique_lock sv_hold(g_server_lock);
		double_list_append_as_tail(&pconn->psvr->conn_list, &pconn->node);
	} else {
		close(pconn->sockd);
		pconn->sockd = -1;
		std::unique_lock sv_hold(g_server_lock);
		double_list_append_as_tail(&g_lost_list, &pconn->node);
	}
}

void exmdb_client_init(int conn_num, const char *list_path)
{
	g_notify_stop = TRUE;
	g_conn_num = conn_num;
	HX_strlcpy(g_list_path, list_path, GX_ARRAY_SIZE(g_list_path));
	double_list_init(&g_server_list);
	double_list_init(&g_lost_list);
}

int exmdb_client_run()
{
	int i, j;
	BOOL b_private;
	REMOTE_CONN *pconn;
	REMOTE_SVR *pserver;
	
	auto plist = list_file_init(g_list_path, /* EXMDB_ITEM */ "%s:256%s:16%s:32%d", false);
	if (NULL == plist) {
		printf("[exmdb_local]: Failed to read exmdb list from %s: %s\n",
			g_list_path, strerror(errno));
		return 1;
	}
	g_notify_stop = FALSE;
	auto list_num = plist->get_size();
	auto pitem = static_cast<EXMDB_ITEM *>(plist->get_list());
	for (i=0; i<list_num; i++) {
		if (0 == strcasecmp(pitem[i].type, "private")) {
			b_private = TRUE;
		} else if (0 == strcasecmp(pitem[i].type, "public")) {
			b_private = FALSE;
		} else {
			printf("[exmdb_local]: unknown type \"%s\", "
				"can only be \"private\" or \"public\"!", pitem[i].type);
			g_notify_stop = TRUE;
			return 2;
		}
		pserver = static_cast<REMOTE_SVR *>(malloc(sizeof(REMOTE_SVR)));
		if (NULL == pserver) {
			printf("[exmdb_local]: Failed to allocate memory for exmdb\n");
			g_notify_stop = TRUE;
			return 3;
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
				printf("[exmdb_local]: fail to "
					"allocate memory for exmdb\n");
				g_notify_stop = TRUE;
				return 4;
			}
			pconn->node.pdata = pconn;
			pconn->sockd = -1;
			pconn->psvr = pserver;
			double_list_append_as_tail(&g_lost_list, &pconn->node);
		}
	}
	int ret = pthread_create(&g_scan_id, nullptr, scan_work_func, nullptr);
	if (ret != 0) {
		printf("[exmdb_local]: failed to create proxy scan thread: %s\n", strerror(ret));
		g_notify_stop = TRUE;
		return 5;
	}
	pthread_setname_np(g_scan_id, "mdbloc/scan");
	return 0;
}

int exmdb_client_stop()
{
	REMOTE_CONN *pconn;
	REMOTE_SVR *pserver;
	DOUBLE_LIST_NODE *pnode;
	
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_scan_id, NULL);
	}
	g_notify_stop = TRUE;
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
	double_list_free(&g_lost_list);
	double_list_free(&g_server_list);
}

int exmdb_client_delivery_message(const char *dir,
	const char *from_address, const char *account,
	uint32_t cpid, const MESSAGE_CONTENT *pmsg,
	const char *pdigest)
{
	BINARY tmp_bin;
	uint32_t result;
	REMOTE_CONN *pconn;
	uint8_t tmp_buff[1024];
	DELIVERY_MESSAGE_REQUEST request;
	
	request.dir = dir;
	request.from_address = from_address;
	request.account = account;
	request.cpid = cpid;
	request.pmsg = pmsg;
	request.pdigest = pdigest;
	if (exmdb_client_push_request(exmdb_callid::DELIVERY_MESSAGE,
	    &request, &tmp_bin) != EXT_ERR_SUCCESS)
		return EXMDB_RUNTIME_ERROR;
	pconn = exmdb_client_get_connection(dir);
	if (NULL == pconn) {
		free(tmp_bin.pb);
		return EXMDB_NO_SERVER;
	}
	if (FALSE == exmdb_client_write_socket(pconn->sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		exmdb_client_put_connection(pconn, TRUE);
		return EXMDB_RDWR_ERROR;
	}
	free(tmp_bin.pb);
	tmp_bin.pb = tmp_buff;
	if (FALSE == exmdb_client_read_socket(pconn->sockd, &tmp_bin)) {
		exmdb_client_put_connection(pconn, TRUE);
		return EXMDB_RDWR_ERROR;
	}
	time(&pconn->last_time);
	exmdb_client_put_connection(pconn, FALSE);
	if (5 + sizeof(uint32_t) != tmp_bin.cb ||
	    tmp_buff[0] != exmdb_response::SUCCESS)
		return EXMDB_RUNTIME_ERROR;
	result = IVAL(tmp_buff, 5);
	if (0 == result) {
		return EXMDB_RESULT_OK;
	} else if (1 == result) {
		return EXMDB_MAILBOX_FULL;
	} else {
		return EXMDB_RESULT_ERROR;
	}
}

int exmdb_client_check_contact_address(const char *dir,
	const char *paddress, BOOL *pb_found)
{
	BINARY tmp_bin;
	REMOTE_CONN *pconn;
	uint8_t tmp_buff[1024];
	CHECK_CONTACT_ADDRESS_REQUEST request;
	
	request.dir = dir;
	request.paddress = paddress;
	if (exmdb_client_push_request(exmdb_callid::CHECK_CONTACT_ADDRESS,
	    &request, &tmp_bin) != EXT_ERR_SUCCESS)
		return EXMDB_RUNTIME_ERROR;
	pconn = exmdb_client_get_connection(dir);
	if (NULL == pconn) {
		free(tmp_bin.pb);
		return EXMDB_NO_SERVER;
	}
	if (FALSE == exmdb_client_write_socket(pconn->sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		exmdb_client_put_connection(pconn, TRUE);
		return EXMDB_RDWR_ERROR;
	}
	free(tmp_bin.pb);
	tmp_bin.pb = tmp_buff;
	if (FALSE == exmdb_client_read_socket(pconn->sockd, &tmp_bin)) {
		exmdb_client_put_connection(pconn, TRUE);
		return EXMDB_RDWR_ERROR;
	}
	time(&pconn->last_time);
	exmdb_client_put_connection(pconn, FALSE);
	if (5 + sizeof(uint8_t) != tmp_bin.cb ||
	    tmp_buff[0] != exmdb_response::SUCCESS)
		return EXMDB_RUNTIME_ERROR;
	if (0 == tmp_bin.pb[5]) {
		*pb_found = FALSE;
	} else {
		*pb_found = TRUE;
	}
	return EXMDB_RESULT_OK;
}
