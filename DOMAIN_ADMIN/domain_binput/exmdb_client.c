#include "exmdb_client.h"
#include "double_list.h"
#include "ext_buffer.h"
#include <gromox/socket.h>
#include <gromox/system_log.h>
#include "list_file.h"
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

#define SOCKET_TIMEOUT								60

#define RESPONSE_CODE_SUCCESS						0x00
#define RESPONSE_CODE_ACCESS_DENY					0x01
#define RESPONSE_CODE_MAX_REACHED					0x02
#define RESPONSE_CODE_LACK_MEMORY					0x03
#define RESPONSE_CODE_MISCONFIG_PREFIX				0x04
#define RESPONSE_CODE_MISCONFIG_MODE				0x05
#define RESPONSE_CODE_CONNECT_INCOMPLETE			0x06
#define RESPONSE_CODE_PULL_ERROR					0x07
#define RESPONSE_CODE_DISPATCH_ERROR				0x08
#define RESPONSE_CODE_PUSH_ERROR					0x09

#define CALL_ID_CONNECT								0x00
#define CALL_ID_SET_STORE_PROPERTIES				0x0a
#define CALL_ID_UNLOAD_STORE						0x80


typedef struct _EXMDB_ITEM {
	char prefix[256];
	char type[16];
	char ip_addr[16];
	int port;
} EXMDB_ITEM;

typedef struct _REMOTE_SVR {
	DOUBLE_LIST_NODE node;
	char ip_addr[16];
	char prefix[256];
	int prefix_len;
	BOOL b_private;
	int port;
} REMOTE_SVR;

typedef struct _CONNECT_REQUEST {
	char *prefix;
	char *remote_id;
	BOOL b_private;
} CONNECT_REQUEST;

typedef struct _GET_STORE_PROPERTIES_REQUEST {
	const char *dir;
	uint32_t cpid;
	const PROPTAG_ARRAY *pproptags;
} GET_STORE_PROPERTIES_REQUEST;

typedef struct _SET_STORE_PROPERTIES_REQUEST {
	const char *dir;
	uint32_t cpid;
	const TPROPVAL_ARRAY *ppropvals;
} SET_STORE_PROPERTIES_REQUEST;

typedef struct _UNLOAD_STORE_REQUEST {
	const char *dir;
} UNLOAD_STORE_REQUEST;


static BOOL g_notify_stop;
static char g_list_path[256];
static DOUBLE_LIST g_server_list;

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

static int exmdb_client_push_set_store_properties_request(
	EXT_PUSH *pext, const SET_STORE_PROPERTIES_REQUEST *r)
{
	int status;
	
	status = ext_buffer_push_string(pext, r->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_tpropval_array(pext, r->ppropvals);
}

static int exmdb_client_push_unload_store_request(
	EXT_PUSH *pext, const UNLOAD_STORE_REQUEST *r)
{
	return ext_buffer_push_string(pext, r->dir);
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
	case CALL_ID_CONNECT:
		status = exmdb_client_push_connect_request(
								&ext_push, prequest);
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case CALL_ID_SET_STORE_PROPERTIES:
		status = exmdb_client_push_set_store_properties_request(
											&ext_push, prequest);
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case CALL_ID_UNLOAD_STORE:
		status = exmdb_client_push_unload_store_request(
									&ext_push, prequest);
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
	pbin->pb = NULL;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			if (NULL != pbin->pb) {
				free(pbin->pb);
			}
			return FALSE;
		}
		if (0 == pbin->cb) {
			read_len = read(sockd, resp_buff, 5);
			if (1 == read_len) {
				pbin->cb = 1;
				pbin->pb = malloc(1);
				if (NULL == pbin->pb) {
					return FALSE;
				}
				*(uint8_t*)pbin->pb = resp_buff[0];
				return TRUE;
			} else if (5 == read_len) {
				pbin->cb = *(uint32_t*)(resp_buff + 1) + 5;
				pbin->pb = malloc(pbin->cb);
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
			if (NULL != pbin->pb) {
				free(pbin->pb);
			}
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

static int exmdb_client_connect_exmdb(REMOTE_SVR *pserver)
{
	int process_id;
	BINARY tmp_bin;
	char remote_id[128];
	uint8_t response_code;
	CONNECT_REQUEST request;
	int sockd = gx_inet_connect(pserver->ip_addr, pserver->port, 0);
	if (sockd < 0)
		return -1;
	process_id = getpid();
	sprintf(remote_id, "posidon:%d", process_id);
	request.prefix = pserver->prefix;
	request.remote_id = remote_id;
	request.b_private = pserver->b_private;
	if (EXT_ERR_SUCCESS != exmdb_client_push_request(
		CALL_ID_CONNECT, &request, &tmp_bin)) {
		close(sockd);
		return -1;
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		close(sockd);
		return -1;
	}
	free(tmp_bin.pb);
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		close(sockd);
		return -1;
	}
	response_code = tmp_bin.pb[0];
	if (RESPONSE_CODE_SUCCESS == response_code) {
		if (5 != tmp_bin.cb || 0 != *(uint32_t*)(tmp_bin.pb + 1)) {
			system_log_info("[exmdb_client]: response format "
				"error when connect to %s:%d for prefix \"%s\"",
				pserver->ip_addr, pserver->port, pserver->prefix);
			close(sockd);
			free(tmp_bin.pb);
			return -1;
		}
		free(tmp_bin.pb);
		return sockd;
	}
	free(tmp_bin.pb);
	close(sockd);
	switch (response_code) {
	case RESPONSE_CODE_ACCESS_DENY:
		system_log_info("[exmdb_client]: Failed to connect"
			" to %s:%d for prefix \"%s\", access denied.\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_MAX_REACHED:
		system_log_info("[exmdb_client]: Failed to connect to %s:%d for"
			" prefix \"%s\",maximum connections reached in server!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_LACK_MEMORY:
		system_log_info("[exmdb_client]: Failed to connect to "
			"%s:%d for prefix \"%s\", server out of memory!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_MISCONFIG_PREFIX:
		system_log_info("[exmdb_client]: Failed to connect to %s:%d "
			"for prefix \"%s\", server does not serve the prefix, "
			"configuation file of client or server may be incorrect!",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_MISCONFIG_MODE:
		system_log_info("[exmdb_client]: Failed to connect to %s:%d for"
			" prefix \"%s\", work mode with the prefix in server is"
			"different from the mode in client, configuation file "
			"of client or server may be incorrect!",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	default:
		system_log_info("[exmdb_client]: Failed to connect "
			"to %s:%d for prefix \"%s\", error code %d!\n",
			pserver->ip_addr, pserver->port,
			pserver->prefix, (int)response_code);
		break;
	}
	return -1;
}

static int exmdb_client_get_connection(const char *dir)
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
		return -1;
	}
	return exmdb_client_connect_exmdb(pserver);
}

void exmdb_client_init(const char *list_path)
{
	strcpy(g_list_path, list_path);
	double_list_init(&g_server_list);
}

int exmdb_client_run()
{
	int i;
	int list_num;
	BOOL b_private;
	LIST_FILE *plist;
	EXMDB_ITEM *pitem;
	REMOTE_SVR *pserver;
	
	plist = list_file_init3(g_list_path, "%s:256%s:16%s:16%d", false);
	if (NULL == plist) {
		system_log_info("[exmdb_client]: Failed to read exmdb list from %s: %s",
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
			system_log_info("[exmdb_client]: unknown type \"%s\","
						" only can be \"private\" or \"public\"!");
			list_file_free(plist);
			g_notify_stop = TRUE;
			return 2;
		}
		pserver = malloc(sizeof(REMOTE_SVR));
		if (NULL == pserver) {
			list_file_free(plist);
			g_notify_stop = TRUE;
			return 3;
		}
		pserver->node.pdata = pserver;
		strcpy(pserver->prefix, pitem[i].prefix);
		pserver->prefix_len = strlen(pserver->prefix);
		pserver->b_private = b_private;
		strcpy(pserver->ip_addr, pitem[i].ip_addr);
		pserver->port = pitem[i].port;
		double_list_append_as_tail(&g_server_list, &pserver->node);
	}
	list_file_free(plist);
	return 0;
}

int exmdb_client_stop()
{
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_get_from_head(&g_server_list)) != NULL)
		free(pnode->pdata);
	return 0;
}

void exmdb_client_free()
{
	double_list_free(&g_server_list);
}

BOOL exmdb_client_set_store_properties(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *ppropvals,
	PROBLEM_ARRAY *pproblems)
{
	int sockd;
	BINARY tmp_bin;
	EXT_PULL ext_pull;
	SET_STORE_PROPERTIES_REQUEST request;
	
	request.dir = dir;
	request.cpid = cpid;
	request.ppropvals = ppropvals;
	if (EXT_ERR_SUCCESS != exmdb_client_push_request(
		CALL_ID_SET_STORE_PROPERTIES, &request, &tmp_bin)) {
		return FALSE;
	}
	sockd = exmdb_client_get_connection(dir);
	if (-1 == sockd) {
		free(tmp_bin.pb);
		return FALSE;
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		close(sockd);
		return FALSE;
	}
	free(tmp_bin.pb);
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		close(sockd);
		return FALSE;
	}
	close(sockd);
	if (tmp_bin.cb < 5 || RESPONSE_CODE_SUCCESS != tmp_bin.pb[0]) {
		free(tmp_bin.pb);
		return FALSE;
	}
	ext_buffer_pull_init(&ext_pull, tmp_bin.pb + 5,
		tmp_bin.cb - 5, malloc, EXT_FLAG_WCOUNT);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_problem_array(
		&ext_pull, pproblems)) {
		free(tmp_bin.pb);
		return FALSE;
	}
	free(tmp_bin.pb);
	return TRUE;
}

BOOL exmdb_client_unload_store(const char *dir)
{
	int sockd;
	BINARY tmp_bin;
	UNLOAD_STORE_REQUEST request;
	
	request.dir = dir;
	if (EXT_ERR_SUCCESS != exmdb_client_push_request(
		CALL_ID_UNLOAD_STORE, &request, &tmp_bin)) {
		return FALSE;
	}
	sockd = exmdb_client_get_connection(dir);
	if (-1 == sockd) {
		free(tmp_bin.pb);
		return FALSE;
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		close(sockd);
		return FALSE;
	}
	free(tmp_bin.pb);
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		close(sockd);
		return FALSE;
	}
	close(sockd);
	if (tmp_bin.cb != 5 || RESPONSE_CODE_SUCCESS != tmp_bin.pb[0]) {
		free(tmp_bin.pb);
		return FALSE;
	}
	free(tmp_bin.pb);
	return TRUE;
}
