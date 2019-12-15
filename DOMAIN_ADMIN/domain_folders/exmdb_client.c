#include "exmdb_client.h"
#include "endian_macro.h"
#include "double_list.h"
#include "ext_buffer.h"
#include <gromox/system_log.h>
#include "list_file.h"
#include "rop_util.h"
#include "pcl.h"
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
#define CALL_ID_CREATE_FOLDER_BY_PROPERTIES			0x15
#define CALL_ID_DELETE_FOLDER						0x1a
#define CALL_ID_LOAD_HIERARCHY_TABLE				0x26
#define CALL_ID_LOAD_PERMISSION_TABLE				0x29
#define CALL_ID_UNLOAD_TABLE						0x2b
#define CALL_ID_QUERY_TABLE							0x2d
#define CALL_ID_ALLOCATE_CN							0x5c
#define CALL_ID_UPDATE_FOLDER_PERMISSION			0x6a


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

typedef struct _CREATE_FOLDER_BY_PROPERTIES_REQUEST {
	const char *dir;
	uint32_t cpid;
	const TPROPVAL_ARRAY *pproperties;
} CREATE_FOLDER_BY_PROPERTIES_REQUEST;

typedef struct _DELETE_FOLDER_REQUEST {
	const char *dir;
	uint32_t cpid;
	uint64_t folder_id;
	BOOL b_hard;
} DELETE_FOLDER_REQUEST;

typedef struct _LOAD_HIERARCHY_TABLE_REQUEST {
	const char *dir;
	uint64_t folder_id;
	const char *username;
	uint8_t table_flags;
	const RESTRICTION *prestriction;
} LOAD_HIERARCHY_TABLE_REQUEST;

typedef struct _LOAD_PERMISSION_TABLE_REQUEST {
	const char *dir;
	uint64_t folder_id;
	uint8_t table_flags;
} LOAD_PERMISSION_TABLE_REQUEST;

typedef struct _UNLOAD_TABLE_REQUEST {
	const char *dir;
	uint32_t table_id;
} UNLOAD_TABLE_REQUEST;

typedef struct _QUERY_TABLE_REQUEST {
	const char *dir;
	const char *username;
	uint32_t cpid;
	uint32_t table_id;
	const PROPTAG_ARRAY *pproptags;
	uint32_t start_pos;
	int32_t row_needed;
} QUERY_TABLE_REQUEST;

typedef struct _ALLOCATE_ID_REQUEST {
	const char *dir;
} ALLOCATE_ID_REQUEST;

typedef struct _UPDATE_FOLDER_PERMISSION_REQUEST {
	const char *dir;
	uint64_t folder_id;
	BOOL b_freebusy;
	uint16_t count;
	const PERMISSION_DATA *prow;
} UPDATE_FOLDER_PERMISSION_REQUEST;

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

static int exmdb_client_push_create_folder_by_properties_request(
	EXT_PUSH *pext, const CREATE_FOLDER_BY_PROPERTIES_REQUEST *r)
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
	return ext_buffer_push_tpropval_array(pext, r->pproperties);
}

static int exmdb_client_push_delete_folder_request(
	EXT_PUSH *pext, const DELETE_FOLDER_REQUEST *r)
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
	status = ext_buffer_push_uint64(pext, r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext, r->b_hard);
}

static int exmdb_client_push_load_hierarchy_table_request(
	EXT_PUSH *pext, const LOAD_HIERARCHY_TABLE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_push_string(pext, r->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext, r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == r->username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext, r->username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint8(pext, r->table_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == r->prestriction) {
		return ext_buffer_push_uint8(pext, 0);
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_restriction(pext, r->prestriction);
	}
}

static int exmdb_client_push_load_permission_table_request(
	EXT_PUSH *pext, const LOAD_PERMISSION_TABLE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_push_string(pext, r->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext, r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint8(pext, r->table_flags);
}

static int exmdb_client_push_unload_table_request(
	EXT_PUSH *pext, const UNLOAD_TABLE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_push_string(pext, r->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext, r->table_id);
}

static int exmdb_client_push_query_table_request(
	EXT_PUSH *pext, const QUERY_TABLE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_push_string(pext, r->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == r->username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext, r->username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint32(pext, r->cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_proptag_array(pext, r->pproptags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->start_pos);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_int32(pext, r->row_needed);
}

static int exmdb_client_push_allocate_cn_request(
	EXT_PUSH *pext, const ALLOCATE_ID_REQUEST *r)
{
	return ext_buffer_push_string(pext, r->dir);
}

static int exmdb_client_push_update_folder_permission_request(
	EXT_PUSH *pext, const UPDATE_FOLDER_PERMISSION_REQUEST *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_string(pext, r->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext, r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext, r->b_freebusy);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_permission_data(pext, r->prow + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
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
	case CALL_ID_CREATE_FOLDER_BY_PROPERTIES:
		status = exmdb_client_push_create_folder_by_properties_request(
													&ext_push, prequest);
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case CALL_ID_DELETE_FOLDER:
		status = exmdb_client_push_delete_folder_request(
									&ext_push, prequest);
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case CALL_ID_LOAD_HIERARCHY_TABLE:
		status = exmdb_client_push_load_hierarchy_table_request(
											&ext_push, prequest);
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case CALL_ID_LOAD_PERMISSION_TABLE:
		status = exmdb_client_push_load_permission_table_request(
											&ext_push, prequest);
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case CALL_ID_UNLOAD_TABLE:
		status = exmdb_client_push_unload_table_request(
									&ext_push, prequest);
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case CALL_ID_QUERY_TABLE:
		status = exmdb_client_push_query_table_request(
									&ext_push, prequest);
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case CALL_ID_ALLOCATE_CN:
		status = exmdb_client_push_allocate_cn_request(
									&ext_push, prequest);
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case CALL_ID_UPDATE_FOLDER_PERMISSION:
		status = exmdb_client_push_update_folder_permission_request(
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
	int sockd;
	int process_id;
	BINARY tmp_bin;
	char remote_id[128];
	uint8_t response_code;
	CONNECT_REQUEST request;
	struct sockaddr_in servaddr;
	
    sockd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(pserver->port);
    inet_pton(AF_INET, pserver->ip_addr, &servaddr.sin_addr);
    if (0 != connect(sockd,
		(struct sockaddr*)&servaddr,
		sizeof(servaddr))) {
        close(sockd);
        return -1;
    }
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
		system_log_info("[exmdb_client]: fail to connect"
			" to %s:%d for prefix \"%s\", access denied.\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_MAX_REACHED:
		system_log_info("[exmdb_client]: fail to connect to %s:%d for"
			" prefix \"%s\",maximum connections reached in server!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_LACK_MEMORY:
		system_log_info("[exmdb_client]: fail to connect to "
			"%s:%d for prefix \"%s\", server out of memory!\n",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_MISCONFIG_PREFIX:
		system_log_info("[exmdb_client]: fail to connect to %s:%d "
			"for prefix \"%s\", server does not serve the prefix, "
			"configuation file of client or server may be incorrect!",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	case RESPONSE_CODE_MISCONFIG_MODE:
		system_log_info("[exmdb_client]: fail to connect to %s:%d for"
			" prefix \"%s\", work mode with the prefix in server is"
			"different from the mode in client, configuation file "
			"of client or server may be incorrect!",
			pserver->ip_addr, pserver->port, pserver->prefix);
		break;
	default:
		system_log_info("[exmdb_client]: fail to connect "
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

BOOL exmdb_client_create_folder_by_properties(
	int sockd, const char *dir, uint32_t cpid,
	const TPROPVAL_ARRAY *pproperties, uint64_t *pfolder_id)
{
	BINARY tmp_bin;
	CREATE_FOLDER_BY_PROPERTIES_REQUEST request;
	
	request.dir = dir;
	request.cpid = cpid;
	request.pproperties = pproperties;
	if (EXT_ERR_SUCCESS != exmdb_client_push_request(
		CALL_ID_CREATE_FOLDER_BY_PROPERTIES, &request, &tmp_bin)) {
		return FALSE;
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		return FALSE;
	}
	free(tmp_bin.pb);
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		return FALSE;
	}
	if (13 != tmp_bin.cb  || RESPONSE_CODE_SUCCESS != tmp_bin.pb[0]) {
		free(tmp_bin.pb);
		return FALSE;
	}
	*pfolder_id = BVAL(tmp_bin.pb, 5);
	free(tmp_bin.pb);
	return TRUE;
}

BOOL exmdb_client_delete_folder(const char *dir, uint32_t cpid,
	uint64_t folder_id, BOOL b_hard, BOOL *pb_result)
{
	int sockd;
	BINARY tmp_bin;
	DELETE_FOLDER_REQUEST request;
	
	request.dir = dir;
	request.cpid = cpid;
	request.folder_id = folder_id;
	request.b_hard = b_hard;
	if (EXT_ERR_SUCCESS != exmdb_client_push_request(
		CALL_ID_DELETE_FOLDER, &request, &tmp_bin)) {
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
	if (6 != tmp_bin.cb  || RESPONSE_CODE_SUCCESS != tmp_bin.pb[0]) {
		free(tmp_bin.pb);
		return FALSE;
	}
	if (0 == tmp_bin.pb[5]) {
		*pb_result = FALSE;
	} else {
		*pb_result = TRUE;
	}
	free(tmp_bin.pb);
	return TRUE;
}

static BOOL exmdb_client_load_hierarchy_table(int sockd,
	const char *dir, uint64_t folder_id, const char *username,
	uint8_t table_flags, const RESTRICTION *prestriction,
	uint32_t *ptable_id, uint32_t *prow_count)
{
	BINARY tmp_bin;
	LOAD_HIERARCHY_TABLE_REQUEST request;
	
	request.dir = dir;
	request.folder_id = folder_id;
	request.username = username;
	request.table_flags = table_flags;
	request.prestriction = prestriction;
	if (EXT_ERR_SUCCESS != exmdb_client_push_request(
		CALL_ID_LOAD_HIERARCHY_TABLE, &request, &tmp_bin)) {
		return FALSE;
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		return FALSE;
	}
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		return FALSE;
	}
	if (13 != tmp_bin.cb || RESPONSE_CODE_SUCCESS != tmp_bin.pb[0]) {
		free(tmp_bin.pb);
		return FALSE;
	}
	*ptable_id = IVAL(tmp_bin.pb, 5);
	*prow_count = IVAL(tmp_bin.pb, 9);
	free(tmp_bin.pb);
	return TRUE;
}

static BOOL exmdb_client_load_permission_table(int sockd,
	const char *dir, uint64_t folder_id, uint8_t table_flags,
	uint32_t *ptable_id, uint32_t *prow_count)
{
	BINARY tmp_bin;
	LOAD_HIERARCHY_TABLE_REQUEST request;
	
	request.dir = dir;
	request.folder_id = folder_id;
	request.table_flags = table_flags;
	if (EXT_ERR_SUCCESS != exmdb_client_push_request(
		CALL_ID_LOAD_PERMISSION_TABLE, &request, &tmp_bin)) {
		return FALSE;
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		return FALSE;
	}
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		return FALSE;
	}
	if (13 != tmp_bin.cb || RESPONSE_CODE_SUCCESS != tmp_bin.pb[0]) {
		free(tmp_bin.pb);
		return FALSE;
	}
	*ptable_id = IVAL(tmp_bin.pb, 5);
	*prow_count = IVAL(tmp_bin.pb, 9);
	free(tmp_bin.pb);
	return TRUE;
}

static BOOL exmdb_client_unload_table(int sockd,
	const char *dir, uint32_t table_id)
{
	BINARY tmp_bin;
	UNLOAD_TABLE_REQUEST request;
	
	request.dir = dir;
	request.table_id = table_id;
	if (EXT_ERR_SUCCESS != exmdb_client_push_request(
		CALL_ID_UNLOAD_TABLE, &request, &tmp_bin)) {
		return FALSE;
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		return FALSE;
	}
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		return FALSE;
	}
	if (5 != tmp_bin.cb || RESPONSE_CODE_SUCCESS != tmp_bin.pb[0]) {
		free(tmp_bin.pb);
		return FALSE;
	}
	free(tmp_bin.pb);
	return TRUE;
}

static BOOL exmdb_client_query_table(int sockd, const char *dir,
	const char *username, uint32_t cpid, uint32_t table_id,
	const PROPTAG_ARRAY *pproptags, uint32_t start_pos,
	int32_t row_needed, TARRAY_SET *pset)
{
	BINARY tmp_bin;
	EXT_PULL ext_pull;
	QUERY_TABLE_REQUEST request;
	
	request.dir = dir;
	request.username = username;
	request.cpid = cpid;
	request.table_id = table_id;
	request.pproptags = pproptags;
	request.start_pos = start_pos;
	request.row_needed = row_needed;
	if (EXT_ERR_SUCCESS != exmdb_client_push_request(
		CALL_ID_QUERY_TABLE, &request, &tmp_bin)) {
		return FALSE;	
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		return FALSE;
	}
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		return FALSE;
	}
	if (RESPONSE_CODE_SUCCESS != tmp_bin.pb[0]) {
		free(tmp_bin.pb);
		return FALSE;
	}
	ext_buffer_pull_init(&ext_pull, tmp_bin.pb + 5,
		tmp_bin.cb - 5, malloc, EXT_FLAG_WCOUNT);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_tarray_set(
		&ext_pull, pset)) {
		free(tmp_bin.pb);
		return FALSE;
	}
	free(tmp_bin.pb);
	return TRUE;
}

static BOOL exmdb_client_allocate_cn(int sockd, const char *dir, uint64_t *pcn)
{
	BINARY tmp_bin;
	ALLOCATE_ID_REQUEST request;
	
	request.dir = dir;
	if (EXT_ERR_SUCCESS != exmdb_client_push_request(
		CALL_ID_ALLOCATE_CN, &request, &tmp_bin)) {
		return FALSE;	
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		return FALSE;
	}
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		return FALSE;
	}
	if (13 != tmp_bin.cb || RESPONSE_CODE_SUCCESS != tmp_bin.pb[0]) {
		free(tmp_bin.pb);
		return FALSE;
	}
	*pcn = BVAL(tmp_bin.pb, 5);
	free(tmp_bin.pb);
	return TRUE;
}

static BOOL exmdb_client_update_folder_permission(int sockd,
	const char *dir, uint64_t folder_id, BOOL b_freebusy,
	uint16_t count, const PERMISSION_DATA *prow)
{
	BINARY tmp_bin;
	UPDATE_FOLDER_PERMISSION_REQUEST request;
	
	request.dir = dir;
	request.folder_id = folder_id;
	request.b_freebusy = b_freebusy;
	request.count = count;
	request.prow = prow;
	if (EXT_ERR_SUCCESS != exmdb_client_push_request(
		CALL_ID_UPDATE_FOLDER_PERMISSION, &request, &tmp_bin)) {
		return FALSE;	
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		return FALSE;
	}
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		return FALSE;
	}
	if (RESPONSE_CODE_SUCCESS != tmp_bin.pb[0]) {
		free(tmp_bin.pb);
		return FALSE;
	}
	free(tmp_bin.pb);
	return TRUE;
}

BOOL exmdb_client_create_folder(const char *dir, int domain_id,
	const char *folder_name, const char *container, const char *comment)
{
	PCL *ppcl;
	int sockd;
	BINARY *pbin;
	SIZED_XID xid;
	BINARY tmp_bin;
	uint32_t tmp_type;
	EXT_PUSH ext_push;
	uint64_t folder_id;
	uint64_t last_time;
	uint64_t parent_id;
	char tmp_buff[128];
	uint64_t change_num;
	TPROPVAL_ARRAY tmp_propvals;
	TAGGED_PROPVAL propval_buff[10];
	
	sockd = exmdb_client_get_connection(dir);
	if (-1 == sockd) {
		return FALSE;
	}
	if (FALSE == exmdb_client_allocate_cn(sockd, dir, &change_num)) {
		close(sockd);
		return FALSE;
	}
	tmp_type = FOLDER_TYPE_GENERIC;
	last_time = rop_util_unix_to_nttime(time(NULL));
	parent_id = rop_util_make_eid_ex(1, PUBLIC_FID_IPMSUBTREE);
	tmp_propvals.count = 9;
	tmp_propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PROP_TAG_PARENTFOLDERID;
	propval_buff[0].pvalue = &parent_id;
	propval_buff[1].proptag = PROP_TAG_FOLDERTYPE;
	propval_buff[1].pvalue = &tmp_type;
	propval_buff[2].proptag = PROP_TAG_DISPLAYNAME;
	propval_buff[2].pvalue = (void*)folder_name;
	propval_buff[3].proptag = PROP_TAG_COMMENT;
	propval_buff[3].pvalue = (void*)comment;
	propval_buff[4].proptag = PROP_TAG_CREATIONTIME;
	propval_buff[4].pvalue = &last_time;
	propval_buff[5].proptag = PROP_TAG_LASTMODIFICATIONTIME;
	propval_buff[5].pvalue = &last_time;
	propval_buff[6].proptag = PROP_TAG_CHANGENUMBER;
	propval_buff[6].pvalue = &change_num;
	xid.size = 22;
	xid.xid.guid = rop_util_make_domain_guid(domain_id);
	rop_util_value_to_gc(change_num, xid.xid.local_id);
	ext_buffer_push_init(&ext_push, tmp_buff, sizeof(tmp_buff), 0);
	ext_buffer_push_xid(&ext_push, 22, &xid.xid);
	tmp_bin.pb = tmp_buff;
	tmp_bin.cb = ext_push.offset;
	propval_buff[7].proptag = PROP_TAG_CHANGEKEY;
	propval_buff[7].pvalue = &tmp_bin;
	ppcl = pcl_init();
	if (NULL == ppcl) {
		close(sockd);
		return FALSE;
	}
	if (FALSE == pcl_append(ppcl, &xid)) {
		pcl_free(ppcl);
		close(sockd);
		return FALSE;
	}
	pbin = pcl_serialize(ppcl);
	if (NULL == pbin) {
		pcl_free(ppcl);
		close(sockd);
		return FALSE;
	}
	pcl_free(ppcl);
	propval_buff[8].proptag = PROP_TAG_PREDECESSORCHANGELIST;
	propval_buff[8].pvalue = pbin;
	if (NULL != container && '\0' != container[0]) {
		tmp_propvals.count ++;
		propval_buff[9].proptag = PROP_TAG_CONTAINERCLASS;
		propval_buff[9].pvalue = (void*)container;
	}
	if (FALSE == exmdb_client_create_folder_by_properties(
		sockd, dir, 0, &tmp_propvals, &folder_id)) {
		close(sockd);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	close(sockd);
	if (0 == folder_id) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_client_get_folder_list(const char *dir, TARRAY_SET *pset)
{
	int sockd;
	uint32_t table_id;
	uint32_t row_count;
	PROPTAG_ARRAY proptags;
	uint32_t proptag_buff[4];
	
	sockd = exmdb_client_get_connection(dir);
	if (-1 == sockd) {
		return FALSE;
	}
	if (FALSE == exmdb_client_load_hierarchy_table(sockd, dir,
		rop_util_make_eid_ex(1, PUBLIC_FID_IPMSUBTREE), NULL,
		0, NULL, &table_id, &row_count)) {
		close(sockd);
		return FALSE;	
	}
	proptags.count = 4;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_FOLDERID;
	proptag_buff[1] = PROP_TAG_DISPLAYNAME;
	proptag_buff[2] = PROP_TAG_COMMENT;
	proptag_buff[3] = PROP_TAG_CREATIONTIME;
	if (FALSE == exmdb_client_query_table(sockd, dir,
		NULL, 0, table_id, &proptags, 0, row_count, pset)) {
		close(sockd);
		return FALSE;
	}
	exmdb_client_unload_table(sockd, dir, table_id);
	close(sockd);
	return TRUE;
}

BOOL exmdb_client_get_permission_list(const char *dir,
	uint64_t folder_id, TARRAY_SET *pset)
{
	int sockd;
	uint32_t table_id;
	uint32_t row_count;
	PROPTAG_ARRAY proptags;
	uint32_t proptag_buff[3];
	
	sockd = exmdb_client_get_connection(dir);
	if (-1 == sockd) {
		return FALSE;
	}
	if (FALSE == exmdb_client_load_permission_table(
		sockd, dir, folder_id, 0, &table_id, &row_count)) {
		close(sockd);
		return FALSE;
	}
	proptags.count = 3;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_MEMBERID;
	proptag_buff[1] = PROP_TAG_MEMBERNAME;
	proptag_buff[2] = PROP_TAG_MEMBERRIGHTS;
	if (FALSE == exmdb_client_query_table(sockd, dir,
		NULL, 0, table_id, &proptags, 0, row_count, pset)) {
		close(sockd);
		return FALSE;
	}
	exmdb_client_unload_table(sockd, dir, table_id);
	close(sockd);
	return TRUE;
}

BOOL exmdb_client_add_folder_owner(const char *dir,
	uint64_t folder_id, const char *username)
{
	int sockd;
	uint32_t member_rights;
	TAGGED_PROPVAL propval_buff[2];
	PERMISSION_DATA permission_data;
	
	permission_data.flags = PERMISSION_DATA_FLAG_ADD_ROW;
	permission_data.propvals.count = 2;
	permission_data.propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PROP_TAG_SMTPADDRESS;
	propval_buff[0].pvalue = (void*)username;
	propval_buff[1].proptag = PROP_TAG_MEMBERRIGHTS;
	propval_buff[1].pvalue = &member_rights;
	member_rights = PERMISSION_READANY |PERMISSION_CREATE
			| PERMISSION_EDITANY | PERMISSION_DELETEANY
			| PERMISSION_CREATESUBFOLDER | PERMISSION_FOLDEROWNER
			| PERMISSION_FOLDERCONTACT| PERMISSION_FOLDERVISIBLE;
	sockd = exmdb_client_get_connection(dir);
	if (-1 == sockd) {
		return FALSE;
	}
	if (FALSE == exmdb_client_update_folder_permission(
		sockd, dir, folder_id, FALSE, 1, &permission_data)) {
		close(sockd);
		return FALSE;
	}
	close(sockd);
	return TRUE;
}

BOOL exmdb_client_remove_folder_owner(const char *dir,
	uint64_t folder_id, uint64_t member_id)
{
	int sockd;
	TAGGED_PROPVAL propval_buff;
	PERMISSION_DATA permission_data;
	
	permission_data.flags = PERMISSION_DATA_FLAG_REMOVE_ROW;
	permission_data.propvals.count = 1;
	permission_data.propvals.ppropval = &propval_buff;
	propval_buff.proptag = PROP_TAG_MEMBERID;
	propval_buff.pvalue = &member_id;
	sockd = exmdb_client_get_connection(dir);
	if (-1 == sockd) {
		return FALSE;
	}
	if (FALSE == exmdb_client_update_folder_permission(
		sockd, dir, folder_id, FALSE, 1, &permission_data)) {
		close(sockd);
		return FALSE;
	}
	close(sockd);
	return TRUE;
}
