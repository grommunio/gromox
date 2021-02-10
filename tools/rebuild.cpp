// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <libHX/defs.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/database.h>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/paths.h>
#include <gromox/socket.h>
#include <gromox/list_file.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/double_list.hpp>
#include <cstdio>
#include <fcntl.h>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#define SOCKET_TIMEOUT								60

struct EXMDB_ITEM {
	char prefix[256];
	char type[16];
	char ip_addr[32];
	int port;
};

struct EXMDB_NODE {
	DOUBLE_LIST_NODE node;
	EXMDB_ITEM exmdb_info;
};

struct CONNECT_REQUEST {
	char *prefix;
	char *remote_id;
	BOOL b_private;
};

struct UNLOAD_STORE_REQUEST {
	const char *dir;
};

static DOUBLE_LIST g_exmdb_list;
static char *opt_datadir;
static const struct HXoption g_options_table[] = {
	{nullptr, 'd', HXTYPE_STRING, &opt_datadir, nullptr, nullptr, 0, "Data directory", "DIR"},
	HXOPT_TABLEEND,
};

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
	case exmdb_callid::CONNECT:
		status = exmdb_client_push_connect_request(&ext_push, static_cast<CONNECT_REQUEST *>(prequest));
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case exmdb_callid::UNLOAD_STORE:
		status = exmdb_client_push_unload_store_request(&ext_push, static_cast<UNLOAD_STORE_REQUEST *>(prequest));
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
				pbin->pb = NULL;
			}
			return FALSE;
		}
		if (0 == pbin->cb) {
			read_len = read(sockd, resp_buff, 5);
			if (1 == read_len) {
				pbin->cb = 1;
				pbin->pv = malloc(1);
				if (pbin->pv == nullptr)
					return FALSE;
				*(uint8_t*)pbin->pb = resp_buff[0];
				return TRUE;
			} else if (5 == read_len) {
				pbin->cb = *(uint32_t*)(resp_buff + 1) + 5;
				pbin->pv = malloc(pbin->cb);
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
		read_len = read(sockd,
			pbin->pb + offset,
			pbin->cb - offset);
		if (read_len <= 0) {
			free(pbin->pb);
			pbin->pb = NULL;
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

static int connect_exmdb(const char *dir)
{
	int prefix_len;
	int process_id;
	BINARY tmp_bin;
	EXMDB_NODE *pexnode;
	char remote_id[128];
	char tmp_buff[1024];
	uint8_t response_code;
	CONNECT_REQUEST request;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&g_exmdb_list); NULL!=pnode;
		pnode=double_list_get_after(&g_exmdb_list, pnode)) {
		pexnode = (EXMDB_NODE*)pnode->pdata;
		prefix_len = strlen(pexnode->exmdb_info.prefix);
		if (0 == strncmp(pexnode->exmdb_info.prefix, dir, prefix_len)) {
			break;
		}
	}
	if (NULL == pnode) {
		return -1;
	}
	int sockd = gx_inet_connect(pexnode->exmdb_info.ip_addr, pexnode->exmdb_info.port, 0);
	if (sockd < 0)
	        return -1;
	process_id = getpid();
	sprintf(remote_id, "freebusy:%d", process_id);
	request.prefix = pexnode->exmdb_info.prefix;
	request.remote_id = remote_id;
	request.b_private = TRUE;
	if (exmdb_client_push_request(exmdb_callid::CONNECT, &request,
	    &tmp_bin) != EXT_ERR_SUCCESS) {
		close(sockd);
		return -1;
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		close(sockd);
		return -1;
	}
	tmp_bin.pv = tmp_buff;
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		close(sockd);
		return -1;
	}
	response_code = tmp_bin.pb[0];
	if (response_code == exmdb_response::SUCCESS) {
		if (5 != tmp_bin.cb || 0 != *(uint32_t*)(tmp_bin.pb + 1)) {
			fprintf(stderr, "response format error when connect to "
				"%s:%d for prefix \"%s\"\n", pexnode->exmdb_info.ip_addr,
				pexnode->exmdb_info.port, pexnode->exmdb_info.prefix);
			close(sockd);
			return -1;
		}
		return sockd;
	}
	switch (response_code) {
	case exmdb_response::ACCESS_DENY:
		fprintf(stderr, "Failed to connect to %s:%d for prefix "
			"\"%s\", access denied.\n", pexnode->exmdb_info.ip_addr,
			pexnode->exmdb_info.port, pexnode->exmdb_info.prefix);
		break;
	case exmdb_response::MAX_REACHED:
		fprintf(stderr, "Failed to connect to %s:%d for prefix"
			" \"%s\",maximum connections reached in server!\n",
			pexnode->exmdb_info.ip_addr, pexnode->exmdb_info.port,
			pexnode->exmdb_info.prefix);
		break;
	case exmdb_response::LACK_MEMORY:
		fprintf(stderr, "Failed to connect to %s:%d for prefix \"%s\","
			"server out of memory!\n", pexnode->exmdb_info.ip_addr,
			pexnode->exmdb_info.port, pexnode->exmdb_info.prefix);
		break;
	case exmdb_response::MISCONFIG_PREFIX:
		fprintf(stderr, "Failed to connect to %s:%d for prefix \"%s\","
			"server does not serve the prefix, configuation file of "
			"client or server may be incorrect!", pexnode->exmdb_info.ip_addr,
			pexnode->exmdb_info.port, pexnode->exmdb_info.prefix);
		break;
	case exmdb_response::MISCONFIG_MODE:
		fprintf(stderr, "Failed to connect to %s:%d for prefix \"%s\","
			" work mode with the prefix in server is different from "
			"the mode in client, configuation file of client or server"
			" may be incorrect!", pexnode->exmdb_info.ip_addr,
			pexnode->exmdb_info.port, pexnode->exmdb_info.prefix);
		break;
	default:
		fprintf(stderr, "Failed to connect to %s:%d for prefix "
			"\"%s\", error code %d!\n", pexnode->exmdb_info.ip_addr,
			pexnode->exmdb_info.port, pexnode->exmdb_info.prefix,
			(int)response_code);
		break;
	}
	close(sockd);
	return -1;
}

static BOOL exmdb_client_unload_store(const char *dir)
{
	int sockd;
	BINARY tmp_bin;
	UNLOAD_STORE_REQUEST request;
	
	request.dir = dir;
	if (exmdb_client_push_request(exmdb_callid::UNLOAD_STORE,
	    &request, &tmp_bin) != EXT_ERR_SUCCESS)
		return FALSE;
	sockd = connect_exmdb(dir);
	if (-1 == sockd) {
		return FALSE;
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		close(sockd);
		return FALSE;
	}
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		close(sockd);
		return FALSE;
	}
	if (tmp_bin.cb != 5 || tmp_bin.pb[0] != exmdb_response::SUCCESS) {
		close(sockd);
		return FALSE;
	}
	close(sockd);
	return TRUE;
}

int main(int argc, const char **argv)
{
	int i, fd;
	char *err_msg;
	sqlite3 *psqlite;
	char tmp_sql[1024];
	EXMDB_NODE *pexnode;
	const char *presult;
	sqlite3_stmt *pstmt;
	char temp_path[256];
	char temp_path1[256];
	struct stat node_stat;
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (2 != argc) {
		printf("usage: %s <maildir>\n", argv[0]);
		return 1;
	}
	snprintf(temp_path, 256, "%s/exmdb/exchange.sqlite3", argv[1]);
	if (0 != stat(temp_path, &node_stat)) {
		printf("can not find sotre database,"
			" %s does not exit\n", temp_path);
		return 1;
	}

	const char *datadir = opt_datadir != nullptr ? opt_datadir : PKGDATADIR;
	char common_tpl[256], priv_tpl[256];
	snprintf(common_tpl, GX_ARRAY_SIZE(common_tpl), "%s/sqlite3_common.txt", datadir);
	snprintf(priv_tpl, GX_ARRAY_SIZE(priv_tpl), "%s/sqlite3_private.txt", datadir);
	fd = open(common_tpl, O_RDONLY);
	if (fd < 0) {
		printf("Failed to open \"%s\": %s\n", common_tpl, strerror(errno));
		return 7;
	}
	size_t str_size = fstat(fd, &node_stat) ? node_stat.st_size : 0;
	auto sql_string = static_cast<char *>(malloc(str_size));
	if (read(fd, sql_string, str_size) != str_size) {
		printf("read %s: %s\n", common_tpl, strerror(errno));
		close(fd);
		free(sql_string);
		return 7;
	}
	close(fd);
	fd = open(priv_tpl, O_RDONLY);
	if (fd < 0) {
		printf("Failed to open \"%s\": %s\n", priv_tpl, strerror(errno));
		return 7;
	}
	size_t str_size1 = fstat(fd, &node_stat) ? node_stat.st_size : 0;
	auto sql_string1 = static_cast<char *>(realloc(sql_string, str_size + str_size1 + 1));
	if (sql_string1 == nullptr) {
		printf("%s\n", strerror(errno));
		close(fd);
		return 7;
	}
	sql_string = sql_string1;
	if (read(fd, sql_string + str_size, str_size1) != str_size1) {
		printf("read %s: %s\n", priv_tpl, strerror(errno));
		close(fd);
		free(sql_string);
		return 7;
	}
	sql_string[str_size + str_size1] = '\0';
	if (SQLITE_OK != sqlite3_initialize()) {
		printf("Failed to initialize sqlite engine\n");
		free(sql_string);
		return 8;
	}
	snprintf(temp_path1, 256, "%s/exmdb/new.sqlite3", argv[1]);
	remove(temp_path1);
	if (SQLITE_OK != sqlite3_open_v2(temp_path1, &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		printf("fail to create store database\n");
		free(sql_string);
		sqlite3_shutdown();
		return 9;
	}
	chmod(temp_path1, 0666);
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table creation sql, error: %s\n", err_msg);
		free(sql_string);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	free(sql_string);
	/* commit the transaction */
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	snprintf(tmp_sql, 1024, "ATTACH DATABASE "
		"'%s/exmdb/exchange.sqlite3' AS source_db", argv[1]);
	if (SQLITE_OK != sqlite3_exec(psqlite,
		tmp_sql, NULL, NULL, &err_msg)) {
		printf("fail to execute attach database sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	const char *csql_string = "INSERT INTO configurations "
		"SELECT * FROM source_db.configurations";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO allocated_eids "
		"SELECT * FROM source_db.allocated_eids";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO named_properties "
		"SELECT * FROM source_db.named_properties";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO store_properties "
		"SELECT * FROM source_db.store_properties";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO permissions "
		"SELECT * FROM source_db.permissions";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO rules "
		"SELECT * FROM source_db.rules";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO folders "
		"SELECT * FROM source_db.folders";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO folder_properties "
		"SELECT * FROM source_db.folder_properties";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO receive_table "
		"SELECT * FROM source_db.receive_table";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO messages "
		"SELECT * FROM source_db.messages";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO message_properties "
		"SELECT * FROM source_db.message_properties";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO message_changes "
		"SELECT * FROM source_db.message_changes";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO recipients "
		"SELECT * FROM source_db.recipients";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO recipients_properties "
		"SELECT * FROM source_db.recipients_properties";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO attachments "
		"SELECT * FROM source_db.attachments";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO attachment_properties "
		"SELECT * FROM source_db.attachment_properties";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO search_scopes "
		"SELECT * FROM source_db.search_scopes";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "INSERT INTO search_result "
		"SELECT * FROM source_db.search_result";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	/* commit the transaction */
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	sqlite3_exec(psqlite, "DETACH DATABASE source_db", NULL, NULL, NULL);
	csql_string = "REINDEX";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute reindex sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	csql_string = "PRAGMA integrity_check";
	if (!gx_sql_prep(psqlite, csql_string, &pstmt)) {
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			presult = reinterpret_cast<const char *>(sqlite3_column_text(pstmt, 0));
			if (NULL == presult || 0 != strcmp(presult, "ok")) {
				printf("new database is still "
					"malformed, can not be fixed!\n");
				return 10;
			}
		}
		sqlite3_finalize(pstmt);
	}
	sqlite3_close(psqlite);
	sqlite3_shutdown();
	
	double_list_init(&g_exmdb_list);
	auto plist = list_file_init(PKGDATASADIR "/exmdb_list.txt", /* EXMDB_ITEM */ "%s:256%s:16%s:32%d", false);
	if (NULL == plist) {
		printf("Failed to read exmdb list from %s: %s\n",
			PKGDATASADIR "/exmdb_list.txt", strerror(errno));
		return 11;
	}
	auto list_num = plist->get_size();
	auto pitem = static_cast<EXMDB_ITEM *>(plist->get_list());
	for (i=0; i<list_num; i++) {
		if (0 != strcasecmp(pitem[i].type, "private")) {
			continue;
		}
		pexnode = static_cast<EXMDB_NODE *>(malloc(sizeof(EXMDB_NODE)));
		if (NULL == pexnode) {
			continue;
		}
		pexnode->node.pdata = pexnode;
		memcpy(&pexnode->exmdb_info, pitem + i, sizeof(EXMDB_ITEM));
		double_list_append_as_tail(&g_exmdb_list, &pexnode->node);
	}
	if (FALSE == exmdb_client_unload_store(argv[1])) {
		printf("fail to unload store\n");
		return 12;
	}
	remove(temp_path);
	link(temp_path1, temp_path);
	remove(temp_path1);
	exit(0);
}
