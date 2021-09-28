// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <utility>
#include <vector>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/database.h>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/socket.h>
#include <gromox/list_file.hpp>
#include <gromox/ext_buffer.hpp>
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
#include "mkshared.hpp"
#define SOCKET_TIMEOUT								60

using namespace gromox;

namespace {

struct CONNECT_REQUEST {
	char *prefix;
	char *remote_id;
	BOOL b_private;
};

struct UNLOAD_STORE_REQUEST {
	const char *dir;
};

}

static std::vector<EXMDB_ITEM> g_exmdb_list;
static char *opt_config_file, *opt_datadir;
static const struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{nullptr, 'd', HXTYPE_STRING, &opt_datadir, nullptr, nullptr, 0, "Data directory", "DIR"},
	HXOPT_TABLEEND,
};

static int cl_rd_sock(int fd, BINARY *b) { return ::exmdb_client_read_socket(fd, b, SOCKET_TIMEOUT * 1000); }

static int exmdb_client_push_connect_request(
	EXT_PUSH *pext, const CONNECT_REQUEST *r)
{
	auto status = pext->p_str(r->prefix);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = pext->p_str(r->remote_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return pext->p_bool(r->b_private);
}

static int exmdb_client_push_unload_store_request(
	EXT_PUSH *pext, const UNLOAD_STORE_REQUEST *r)
{
	return pext->p_str(r->dir);
}

static int exmdb_client_push_request(uint8_t call_id,
	void *prequest, BINARY *pbin_out)
{
	int status;
	EXT_PUSH ext_push;
	
	if (!ext_push.init(nullptr, 0, EXT_FLAG_WCOUNT))
		return EXT_ERR_ALLOC;
	status = ext_push.advance(sizeof(uint32_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_push.p_uint8(call_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch (call_id) {
	case exmdb_callid::CONNECT:
		status = exmdb_client_push_connect_request(&ext_push, static_cast<CONNECT_REQUEST *>(prequest));
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case exmdb_callid::UNLOAD_STORE:
		status = exmdb_client_push_unload_store_request(&ext_push, static_cast<UNLOAD_STORE_REQUEST *>(prequest));
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		break;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
	pbin_out->cb = ext_push.m_offset;
	ext_push.m_offset = 0;
	status = ext_push.p_uint32(pbin_out->cb - sizeof(uint32_t));
	if (status != EXT_ERR_SUCCESS)
		return status;
	/* memory referenced by ext_push.data will be freed outside */
	pbin_out->pb = ext_push.release();
	return EXT_ERR_SUCCESS;
}

static int connect_exmdb(const char *dir)
{
	int process_id;
	BINARY tmp_bin;
	char remote_id[128];
	uint8_t response_code;
	CONNECT_REQUEST request;
	
	auto pexnode = std::find_if(g_exmdb_list.cbegin(), g_exmdb_list.cend(),
	               [&](const EXMDB_ITEM &s) { return strncmp(s.prefix.c_str(), dir, s.prefix.size()) == 0; });
	if (pexnode == g_exmdb_list.cend())
		return -1;
	int sockd = gx_inet_connect(pexnode->host.c_str(), pexnode->port, 0);
	if (sockd < 0) {
		fprintf(stderr, "gx_inet_connect rebuild@[%s]:%hu: %s\n",
		        pexnode->host.c_str(), pexnode->port, strerror(-sockd));
	        return -1;
	}
	process_id = getpid();
	sprintf(remote_id, "freebusy:%d", process_id);
	request.prefix    = deconst(pexnode->prefix.c_str());
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
	if (!cl_rd_sock(sockd, &tmp_bin)) {
		close(sockd);
		return -1;
	}
	response_code = tmp_bin.pb[0];
	if (response_code == exmdb_response::SUCCESS) {
		if (tmp_bin.cb != 5) {
			fprintf(stderr, "response format error during connect to "
				"[%s]:%hu/%s\n", pexnode->host.c_str(),
				pexnode->port, pexnode->prefix.c_str());
			close(sockd);
			return -1;
		}
		return sockd;
	}
	fprintf(stderr, "Failed to connect to [%s]:%hu/%s: %s\n",
	        pexnode->host.c_str(), pexnode->port, pexnode->prefix.c_str(),
	        exmdb_rpc_strerror(response_code));
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
	if (!exmdb_client_write_socket(sockd, &tmp_bin) ||
	    !cl_rd_sock(sockd, &tmp_bin) ||
	    tmp_bin.cb != 5 || tmp_bin.pb[0] != exmdb_response::SUCCESS) {
		close(sockd);
		return FALSE;
	}
	close(sockd);
	return TRUE;
}

int main(int argc, const char **argv)
{
	char *err_msg;
	sqlite3 *psqlite;
	char tmp_sql[1024];
	const char *presult;
	char temp_path[256];
	char temp_path1[256];
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (2 != argc) {
		printf("usage: %s <maildir>\n", argv[0]);
		return 1;
	}
	auto pconfig = config_file_prg(opt_config_file, "sa.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return 2;
	snprintf(temp_path, 256, "%s/exmdb/exchange.sqlite3", argv[1]);
	if (access(temp_path, R_OK) < 0) {
		printf("%s: %s\n", temp_path, strerror(errno));
		return 1;
	}

	const char *datadir = opt_datadir != nullptr ? opt_datadir :
	                      pconfig->get_value("data_file_path");
	if (datadir == nullptr)
		datadir = PKGDATADIR;

	auto filp = fopen_sd("sqlite3_common.txt", datadir);
	if (filp == nullptr) {
		fprintf(stderr, "fopen_sd sqlite3_common.txt: %s\n", strerror(errno));
		return 7;
	}
	auto sql_string = slurp_file(filp.get());
	filp = fopen_sd("sqlite3_private.txt", datadir);
	if (filp == nullptr) {
		fprintf(stderr, "fopen_sd sqlite3_private.txt: %s\n", strerror(errno));
		return 7;
	}
	sql_string += slurp_file(filp.get());
	filp.reset();
	if (SQLITE_OK != sqlite3_initialize()) {
		printf("Failed to initialize sqlite engine\n");
		return 8;
	}
	{
	auto cl_0 = make_scope_exit([]() { sqlite3_shutdown(); });
	snprintf(temp_path1, 256, "%s/exmdb/new.sqlite3", argv[1]);
	if (remove(temp_path1) < 0 && errno != ENOENT)
		fprintf(stderr, "W-1393: remove %s: %s\n", temp_path1, strerror(errno));
	if (SQLITE_OK != sqlite3_open_v2(temp_path1, &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		printf("fail to create store database\n");
		return 9;
	}
	auto cl_1 = make_scope_exit([&]() { sqlite3_close(psqlite); });
	adjust_rights(temp_path1);
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (sqlite3_exec(psqlite, sql_string.c_str(), nullptr, nullptr,
	    &err_msg) != SQLITE_OK) {
		printf("fail to execute table creation sql, error: %s\n", err_msg);
		return 9;
	}
	/* commit the transaction */
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	snprintf(tmp_sql, 1024, "ATTACH DATABASE "
		"'%s/exmdb/exchange.sqlite3' AS source_db", argv[1]);
	if (SQLITE_OK != sqlite3_exec(psqlite,
		tmp_sql, NULL, NULL, &err_msg)) {
		printf("fail to execute attach database sql, error: %s\n", err_msg);
		return 9;
	}
	
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	const char *csql_string = "INSERT INTO configurations "
		"SELECT * FROM source_db.configurations";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO allocated_eids "
		"SELECT * FROM source_db.allocated_eids";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO named_properties "
		"SELECT * FROM source_db.named_properties";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO store_properties "
		"SELECT * FROM source_db.store_properties";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO permissions "
		"SELECT * FROM source_db.permissions";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO rules "
		"SELECT * FROM source_db.rules";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO folders "
		"SELECT * FROM source_db.folders";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO folder_properties "
		"SELECT * FROM source_db.folder_properties";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO receive_table "
		"SELECT * FROM source_db.receive_table";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO messages "
		"SELECT * FROM source_db.messages";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO message_properties "
		"SELECT * FROM source_db.message_properties";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO message_changes "
		"SELECT * FROM source_db.message_changes";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO recipients "
		"SELECT * FROM source_db.recipients";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO recipients_properties "
		"SELECT * FROM source_db.recipients_properties";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO attachments "
		"SELECT * FROM source_db.attachments";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO attachment_properties "
		"SELECT * FROM source_db.attachment_properties";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO search_scopes "
		"SELECT * FROM source_db.search_scopes";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "INSERT INTO search_result "
		"SELECT * FROM source_db.search_result";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table copy sql, error: %s\n", err_msg);
		return 9;
	}
	/* commit the transaction */
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	sqlite3_exec(psqlite, "DETACH DATABASE source_db", NULL, NULL, NULL);
	csql_string = "REINDEX";
	if (SQLITE_OK != sqlite3_exec(psqlite,
		csql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute reindex sql, error: %s\n", err_msg);
		return 9;
	}
	csql_string = "PRAGMA integrity_check";
	auto pstmt = gx_sql_prep(psqlite, csql_string);
	if (pstmt == nullptr) {
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			presult = reinterpret_cast<const char *>(sqlite3_column_text(pstmt, 0));
			if (NULL == presult || 0 != strcmp(presult, "ok")) {
				printf("new database is still "
					"malformed, can not be fixed!\n");
				return 10;
			}
		}
		pstmt.finalize();
	}
	}
	
	auto ret = list_file_read_exmdb("exmdb_list.txt", PKGSYSCONFDIR, g_exmdb_list);
	if (ret < 0) {
		fprintf(stderr, "list_file_read_exmdb: %s\n", strerror(-ret));
		return 11;
	}
	g_exmdb_list.erase(std::remove_if(g_exmdb_list.begin(), g_exmdb_list.end(),
		[&](const EXMDB_ITEM &s) { return s.type != EXMDB_ITEM::EXMDB_PRIVATE; }),
		g_exmdb_list.end());
	if (FALSE == exmdb_client_unload_store(argv[1])) {
		printf("fail to unload store\n");
		return 12;
	}
	if (remove(temp_path) < 0 && errno != ENOENT)
		fprintf(stderr, "W-1394: remove %s: %s\n", temp_path, strerror(errno));
	if (link(temp_path1, temp_path) < 0)
		fprintf(stderr, "W-1395: link %s %s: %s\n", temp_path1, temp_path, strerror(errno));
	if (remove(temp_path1) < 0 && errno != ENOENT)
		fprintf(stderr, "W-1396: remove %s: %s\n", temp_path1, strerror(errno));
	exit(0);
}
