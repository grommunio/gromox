// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <libHX/io.h>
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
static constexpr HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{nullptr, 'd', HXTYPE_STRING, &opt_datadir, nullptr, nullptr, 0, "Data directory", "DIR"},
	HXOPT_TABLEEND,
};

static int cl_rd_sock(int fd, BINARY *b) { return ::exmdb_client_read_socket(fd, b, SOCKET_TIMEOUT * 1000); }

static int exmdb_client_push_connect_request(
	EXT_PUSH *pext, const CONNECT_REQUEST *r)
{
	auto status = pext->p_str(r->prefix);
	if (status != EXT_ERR_SUCCESS)
		return status;
	status = pext->p_str(r->remote_id);
	if (status != EXT_ERR_SUCCESS)
		return status;
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
	if (status != EXT_ERR_SUCCESS)
		return status;
	status = ext_push.p_uint8(call_id);
	if (status != EXT_ERR_SUCCESS)
		return status;
	switch (call_id) {
	case exmdb_callid::CONNECT:
		status = exmdb_client_push_connect_request(&ext_push, static_cast<CONNECT_REQUEST *>(prequest));
		if (status != EXT_ERR_SUCCESS)
			return status;
		break;
	case exmdb_callid::UNLOAD_STORE:
		status = exmdb_client_push_unload_store_request(&ext_push, static_cast<UNLOAD_STORE_REQUEST *>(prequest));
		if (status != EXT_ERR_SUCCESS)
			return status;
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
	if (!exmdb_client_write_socket(sockd, &tmp_bin)) {
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
	if (sockd < 0)
		return FALSE;
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
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_fd(fileno(filp.get()), &slurp_len));
	std::string sql_string;
	if (slurp_data != nullptr)
		sql_string.append(slurp_data.get(), slurp_len);
	filp = fopen_sd("sqlite3_private.txt", datadir);
	if (filp == nullptr) {
		fprintf(stderr, "fopen_sd sqlite3_private.txt: %s\n", strerror(errno));
		return 7;
	}
	slurp_data.reset(HX_slurp_fd(fileno(filp.get()), &slurp_len));
	if (slurp_data != nullptr)
		sql_string.append(slurp_data.get(), slurp_len);
	slurp_data.reset();
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
	auto transact1 = gx_sql_begin_trans(psqlite);
	if (gx_sql_exec(psqlite, sql_string.c_str()) != SQLITE_OK)
		return 9;
	transact1.commit();
	snprintf(tmp_sql, 1024, "ATTACH DATABASE "
		"'%s/exmdb/exchange.sqlite3' AS source_db", argv[1]);
	if (gx_sql_exec(psqlite, tmp_sql) != SQLITE_OK)
		return 9;
	
	auto sql_transact = gx_sql_begin_trans(psqlite);
	static constexpr const char *statements[] = {
		"INSERT INTO configurations SELECT * FROM source_db.configurations",
		"INSERT INTO allocated_eids SELECT * FROM source_db.allocated_eids",
		"INSERT INTO named_properties SELECT * FROM source_db.named_properties",
		"INSERT INTO store_properties SELECT * FROM source_db.store_properties",
		"INSERT INTO permissions SELECT * FROM source_db.permissions",
		"INSERT INTO rules SELECT * FROM source_db.rules",
		"INSERT INTO folders SELECT * FROM source_db.folders",
		"INSERT INTO folder_properties SELECT * FROM source_db.folder_properties",
		"INSERT INTO receive_table SELECT * FROM source_db.receive_table",
		"INSERT INTO messages SELECT * FROM source_db.messages",
		"INSERT INTO message_properties SELECT * FROM source_db.message_properties",
		"INSERT INTO message_changes SELECT * FROM source_db.message_changes",
		"INSERT INTO recipients SELECT * FROM source_db.recipients",
		"INSERT INTO recipients_properties SELECT * FROM source_db.recipients_properties",
		"INSERT INTO attachments SELECT * FROM source_db.attachments",
		"INSERT INTO attachment_properties SELECT * FROM source_db.attachment_properties",
		"INSERT INTO search_scopes SELECT * FROM source_db.search_scopes",
		"INSERT INTO search_result SELECT * FROM source_db.search_result",
	};
	for (auto q : statements)
		if (gx_sql_exec(psqlite, q) != SQLITE_OK)
			return 9;
	sql_transact.commit();
	sqlite3_exec(psqlite, "DETACH DATABASE source_db", NULL, NULL, NULL);
	if (gx_sql_exec(psqlite, "REINDEX") != SQLITE_OK)
		return 9;
	auto pstmt = gx_sql_prep(psqlite, "PRAGMA integrity_check");
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
#if __cplusplus >= 202000L
	std::erase_if(g_exmdb_list,
		[&](const EXMDB_ITEM &s) { return s.type != EXMDB_ITEM::EXMDB_PRIVATE; });
#else
	g_exmdb_list.erase(std::remove_if(g_exmdb_list.begin(), g_exmdb_list.end(),
		[&](const EXMDB_ITEM &s) { return s.type != EXMDB_ITEM::EXMDB_PRIVATE; }),
		g_exmdb_list.end());
#endif
	if (!exmdb_client_unload_store(argv[1])) {
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
