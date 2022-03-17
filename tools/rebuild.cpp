// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <sqlite3.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/config_file.hpp>
#include <gromox/database.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/socket.h>
#include "mkshared.hpp"

using namespace gromox;
namespace exmdb_client = exmdb_client_remote;

static char *opt_config_file, *opt_datadir;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{nullptr, 'd', HXTYPE_STRING, &opt_datadir, nullptr, nullptr, 0, "Data directory", "DIR"},
	HXOPT_TABLEEND,
};

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
	gx_sql_exec(psqlite, "DETACH DATABASE source_db");
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
	
	exmdb_client_init(1, 0);
	auto cl_0 = make_scope_exit(exmdb_client_stop);
	auto ret = exmdb_client_run(PKGSYSCONFDIR, EXMDB_CLIENT_SKIP_PUBLIC);
	if (ret < 0)
		return EXIT_FAILURE;
	if (!exmdb_client::unload_store(argv[1])) {
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
