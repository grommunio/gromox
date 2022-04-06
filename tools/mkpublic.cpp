// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <memory>
#include <mysql.h>
#include <optional>
#include <sqlite3.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <libHX/option.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/config_file.hpp>
#include <gromox/database.h>
#include <gromox/dbop.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/paths.h>
#include <gromox/pcl.hpp>
#include <gromox/proptags.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include "mkshared.hpp"
#include "exch/mysql_adaptor/mysql_adaptor.h"

using namespace std::string_literals;
using namespace gromox;

static char *opt_config_file, *opt_datadir;
static unsigned int opt_force, opt_create_old, opt_upgrade, opt_verbose;

static constexpr HXoption g_options_table[] = {
	{nullptr, 'T', HXTYPE_STRING, &opt_datadir, nullptr, nullptr, 0, "Directory with templates (default: " PKGDATADIR ")", "DIR"},
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{nullptr, 'f', HXTYPE_NONE, &opt_force, nullptr, nullptr, 0, "Allow overwriting exchange.sqlite3"},
	{nullptr, 'U', HXTYPE_NONE, &opt_upgrade, nullptr, nullptr, 0, "Perform schema upgrade"},
	{nullptr, 'v', HXTYPE_NONE, &opt_verbose, nullptr, nullptr, 0, "Bump verbosity"},
	{"create-old", 0, HXTYPE_NONE, &opt_create_old, nullptr, nullptr, 0, "Create SQLite database tables version 0"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr cfg_directive mkpublic_cfg_defaults[] = {
	{"mysql_dbname", "email"},
	{"mysql_host", "localhost"},
	{"mysql_port", "3306"},
	{"mysql_username", "root"},
	CFG_TABLE_END,
};

int main(int argc, const char **argv) try
{
	MYSQL_ROW myrow;
	uint64_t nt_time;
	sqlite3 *psqlite;
	MYSQL_RES *pmyres;
	char mysql_string[1024];
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (2 != argc) {
		printf("usage: %s <domainname>\n", argv[0]);
		return EXIT_FAILURE;
	}
	auto pconfig = config_file_prg(opt_config_file, "mysql_adaptor.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return EXIT_FAILURE;
	config_file_apply(*pconfig, mkpublic_cfg_defaults);
	std::string mysql_host = znul(pconfig->get_value("mysql_host"));
	uint16_t mysql_port = pconfig->get_ll("mysql_port");
	std::string mysql_user = znul(pconfig->get_value("mysql_username"));
	std::optional<std::string> mysql_pass;
	if (auto s = pconfig->get_value("mysql_password"))
		mysql_pass.emplace(s);
	std::string db_name = znul(pconfig->get_value("mysql_dbname"));

	const char *datadir = opt_datadir != nullptr ? opt_datadir : PKGDATADIR;
	auto pmysql = mysql_init(nullptr);
	if (pmysql == nullptr) {
		printf("Failed to init mysql object\n");
		return EXIT_FAILURE;
	}

	if (mysql_real_connect(pmysql, mysql_host.c_str(), mysql_user.c_str(),
	    mysql_pass.has_value() ? mysql_pass->c_str() : nullptr,
	    db_name.c_str(), mysql_port, nullptr, 0) == nullptr) {
		mysql_close(pmysql);
		printf("Failed to connect to the database %s@%s/%s\n",
		       mysql_user.c_str(), mysql_host.c_str(), db_name.c_str());
		return EXIT_FAILURE;
	}
	if (mysql_set_character_set(pmysql, "utf8mb4") != 0) {
		fprintf(stderr, "\"utf8mb4\" not available: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		return EXIT_FAILURE;
	}
	
	snprintf(mysql_string, arsizeof(mysql_string), "SELECT 0, homedir, 0, "
		"domain_status, id FROM domains WHERE domainname='%s'", argv[1]);
	
	if (0 != mysql_query(pmysql, mysql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		printf("fail to query database\n");
		mysql_close(pmysql);
		return EXIT_FAILURE;
	}
		
	if (1 != mysql_num_rows(pmyres)) {
		printf("cannot find information from database "
				"for username %s\n", argv[1]);
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return EXIT_FAILURE;
	}

	myrow = mysql_fetch_row(pmyres);
	auto domain_status = strtoul(myrow[3], nullptr, 0);
	if (domain_status != AF_DOMAIN_NORMAL)
		printf("Warning: Domain status is not \"alive\"(0) but %lu\n", domain_status);
	
	std::string dir = znul(myrow[1]);
	int domain_id = strtol(myrow[4], nullptr, 0);
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	
	if (!make_mailbox_hierarchy(dir))
		return EXIT_FAILURE;
	auto temp_path = dir + "/exmdb/exchange.sqlite3";
	if (!opt_upgrade) {
		auto ret = mbop_truncate_chown(argv[0], temp_path.c_str(), opt_force);
		if (ret != 0)
			return EXIT_FAILURE;
	}
	if (SQLITE_OK != sqlite3_initialize()) {
		printf("Failed to initialize sqlite engine\n");
		return EXIT_FAILURE;
	}
	auto cl_0 = make_scope_exit([]() { sqlite3_shutdown(); });
	if (opt_upgrade)
		return mbop_upgrade(temp_path.c_str(), sqlite_kind::pub);
	if (sqlite3_open_v2(temp_path.c_str(), &psqlite,
	    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
		printf("fail to create store database\n");
		return EXIT_FAILURE;
	}
	auto cl_1 = make_scope_exit([&]() { sqlite3_close(psqlite); });
	unsigned int flags = 0;
	if (opt_upgrade) {
		auto ret = dbop_sqlite_upgrade(psqlite, temp_path.c_str(),
		           sqlite_kind::pub, flags);
		if (ret != 0) {
			fprintf(stderr, "dbop_sqlite_upgrade: %s\n", strerror(ret));
			return EXIT_FAILURE;
		}
		return EXIT_SUCCESS;
	}

	auto sql_transact = gx_sql_begin_trans(psqlite);
	if (opt_create_old)
		flags |= DBOP_SCHEMA_0;
	if (opt_verbose)
		flags |= DBOP_VERBOSE;
	auto ret = dbop_sqlite_create(psqlite, sqlite_kind::pub, flags);
	if (ret != 0) {
		fprintf(stderr, "dbop_sqlite_create_top: %s\n", strerror(-ret));
		return EXIT_FAILURE;
	}
	ret = mbop_insert_namedprops(psqlite, datadir);
	if (ret != 0)
		return EXIT_FAILURE;
	
	std::pair<uint32_t, uint64_t> storeprops[] = {
		{PR_CREATION_TIME, nt_time},
		{PR_MESSAGE_SIZE_EXTENDED, 0},
		{PR_ASSOC_MESSAGE_SIZE_EXTENDED, 0},
		{PR_NORMAL_MESSAGE_SIZE_EXTENDED, 0},
		{},
	};
	ret = mbop_insert_storeprops(psqlite, storeprops);
	if (ret != 0)
		return EXIT_FAILURE;
	static constexpr struct {
		uint64_t parent = 0, fid = 0;
		const char *name = nullptr;
	} generic_folders[] = {
		{0, PUBLIC_FID_ROOT, "Root Container"},
		{PUBLIC_FID_ROOT, PUBLIC_FID_IPMSUBTREE, "IPM_SUBTREE"},
		{PUBLIC_FID_ROOT, PUBLIC_FID_NONIPMSUBTREE, "NON_IPM_SUBTREE"},
		{PUBLIC_FID_NONIPMSUBTREE, PUBLIC_FID_EFORMSREGISTRY, "EFORMS REGISTRY"},
	};
	for (const auto &e : generic_folders) {
		if (mbop_create_generic_folder(psqlite, e.fid, e.parent,
		    domain_id, e.name)) {
			printf("Failed to create \"%s\" folder\n", e.name);
			return EXIT_FAILURE;
		}
	}

	auto pstmt = gx_sql_prep(psqlite, "INSERT INTO configurations VALUES (?, ?)");
	if (pstmt == nullptr)
		return EXIT_FAILURE;
	char tmp_bguid[GUIDSTR_SIZE];
	GUID::random_new().to_str(tmp_bguid, arsizeof(tmp_bguid));
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_MAILBOX_GUID);
	sqlite3_bind_text(pstmt, 2, tmp_bguid, -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return EXIT_FAILURE;
	}
	sqlite3_reset(pstmt);
	std::pair<uint32_t, uint64_t> confprops[] = {
		{CONFIG_ID_CURRENT_EID, 0x100},
		{CONFIG_ID_MAXIMUM_EID, ALLOCATED_EID_RANGE},
		{CONFIG_ID_LAST_CHANGE_NUMBER, g_last_cn},
		{CONFIG_ID_LAST_CID, 0},
		{CONFIG_ID_LAST_ARTICLE_NUMBER, g_last_art},
		{CONFIG_ID_SEARCH_STATE, 0},
		{CONFIG_ID_DEFAULT_PERMISSION, frightsReadAny | frightsCreate | frightsVisible | frightsEditOwned | frightsDeleteOwned},
		{CONFIG_ID_ANONYMOUS_PERMISSION, 0},
	};
	for (const auto &e : confprops) {
		sqlite3_bind_int64(pstmt, 1, e.first);
		sqlite3_bind_int64(pstmt, 2, e.second);
		if (sqlite3_step(pstmt) != SQLITE_DONE) {
			printf("fail to step sql inserting\n");
			return EXIT_FAILURE;
		}
		sqlite3_reset(pstmt);
	}
	pstmt.finalize();
	sql_transact.commit();
	return EXIT_SUCCESS;
} catch (const cfg_error &) {
	return EXIT_FAILURE;
}
