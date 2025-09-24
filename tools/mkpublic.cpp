// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <cassert>
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
#include <fmt/core.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/config_file.hpp>
#include <gromox/database.h>
#include <gromox/database_mysql.hpp>
#include <gromox/dbop.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/paths.h>
#include <gromox/pcl.hpp>
#include <gromox/rop_util.hpp>
#include "mkshared.hpp"

using namespace std::string_literals;
using namespace gromox;

static char *opt_config_file, *opt_datadir;
static unsigned int opt_force, opt_create_old, opt_upgrade;
static unsigned int opt_verbose, opt_integ;

static constexpr HXoption g_options_table[] = {
	{"integrity", 0, HXTYPE_NONE, &opt_integ, nullptr, nullptr, 0, "Perform integrity SQLite check"},
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

static constexpr unsigned int rightsGromoxPubDefault = /* (0x41b/1051) */
	frightsReadAny | frightsCreate | frightsVisible | frightsEditOwned |
	frightsDeleteOwned;

static int mk_storeprops(sqlite3 *psqlite, mapitime_t nt_time)
{
	std::pair<uint32_t, uint64_t> storeprops[] = {
		{PR_CREATION_TIME, nt_time},
		{PR_MESSAGE_SIZE_EXTENDED, 0},
		{PR_ASSOC_MESSAGE_SIZE_EXTENDED, 0},
		{PR_NORMAL_MESSAGE_SIZE_EXTENDED, 0},
		{},
	};
	return mbop_insert_storeprops(psqlite, storeprops);
}

static int mk_folders(sqlite3 *psqlite, uint32_t domain_id)
{
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
	return EXIT_SUCCESS;
}

static int mk_options(sqlite3 *psqlite, time_t ux_time)
{
	auto record_key  = GUID::random_new();
	auto mapping_sig = GUID::random_new();
	char rgtxt[5][GUIDSTR_SIZE];
	record_key.to_str(rgtxt[0], sizeof(rgtxt[0]));
	exc_replid2.to_str(rgtxt[1], sizeof(rgtxt[1]));
	exc_replid3.to_str(rgtxt[2], sizeof(rgtxt[2]));
	exc_replid4.to_str(rgtxt[3], sizeof(rgtxt[3]));
	mapping_sig.to_str(rgtxt[4], sizeof(rgtxt[4]));

	auto pstmt = gx_sql_prep(psqlite, "INSERT INTO configurations VALUES (?, ?)");
	if (pstmt == nullptr)
		return EXIT_FAILURE;
	pstmt.bind_int64(1, CONFIG_ID_MAILBOX_GUID);
	pstmt.bind_text(2, rgtxt[0]);
	if (pstmt.step() != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return EXIT_FAILURE;
	}
	pstmt.reset();
	if (!opt_create_old) {
		pstmt.bind_int64(1, CONFIG_ID_MAPPING_SIGNATURE);
		pstmt.bind_text(2, rgtxt[4]);
		if (pstmt.step() != SQLITE_DONE)
			return EXIT_FAILURE;
		pstmt.reset();
	}

	std::pair<uint32_t, uint64_t> confprops[] = {
		{CONFIG_ID_CURRENT_EID, CUSTOM_EID_BEGIN},
		{CONFIG_ID_MAXIMUM_EID, ALLOCATED_EID_RANGE - 1},
		{CONFIG_ID_LAST_CHANGE_NUMBER, g_last_cn},
		{CONFIG_ID_LAST_CID, 0},
		{CONFIG_ID_LAST_ARTICLE_NUMBER, g_last_art},
		{CONFIG_ID_SEARCH_STATE, 0},
		{CONFIG_ID_DEFAULT_PERMISSION, rightsGromoxPubDefault},
		{CONFIG_ID_ANONYMOUS_PERMISSION, 0},
	};
	for (const auto &e : confprops) {
		sqlite3_bind_int64(pstmt, 1, e.first);
		sqlite3_bind_int64(pstmt, 2, e.second);
		if (pstmt.step() != SQLITE_DONE) {
			printf("fail to step sql inserting\n");
			return EXIT_FAILURE;
		}
		sqlite3_reset(pstmt);
	}
	assert(confprops[1].first == CONFIG_ID_MAXIMUM_EID);
	if (gx_sql_exec(psqlite, fmt::format("INSERT INTO allocated_eids VALUES ({}, {}, {}, 1)",
	    1, confprops[1].second, ux_time).c_str()) != SQLITE_OK)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	sqlite3 *psqlite;
	char mysql_string[1024];
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0a = HX::make_scope_exit([=]() { HX_zvecfree(argv); });
	if (2 != argc) {
		printf("usage: %s <domainname>\n", argv[0]);
		return EXIT_FAILURE;
	}
	auto pconfig = config_file_prg(opt_config_file, "mysql_adaptor.cfg",
	               mkpublic_cfg_defaults);
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return EXIT_FAILURE;
	std::string mysql_host = znul(pconfig->get_value("mysql_host"));
	uint16_t mysql_port = pconfig->get_ll("mysql_port");
	std::string mysql_user = znul(pconfig->get_value("mysql_username"));
	std::optional<std::string> mysql_pass;
	if (auto s = pconfig->get_value("mysql_password"))
		mysql_pass.emplace(s);
	std::string db_name = znul(pconfig->get_value("mysql_dbname"));

	const char *datadir = opt_datadir != nullptr ? opt_datadir : PKGDATADIR;
	std::unique_ptr<MYSQL, mysql_delete> conn(mysql_init(nullptr));
	if (conn == nullptr) {
		printf("Failed to init mysql object\n");
		return EXIT_FAILURE;
	}

	if (mysql_real_connect(conn.get(), mysql_host.c_str(), mysql_user.c_str(),
	    mysql_pass.has_value() ? mysql_pass->c_str() : nullptr,
	    db_name.c_str(), mysql_port, nullptr, 0) == nullptr) {
		printf("Failed to connect to the MariaDB/MySQL database %s@%s/%s\n",
		       mysql_user.c_str(), mysql_host.c_str(), db_name.c_str());
		return EXIT_FAILURE;
	}
	if (mysql_set_character_set(conn.get(), "utf8mb4") != 0) {
		fprintf(stderr, "\"utf8mb4\" not available: %s", mysql_error(conn.get()));
		return EXIT_FAILURE;
	}
	
	snprintf(mysql_string, std::size(mysql_string), "SELECT 0, homedir, 0, "
		"domain_status, id FROM domains WHERE domainname='%s'", argv[1]);
	if (mysql_query(conn.get(), mysql_string) != 0) {
		fprintf(stderr, "%s: %s\n", mysql_string, mysql_error(conn.get()));
		return EXIT_FAILURE;
	}
	DB_RESULT myres = mysql_store_result(conn.get());
	if (myres == nullptr) {
		fprintf(stderr, "result: %s\n", mysql_error(conn.get()));
		return EXIT_FAILURE;
	}
	auto myrow = myres.fetch_row();
	if (myrow == nullptr || myres.num_rows() > 1) {
		printf("cannot find information from database "
				"for username %s\n", argv[1]);
		return EXIT_FAILURE;
	} else if (myres.num_rows() > 1) {
		fprintf(stderr, "Ambiguous result from database\n");
		return EXIT_FAILURE;
	}
	auto domain_status = strtoul(myrow[3], nullptr, 0);
	if (domain_status != AF_DOMAIN_NORMAL)
		printf("Warning: Domain status is not \"alive\"(0) but %lu\n", domain_status);
	
	std::string dir = znul(myrow[1]);
	int domain_id = strtol(myrow[4], nullptr, 0);
	myres.clear();
	conn.reset();
	
	if (!make_mailbox_hierarchy(dir))
		return EXIT_FAILURE;
	auto temp_path = dir + "/exmdb/exchange.sqlite3";
	if (!opt_upgrade && !opt_integ) {
		auto ret = mbop_truncate_chown(argv[0], temp_path.c_str(), opt_force);
		if (ret != 0)
			return EXIT_FAILURE;
	}
	if (SQLITE_OK != sqlite3_initialize()) {
		printf("Failed to initialize sqlite engine\n");
		return EXIT_FAILURE;
	}
	auto cl_0 = HX::make_scope_exit(sqlite3_shutdown);
	if (opt_upgrade) {
		unsigned int flags = opt_integ ? DBOP_INTEGCHECK : 0;
		return mbop_upgrade(temp_path.c_str(), sqlite_kind::pub, flags | DBOP_VERBOSE);
	}
	unsigned int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX;
	if (sqlite3_open_v2(temp_path.c_str(), &psqlite, flags,
	    nullptr) != SQLITE_OK) {
		printf("fail to create store database\n");
		return EXIT_FAILURE;
	}
	auto cl_1 = HX::make_scope_exit([&]() { sqlite3_close(psqlite); });
	if (gx_sql_exec(psqlite, "PRAGMA journal_mode=WAL") != SQLITE_OK)
		return EXIT_FAILURE;
	if (opt_integ)
		return dbop_sqlite_integcheck(psqlite, LV_ERR) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
	flags = 0;
	if (opt_upgrade) {
		auto ret = dbop_sqlite_upgrade(psqlite, temp_path.c_str(),
		           sqlite_kind::pub, flags);
		if (ret != 0) {
			fprintf(stderr, "dbop_sqlite_upgrade: %s\n", strerror(ret));
			return EXIT_FAILURE;
		}
		return EXIT_SUCCESS;
	}

	auto sql_transact = gx_sql_begin(psqlite, txn_mode::write);
	if (!sql_transact)
		return EXIT_FAILURE;
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

	auto ux_time = time(nullptr);
	auto nt_time = rop_util_unix_to_nttime(ux_time);
	ret = mk_storeprops(psqlite, nt_time);
	if (ret != 0)
		return EXIT_FAILURE;
	ret = mk_folders(psqlite, domain_id);
	if (ret != EXIT_SUCCESS)
		return ret;
	ret = mk_options(psqlite, ux_time);
	if (ret != EXIT_SUCCESS)
		return ret;
	return sql_transact.commit() == SQLITE_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
