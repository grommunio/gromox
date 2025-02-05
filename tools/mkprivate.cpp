// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2024 grommunio GmbH
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
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include "mkshared.hpp"

using namespace std::string_literals;
using namespace gromox;

enum {
	RES_ID_IPM,
	RES_ID_INBOX,
	RES_ID_DRAFT,
	RES_ID_OUTBOX,
	RES_ID_SENT,
	RES_ID_DELETED,
	RES_ID_CONTACTS,
	RES_ID_CALENDAR,
	RES_ID_JOURNAL,
	RES_ID_NOTES,
	RES_ID_TASKS,
	RES_ID_JUNK,
	RES_ID_SYNC,
	RES_ID_CONFLICT,
	RES_ID_LOCAL,
	RES_ID_SERVER,
	RES_TOTAL_NUM
};

static char *opt_config_file, *opt_datadir;
static const char *g_lang;
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

static constexpr cfg_directive mkprivate_cfg_defaults[] = {
	{"mysql_dbname", "email"},
	{"mysql_host", "localhost"},
	{"mysql_port", "3306"},
	{"mysql_username", "root"},
	CFG_TABLE_END,
};

static int create_generic_folder(sqlite3 *sq, uint64_t fid, uint64_t parent,
    int user, const char *fldclass, BOOL hidden)
{
	auto dn_eng  = folder_namedb_get("en", fid);
	auto dn_lang = folder_namedb_get(g_lang, fid);
	auto ret = mbop_create_generic_folder(sq, fid, parent, user, dn_lang,
	           fldclass, hidden);
	if (ret != 0)
		fprintf(stderr, "Failed to create folder \"%s\" (%s)\n", dn_lang, dn_eng);
	return ret;
}

static int create_search_folder(sqlite3 *sdb, uint64_t fid, uint64_t parent,
    int sec_id)
{
	auto dn_eng  = folder_namedb_get("en", fid);
	auto dn_lang = folder_namedb_get(g_lang, fid);
	auto ret = mbop_create_search_folder(sdb, fid, parent, sec_id, dn_lang);
	if (ret != 0)
		fprintf(stderr, "Failed to create folder \"%s\" (%s)\n", dn_lang, dn_eng);
	return ret;
}

static int mk_storeprops(sqlite3 *psqlite, mapitime_t nt_time)
{
	std::pair<uint32_t, uint64_t> storeprops[] = {
		{PR_CREATION_TIME, nt_time},
		{PR_OOF_STATE, 0},
		{PR_MESSAGE_SIZE_EXTENDED, 0},
		{PR_ASSOC_MESSAGE_SIZE_EXTENDED, 0},
		{PR_NORMAL_MESSAGE_SIZE_EXTENDED, 0},
		{},
	};
	return mbop_insert_storeprops(psqlite, storeprops);
}

static int mk_receivefolders(sqlite3 *psqlite, mapitime_t nt_time)
{
	auto pstmt = gx_sql_prep(psqlite, "INSERT INTO receive_table VALUES (?, ?, ?)");
	if (pstmt == nullptr)
		return EXIT_FAILURE;
	static constexpr std::pair<const char *, uint64_t> receive_folders[] = {
		{"", PRIVATE_FID_INBOX}, {"IPC", PRIVATE_FID_ROOT},
		{"IPM", PRIVATE_FID_INBOX}, {"REPORT.IPM", PRIVATE_FID_INBOX},
	};
	for (const auto &e : receive_folders) {
		sqlite3_bind_text(pstmt, 1, e.first, -1, SQLITE_STATIC);
		sqlite3_bind_int64(pstmt, 2, e.second);
		sqlite3_bind_int64(pstmt, 3, nt_time);
		if (pstmt.step() != SQLITE_DONE) {
			printf("fail to step sql inserting\n");
			return EXIT_FAILURE;
		}
		sqlite3_reset(pstmt);
	}
	return EXIT_SUCCESS;
}

static int mk_folders(sqlite3 *psqlite, uint32_t user_id)
{
	static constexpr struct {
		uint64_t parent = 0, fid = 0;
		const char *fldclass = nullptr;
		BOOL hidden = false;
	} generic_folders[] = {
		{0, PRIVATE_FID_ROOT},
		{PRIVATE_FID_ROOT, PRIVATE_FID_IPMSUBTREE},
		{PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_INBOX, "IPF.Note"},
		{PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_DRAFT, "IPF.Note"},
		{PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_OUTBOX, "IPF.Note"},
		{PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_SENT_ITEMS, "IPF.Note"},
		{PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_DELETED_ITEMS, "IPF.Note"},
		{PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_CONTACTS, "IPF.Contact"},
		{PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_CALENDAR, "IPF.Appointment"},
		{PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_JOURNAL, "IPF.Journal"},
		{PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_NOTES, "IPF.StickyNote"},
		{PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_TASKS, "IPF.Task"},
		{PRIVATE_FID_CONTACTS, PRIVATE_FID_QUICKCONTACTS, "IPF.Contact.MOC.QuickContacts", TRUE},
		{PRIVATE_FID_CONTACTS, PRIVATE_FID_IMCONTACTLIST, "IPF.Contact.MOC.ImContactList", TRUE},
		{PRIVATE_FID_CONTACTS, PRIVATE_FID_GALCONTACTS, "IPF.Contact.GalContacts", TRUE},
		{PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_JUNK, "IPF.Note"},
		{PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_CONVERSATION_ACTION_SETTINGS, "IPF.Configuration", TRUE},
		{PRIVATE_FID_ROOT, PRIVATE_FID_DEFERRED_ACTION},
		{PRIVATE_FID_ROOT, PRIVATE_FID_COMMON_VIEWS},
		{PRIVATE_FID_ROOT, PRIVATE_FID_SCHEDULE},
		{PRIVATE_FID_ROOT, PRIVATE_FID_FINDER},
		{PRIVATE_FID_ROOT, PRIVATE_FID_VIEWS},
		{PRIVATE_FID_ROOT, PRIVATE_FID_SHORTCUTS},
		{PRIVATE_FID_IPMSUBTREE, PRIVATE_FID_SYNC_ISSUES, "IPF.Note"},
		{PRIVATE_FID_SYNC_ISSUES, PRIVATE_FID_CONFLICTS, "IPF.Note"},
		{PRIVATE_FID_SYNC_ISSUES, PRIVATE_FID_LOCAL_FAILURES, "IPF.Note"},
		{PRIVATE_FID_SYNC_ISSUES, PRIVATE_FID_SERVER_FAILURES, "IPF.Note"},
		{PRIVATE_FID_ROOT, PRIVATE_FID_LOCAL_FREEBUSY},
	};
	for (const auto &e : generic_folders)
		if (create_generic_folder(psqlite, e.fid,
		    e.parent, user_id, e.fldclass, e.hidden) != 0)
			return EXIT_FAILURE;
	if (create_search_folder(psqlite, PRIVATE_FID_SPOOLER_QUEUE,
	    PRIVATE_FID_ROOT, user_id) != 0) {
		printf("fail to create \"spooler queue\" folder\n");
		return EXIT_FAILURE;
	}
	char tmp_sql[1024];
	snprintf(tmp_sql, std::size(tmp_sql), "INSERT INTO permissions (folder_id, "
		"username, permission) VALUES (%llu, 'default', %u)",
		static_cast<unsigned long long>(PRIVATE_FID_CALENDAR), frightsFreeBusySimple | frightsVisible);
	gx_sql_exec(psqlite, tmp_sql);
	snprintf(tmp_sql, std::size(tmp_sql), "INSERT INTO permissions (folder_id, "
		"username, permission) VALUES (%llu, 'default', %u)",
		static_cast<unsigned long long>(PRIVATE_FID_LOCAL_FREEBUSY), frightsFreeBusySimple);
	gx_sql_exec(psqlite, tmp_sql);
	return EXIT_SUCCESS;
}

static int mk_options(sqlite3 *psqlite, time_t ux_time)
{
	auto pstmt = gx_sql_prep(psqlite, "INSERT INTO configurations VALUES (?, ?)");
	if (pstmt == nullptr)
		return EXIT_FAILURE;
	char tmp_bguid[GUIDSTR_SIZE];
	GUID::random_new().to_str(tmp_bguid, std::size(tmp_bguid));
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_MAILBOX_GUID);
	sqlite3_bind_text(pstmt, 2, tmp_bguid, -1, SQLITE_STATIC);
	if (pstmt.step() != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return EXIT_FAILURE;
	}
	sqlite3_reset(pstmt);
	/*
	 * By now, we have already created some built-in folders,
	 * given them message reservation ranges,
	 * and used some CNs already.
	 *
	 * - EIDs 1 .. 0x1d (PRIVATE_FID_UNASSIGNED_START-1) are used for folders
	 * - EIDs 0x10001 .. 0x170000 are reserved for folders' messages
	 * - g_cur_eid is 0x170001
	 * - CNs 1 .. 0x1d are used
	 * - g_last_cn is 0x1d
	 *
	 * The region 0x1e .. 0xff is set aside for built-in folders.
	 *
	 * The region 0x100 .. 0x10000 is free for use, and that is what we
	 * enter for CONFIG_ID_*_EID instead of g_last_eid. Once this region is
	 * used up, exmdb will automatically jump and continue at e.g.
	 * 0x170001.
	 */
	std::pair<uint32_t, uint64_t> confprops[] = {
		{CONFIG_ID_CURRENT_EID, CUSTOM_EID_BEGIN},
		{CONFIG_ID_MAXIMUM_EID, ALLOCATED_EID_RANGE - 1},
		{CONFIG_ID_LAST_CHANGE_NUMBER, g_last_cn},
		{CONFIG_ID_LAST_CID, 0},
		{CONFIG_ID_LAST_ARTICLE_NUMBER, g_last_art},
		{CONFIG_ID_SEARCH_STATE, 0},
		{CONFIG_ID_DEFAULT_PERMISSION, 0},
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
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0a = make_scope_exit([=]() { HX_zvecfree(argv); });
	if (2 != argc) {
		printf("usage: %s <username>\n", argv[0]);
		return EXIT_FAILURE;
	}
	auto pconfig = config_file_prg(opt_config_file, "mysql_adaptor.cfg",
	               mkprivate_cfg_defaults);
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
	textmaps_init(datadir);
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
	
	auto qstr = "SELECT 0, u.maildir, u.lang, up.propval_str AS dtypx, u.address_status, u.id "
	            "FROM users AS u "
	            "LEFT JOIN user_properties AS up ON u.id=up.user_id AND up.proptag=956628995 " /* PR_DISPLAY_TYPE_EX */
	            "WHERE u.username='"s + argv[1] + "'";
	if (mysql_query(conn.get(), qstr.c_str()) != 0) {
		fprintf(stderr, "%s: %s\n", qstr.c_str(), mysql_error(conn.get()));
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
	}
	auto dtypx = DT_MAILUSER;
	if (myrow[3] != nullptr)
		dtypx = static_cast<enum display_type>(strtoul(myrow[3], nullptr, 0));
	if (dtypx != DT_MAILUSER && dtypx != DT_ROOM && dtypx != DT_EQUIPMENT) {
		printf("Refusing to create a private store for mailing lists, groups and aliases. "
		       "(PR_DISPLAY_TYPE=%xh)\n", dtypx);
		return EXIT_FAILURE;
	}
	
	unsigned int address_status = strtoul(myrow[4], nullptr, 0);
	if (!afuser_store_present(address_status))
		printf("Warning: Account status (0x%x) indicates this user object normally does not have a mailbox. Proceeding anyway for now...\n", address_status);
	
	std::string dir = znul(myrow[1]), lang = znul(myrow[2]);
	g_lang = folder_namedb_resolve(lang.c_str());
	if (g_lang == nullptr)
		g_lang = "en";
	int user_id = strtol(myrow[5], nullptr, 0);
	myres.clear();
	conn.reset();
	
	make_mailbox_hierarchy(dir);
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
	auto cl_0 = make_scope_exit(sqlite3_shutdown);
	if (opt_upgrade) {
		unsigned int flags = opt_integ ? DBOP_INTEGCHECK : 0;
		return mbop_upgrade(temp_path.c_str(), sqlite_kind::pvt, flags | DBOP_VERBOSE);
	}
	unsigned int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX;
	if (sqlite3_open_v2(temp_path.c_str(), &psqlite, flags,
	    nullptr) != SQLITE_OK) {
		printf("fail to create store database\n");
		return EXIT_FAILURE;
	}
	auto cl_1 = make_scope_exit([&]() { sqlite3_close(psqlite); });
	if (gx_sql_exec(psqlite, "PRAGMA journal_mode=WAL") != SQLITE_OK)
		return EXIT_FAILURE;
	if (opt_integ)
		return dbop_sqlite_integcheck(psqlite, LV_ERR) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
	flags = 0;
	auto sql_transact = gx_sql_begin(psqlite, txn_mode::write);
	if (!sql_transact)
		return EXIT_FAILURE;
	if (opt_create_old)
		flags |= DBOP_SCHEMA_0;
	if (opt_verbose)
		flags |= DBOP_VERBOSE;
	auto ret = dbop_sqlite_create(psqlite, sqlite_kind::pvt, flags);
	if (ret != 0) {
		fprintf(stderr, "sqlite_create: %s\n", strerror(-ret));
		return EXIT_FAILURE;
	}
	ret = mbop_insert_namedprops(psqlite, datadir);
	if (ret != 0)
		return EXIT_FAILURE;
	
	auto ux_time = time(nullptr);
	auto nt_time = rop_util_unix_to_nttime(ux_time);
	ret = mk_receivefolders(psqlite, nt_time);
	if (ret != EXIT_SUCCESS)
		return ret;
	ret = mk_storeprops(psqlite, nt_time);
	if (ret != EXIT_SUCCESS)
		return ret;
	ret = mk_folders(psqlite, user_id);
	if (ret != EXIT_SUCCESS)
		return ret;
	ret = mk_options(psqlite, ux_time);
	if (ret != EXIT_SUCCESS)
		return ret;
	return sql_transact.commit() == SQLITE_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
