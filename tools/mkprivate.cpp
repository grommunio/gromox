// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <memory>
#include <string>
#include <vector>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/config_file.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/list_file.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/proptags.hpp>
#include <gromox/guid.hpp>
#include <gromox/pcl.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <ctime>
#include <cstdio>
#include <fcntl.h>
#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <mysql.h>
#include "exch/mysql_adaptor/mysql_adaptor.h"
#include "mkshared.hpp"
#define LLU(x) static_cast<unsigned long long>(x)

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

static uint32_t g_last_art;
static uint64_t g_last_cn = CHANGE_NUMBER_BEGIN;
static uint64_t g_last_eid = ALLOCATED_EID_RANGE;
static char *opt_config_file, *opt_datadir;
static const char *g_lang;

static constexpr HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{nullptr, 'd', HXTYPE_STRING, &opt_datadir, nullptr, nullptr, 0, "Data directory", "DIR"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static BOOL create_generic_folder(sqlite3 *psqlite, uint64_t folder_id,
    uint64_t parent_id, int user_id, const char *pcontainer_class = nullptr,
    BOOL b_hidden = false)
{
	auto pdisplayname = folder_namedb_get(g_lang, folder_id);
	uint64_t cur_eid;
	uint64_t max_eid;
	uint32_t art_num;
	uint64_t change_num;
	char sql_string[256];
	
	cur_eid = g_last_eid + 1;
	g_last_eid += ALLOCATED_EID_RANGE;
	max_eid = g_last_eid;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO allocated_eids"
	        " VALUES (%llu, %llu, %lld, 1)", LLU(cur_eid),
	        LLU(max_eid), static_cast<long long>(time(nullptr)));
	if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	g_last_cn ++;
	change_num = g_last_cn;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO folders "
				"(folder_id, parent_id, change_number, "
				"cur_eid, max_eid) VALUES (?, ?, ?, ?, ?)");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, folder_id);
	if (parent_id == 0)
		sqlite3_bind_null(pstmt, 2);
	else
		sqlite3_bind_int64(pstmt, 2, parent_id);
	sqlite3_bind_int64(pstmt, 3, change_num);
	sqlite3_bind_int64(pstmt, 4, cur_eid);
	sqlite3_bind_int64(pstmt, 5, max_eid);
	if (sqlite3_step(pstmt) != SQLITE_DONE)
		return FALSE;
	pstmt.finalize();
	g_last_art ++;
	art_num = g_last_art;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO "
		"folder_properties VALUES (%llu, ?, ?)", LLU(folder_id));
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (!add_folderprop_iv(pstmt, art_num, true) ||
	    !add_folderprop_sv(pstmt, pdisplayname, pcontainer_class) ||
	    !add_folderprop_tv(pstmt) ||
	    !add_changenum(pstmt, CN_USER, user_id, change_num))
		return false;
	if (TRUE == b_hidden) {
		sqlite3_bind_int64(pstmt, 1, PR_ATTR_HIDDEN);
		sqlite3_bind_int64(pstmt, 2, 1);
		if (sqlite3_step(pstmt) != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt);
	}
	return TRUE;
}

static BOOL create_search_folder(sqlite3 *psqlite, uint64_t folder_id,
    uint64_t parent_id, int user_id, const char *pcontainer_class)
{
	auto pdisplayname = folder_namedb_get(g_lang, folder_id);
	uint32_t art_num;
	uint64_t change_num;
	char sql_string[256];
	
	g_last_cn ++;
	change_num = g_last_cn;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO folders "
		"(folder_id, parent_id, change_number, is_search,"
		" cur_eid, max_eid) VALUES (?, ?, ?, 1, 0, 0)");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, folder_id);
	if (parent_id == 0)
		sqlite3_bind_null(pstmt, 2);
	else
		sqlite3_bind_int64(pstmt, 2, parent_id);
	sqlite3_bind_int64(pstmt, 3, change_num);
	if (sqlite3_step(pstmt) != SQLITE_DONE)
		return FALSE;
	pstmt.finalize();
	g_last_art ++;
	art_num = g_last_art;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO "
	          "folder_properties VALUES (%llu, ?, ?)", LLU(folder_id));
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (!add_folderprop_iv(pstmt, art_num, false) ||
	    !add_folderprop_sv(pstmt, pdisplayname, pcontainer_class) ||
	    !add_folderprop_tv(pstmt) ||
	    !add_changenum(pstmt, CN_USER, user_id, change_num))
		return false;
	return TRUE;
}

int main(int argc, const char **argv)
{
	MYSQL *pmysql;
	GUID tmp_guid;
	int mysql_port;
	uint16_t propid;
	MYSQL_ROW myrow;
	uint64_t nt_time;
	sqlite3 *psqlite;
	MYSQL_RES *pmyres;
	char tmp_sql[1024];
	char mysql_host[UDOM_SIZE], mysql_user[256], db_name[256], dir[256], lang[32];
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (2 != argc) {
		printf("usage: %s <username>\n", argv[0]);
		return 1;
	}
	auto pconfig = config_file_prg(opt_config_file, "sa.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return 2;
	auto str_value = pconfig->get_value("MYSQL_HOST");
	if (str_value == nullptr)
		strcpy(mysql_host, "localhost");
	else
		gx_strlcpy(mysql_host, str_value, GX_ARRAY_SIZE(mysql_host));
	
	str_value = pconfig->get_value("MYSQL_PORT");
	if (NULL == str_value) {
		mysql_port = 3306;
	} else {
		mysql_port = strtol(str_value, nullptr, 0);
		if (mysql_port <= 0)
			mysql_port = 3306;
	}

	str_value = pconfig->get_value("MYSQL_USERNAME");
	gx_strlcpy(mysql_user, str_value != nullptr ? str_value : "root", GX_ARRAY_SIZE(mysql_user));
	auto mysql_passwd = pconfig->get_value("MYSQL_PASSWORD");
	str_value = pconfig->get_value("MYSQL_DBNAME");
	if (str_value == nullptr)
		strcpy(db_name, "email");
	else
		gx_strlcpy(db_name, str_value, GX_ARRAY_SIZE(db_name));

	const char *datadir = opt_datadir != nullptr ? opt_datadir :
	                      pconfig->get_value("data_file_path");
	if (datadir == nullptr)
		datadir = PKGDATADIR;
	
	textmaps_init(datadir);
	if (NULL == (pmysql = mysql_init(NULL))) {
		printf("Failed to init mysql object\n");
		return 3;
	}

	if (NULL == mysql_real_connect(pmysql, mysql_host, mysql_user,
		mysql_passwd, db_name, mysql_port, NULL, 0)) {
		mysql_close(pmysql);
		printf("Failed to connect to the database %s@%s/%s\n",
		       mysql_user, mysql_host, db_name);
		return 3;
	}
	if (mysql_set_character_set(pmysql, "utf8mb4") != 0) {
		fprintf(stderr, "\"utf8mb4\" not available: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		return 3;
	}
	
	auto qstr = "SELECT 0, u.maildir, u.lang, up.propval_str AS dtypx, u.address_status, u.id "
	            "FROM users AS u "
	            "LEFT JOIN user_properties AS up ON u.id=up.user_id AND up.proptag=956628995 " /* PR_DISPLAY_TYPE_EX */
	            "WHERE u.username='"s + argv[1] + "'";
	if (mysql_query(pmysql, qstr.c_str()) != 0 ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		printf("Query failed: %s: %s\n", qstr.c_str(), mysql_error(pmysql));
		mysql_close(pmysql);
		return 3;
	}
		
	if (1 != mysql_num_rows(pmyres)) {
		printf("cannot find information from database "
				"for username %s\n", argv[1]);
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return 3;
	}

	myrow = mysql_fetch_row(pmyres);
	auto dtypx = DT_MAILUSER;
	if (myrow[3] != nullptr)
		dtypx = static_cast<enum display_type>(strtoul(myrow[3], nullptr, 0));
	if (dtypx != DT_MAILUSER && dtypx != DT_ROOM && dtypx != DT_EQUIPMENT) {
		printf("Refusing to create a private store for mailing lists, groups and aliases. "
		       "(PR_DISPLAY_TYPE=%xh)\n", dtypx);
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return 4;
	}
	
	auto address_status = strtoul(myrow[4], nullptr, 0);
	if (address_status != AF_USER_NORMAL && address_status != AF_USER_SHAREDMBOX)
		printf("Warning: Address status is not \"alive\"(0) but %lu\n", address_status);
	
	gx_strlcpy(dir, myrow[1], GX_ARRAY_SIZE(dir));
	gx_strlcpy(lang, myrow[2], arsizeof(lang));
	g_lang = folder_namedb_resolve(lang);
	if (g_lang == nullptr)
		g_lang = "en";
	int user_id = strtol(myrow[5], nullptr, 0);
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	
	auto temp_path = dir + "/exmdb"s;
	if (mkdir(temp_path.c_str(), 0777) && errno != EEXIST) {
		fprintf(stderr, "E-1420: mkdir %s: %s\n", temp_path.c_str(), strerror(errno));
		return 6;
	}
	temp_path += "/exchange.sqlite3";
	/*
	 * sqlite3_open does not expose O_EXCL, so let's create the file under
	 * EXCL semantics ahead of time.
	 */
	auto tfd = open(temp_path.c_str(), O_RDWR | O_CREAT | O_EXCL, 0660);
	if (tfd >= 0) {
		adjust_rights(tfd);
		close(tfd);
	} else if (errno == EEXIST) {
		printf("can not create store database, %s already exists\n", temp_path.c_str());
		return 6;
	}
	
	auto filp = fopen_sd("sqlite3_common.txt", datadir);
	if (filp == nullptr) {
		fprintf(stderr, "fopen_sd sqlite3_common.txt: %s\n", strerror(errno));
		return 7;
	}
	std::string sql_string;
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_fd(fileno(filp.get()), &slurp_len));
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
		return 9;
	}
	auto cl_0 = make_scope_exit([]() { sqlite3_shutdown(); });
	if (sqlite3_open_v2(temp_path.c_str(), &psqlite,
	    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
		printf("fail to create store database\n");
		return 9;
	}
	auto cl_1 = make_scope_exit([&]() { sqlite3_close(psqlite); });
	auto sql_transact = gx_sql_begin_trans(psqlite);
	if (gx_sql_exec(psqlite, sql_string.c_str()) != SQLITE_OK)
		return 9;
	
	std::vector<std::string> namedprop_list;
	auto ret = list_file_read_fixedstrings("propnames.txt", datadir, namedprop_list);
	if (ret == -ENOENT) {
	} else if (ret < 0) {
		printf("list_file_initd propnames.txt: %s\n", strerror(-ret));
		return 7;
	}
	auto pstmt = gx_sql_prep(psqlite, "INSERT INTO named_properties VALUES (?, ?)");
	if (pstmt == nullptr)
		return 9;
	
	size_t i = 0;
	for (const auto &name : namedprop_list) {
		propid = 0x8001 + i++;
		sqlite3_bind_int64(pstmt, 1, propid);
		sqlite3_bind_text(pstmt, 2, name.c_str(), -1, SQLITE_STATIC);
		ret = sqlite3_step(pstmt);
		if (ret != SQLITE_DONE) {
			printf("sqlite3_step on namedprop \"%s\": %s\n", name.c_str(), sqlite3_errstr(ret));
			return 9;
		}
		sqlite3_reset(pstmt);
	}
	pstmt.finalize();
	
	nt_time = rop_util_unix_to_nttime(time(NULL));
	pstmt = gx_sql_prep(psqlite, "INSERT INTO receive_table VALUES (?, ?, ?)");
	if (pstmt == nullptr)
		return 9;
	sqlite3_bind_text(pstmt, 1, "", -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, PRIVATE_FID_INBOX);
	sqlite3_bind_int64(pstmt, 3, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_text(pstmt, 1, "IPC", -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, PRIVATE_FID_ROOT);
	sqlite3_bind_int64(pstmt, 3, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_text(pstmt, 1, "IPM", -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, PRIVATE_FID_INBOX);
	sqlite3_bind_int64(pstmt, 3, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_text(pstmt, 1, "REPORT.IPM", -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, PRIVATE_FID_INBOX);
	sqlite3_bind_int64(pstmt, 3, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	pstmt.finalize();
	
	pstmt = gx_sql_prep(psqlite, "INSERT INTO store_properties VALUES (?, ?)");
	if (pstmt == nullptr)
		return 9;
	sqlite3_bind_int64(pstmt, 1, PR_CREATION_TIME);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PR_OOF_STATE);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PR_MESSAGE_SIZE_EXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PR_ASSOC_MESSAGE_SIZE_EXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PR_NORMAL_MESSAGE_SIZE_EXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	pstmt.finalize();
	if (!create_generic_folder(psqlite, PRIVATE_FID_ROOT, 0, user_id)) {
		printf("fail to create \"root container\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_IPMSUBTREE,
	    PRIVATE_FID_ROOT, user_id)) {
		printf("fail to create \"ipmsubtree\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_INBOX,
	    PRIVATE_FID_IPMSUBTREE, user_id, "IPF.Note")) {
		printf("fail to create \"inbox\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_DRAFT,
	    PRIVATE_FID_IPMSUBTREE, user_id, "IPF.Note")) {
		printf("fail to create \"draft\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_OUTBOX,
	    PRIVATE_FID_IPMSUBTREE, user_id, "IPF.Note")) {
		printf("fail to create \"outbox\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_SENT_ITEMS,
	    PRIVATE_FID_IPMSUBTREE, user_id, "IPF.Note")) {
		printf("fail to create \"sent\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_DELETED_ITEMS,
	    PRIVATE_FID_IPMSUBTREE, user_id, "IPF.Note")) {
		printf("fail to create \"deleted\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_CONTACTS,
	    PRIVATE_FID_IPMSUBTREE, user_id, "IPF.Contact")) {
		printf("fail to create \"contacts\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_CALENDAR,
	    PRIVATE_FID_IPMSUBTREE, user_id, "IPF.Appointment")) {
		printf("fail to create \"calendar\" folder\n");
		return 10;
	}
	snprintf(tmp_sql, arsizeof(tmp_sql), "INSERT INTO permissions (folder_id, "
		"username, permission) VALUES (%u, 'default', %u)",
	        PRIVATE_FID_CALENDAR, frightsFreeBusySimple);
	gx_sql_exec(psqlite, tmp_sql);
	if (!create_generic_folder(psqlite, PRIVATE_FID_JOURNAL,
	    PRIVATE_FID_IPMSUBTREE, user_id, "IPF.Journal")) {
		printf("fail to create \"journal\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_NOTES,
	    PRIVATE_FID_IPMSUBTREE, user_id, "IPF.StickyNote")) {
		printf("fail to create \"notes\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_TASKS,
	    PRIVATE_FID_IPMSUBTREE, user_id, "IPF.Task")) {
		printf("fail to create \"tasks\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_QUICKCONTACTS,
	    PRIVATE_FID_CONTACTS, user_id, "IPF.Contact.MOC.QuickContacts", TRUE)) {
		printf("fail to create \"quick contacts\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_IMCONTACTLIST,
	    PRIVATE_FID_CONTACTS, user_id, "IPF.Contact.MOC.ImContactList", TRUE)) {
		printf("fail to create \"im contacts list\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_GALCONTACTS,
	    PRIVATE_FID_CONTACTS, user_id, "IPF.Contact.GalContacts", TRUE)) {
		printf("fail to create \"contacts\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_JUNK,
	    PRIVATE_FID_IPMSUBTREE, user_id, "IPF.Note")) {
		printf("fail to create \"junk\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_CONVERSATION_ACTION_SETTINGS,
	    PRIVATE_FID_IPMSUBTREE, user_id, "IPF.Configuration", TRUE)) {
		printf("fail to create \"conversation action settings\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_DEFERRED_ACTION,
	    PRIVATE_FID_ROOT, user_id)) {
		printf("fail to create \"deferred action\" folder\n");
		return 10;
	}
	if (!create_search_folder(psqlite, PRIVATE_FID_SPOOLER_QUEUE,
	    PRIVATE_FID_ROOT, user_id, "IPF.Note")) {
		printf("fail to create \"spooler queue\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_COMMON_VIEWS,
	    PRIVATE_FID_ROOT, user_id)) {
		printf("fail to create \"common views\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_SCHEDULE,
	    PRIVATE_FID_ROOT, user_id)) {
		printf("fail to create \"schedule\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_FINDER,
	    PRIVATE_FID_ROOT, user_id)) {
		printf("fail to create \"finder\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_VIEWS,
	    PRIVATE_FID_ROOT, user_id)) {
		printf("fail to create \"views\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_SHORTCUTS,
	    PRIVATE_FID_ROOT, user_id)) {
		printf("fail to create \"shortcuts\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_SYNC_ISSUES,
	    PRIVATE_FID_IPMSUBTREE, user_id, "IPF.Note")) {
		printf("fail to create \"sync issues\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_CONFLICTS,
	    PRIVATE_FID_SYNC_ISSUES, user_id, "IPF.Note")) {
		printf("fail to create \"conflicts\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_LOCAL_FAILURES,
	    PRIVATE_FID_SYNC_ISSUES, user_id, "IPF.Note")) {
		printf("fail to create \"local failures\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_SERVER_FAILURES,
	    PRIVATE_FID_SYNC_ISSUES, user_id, "IPF.Note")) {
		printf("fail to create \"server failures\" folder\n");
		return 10;
	}
	if (!create_generic_folder(psqlite, PRIVATE_FID_LOCAL_FREEBUSY,
	    PRIVATE_FID_ROOT, user_id)) {
		printf("fail to create \"freebusy data\" folder\n");
		return 10;
	}
	snprintf(tmp_sql, arsizeof(tmp_sql), "INSERT INTO permissions (folder_id, "
		"username, permission) VALUES (%u, 'default', %u)",
	        PRIVATE_FID_LOCAL_FREEBUSY, frightsFreeBusySimple);
	gx_sql_exec(psqlite, tmp_sql);
	pstmt = gx_sql_prep(psqlite, "INSERT INTO configurations VALUES (?, ?)");
	if (pstmt == nullptr)
		return 9;
	tmp_guid = guid_random_new();
	char tmp_bguid[GUIDSTR_SIZE];
	guid_to_string(&tmp_guid, tmp_bguid, arsizeof(tmp_bguid));
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_MAILBOX_GUID);
	sqlite3_bind_text(pstmt, 2, tmp_bguid, -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_CURRENT_EID);
	sqlite3_bind_int64(pstmt, 2, 0x100);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_MAXIMUM_EID);
	sqlite3_bind_int64(pstmt, 2, ALLOCATED_EID_RANGE);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_LAST_CHANGE_NUMBER);
	sqlite3_bind_int64(pstmt, 2, g_last_cn);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_LAST_CID);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_LAST_ARTICLE_NUMBER);
	sqlite3_bind_int64(pstmt, 2, g_last_art);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_SEARCH_STATE);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_DEFAULT_PERMISSION);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_ANONYMOUS_PERMISSION);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	pstmt.finalize();
	sql_transact.commit();
	return EXIT_SUCCESS;
}
