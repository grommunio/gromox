// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <string>
#include <vector>
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
#define LLU(x) static_cast<unsigned long long>(x)

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

static const struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{nullptr, 'd', HXTYPE_STRING, &opt_datadir, nullptr, nullptr, 0, "Data directory", "DIR"},
	HXOPT_TABLEEND,
};

static BOOL create_generic_folder(sqlite3 *psqlite,
	uint64_t folder_id, uint64_t parent_id, int user_id,
	const char *pdisplayname, const char *pcontainer_class,
	BOOL b_hidden)
{
	PCL *ppcl;
	BINARY *pbin;
	SIZED_XID xid;
	time_t cur_time;
	uint64_t nt_time;
	uint64_t cur_eid;
	uint64_t max_eid;
	uint32_t art_num;
	EXT_PUSH ext_push;
	uint64_t change_num;
	char sql_string[256];
	uint8_t tmp_buff[24];
	
	cur_eid = g_last_eid + 1;
	g_last_eid += ALLOCATED_EID_RANGE;
	max_eid = g_last_eid;
	sprintf(sql_string, "INSERT INTO allocated_eids"
	        " VALUES (%llu, %llu, %lld, 1)", LLU(cur_eid),
	        LLU(max_eid), static_cast<long long>(time(nullptr)));
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	g_last_cn ++;
	change_num = g_last_cn;
	sprintf(sql_string, "INSERT INTO folders "
				"(folder_id, parent_id, change_number, "
				"cur_eid, max_eid) VALUES (?, ?, ?, ?, ?)");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, folder_id);
	if (0 == parent_id) {
		sqlite3_bind_null(pstmt, 2);
	} else {
		sqlite3_bind_int64(pstmt, 2, parent_id);
	}
	sqlite3_bind_int64(pstmt, 3, change_num);
	sqlite3_bind_int64(pstmt, 4, cur_eid);
	sqlite3_bind_int64(pstmt, 5, max_eid);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	pstmt.finalize();
	g_last_art ++;
	art_num = g_last_art;
	sprintf(sql_string, "INSERT INTO "
		"folder_properties VALUES (%llu, ?, ?)", LLU(folder_id));
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_DELETEDCOUNTTOTAL);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_DELETEDFOLDERTOTAL);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_HIERARCHYCHANGENUMBER);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_INTERNETARTICLENUMBER);
	sqlite3_bind_int64(pstmt, 2, art_num);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_ARTICLENUMBERNEXT);
	sqlite3_bind_int64(pstmt, 2, 1);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PR_DISPLAY_NAME);
	sqlite3_bind_text(pstmt, 2, pdisplayname, -1, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_COMMENT);
	sqlite3_bind_text(pstmt, 2, "", -1, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	if (NULL != pcontainer_class) {
		sqlite3_bind_int64(pstmt, 1, PROP_TAG_CONTAINERCLASS);
		sqlite3_bind_text(pstmt, 2, pcontainer_class, -1, SQLITE_STATIC);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			return FALSE;
		}
		sqlite3_reset(pstmt);
	}
	if (TRUE == b_hidden) {
		sqlite3_bind_int64(pstmt, 1, PROP_TAG_ATTRIBUTEHIDDEN);
		sqlite3_bind_int64(pstmt, 2, 1);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			return FALSE;
		}
		sqlite3_reset(pstmt);
	}
	time(&cur_time);
	nt_time =  rop_util_unix_to_nttime(cur_time);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_CREATIONTIME);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_LASTMODIFICATIONTIME);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_HIERREV);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_LOCALCOMMITTIMEMAX);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	xid.size = 22;
	xid.xid.guid = rop_util_make_user_guid(user_id);
	rop_util_value_to_gc(change_num, xid.xid.local_id);
	if (!ext_buffer_push_init(&ext_push, tmp_buff, sizeof(tmp_buff), 0) ||
	    ext_buffer_push_xid(&ext_push, 22, &xid.xid) != EXT_ERR_SUCCESS)
		return false;
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_CHANGEKEY);
	sqlite3_bind_blob(pstmt, 2, ext_push.data,
			ext_push.offset, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	ppcl = pcl_init();
	if (NULL == ppcl) {
		return FALSE;
	}
	if (FALSE == pcl_append(ppcl, &xid)) {
		pcl_free(ppcl);
		return FALSE;
	}
	pbin = pcl_serialize(ppcl);
	if (NULL == pbin) {
		pcl_free(ppcl);
		return FALSE;
	}
	pcl_free(ppcl);
	
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_PREDECESSORCHANGELIST);
	sqlite3_bind_blob(pstmt, 2, pbin->pb, pbin->cb, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		rop_util_free_binary(pbin);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	return TRUE;
}

static BOOL create_search_folder(sqlite3 *psqlite,
	uint64_t folder_id, uint64_t parent_id, int user_id,
	const char *pdisplayname, const char *pcontainer_class)
{
	PCL *ppcl;
	BINARY *pbin;
	SIZED_XID xid;
	time_t cur_time;
	uint64_t nt_time;
	uint32_t art_num;
	EXT_PUSH ext_push;
	uint64_t change_num;
	char sql_string[256];
	uint8_t tmp_buff[24];
	
	g_last_cn ++;
	change_num = g_last_cn;
	sprintf(sql_string, "INSERT INTO folders "
		"(folder_id, parent_id, change_number, is_search,"
		" cur_eid, max_eid) VALUES (?, ?, ?, 1, 0, 0)");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, folder_id);
	if (0 == parent_id) {
		sqlite3_bind_null(pstmt, 2);
	} else {
		sqlite3_bind_int64(pstmt, 2, parent_id);
	}
	sqlite3_bind_int64(pstmt, 3, change_num);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	pstmt.finalize();
	g_last_art ++;
	art_num = g_last_art;
	sprintf(sql_string, "INSERT INTO "
	          "folder_properties VALUES (%llu, ?, ?)", LLU(folder_id));
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_DELETEDCOUNTTOTAL);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_DELETEDFOLDERTOTAL);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_HIERARCHYCHANGENUMBER);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_INTERNETARTICLENUMBER);
	sqlite3_bind_int64(pstmt, 2, art_num);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PR_DISPLAY_NAME);
	sqlite3_bind_text(pstmt, 2, pdisplayname, -1, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_COMMENT);
	sqlite3_bind_text(pstmt, 2, "", -1, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	if (NULL != pcontainer_class) {
		sqlite3_bind_int64(pstmt, 1, PROP_TAG_CONTAINERCLASS);
		sqlite3_bind_text(pstmt, 2, pcontainer_class, -1, SQLITE_STATIC);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			return FALSE;
		}
		sqlite3_reset(pstmt);
	}
	sqlite3_reset(pstmt);
	time(&cur_time);
	nt_time = rop_util_unix_to_nttime(cur_time);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_CREATIONTIME);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_LASTMODIFICATIONTIME);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_HIERREV);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_LOCALCOMMITTIMEMAX);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	xid.size = 22;
	xid.xid.guid = rop_util_make_user_guid(user_id);
	rop_util_value_to_gc(change_num, xid.xid.local_id);
	if (!ext_buffer_push_init(&ext_push, tmp_buff, sizeof(tmp_buff), 0) ||
	    ext_buffer_push_xid(&ext_push, 22, &xid.xid) != EXT_ERR_SUCCESS)
		return false;
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_CHANGEKEY);
	sqlite3_bind_blob(pstmt, 2, ext_push.data,
			ext_push.offset, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	ppcl = pcl_init();
	if (NULL == ppcl) {
		return FALSE;
	}
	if (FALSE == pcl_append(ppcl, &xid)) {
		pcl_free(ppcl);
		return FALSE;
	}
	pbin = pcl_serialize(ppcl);
	if (NULL == pbin) {
		pcl_free(ppcl);
		return FALSE;
	}
	pcl_free(ppcl);
	
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_PREDECESSORCHANGELIST);
	sqlite3_bind_blob(pstmt, 2, pbin->pb, pbin->cb, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		rop_util_free_binary(pbin);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	return TRUE;
}

int main(int argc, const char **argv)
{
	int user_id;
	char *err_msg;
	char lang[32];
	MYSQL *pmysql;
	char dir[256];
	GUID tmp_guid;
	int mysql_port;
	uint16_t propid;
	MYSQL_ROW myrow;
	uint64_t nt_time;
	sqlite3 *psqlite;
	uint64_t max_size;
	char db_name[256];
	MYSQL_RES *pmyres;
	char tmp_buff[256];
	char tmp_sql[1024];
	char temp_path[256];
	char mysql_host[256];
	char mysql_user[256];
	static char folder_lang[RES_TOTAL_NUM][64];
	
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
	auto str_value = config_file_get_value(pconfig, "MYSQL_HOST");
	if (NULL == str_value) {
		strcpy(mysql_host, "localhost");
	} else {
		gx_strlcpy(mysql_host, str_value, GX_ARRAY_SIZE(mysql_host));
	}
	
	str_value = config_file_get_value(pconfig, "MYSQL_PORT");
	if (NULL == str_value) {
		mysql_port = 3306;
	} else {
		mysql_port = atoi(str_value);
		if (mysql_port <= 0) {
			mysql_port = 3306;
		}
	}

	str_value = config_file_get_value(pconfig, "MYSQL_USERNAME");
	gx_strlcpy(mysql_user, str_value != nullptr ? str_value : "root", GX_ARRAY_SIZE(mysql_user));
	auto mysql_passwd = config_file_get_value(pconfig, "MYSQL_PASSWORD");
	str_value = config_file_get_value(pconfig, "MYSQL_DBNAME");
	if (NULL == str_value) {
		strcpy(db_name, "email");
	} else {
		gx_strlcpy(db_name, str_value, GX_ARRAY_SIZE(db_name));
	}
	const char *datadir = opt_datadir != nullptr ? opt_datadir :
	                      config_file_get_value(pconfig, "data_file_path");
	if (datadir == nullptr)
		datadir = PKGDATADIR;
	
	if (NULL == (pmysql = mysql_init(NULL))) {
		printf("Failed to init mysql object\n");
		return 3;
	}

	if (NULL == mysql_real_connect(pmysql, mysql_host, mysql_user,
		mysql_passwd, db_name, mysql_port, NULL, 0)) {
		mysql_close(pmysql);
		printf("Failed to connect to the database\n");
		return 3;
	}
	
	sprintf(tmp_sql, "SELECT max_size, maildir, lang,"
		"address_type, address_status, id FROM users "
		"WHERE username='%s'", argv[1]);
	
	if (0 != mysql_query(pmysql, tmp_sql) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		printf("fail to query database\n");
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
	
	if (0 != atoi(myrow[3])) {
		printf("address type is not normal\n");
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return 4;
	}
	
	if (0 != atoi(myrow[4])) {
		printf("warning: address status is not alive!\n");
	}
	
	max_size = atoi(myrow[0])*1024;
	gx_strlcpy(dir, myrow[1], GX_ARRAY_SIZE(dir));
	gx_strlcpy(lang, myrow[2], GX_ARRAY_SIZE(lang));
	user_id = atoi(myrow[5]);
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	
	auto pfile = list_file_initd("folder_lang.txt", datadir,
		"%s:64%s:64%s:64%s:64%s:64%s:64%s:64%s:64%s"
		":64%s:64%s:64%s:64%s:64%s:64%s:64%s:64%s:64");
	if (NULL == pfile) {
		printf("list_file_initd folder_lang.txt: %s\n", strerror(errno));
		return 7;
	}
	auto line_num = pfile->get_size();
	auto pline = static_cast<char *>(pfile->get_list());
	size_t i;
	for (i = 0; i < line_num; ++i) {
		if (0 != strcasecmp(pline + 1088*i, lang)) {
			continue;
		}
		for (size_t j = 0; j < RES_TOTAL_NUM; ++j)
			gx_strlcpy(folder_lang[j], pline + 1088 * i + 64 * (j + 1), GX_ARRAY_SIZE(folder_lang[j]));
		break;
	}
	pfile.reset();
	if (i >= line_num) {
		strcpy(folder_lang[RES_ID_IPM], "Top of Information Store");
		strcpy(folder_lang[RES_ID_INBOX], "Inbox");
		strcpy(folder_lang[RES_ID_DRAFT], "Drafts");
		strcpy(folder_lang[RES_ID_OUTBOX], "Outbox");
		strcpy(folder_lang[RES_ID_SENT], "Sent Items");
		strcpy(folder_lang[RES_ID_DELETED], "Deleted Items");
		strcpy(folder_lang[RES_ID_CONTACTS], "Contacts");
		strcpy(folder_lang[RES_ID_CALENDAR], "Calendar");
		strcpy(folder_lang[RES_ID_JOURNAL], "Journal");
		strcpy(folder_lang[RES_ID_NOTES], "Notes");
		strcpy(folder_lang[RES_ID_TASKS], "Tasks");
		strcpy(folder_lang[RES_ID_JUNK], "Junk E-mail");
		strcpy(folder_lang[RES_ID_SYNC], "Sync Issues");
		strcpy(folder_lang[RES_ID_CONFLICT], "Conflicts");
		strcpy(folder_lang[RES_ID_LOCAL], "Local Failures");
		strcpy(folder_lang[RES_ID_SERVER], "Server Failures");
	}
	
	snprintf(temp_path, 256, "%s/exmdb", dir);
	if (mkdir(temp_path, 0777) && errno != EEXIST) {
		fprintf(stderr, "E-1420: mkdir %s: %s\n", temp_path, strerror(errno));
		return 6;
	}
	snprintf(temp_path, 256, "%s/exmdb/exchange.sqlite3", dir);
	/*
	 * sqlite3_open does not expose O_EXCL, so let's create the file under
	 * EXCL semantics ahead of time.
	 */
	auto tfd = open(temp_path, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (tfd >= 0) {
		close(tfd);
	} else if (errno == EEXIST) {
		printf("can not create store database,"
			" %s already exists\n", temp_path);
		return 6;
	}
	
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
		return 9;
	}
	auto cl_0 = make_scope_exit([]() { sqlite3_shutdown(); });
	if (SQLITE_OK != sqlite3_open_v2(temp_path, &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		printf("fail to create store database\n");
		return 9;
	}
	auto cl_1 = make_scope_exit([&]() { sqlite3_close(psqlite); });
	if (chmod(temp_path, 0666) < 0)
		fprintf(stderr, "W-1350: chmod %s: %s\n", temp_path, strerror(errno));
	/* begin the transaction */
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (sqlite3_exec(psqlite, sql_string.c_str(), nullptr, nullptr,
	    &err_msg) != SQLITE_OK) {
		printf("fail to execute table creation sql, error: %s\n", err_msg);
		return 9;
	}
	
	std::vector<std::string> namedprop_list;
	auto ret = list_file_read_fixedstrings("propnames.txt", datadir, namedprop_list);
	if (ret == -ENOENT) {
	} else if (ret < 0) {
		printf("list_file_initd propnames.txt: %s\n", strerror(-ret));
		return 7;
	}
	const char *csql_string = "INSERT INTO named_properties VALUES (?, ?)";
	auto pstmt = gx_sql_prep(psqlite, csql_string);
	if (pstmt == nullptr) {
		return 9;
	}
	
	i = 0;
	for (const auto &name : namedprop_list) {
		propid = 0x8001 + i;
		sqlite3_bind_int64(pstmt, 1, propid);
		sqlite3_bind_text(pstmt, 2, name.c_str(), -1, SQLITE_STATIC);
		if (sqlite3_step(pstmt) != SQLITE_DONE) {
			printf("fail to step sql inserting\n");
			return 9;
		}
		sqlite3_reset(pstmt);
	}
	pstmt.finalize();
	
	nt_time = rop_util_unix_to_nttime(time(NULL));
	
	csql_string = "INSERT INTO receive_table VALUES (?, ?, ?)";
	pstmt = gx_sql_prep(psqlite, csql_string);
	if (pstmt == nullptr) {
		return 9;
	}
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
	
	csql_string = "INSERT INTO store_properties VALUES (?, ?)";
	pstmt = gx_sql_prep(psqlite, csql_string);
	if (pstmt == nullptr) {
		return 9;
	}
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_CREATIONTIME);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_PROHIBITRECEIVEQUOTA);
	sqlite3_bind_int64(pstmt, 2, max_size);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_PROHIBITSENDQUOTA);
	sqlite3_bind_int64(pstmt, 2, max_size);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_STORAGEQUOTALIMIT);
	sqlite3_bind_int64(pstmt, 2, max_size);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_OUTOFOFFICESTATE);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_MESSAGESIZEEXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_ASSOCMESSAGESIZEEXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_NORMALMESSAGESIZEEXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	pstmt.finalize();
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_ROOT,
		0, user_id, "Root Container", NULL, FALSE)) {
		printf("fail to create \"root container\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_IPMSUBTREE,
		PRIVATE_FID_ROOT, user_id, folder_lang[RES_ID_IPM], NULL, FALSE)) {
		printf("fail to create \"ipmsubtree\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_INBOX,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_INBOX],
		"IPF.Note", FALSE)) {
		printf("fail to create \"inbox\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_DRAFT,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_DRAFT],
		"IPF.Note", FALSE)) {
		printf("fail to create \"draft\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_OUTBOX,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_OUTBOX],
		"IPF.Note", FALSE)) {
		printf("fail to create \"outbox\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_SENT_ITEMS,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_SENT],
		"IPF.Note", FALSE)) {
		printf("fail to create \"sent\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_DELETED_ITEMS,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_DELETED],
		"IPF.Note", FALSE)) {
		printf("fail to create \"deleted\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_CONTACTS,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_CONTACTS],
		"IPF.Contact", FALSE)) {
		printf("fail to create \"contacts\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_CALENDAR,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_CALENDAR],
		"IPF.Appointment", FALSE)) {
		printf("fail to create \"calendar\" folder\n");
		return 10;
	}
	sprintf(tmp_sql, "INSERT INTO permissions (folder_id, "
		"username, permission) VALUES (%u, 'default', %u)",
		PRIVATE_FID_CALENDAR, PERMISSION_FREEBUSYSIMPLE);
	sqlite3_exec(psqlite, tmp_sql, NULL, NULL, NULL);
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_JOURNAL,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_JOURNAL],
		"IPF.Journal", FALSE)) {
		printf("fail to create \"journal\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_NOTES,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_NOTES],
		"IPF.StickyNote", FALSE)) {
		printf("fail to create \"notes\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_TASKS,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_TASKS],
		"IPF.Task", FALSE)) {
		printf("fail to create \"tasks\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_QUICKCONTACTS,
		PRIVATE_FID_CONTACTS, user_id, "Quick Contacts",
		"IPF.Contact.MOC.QuickContacts", TRUE)) {
		printf("fail to create \"quick contacts\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_IMCONTACTLIST,
		PRIVATE_FID_CONTACTS, user_id, "IM Contacts List",
		"IPF.Contact.MOC.ImContactList", TRUE)) {
		printf("fail to create \"im contacts list\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_GALCONTACTS,
		PRIVATE_FID_CONTACTS, user_id, "GAL Contacts",
		"IPF.Contact.GalContacts", TRUE)) {
		printf("fail to create \"contacts\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_JUNK,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_JUNK],
		"IPF.Note", FALSE)) {
		printf("fail to create \"junk\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite,
		PRIVATE_FID_CONVERSATION_ACTION_SETTINGS, PRIVATE_FID_IPMSUBTREE,
		user_id, "Conversation Action Settings", "IPF.Configuration", TRUE)) {
		printf("fail to create \"conversation action settings\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_DEFERRED_ACTION,
		PRIVATE_FID_ROOT, user_id, "Deferred Action", NULL, FALSE)) {
		printf("fail to create \"deferred action\" folder\n");
		return 10;
	}
	if (FALSE == create_search_folder(psqlite, PRIVATE_FID_SPOOLER_QUEUE,
		PRIVATE_FID_ROOT, user_id, "Spooler Queue", "IPF.Note")) {
		printf("fail to create \"spooler queue\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_COMMON_VIEWS,
		PRIVATE_FID_ROOT, user_id, "Common Views", NULL, FALSE)) {
		printf("fail to create \"common views\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_SCHEDULE,
		PRIVATE_FID_ROOT, user_id, "Schedule", NULL, FALSE)) {
		printf("fail to create \"schedule\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_FINDER,
		PRIVATE_FID_ROOT, user_id, "Finder", NULL, FALSE)) {
		printf("fail to create \"finder\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_VIEWS,
		PRIVATE_FID_ROOT, user_id, "Views", NULL, FALSE)) {
		printf("fail to create \"views\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_SHORTCUTS,
		PRIVATE_FID_ROOT, user_id, "Shortcuts", NULL, FALSE)) {
		printf("fail to create \"shortcuts\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_SYNC_ISSUES,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_SYNC],
		"IPF.Note", FALSE)) {
		printf("fail to create \"sync issues\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_CONFLICTS,
		PRIVATE_FID_SYNC_ISSUES, user_id, folder_lang[RES_ID_CONFLICT],
		"IPF.Note", FALSE)) {
		printf("fail to create \"conflicts\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite,
		PRIVATE_FID_LOCAL_FAILURES, PRIVATE_FID_SYNC_ISSUES,
		user_id, folder_lang[RES_ID_LOCAL], "IPF.Note", FALSE)) {
		printf("fail to create \"local failures\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite,
		PRIVATE_FID_SERVER_FAILURES, PRIVATE_FID_SYNC_ISSUES,
		user_id, folder_lang[RES_ID_SERVER], "IPF.Note", FALSE)) {
		printf("fail to create \"server failures\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_LOCAL_FREEBUSY,
		PRIVATE_FID_ROOT, user_id, "Freebusy Data", NULL, FALSE)) {
		printf("fail to create \"freebusy data\" folder\n");
		return 10;
	}
	sprintf(tmp_sql, "INSERT INTO permissions (folder_id, "
		"username, permission) VALUES (%u, 'default', %u)",
		PRIVATE_FID_LOCAL_FREEBUSY, PERMISSION_FREEBUSYSIMPLE);
	sqlite3_exec(psqlite, tmp_sql, NULL, NULL, NULL);
	csql_string = "INSERT INTO configurations VALUES (?, ?)";
	pstmt = gx_sql_prep(psqlite, csql_string);
	if (pstmt == nullptr) {
		return 9;
	}
	tmp_guid = guid_random_new();
	guid_to_string(&tmp_guid, tmp_buff, sizeof(tmp_buff));
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_MAILBOX_GUID);
	sqlite3_bind_text(pstmt, 2, tmp_buff, -1, SQLITE_STATIC);
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
	
	/* commit the transaction */
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	return EXIT_SUCCESS;
}
