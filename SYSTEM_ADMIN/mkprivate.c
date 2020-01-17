#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <errno.h>
#include <libHX/option.h>
#include <gromox/paths.h>
#include "config_file.h"
#include "ext_buffer.h"
#include "mapi_types.h"
#include "list_file.h"
#include "rop_util.h"
#include "proptags.h"
#include "guid.h"
#include "pcl.h"
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <mysql/mysql.h>

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
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{.ln = "version", .type = HXTYPE_NONE, .ptr = &opt_show_version, .help = "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static BOOL create_generic_folder(sqlite3 *psqlite,
	uint64_t folder_id, uint64_t parent_id, int user_id,
	const char *pdisplayname, const char *pcontainer_class,
	BOOL b_hidden)
{
	PCL *ppcl;
	int sql_len;
	BINARY *pbin;
	SIZED_XID xid;
	time_t cur_time;
	uint64_t nt_time;
	uint64_t cur_eid;
	uint64_t max_eid;
	uint32_t art_num;
	EXT_PUSH ext_push;
	uint64_t change_num;
	sqlite3_stmt* pstmt;
	char sql_string[256];
	uint8_t tmp_buff[24];
	
	cur_eid = g_last_eid + 1;
	g_last_eid += ALLOCATED_EID_RANGE;
	max_eid = g_last_eid;
	sprintf(sql_string, "INSERT INTO allocated_eids"
			" VALUES (%llu, %llu, %lu, 1)", cur_eid,
			max_eid, time(NULL));
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	g_last_cn ++;
	change_num = g_last_cn;
	sql_len = sprintf(sql_string, "INSERT INTO folders "
				"(folder_id, parent_id, change_number, "
				"cur_eid, max_eid) VALUES (?, ?, ?, ?, ?)");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
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
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_finalize(pstmt);
	g_last_art ++;
	art_num = g_last_art;
	sql_len = sprintf(sql_string, "INSERT INTO "
		"folder_properties VALUES (%llu, ?, ?)", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_DELETEDCOUNTTOTAL);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_DELETEDFOLDERTOTAL);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_HIERARCHYCHANGENUMBER);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_INTERNETARTICLENUMBER);
	sqlite3_bind_int64(pstmt, 2, art_num);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_ARTICLENUMBERNEXT);
	sqlite3_bind_int64(pstmt, 2, 1);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_DISPLAYNAME);
	sqlite3_bind_text(pstmt, 2, pdisplayname, -1, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_COMMENT);
	sqlite3_bind_text(pstmt, 2, "", -1, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	if (NULL != pcontainer_class) {
		sqlite3_bind_int64(pstmt, 1, PROP_TAG_CONTAINERCLASS);
		sqlite3_bind_text(pstmt, 2, pcontainer_class, -1, SQLITE_STATIC);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		sqlite3_reset(pstmt);
	}
	if (TRUE == b_hidden) {
		sqlite3_bind_int64(pstmt, 1, PROP_TAG_ATTRIBUTEHIDDEN);
		sqlite3_bind_int64(pstmt, 2, 1);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		sqlite3_reset(pstmt);
	}
	time(&cur_time);
	nt_time =  rop_util_unix_to_nttime(cur_time);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_CREATIONTIME);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_LASTMODIFICATIONTIME);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_HIERREV);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_LOCALCOMMITTIMEMAX);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	xid.size = 22;
	xid.xid.guid = rop_util_make_user_guid(user_id);
	rop_util_value_to_gc(change_num, xid.xid.local_id);
	ext_buffer_push_init(&ext_push, tmp_buff, sizeof(tmp_buff), 0);
	ext_buffer_push_xid(&ext_push, 22, &xid.xid);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_CHANGEKEY);
	sqlite3_bind_blob(pstmt, 2, ext_push.data,
			ext_push.offset, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	ppcl = pcl_init();
	if (NULL == ppcl) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	if (FALSE == pcl_append(ppcl, &xid)) {
		pcl_free(ppcl);
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	pbin = pcl_serialize(ppcl);
	if (NULL == pbin) {
		pcl_free(ppcl);
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	pcl_free(ppcl);
	
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_PREDECESSORCHANGELIST);
	sqlite3_bind_blob(pstmt, 2, pbin->pb, pbin->cb, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		rop_util_free_binary(pbin);
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	sqlite3_finalize(pstmt);
	
	return TRUE;
}

static BOOL create_search_folder(sqlite3 *psqlite,
	uint64_t folder_id, uint64_t parent_id, int user_id,
	const char *pdisplayname, const char *pcontainer_class)
{
	PCL *ppcl;
	int sql_len;
	BINARY *pbin;
	SIZED_XID xid;
	time_t cur_time;
	uint64_t nt_time;
	uint32_t art_num;
	EXT_PUSH ext_push;
	uint64_t change_num;
	sqlite3_stmt* pstmt;
	char sql_string[256];
	uint8_t tmp_buff[24];
	
	g_last_cn ++;
	change_num = g_last_cn;
	sql_len = sprintf(sql_string, "INSERT INTO folders "
		"(folder_id, parent_id, change_number, is_search,"
		" cur_eid, max_eid) VALUES (?, ?, ?, 1, 0, 0)");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	sqlite3_bind_int64(pstmt, 1, folder_id);
	if (0 == parent_id) {
		sqlite3_bind_null(pstmt, 2);
	} else {
		sqlite3_bind_int64(pstmt, 2, parent_id);
	}
	sqlite3_bind_int64(pstmt, 3, change_num);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_finalize(pstmt);
	g_last_art ++;
	art_num = g_last_art;
	sql_len = sprintf(sql_string, "INSERT INTO "
		"folder_properties VALUES (%llu, ?, ?)", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_DELETEDCOUNTTOTAL);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_DELETEDFOLDERTOTAL);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_HIERARCHYCHANGENUMBER);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_INTERNETARTICLENUMBER);
	sqlite3_bind_int64(pstmt, 2, art_num);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_DISPLAYNAME);
	sqlite3_bind_text(pstmt, 2, pdisplayname, -1, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_COMMENT);
	sqlite3_bind_text(pstmt, 2, "", -1, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	if (NULL != pcontainer_class) {
		sqlite3_bind_int64(pstmt, 1, PROP_TAG_CONTAINERCLASS);
		sqlite3_bind_text(pstmt, 2, pcontainer_class, -1, SQLITE_STATIC);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
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
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_LASTMODIFICATIONTIME);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_HIERREV);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_LOCALCOMMITTIMEMAX);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	xid.size = 22;
	xid.xid.guid = rop_util_make_user_guid(user_id);
	rop_util_value_to_gc(change_num, xid.xid.local_id);
	ext_buffer_push_init(&ext_push, tmp_buff, sizeof(tmp_buff), 0);
	ext_buffer_push_xid(&ext_push, 22, &xid.xid);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_CHANGEKEY);
	sqlite3_bind_blob(pstmt, 2, ext_push.data,
			ext_push.offset, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	ppcl = pcl_init();
	if (NULL == ppcl) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	if (FALSE == pcl_append(ppcl, &xid)) {
		pcl_free(ppcl);
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	pbin = pcl_serialize(ppcl);
	if (NULL == pbin) {
		pcl_free(ppcl);
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	pcl_free(ppcl);
	
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_PREDECESSORCHANGELIST);
	sqlite3_bind_blob(pstmt, 2, pbin->pb, pbin->cb, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		rop_util_free_binary(pbin);
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	sqlite3_finalize(pstmt);
	
	return TRUE;
}

int main(int argc, const char **argv)
{
	int user_id;
	char *pline;
	int i, j, fd;
	int line_num;
	int str_size;
	int str_size1;
	char *err_msg;
	char lang[32];
	MYSQL *pmysql;
	char dir[256];
	GUID tmp_guid;
	int mysql_port;
	uint16_t propid;
	char *str_value;
	MYSQL_ROW myrow;
	LIST_FILE *pfile;
	uint64_t nt_time;
	char *sql_string;
	sqlite3 *psqlite;
	uint64_t max_size;
	char db_name[256];
	MYSQL_RES *pmyres;
	char *mysql_passwd;
	char tmp_buff[256];
	char tmp_sql[1024];
	char temp_path[256];
	sqlite3_stmt* pstmt;
	char mysql_host[256];
	char mysql_user[256];
	CONFIG_FILE *pconfig;
	struct stat node_stat;
	static char folder_lang[RES_TOTAL_NUM][64];
	
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	
	if (2 != argc) {
		printf("usage: %s <username>\n", argv[0]);
		return 1;
	}
	umask(0);
	pconfig = config_file_init2(NULL, PKGSYSCONFDIR "/sa.cfg");
	if (NULL == pconfig) {
		printf("config_file_init %s: %s\n", PKGSYSCONFDIR "/sa.cfg", strerror(errno));
		return 2;
	}

	str_value = config_file_get_value(pconfig, "MYSQL_HOST");
	if (NULL == str_value) {
		strcpy(mysql_host, "localhost");
	} else {
		strcpy(mysql_host, str_value);
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
	if (NULL == str_value) {
		mysql_user[0] = '\0';
	} else {
		strcpy(mysql_user, str_value);
	}

	mysql_passwd = config_file_get_value(pconfig, "MYSQL_PASSWORD");

	str_value = config_file_get_value(pconfig, "MYSQL_DBNAME");
	if (NULL == str_value) {
		strcpy(db_name, "email");
	} else {
		strcpy(db_name, str_value);
	}
	
	if (NULL == (pmysql = mysql_init(NULL))) {
		printf("fail to init mysql object\n");
		config_file_free(pconfig);
		return 3;
	}

	if (NULL == mysql_real_connect(pmysql, mysql_host, mysql_user,
		mysql_passwd, db_name, mysql_port, NULL, 0)) {
		mysql_close(pmysql);
		config_file_free(pconfig);
		printf("fail to connect database\n");
		return 3;
	}
	
	config_file_free(pconfig);

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
	strcpy(dir, myrow[1]);
	strcpy(lang, myrow[2]);
	user_id = atoi(myrow[5]);
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	
	pfile = list_file_init(PKGDATASADIR "/folder_lang.txt",
		"%s:64%s:64%s:64%s:64%s:64%s:64%s:64%s:64%s"
		":64%s:64%s:64%s:64%s:64%s:64%s:64%s:64%s:64");
	if (NULL == pfile) {
		printf("Failed to read %s: %s\n",
			PKGDATASADIR "/folder_lang.txt", strerror(errno));
		return 7;
	}
	line_num = list_file_get_item_num(pfile);
	pline = list_file_get_list(pfile);
	for (i=0; i<line_num; i++) {
		if (0 != strcasecmp(pline + 1088*i, lang)) {
			continue;
		}
		for (j=0; j<RES_TOTAL_NUM; j++) {
			strcpy(folder_lang[j], pline + 1088*i + 64*(j + 1));
		}
		break;
	}
	list_file_free(pfile);
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
	if (0 != stat(temp_path, &node_stat)) {
		mkdir(temp_path, 0777);
	}
	
	snprintf(temp_path, 256, "%s/exmdb/exchange.sqlite3", dir);
	if (0 == stat(temp_path, &node_stat)) {
		printf("can not create sotre database,"
			" %s already exits\n", temp_path);
		return 6;
	}
	
	if (0 != stat(PKGDATASADIR "/doc/sqlite3_common.txt", &node_stat)) {
		printf("can not find store template"
			" file \"sqlite3_common.txt\"\n");	
		return 7;
	}
	if (0 == S_ISREG(node_stat.st_mode)) {
		printf("\"sqlite3_common.txt\" is not a regular file\n");
		return 7;
	}
	str_size = node_stat.st_size;
	
	if (0 != stat(PKGDATASADIR "/doc/sqlite3_private.txt", &node_stat)) {
		printf("can not find store template "
			"file \"sqlite3_private.txt\"\n");	
		return 7;
	}
	if (0 == S_ISREG(node_stat.st_mode)) {
		printf("\"sqlite3_private.txt\" is not a regular file\n");
		return 7;
	}
	str_size1 = node_stat.st_size;
	
	sql_string = malloc(str_size + str_size1 + 1);
	if (NULL == sql_string) {
		printf("fail to allocate memory\n");
		return 8;
	}
	fd = open(PKGDATASADIR "/doc/sqlite3_common.txt", O_RDONLY);
	if (-1 == fd) {
		printf("fail to open \"sqlite3_common.txt\" for reading\n");
		free(sql_string);
		return 7;
	}
	if (str_size != read(fd, sql_string, str_size)) {
		printf("fail to read content from store"
			" template file \"sqlite3_common.txt\"\n");
		close(fd);
		free(sql_string);
		return 7;
	}
	close(fd);
	fd = open(PKGDATASADIR "/doc/sqlite3_private.txt", O_RDONLY);
	if (-1 == fd) {
		printf("fail to open \"sqlite3_private.txt\" for reading\n");
		free(sql_string);
		return 7;
	}
	if (str_size1 != read(fd, sql_string + str_size, str_size1)) {
		printf("fail to read content from store"
			" template file \"sqlite3_private.txt\"\n");
		close(fd);
		free(sql_string);
		return 7;
	}
	close(fd);
	sql_string[str_size + str_size1] = '\0';
	if (SQLITE_OK != sqlite3_initialize()) {
		printf("fail to initialize sqlite engine\n");
		free(sql_string);
		return 9;
	}
	if (SQLITE_OK != sqlite3_open_v2(temp_path, &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		printf("fail to create store database\n");
		free(sql_string);
		sqlite3_shutdown();
		return 9;
	}
	chmod(temp_path, 0666);
	/* begin the transaction */
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
	
	pfile = list_file_init(PKGDATASADIR "/propnames.txt", "%s:256");
	if (NULL == pfile) {
		printf("fail to read \"propnames.txt\"\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 7;
	}
	line_num = list_file_get_item_num(pfile);
	pline = list_file_get_list(pfile);
	
	const char *csql_string = "INSERT INTO named_properties VALUES (?, ?)";
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		csql_string, strlen(csql_string), &pstmt, NULL)) {
		printf("fail to prepare sql statement\n");
		list_file_free(pfile);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	
	for (i=0; i<line_num; i++) {
		propid = 0x8001 + i;
		sqlite3_bind_int64(pstmt, 1, propid);
		sqlite3_bind_text(pstmt, 2, pline + 256*i, -1, SQLITE_STATIC);
		if (sqlite3_step(pstmt) != SQLITE_DONE) {
			printf("fail to step sql inserting\n");
			list_file_free(pfile);
			sqlite3_finalize(pstmt);
			sqlite3_close(psqlite);
			sqlite3_shutdown();
			return 9;
		}
		sqlite3_reset(pstmt);
	}
	list_file_free(pfile);
	sqlite3_finalize(pstmt);
	
	nt_time = rop_util_unix_to_nttime(time(NULL));
	
	csql_string = "INSERT INTO receive_table VALUES (?, ?, ?)";
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		csql_string, strlen(csql_string), &pstmt, NULL)) {
		printf("fail to prepare sql statement\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_bind_text(pstmt, 1, "", -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, PRIVATE_FID_INBOX);
	sqlite3_bind_int64(pstmt, 3, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_text(pstmt, 1, "IPC", -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, PRIVATE_FID_ROOT);
	sqlite3_bind_int64(pstmt, 3, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_text(pstmt, 1, "IPM", -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, PRIVATE_FID_INBOX);
	sqlite3_bind_int64(pstmt, 3, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_text(pstmt, 1, "REPORT.IPM", -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, PRIVATE_FID_INBOX);
	sqlite3_bind_int64(pstmt, 3, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_finalize(pstmt);
	
	csql_string = "INSERT INTO store_properties VALUES (?, ?)";
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		csql_string, strlen(csql_string), &pstmt, NULL)) {
		printf("fail to prepare sql statement\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_CREATIONTIME);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_PROHIBITRECEIVEQUOTA);
	sqlite3_bind_int64(pstmt, 2, max_size);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_PROHIBITSENDQUOTA);
	sqlite3_bind_int64(pstmt, 2, max_size);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_STORAGEQUOTALIMIT);
	sqlite3_bind_int64(pstmt, 2, max_size);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_OUTOFOFFICESTATE);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_MESSAGESIZEEXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_ASSOCMESSAGESIZEEXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_NORMALMESSAGESIZEEXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_finalize(pstmt);
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_ROOT,
		0, user_id, "Root Container", NULL, FALSE)) {
		printf("fail to create \"root container\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_IPMSUBTREE,
		PRIVATE_FID_ROOT, user_id, folder_lang[RES_ID_IPM], NULL, FALSE)) {
		printf("fail to create \"ipmsubtree\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_INBOX,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_INBOX],
		"IPF.Note", FALSE)) {
		printf("fail to create \"inbox\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_DRAFT,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_DRAFT],
		"IPF.Note", FALSE)) {
		printf("fail to create \"draft\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_OUTBOX,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_OUTBOX],
		"IPF.Note", FALSE)) {
		printf("fail to create \"outbox\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_SENT_ITEMS,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_SENT],
		"IPF.Note", FALSE)) {
		printf("fail to create \"sent\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_DELETED_ITEMS,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_DELETED],
		"IPF.Note", FALSE)) {
		printf("fail to create \"deleted\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_CONTACTS,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_CONTACTS],
		"IPF.Contact", FALSE)) {
		printf("fail to create \"contacts\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_CALENDAR,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_CALENDAR],
		"IPF.Appointment", FALSE)) {
		printf("fail to create \"calendar\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	sprintf(tmp_sql, "INSERT INTO permissions (folder_id, "
		"username, permission) VALUES (%llu, 'default', %u)",
		PRIVATE_FID_CALENDAR, PERMISSION_FREEBUSYSIMPLE);
	sqlite3_exec(psqlite, tmp_sql, NULL, NULL, NULL);
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_JOURNAL,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_JOURNAL],
		"IPF.Journal", FALSE)) {
		printf("fail to create \"journal\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_NOTES,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_NOTES],
		"IPF.StickyNote", FALSE)) {
		printf("fail to create \"notes\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_TASKS,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_TASKS],
		"IPF.Task", FALSE)) {
		printf("fail to create \"tasks\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_QUICKCONTACTS,
		PRIVATE_FID_CONTACTS, user_id, "Quick Contacts",
		"IPF.Contact.MOC.QuickContacts", TRUE)) {
		printf("fail to create \"quick contacts\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_IMCONTACTLIST,
		PRIVATE_FID_CONTACTS, user_id, "IM Contacts List",
		"IPF.Contact.MOC.ImContactList", TRUE)) {
		printf("fail to create \"im contacts list\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_GALCONTACTS,
		PRIVATE_FID_CONTACTS, user_id, "GAL Contacts",
		"IPF.Contact.GalContacts", TRUE)) {
		printf("fail to create \"contacts\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_JUNK,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_JUNK],
		"IPF.Note", FALSE)) {
		printf("fail to create \"junk\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite,
		PRIVATE_FID_CONVERSATION_ACTION_SETTINGS, PRIVATE_FID_IPMSUBTREE,
		user_id, "Conversation Action Settings", "IPF.Configuration", TRUE)) {
		printf("fail to create \"conversation action settings\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_DEFERRED_ACTION,
		PRIVATE_FID_ROOT, user_id, "Deferred Action", NULL, FALSE)) {
		printf("fail to create \"deferred action\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_search_folder(psqlite, PRIVATE_FID_SPOOLER_QUEUE,
		PRIVATE_FID_ROOT, user_id, "Spooler Queue", "IPF.Note")) {
		printf("fail to create \"spooler queue\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_COMMON_VIEWS,
		PRIVATE_FID_ROOT, user_id, "Common Views", NULL, FALSE)) {
		printf("fail to create \"common views\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_SCHEDULE,
		PRIVATE_FID_ROOT, user_id, "Schedule", NULL, FALSE)) {
		printf("fail to create \"schedule\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_FINDER,
		PRIVATE_FID_ROOT, user_id, "Finder", NULL, FALSE)) {
		printf("fail to create \"finder\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_VIEWS,
		PRIVATE_FID_ROOT, user_id, "Views", NULL, FALSE)) {
		printf("fail to create \"views\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_SHORTCUTS,
		PRIVATE_FID_ROOT, user_id, "Shortcuts", NULL, FALSE)) {
		printf("fail to create \"shortcuts\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_SYNC_ISSUES,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_SYNC],
		"IPF.Note", FALSE)) {
		printf("fail to create \"sync issues\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_CONFLICTS,
		PRIVATE_FID_SYNC_ISSUES, user_id, folder_lang[RES_ID_CONFLICT],
		"IPF.Note", FALSE)) {
		printf("fail to create \"conflicts\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite,
		PRIVATE_FID_LOCAL_FAILURES, PRIVATE_FID_SYNC_ISSUES,
		user_id, folder_lang[RES_ID_LOCAL], "IPF.Note", FALSE)) {
		printf("fail to create \"local failures\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite,
		PRIVATE_FID_SERVER_FAILURES, PRIVATE_FID_SYNC_ISSUES,
		user_id, folder_lang[RES_ID_SERVER], "IPF.Note", FALSE)) {
		printf("fail to create \"server failures\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_LOCAL_FREEBUSY,
		PRIVATE_FID_ROOT, user_id, "Freebusy Data", NULL, FALSE)) {
		printf("fail to create \"freebusy data\" folder\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 10;
	}
	sprintf(tmp_sql, "INSERT INTO permissions (folder_id, "
		"username, permission) VALUES (%llu, 'default', %u)",
		PRIVATE_FID_LOCAL_FREEBUSY, PERMISSION_FREEBUSYSIMPLE);
	sqlite3_exec(psqlite, tmp_sql, NULL, NULL, NULL);
	csql_string = "INSERT INTO configurations VALUES (?, ?)";
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		csql_string, strlen(csql_string), &pstmt, NULL)) {
		printf("fail to prepare sql statement\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	tmp_guid = guid_random_new();
	guid_to_string(&tmp_guid, tmp_buff, sizeof(tmp_buff));
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_MAILBOX_GUID);
	sqlite3_bind_text(pstmt, 2, tmp_buff, -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_CURRENT_EID);
	sqlite3_bind_int64(pstmt, 2, 0x100);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_MAXIMUM_EID);
	sqlite3_bind_int64(pstmt, 2, ALLOCATED_EID_RANGE);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_LAST_CHANGE_NUMBER);
	sqlite3_bind_int64(pstmt, 2, g_last_cn);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_LAST_CID);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_LAST_ARTICLE_NUMBER);
	sqlite3_bind_int64(pstmt, 2, g_last_art);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_SEARCH_STATE);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_DEFAULT_PERMISSION);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_ANONYMOUS_PERMISSION);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	sqlite3_finalize(pstmt);
	
	/* commit the transaction */
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	sqlite3_close(psqlite);
	sqlite3_shutdown();
	exit(0);
}
