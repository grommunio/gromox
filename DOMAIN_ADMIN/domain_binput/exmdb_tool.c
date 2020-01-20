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
#include "exmdb_tool.h"

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

static char g_data_path[256];
static uint32_t g_last_art;
static uint64_t g_last_cn = CHANGE_NUMBER_BEGIN;
static uint64_t g_last_eid = ALLOCATED_EID_RANGE;

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

BOOL exmdb_tool_create(const char *dir, uint64_t max_size,
	const char *lang, int user_id)
{
	char *pline;
	int i, j, fd;
	int line_num;
	int str_size;
	int str_size1;
	char *err_msg;
	GUID tmp_guid;
	uint16_t propid;
	LIST_FILE *pfile;
	uint64_t nt_time;
	char *sql_string;
	sqlite3 *psqlite;
	char tmp_buff[256];
	char tmp_sql[1024];
	char temp_path[256];
	sqlite3_stmt* pstmt;
	struct stat node_stat;
	char folder_lang[RES_TOTAL_NUM][64];
	
	sprintf(temp_path, "%s/folder_lang.txt", g_data_path);
	pfile = list_file_init(temp_path,
		"%s:64%s:64%s:64%s:64%s:64%s:64%s:64%s:64%s:"
		"64%s:64%s:64%s:64%s:64%s:64%s:64%s:64%s:64");
	if (NULL == pfile) {
		return FALSE;
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
	sprintf(temp_path, "%s/sqlite3_common.txt", g_data_path);
	if (0 != stat(temp_path, &node_stat)) {
		return FALSE;
	}
	if (0 == S_ISREG(node_stat.st_mode)) {
		return FALSE;
	}
	str_size = node_stat.st_size;
	sprintf(temp_path, "%s/sqlite3_private.txt", g_data_path);
	if (0 != stat(temp_path, &node_stat)) {
		return FALSE;
	}
	if (0 == S_ISREG(node_stat.st_mode)) {
		return FALSE;
	}
	str_size1 = node_stat.st_size;
	
	sql_string = malloc(str_size + str_size1 + 1);
	if (NULL == sql_string) {
		return FALSE;
	}
	sprintf(temp_path, "%s/sqlite3_common.txt", g_data_path);
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		free(sql_string);
		return FALSE;
	}
	if (str_size != read(fd, sql_string, str_size)) {
		close(fd);
		free(sql_string);
		return FALSE;
	}
	close(fd);
	sprintf(temp_path, "%s/sqlite3_private.txt", g_data_path);
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		free(sql_string);
		return FALSE;
	}
	if (str_size1 != read(fd, sql_string + str_size, str_size1)) {
		close(fd);
		free(sql_string);
		return FALSE;
	}
	close(fd);
	sql_string[str_size + str_size1] = '\0';
	if (SQLITE_OK != sqlite3_initialize()) {
		free(sql_string);
		return FALSE;
	}
	snprintf(temp_path, 256, "%s/exmdb/exchange.sqlite3", dir);
	if (SQLITE_OK != sqlite3_open_v2(temp_path, &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		free(sql_string);
		sqlite3_shutdown();
		return FALSE;
	}
	chmod(temp_path, 0666);
	/* begin the transaction */
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, &err_msg)) {
		free(sql_string);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	free(sql_string);
	sprintf(temp_path, "%s/propnames.txt", g_data_path);
	pfile = list_file_init(temp_path, "%s:256");
	if (NULL == pfile) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	line_num = list_file_get_item_num(pfile);
	pline = list_file_get_list(pfile);
	
	const char *csql_string = "INSERT INTO named_properties VALUES (?, ?)";
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		csql_string, strlen(csql_string), &pstmt, NULL)) {
		list_file_free(pfile);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	
	for (i=0; i<line_num; i++) {
		propid = 0x8001 + i;
		sqlite3_bind_int64(pstmt, 1, propid);
		sqlite3_bind_text(pstmt, 2, pline + 256*i, -1, SQLITE_STATIC);
		if (sqlite3_step(pstmt) != SQLITE_DONE) {
			list_file_free(pfile);
			sqlite3_finalize(pstmt);
			sqlite3_close(psqlite);
			sqlite3_shutdown();
			return FALSE;
		}
		sqlite3_reset(pstmt);
	}
	list_file_free(pfile);
	sqlite3_finalize(pstmt);
	
	nt_time = rop_util_unix_to_nttime(time(NULL));
	
	csql_string = "INSERT INTO receive_table VALUES (?, ?, ?)";
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		csql_string, strlen(csql_string), &pstmt, NULL)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_bind_text(pstmt, 1, "", -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, PRIVATE_FID_INBOX);
	sqlite3_bind_int64(pstmt, 3, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_text(pstmt, 1, "IPC", -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, PRIVATE_FID_ROOT);
	sqlite3_bind_int64(pstmt, 3, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_text(pstmt, 1, "IPM", -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, PRIVATE_FID_INBOX);
	sqlite3_bind_int64(pstmt, 3, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_text(pstmt, 1, "REPORT.IPM", -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, PRIVATE_FID_INBOX);
	sqlite3_bind_int64(pstmt, 3, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_finalize(pstmt);
	
	csql_string = "INSERT INTO store_properties VALUES (?, ?)";
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		csql_string, strlen(csql_string), &pstmt, NULL)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_CREATIONTIME);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_PROHIBITRECEIVEQUOTA);
	sqlite3_bind_int64(pstmt, 2, max_size);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_PROHIBITSENDQUOTA);
	sqlite3_bind_int64(pstmt, 2, max_size);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_STORAGEQUOTALIMIT);
	sqlite3_bind_int64(pstmt, 2, max_size);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_OUTOFOFFICESTATE);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_MESSAGESIZEEXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_ASSOCMESSAGESIZEEXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_NORMALMESSAGESIZEEXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_finalize(pstmt);
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_ROOT,
		0, user_id, "Root Container", NULL, FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_IPMSUBTREE,
		PRIVATE_FID_ROOT, user_id, folder_lang[RES_ID_IPM], NULL, FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_INBOX,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_INBOX],
		"IPF.Note", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_DRAFT,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_DRAFT],
		"IPF.Note", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_OUTBOX,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_OUTBOX],
		"IPF.Note", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_SENT_ITEMS,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_SENT],
		"IPF.Note", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_DELETED_ITEMS,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_DELETED],
		"IPF.Note", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_CONTACTS,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_CONTACTS],
		"IPF.Contact", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_CALENDAR,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_CALENDAR],
		"IPF.Appointment", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;	
	}
	sprintf(tmp_sql, "INSERT INTO permissions (folder_id, "
		"username, permission) VALUES (%llu, 'default', %u)",
		PRIVATE_FID_CALENDAR, PERMISSION_FREEBUSYSIMPLE);
	sqlite3_exec(psqlite, tmp_sql, NULL, NULL, NULL);
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_JOURNAL,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_JOURNAL],
		"IPF.Journal", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_NOTES,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_NOTES],
		"IPF.StickyNote", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_TASKS,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_TASKS],
		"IPF.Task", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_QUICKCONTACTS,
		PRIVATE_FID_CONTACTS, user_id, "Quick Contacts",
		"IPF.Contact.MOC.QuickContacts", TRUE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_IMCONTACTLIST,
		PRIVATE_FID_CONTACTS, user_id, "IM Contacts List",
		"IPF.Contact.MOC.ImContactList", TRUE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_GALCONTACTS,
		PRIVATE_FID_CONTACTS, user_id, "GAL Contacts",
		"IPF.Contact.GalContacts", TRUE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_JUNK,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_JUNK],
		"IPF.Note", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite,
		PRIVATE_FID_CONVERSATION_ACTION_SETTINGS, PRIVATE_FID_IPMSUBTREE,
		user_id, "Conversation Action Settings", "IPF.Configuration", TRUE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_DEFERRED_ACTION,
		PRIVATE_FID_ROOT, user_id, "Deferred Action", NULL, FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_search_folder(psqlite, PRIVATE_FID_SPOOLER_QUEUE,
		PRIVATE_FID_ROOT, user_id, "Spooler Queue", "IPF.Note")) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_COMMON_VIEWS,
		PRIVATE_FID_ROOT, user_id, "Common Views", NULL, FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_SCHEDULE,
		PRIVATE_FID_ROOT, user_id, "Schedule", NULL, FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_FINDER,
		PRIVATE_FID_ROOT, user_id, "Finder", NULL, FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_VIEWS,
		PRIVATE_FID_ROOT, user_id, "Views", NULL, FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_SHORTCUTS,
		PRIVATE_FID_ROOT, user_id, "Shortcuts", NULL, FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_SYNC_ISSUES,
		PRIVATE_FID_IPMSUBTREE, user_id, folder_lang[RES_ID_SYNC],
		"IPF.Note", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_CONFLICTS,
		PRIVATE_FID_SYNC_ISSUES, user_id, folder_lang[RES_ID_CONFLICT],
		"IPF.Note", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite,
		PRIVATE_FID_LOCAL_FAILURES, PRIVATE_FID_SYNC_ISSUES,
		user_id, folder_lang[RES_ID_LOCAL], "IPF.Note", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite,
		PRIVATE_FID_SERVER_FAILURES, PRIVATE_FID_SYNC_ISSUES,
		user_id, folder_lang[RES_ID_SERVER], "IPF.Note", FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PRIVATE_FID_LOCAL_FREEBUSY,
		PRIVATE_FID_ROOT, user_id, "Freebusy Data", NULL, FALSE)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sprintf(tmp_sql, "INSERT INTO permissions (folder_id, "
		"username, permission) VALUES (%llu, 'default', %u)",
		PRIVATE_FID_LOCAL_FREEBUSY, PERMISSION_FREEBUSYSIMPLE);
	sqlite3_exec(psqlite, tmp_sql, NULL, NULL, NULL);
	csql_string = "INSERT INTO configurations VALUES (?, ?)";
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		csql_string, strlen(csql_string), &pstmt, NULL)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	tmp_guid = guid_random_new();
	guid_to_string(&tmp_guid, tmp_buff, sizeof(tmp_buff));
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_MAILBOX_GUID);
	sqlite3_bind_text(pstmt, 2, tmp_buff, -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_CURRENT_EID);
	sqlite3_bind_int64(pstmt, 2, 0x100);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_MAXIMUM_EID);
	sqlite3_bind_int64(pstmt, 2, ALLOCATED_EID_RANGE);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_LAST_CHANGE_NUMBER);
	sqlite3_bind_int64(pstmt, 2, g_last_cn);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_LAST_CID);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_LAST_ARTICLE_NUMBER);
	sqlite3_bind_int64(pstmt, 2, g_last_art);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_SEARCH_STATE);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_DEFAULT_PERMISSION);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_ANONYMOUS_PERMISSION);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_finalize(pstmt);
	
	/* commit the transaction */
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	sqlite3_close(psqlite);
	sqlite3_shutdown();
	return TRUE;
}

void exmdb_tool_init(const char *data_path)
{
	strcpy(g_data_path, data_path);
}

int exmdb_tool_run()
{
	return 0;
}

int exmdb_tool_stop()
{
	return 0;
}

void exmdb_tool_free()
{
	/* do nothing */
}
