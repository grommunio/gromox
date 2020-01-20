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
#include "exmdb_tool.h"

static uint32_t g_last_art;
static uint64_t g_last_cn = CHANGE_NUMBER_BEGIN;
static uint64_t g_last_eid = ALLOCATED_EID_RANGE;

static BOOL create_generic_folder(sqlite3 *psqlite,
	uint64_t folder_id, uint64_t parent_id, int domain_id,
	const char *pdisplayname, const char *pcontainer_class)
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
	sqlite3_bind_int64(pstmt, 1, PROP_TAG_LOCALCOMMITTIMEMAX);
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
	
	xid.size = 22;
	xid.xid.guid = rop_util_make_domain_guid(domain_id);
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

BOOL exmdb_tool_create(const char *dir, int domain_id, uint64_t max_size)
{
	int i;
	int fd;
	char *pline;
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
	char temp_path[256];
	sqlite3_stmt* pstmt;
	struct stat node_stat;
	
	if (max_size > 0x7FFFFFFF) {
		max_size = 0x7FFFFFFF;
	}
	if (0 != stat("../doc/sqlite3_common.txt", &node_stat)) {
		return FALSE;
	}
	if (0 == S_ISREG(node_stat.st_mode)) {
		return FALSE;
	}
	str_size = node_stat.st_size;
	if (0 != stat("../doc/sqlite3_public.txt", &node_stat)) {
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
	fd = open("../doc/sqlite3_common.txt", O_RDONLY);
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
	fd = open("../doc/sqlite3_public.txt", O_RDONLY);
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
	
	pfile = list_file_init(PKGDATASADIR "/propnames.txt", "%s:256");
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
	
	csql_string = "INSERT INTO store_properties VALUES (?, ?)";
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		csql_string, strlen(csql_string), &pstmt, NULL)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	csql_string = "INSERT INTO store_properties VALUES (?, ?)";
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		csql_string, strlen(csql_string), &pstmt, NULL)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	
	nt_time = rop_util_unix_to_nttime(time(NULL));
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
	if (FALSE == create_generic_folder(psqlite, PUBLIC_FID_ROOT,
		0, domain_id, "Root Container", NULL)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PUBLIC_FID_IPMSUBTREE,
		PUBLIC_FID_ROOT, domain_id, "IPM_SUBTREE", NULL)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PUBLIC_FID_NONIPMSUBTREE,
		PUBLIC_FID_ROOT, domain_id, "NON_IPM_SUBTREE", NULL)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	if (FALSE == create_generic_folder(psqlite, PUBLIC_FID_EFORMSREGISTRY,
		PUBLIC_FID_NONIPMSUBTREE, domain_id, "EFORMS REGISTRY", NULL)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	
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
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		exit(-9);
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
	sqlite3_bind_int64(pstmt, 2, PERMISSION_READANY|
		PERMISSION_CREATE|PERMISSION_FOLDERVISIBLE|
		PERMISSION_EDITOWNED|PERMISSION_DELETEOWNED);
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

void exmdb_tool_init()
{
	/* do nothing */
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

