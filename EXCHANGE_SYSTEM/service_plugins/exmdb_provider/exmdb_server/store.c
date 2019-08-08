#include "exmdb_server.h"
#include "common_util.h"
#include "list_file.h"
#include "db_engine.h"
#include "rop_util.h"
#include "guid.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define MAXIMUM_ALLOCATION_NUMBER				1000000

#define ALLOCATION_INTERVAL						24*60*60

BOOL exmdb_server_ping_store(const char *dir)
{
	DB_ITEM *pdb;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_get_all_named_propids(
	const char *dir, PROPID_ARRAY *ppropids)
{
	int sql_len;
	DB_ITEM *pdb;
	int total_count;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT "
			"count(*) FROM named_properties");
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return FALSE;
	}
	total_count = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	if (0 == total_count) {
		db_engine_put_db(pdb);
		ppropids->count = 0;
		ppropids->ppropid = NULL;
		return TRUE;
	}
	ppropids->ppropid = common_util_alloc(
			sizeof(uint16_t)*total_count);
	if (NULL == ppropids->ppropid) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT"
		" propid FROM named_properties");
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	ppropids->count = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		ppropids->ppropid[ppropids->count] =
				sqlite3_column_int64(pstmt, 0);
		ppropids->count ++;
	}
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_get_named_propids(const char *dir,
	BOOL b_create, const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids)
{
	DB_ITEM *pdb;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == common_util_get_named_propids(
		pdb->psqlite, b_create, ppropnames, ppropids)) {
		/* rollback the transaction */
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	/* commit the transaction */
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_get_named_propnames(const char *dir,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames)
{
	DB_ITEM *pdb;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == common_util_get_named_propnames(
		pdb->psqlite, ppropids, ppropnames)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_put_db(pdb);
	return TRUE;
}

/* public only */
BOOL exmdb_server_get_mapping_guid(const char *dir,
	uint16_t replid, BOOL *pb_found, GUID *pguid)
{
	int sql_len;
	DB_ITEM *pdb;
	sqlite3_stmt *pstmt;
	char sql_string[128];
	
	if (TRUE == exmdb_server_check_private()) {
		return FALSE;
	}
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == common_util_get_mapping_guid(
		pdb->psqlite, replid, pb_found, pguid)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_put_db(pdb);
	*pb_found = TRUE;
	return TRUE;
}

/* public only */
BOOL exmdb_server_get_mapping_replid(const char *dir,
	GUID guid, BOOL *pb_found, uint16_t *preplid)
{
	int sql_len;
	DB_ITEM *pdb;
	sqlite3_stmt *pstmt;
	char guid_string[64];
	char sql_string[128];
	
	if (TRUE == exmdb_server_check_private()) {
		return FALSE;
	}
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	guid_to_string(&guid, guid_string, 64);
	sql_len = sprintf(sql_string, "SELECT replid FROM "
		"replca_mapping WHERE replguid='%s'", guid_string);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		*pb_found = FALSE;
		return TRUE;
	}
	*preplid = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	*pb_found = TRUE;
	return TRUE;
}

BOOL exmdb_server_get_store_all_proptags(
	const char *dir, PROPTAG_ARRAY *pproptags)
{
	DB_ITEM *pdb;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == common_util_get_proptags(
		STORE_PROPERTIES_TABLE, 0,
		pdb->psqlite, pproptags)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_get_store_properties(const char *dir,
	uint32_t cpid, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals)
{
	DB_ITEM *pdb;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == common_util_get_properties(
		STORE_PROPERTIES_TABLE, 0, cpid, pdb->psqlite,
		pproptags, ppropvals)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_set_store_properties(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *ppropvals,
	PROBLEM_ARRAY *pproblems)
{
	DB_ITEM *pdb;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == common_util_set_properties(
		STORE_PROPERTIES_TABLE, 0, cpid, pdb->psqlite,
		ppropvals, pproblems)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_remove_store_properties(
	const char *dir, const PROPTAG_ARRAY *pproptags)
{
	DB_ITEM *pdb;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == common_util_remove_properties(
		STORE_PROPERTIES_TABLE, 0, pdb->psqlite, pproptags)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	db_engine_put_db(pdb);
	return TRUE;
}

/* private only */
BOOL exmdb_server_check_mailbox_permission(const char *dir,
	const char *username, uint32_t *ppermission)
{
	int i;
	int sql_len;
	char *pitem;
	int item_num;
	DB_ITEM *pdb;
	LIST_FILE *pfile;
	sqlite3_stmt *pstmt;
	char temp_path[256];
	char sql_string[128];
	
	if (FALSE == exmdb_server_check_private()) {
		return FALSE;
	}
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	*ppermission = 0;
	sql_len = sprintf(sql_string, "SELECT permission "
				"FROM permissions WHERE username=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		*ppermission |= sqlite3_column_int64(pstmt, 0);
	}
	sqlite3_finalize(pstmt);
	sql_len = sprintf(sql_string, "SELECT "
		"username, permission FROM permissions");
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		if (TRUE == common_util_check_mlist_include(
			sqlite3_column_text(pstmt, 0), username)) {
			*ppermission |= sqlite3_column_int64(pstmt, 1);
		}
	}
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	sprintf(temp_path, "%s/config/delegates.txt", dir);
	pfile = list_file_init(temp_path, "%s:256");
	if (NULL != pfile) {
		item_num = list_file_get_item_num(pfile);
		pitem = list_file_get_list(pfile);
		for (i=0; i<item_num; i++) {
			if (0 == strcasecmp(pitem + 256*i, username) ||
				TRUE == common_util_check_mlist_include(
				pitem + 256*i, username)) {
				*ppermission |= PERMISSION_SENDAS;
				break;
			}
		}
		list_file_free(pfile);
	}
	return TRUE;
}

BOOL exmdb_server_allocate_cn(const char *dir, uint64_t *pcn)
{
	DB_ITEM *pdb;
	uint64_t change_num;
		
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == common_util_allocate_cn(pdb->psqlite, &change_num)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_put_db(pdb);
	*pcn = rop_util_make_eid_ex(1, change_num);
	return TRUE;
}

/* if *pbegin_eid is 0, means too many
	allocation requests within an interval */
BOOL exmdb_server_allocate_ids(const char *dir,
	uint32_t count, uint64_t *pbegin_eid)
{
	int sql_len;
	DB_ITEM *pdb;
	uint64_t tmp_eid;
	uint64_t range_end;
	sqlite3_stmt *pstmt;
	uint64_t range_begin;
	char sql_string[128];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT range_begin, "
				"range_end, is_system FROM allocated_eids"
				" WHERE allocate_time>=%lu",
				time(NULL) - ALLOCATION_INTERVAL);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	range_begin = 0;
	range_end = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		if (1 == sqlite3_column_int64(pstmt, 2)) {
			continue;
		}
		tmp_eid = sqlite3_column_int64(pstmt, 0);
		if (0 == range_begin) {
			range_begin = tmp_eid;
		} else {
			if (tmp_eid < range_begin) {
				range_begin = tmp_eid;
			}
		}
		tmp_eid = sqlite3_column_int64(pstmt, 1);
		if (0 == range_end) {
			range_end = tmp_eid;
		} else {
			if (tmp_eid > range_end) {
				range_end = tmp_eid;
			}
		}
	}
	sqlite3_finalize(pstmt);
	if (range_end - range_begin + count > MAXIMUM_ALLOCATION_NUMBER) {
		db_engine_put_db(pdb);
		*pbegin_eid = 0;
		return TRUE;
	}
	sql_len = sprintf(sql_string, "SELECT "
		"max(range_end) FROM allocated_eids");
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return FALSE;
	}
	tmp_eid = sqlite3_column_int64(pstmt, 0) + 1;
	sqlite3_finalize(pstmt);
	sql_len = sprintf(sql_string, "INSERT INTO allocated_eids "
		"VALUES (%llu, %llu, %lu, 0)", tmp_eid, tmp_eid + count,
		time(NULL));
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_put_db(pdb);
	*pbegin_eid = rop_util_make_eid_ex(1, tmp_eid);
	return TRUE;
}

BOOL exmdb_server_subscribe_notification(const char *dir,
	uint16_t notificaton_type, BOOL b_whole, uint64_t folder_id,
	uint64_t message_id, uint32_t *psub_id)
{
	DB_ITEM *pdb;
	uint16_t replid;
	NSUB_NODE *pnsub;
	uint32_t last_id;
	const char *remote_id;
	DOUBLE_LIST_NODE *pnode;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	pnode = double_list_get_tail(&pdb->nsub_list);
	if (NULL == pnode) {
		last_id = 0;
	} else {
		last_id = ((NSUB_NODE*)pnode->pdata)->sub_id;
	}
	pnsub = malloc(sizeof(NSUB_NODE));
	if (NULL == pnsub) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	pnsub->node.pdata = pnsub;
	pnsub->sub_id = last_id + 1;
	remote_id = exmdb_server_get_remote_id();
	if (NULL == remote_id) {
		pnsub->remote_id = NULL;
	} else {
		pnsub->remote_id = strdup(remote_id);
		if (NULL == pnsub->remote_id) {
			free(pnsub);
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	pnsub->notificaton_type = notificaton_type;
	pnsub->b_whole = b_whole;
	if (0 == folder_id) {
		pnsub->folder_id = 0;
	} else {
		if (TRUE == exmdb_server_check_private()) {
			pnsub->folder_id = rop_util_get_gc_value(folder_id);
		} else {
			replid = rop_util_get_replid(folder_id);
			if (1 == replid) {
				pnsub->folder_id = rop_util_get_gc_value(folder_id);
			} else {
				pnsub->folder_id = replid;
				pnsub->folder_id <<= 48;
				pnsub->folder_id |= rop_util_get_gc_value(folder_id);
			}
		}
	}
	if (0 == message_id) {
		pnsub->message_id = 0;
	} else {
		pnsub->message_id = rop_util_get_gc_value(message_id);
	}
	double_list_append_as_tail(&pdb->nsub_list, &pnsub->node);
	db_engine_put_db(pdb);
	*psub_id = last_id + 1;
	return TRUE;
}

BOOL exmdb_server_unsubscribe_notification(
	const char *dir, uint32_t sub_id)
{
	DB_ITEM *pdb;
	NSUB_NODE *pnsub;
	DOUBLE_LIST_NODE *pnode;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (sub_id == pnsub->sub_id) {
			double_list_remove(&pdb->nsub_list, pnode);
			if (NULL != pnsub->remote_id) {
				free(pnsub->remote_id);
			}
			free(pnsub);
			break;
		}
	}
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_transport_new_mail(const char *dir, uint64_t folder_id,
	uint64_t message_id, uint32_t message_flags, const char *pstr_class)
{
	DB_ITEM *pdb;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_transport_new_mail(pdb, rop_util_get_gc_value(folder_id),
		rop_util_get_gc_value(message_id), message_flags, pstr_class);
	db_engine_put_db(pdb);
	return TRUE;
}

static BOOL table_check_address_in_contact_folder(
	sqlite3_stmt *pstmt_subfolder, sqlite3_stmt *pstmt_search,
	uint64_t folder_id, const char *paddress, BOOL *pb_found)
{
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST folder_list;
	
	sqlite3_reset(pstmt_search);
	sqlite3_bind_int64(pstmt_search, 1, folder_id);
	sqlite3_bind_text(pstmt_search, 2, paddress, -1, SQLITE_STATIC);
	if (SQLITE_ROW == sqlite3_step(pstmt_search)) {
		*pb_found = TRUE;
		return TRUE;
	}
	double_list_init(&folder_list);
	sqlite3_reset(pstmt_subfolder);
	sqlite3_bind_int64(pstmt_subfolder, 1, folder_id);
	while (SQLITE_ROW == sqlite3_step(pstmt_subfolder)) {
		pnode = common_util_alloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			return FALSE;
		}
		pnode->pdata = common_util_alloc(sizeof(uint64_t));
		if (NULL == pnode->pdata) {
			return FALSE;
		}
		*(uint64_t*)pnode->pdata =
			sqlite3_column_int64(pstmt_subfolder, 0);
		double_list_append_as_tail(&folder_list, pnode);
	}
	while (pnode=double_list_get_from_head(&folder_list)) {
		if (FALSE == table_check_address_in_contact_folder(pstmt_subfolder,
			pstmt_search, *(uint64_t*)pnode->pdata, paddress, pb_found)) {
			return FALSE;	
		}
		if (TRUE == *pb_found) {
			return TRUE;
		}
	}
	*pb_found = FALSE;
	return TRUE;
}

BOOL exmdb_server_check_contact_address(const char *dir,
	const char *paddress, BOOL *pb_found)
{
	int sql_len;
	DB_ITEM *pdb;
	uint32_t lids[3];
	uint32_t proptags[3];
	char sql_string[512];
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	PROPID_ARRAY propids;
	PROPNAME_ARRAY propnames;
	PROPERTY_NAME propname_buff[3];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	propnames.count = 3;
	propnames.ppropname = propname_buff;
	/* PidLidEmail1EmailAddress */
	propname_buff[0].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[0].guid);
	lids[0] = 0x8083;
	propname_buff[0].plid = &lids[0];
	/* PidLidEmail2EmailAddress */
	propname_buff[1].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[1].guid);
	lids[1] = 0x8093;
	propname_buff[1].plid = &lids[1];
	/* PidLidEmail3EmailAddress */
	propname_buff[2].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[2].guid);
	lids[2] = 0x80A3;
	propname_buff[2].plid = &lids[2];
	if (FALSE == common_util_get_named_propids(pdb->psqlite,
		FALSE, &propnames, &propids) || 3 != propids.count) {
		db_engine_put_db(pdb);
		return FALSE;	
	}
	proptags[0] = propids.ppropid[0];
	proptags[0] <<= 16;
	proptags[0] |= PROPVAL_TYPE_WSTRING;
	proptags[1] = propids.ppropid[1];
	proptags[1] <<= 16;
	proptags[1] |= PROPVAL_TYPE_WSTRING;
	proptags[2] = propids.ppropid[2];
	proptags[2] <<= 16;
	proptags[2] |= PROPVAL_TYPE_WSTRING;
	sql_len = sprintf(sql_string, "SELECT folder_id"
				" FROM folders WHERE parent_id=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT messages.message_id"
		" FROM messages JOIN message_properties ON "
		"messages.message_id=message_properties.message_id "
		"WHERE parent_fid=? AND (message_properties.proptag=%u"
		" OR message_properties.proptag=%u"
		" OR message_properties.proptag=%u)"
		" AND message_properties.propval=?"
		" LIMIT 1", proptags[0], proptags[1],
		proptags[2]);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt2, NULL)) {
		sqlite3_finalize(pstmt1);
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == table_check_address_in_contact_folder(
		pstmt1, pstmt2, PRIVATE_FID_CONTACTS, paddress,
		pb_found)) {
		sqlite3_finalize(pstmt1);
		sqlite3_finalize(pstmt2);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_finalize(pstmt1);
	sqlite3_finalize(pstmt2);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_unload_store(const char *dir)
{
	return db_engine_unload_db(dir);
}
