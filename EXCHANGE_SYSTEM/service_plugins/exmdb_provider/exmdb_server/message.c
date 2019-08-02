#include "bounce_producer.h"
#include "service_common.h"
#include "tpropval_array.h"
#include "proptag_array.h"
#include "exmdb_client.h"
#include "exmdb_server.h"
#include "config_file.h"
#include "common_util.h"
#include "ext_buffer.h"
#include "db_engine.h"
#include "rop_util.h"
#include "oxcmail.h"
#include "guid.h"
#include "util.h"
#include <openssl/md5.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>

#define MIN_BATCH_MESSAGE_NUM						20

typedef struct _RULE_NODE {
	DOUBLE_LIST_NODE node;
	uint32_t sequence;
	uint32_t state;
	uint64_t id;
	char *provider;
} RULE_NODE;

typedef struct _DAM_NODE {
	DOUBLE_LIST_NODE node;
	uint64_t rule_id;
	uint64_t folder_id;
	uint64_t message_id;
	char *provider;
	ACTION_BLOCK *pblock;
} DAM_NODE;

typedef struct _MESSAGE_NODE {
	DOUBLE_LIST_NODE node;
	uint64_t folder_id;
	uint64_t message_id;
} MESSAGE_NODE;

/* CAUTION!!! if a message is soft deleted from public folder,
	it also should be removed from read_states! if someone's
	read stat is "unread", the item of this user should be
	removed from read_states */

/* can be used when submitting message */
BOOL exmdb_server_movecopy_message(const char *dir,
	int account_id, uint32_t cpid, uint64_t message_id,
	uint64_t dst_fid, uint64_t dst_id, BOOL b_move,
	BOOL *pb_result)
{
	int sql_len;
	XID tmp_xid;
	DB_ITEM *pdb;
	void *pvalue;
	BOOL b_result;
	BOOL b_update;
	uint64_t tmp_cn;
	uint64_t nt_time;
	uint64_t mid_val;
	uint64_t dst_val;
	uint64_t fid_val;
	int is_associated;
	uint64_t change_num;
	sqlite3_stmt *pstmt;
	uint64_t parent_fid;
	char sql_string[256];
	uint32_t message_size;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	TAGGED_PROPVAL tmp_propval;
	TAGGED_PROPVAL tmp_propvals[5];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == b_move &&
		TRUE == common_util_check_msgsize_overflow(pdb->psqlite) &&
		TRUE == common_util_check_msgcnt_overflow(pdb->psqlite)) {
		db_engine_put_db(pdb);
		*pb_result = FALSE;
		return TRUE;		
	}
	mid_val = rop_util_get_gc_value(message_id);
	fid_val = rop_util_get_gc_value(dst_fid);
	dst_val = rop_util_get_gc_value(dst_id);
	if (FALSE == common_util_check_allocated_eid(
		pdb->psqlite, dst_val, &b_result)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == b_result) {
		db_engine_put_db(pdb);
		*pb_result = FALSE;
		return TRUE;
	}
	sql_len = sprintf(sql_string, "SELECT message_id "
		"FROM messages WHERE message_id=%llu", dst_val);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		*pb_result = FALSE;
		return TRUE;
	}
	sqlite3_finalize(pstmt);
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sql_len = sprintf(sql_string, "SELECT parent_fid, is_associated"
					" FROM messages WHERE message_id=%llu", mid_val);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		*pb_result = FALSE;
		return TRUE;
	}
	parent_fid = sqlite3_column_int64(pstmt, 0);
	is_associated = sqlite3_column_int64(pstmt, 1);
	sqlite3_finalize(pstmt);
	if (TRUE == b_move) {
		db_engine_proc_dynmaic_event(pdb, cpid,
			DYNAMIC_EVENT_DELETE_MESSAGE,
			parent_fid, mid_val, 0);
	}
	if (FALSE == common_util_copy_message(
		pdb->psqlite, account_id, mid_val,
		fid_val, &dst_val, &b_result, &message_size)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == b_result) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		*pb_result = FALSE;
		return TRUE;
	}
	db_engine_proc_dynmaic_event(pdb, cpid,
		DYNAMIC_EVENT_NEW_MESSAGE, fid_val, dst_val, 0);
	if (FALSE == b_move) {
		db_engine_notify_message_movecopy(pdb, TRUE,
				fid_val, dst_val, parent_fid, mid_val);
	} else {
		db_engine_notify_message_movecopy(pdb, FALSE,
				fid_val, dst_val, parent_fid, mid_val);
	}
	b_update = TRUE;
	if (TRUE == b_move) {
		if (TRUE == exmdb_server_check_private()) {
			sprintf(sql_string, "DELETE FROM messages"
					" WHERE message_id=%llu", mid_val);
			if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				db_engine_put_db(pdb);
				return FALSE;
			}
			b_update = FALSE;
		} else {
			sprintf(sql_string, "UPDATE messages SET "
				"is_deleted=1 WHERE message_id=%llu", mid_val);
			if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				db_engine_put_db(pdb);
				return FALSE;
			}
			sql_len = sprintf(sql_string, "DELETE FROM "
				"read_states message_id=%llu", mid_val);
			if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				db_engine_put_db(pdb);
				return FALSE;
			}
		}
	}
	if (TRUE == b_update) {
		if (0 == is_associated) {
			if (FALSE == common_util_increase_store_size(
				pdb->psqlite, message_size, 0)) {
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				db_engine_put_db(pdb);
				return FALSE;
			}
		} else {
			if (FALSE == common_util_increase_store_size(
				pdb->psqlite, 0, message_size)) {
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				db_engine_put_db(pdb);
				return FALSE;
			}
		}
	}
	nt_time = rop_util_current_nttime();
	if (TRUE == b_move) {
		propvals.count = 5;
		propvals.ppropval = tmp_propvals;
		if (FALSE == common_util_allocate_cn(pdb->psqlite, &change_num)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
		tmp_cn = rop_util_make_eid_ex(1, change_num);
		tmp_propvals[0].proptag = PROP_TAG_CHANGENUMBER;
		tmp_propvals[0].pvalue = &tmp_cn;
		if (TRUE == exmdb_server_check_private()) {
			tmp_xid.guid = rop_util_make_user_guid(account_id);
		} else {
			tmp_xid.guid = rop_util_make_domain_guid(account_id);
		}
		rop_util_value_to_gc(change_num, tmp_xid.local_id);
		tmp_propvals[1].proptag = PROP_TAG_CHANGEKEY;
		tmp_propvals[1].pvalue = common_util_xid_to_binary(22, &tmp_xid);
		if (NULL == tmp_propvals[1].pvalue ||
			FALSE == common_util_get_property(
			FOLDER_PROPERTIES_TABLE, parent_fid, 0,
			pdb->psqlite, PROP_TAG_PREDECESSORCHANGELIST,
			&pvalue)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
		tmp_propvals[2].proptag = PROP_TAG_PREDECESSORCHANGELIST;
		tmp_propvals[2].pvalue = common_util_pcl_append(
						pvalue, tmp_propvals[1].pvalue);
		if (NULL == tmp_propvals[2].pvalue) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
		nt_time = rop_util_current_nttime();
		tmp_propvals[3].proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
		tmp_propvals[3].pvalue = &nt_time;
		tmp_propvals[4].proptag = PROP_TAG_LASTMODIFICATIONTIME;
		tmp_propvals[4].pvalue = &nt_time;
		common_util_set_properties(FOLDER_PROPERTIES_TABLE,
			parent_fid, 0, pdb->psqlite, &propvals, &problems);
		common_util_increase_deleted_count(pdb->psqlite, parent_fid, 1);
	}
	tmp_propval.proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
	tmp_propval.pvalue = &nt_time;
	common_util_set_property(FOLDER_PROPERTIES_TABLE,
		fid_val, 0, pdb->psqlite, &tmp_propval, &b_result);
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	db_engine_put_db(pdb);
	*pb_result = TRUE;
	return TRUE;
}

BOOL exmdb_server_movecopy_messages(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest,
	const char *username, uint64_t src_fid, uint64_t dst_fid,
	BOOL b_copy, const EID_ARRAY *pmessage_ids, BOOL *pb_partial)
{
	int i;
	int sql_len;
	XID tmp_xid;
	DB_ITEM *pdb;
	void *pvalue;
	BOOL b_check;
	BOOL b_owner;
	BOOL b_batch;
	BOOL b_result;
	BOOL b_update;
	uint64_t tmp_cn;
	uint64_t nt_time;
	uint64_t src_val;
	uint64_t dst_val;
	uint64_t tmp_val;
	uint64_t tmp_val1;
	int is_associated;
	uint64_t fai_size;
	uint32_t del_count;
	uint64_t change_num;
	uint32_t permission;
	uint64_t parent_fid;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	char sql_string[256];
	uint32_t folder_type;
	uint64_t normal_size;
	uint32_t message_size;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	TAGGED_PROPVAL tmp_propval;
	TAGGED_PROPVAL tmp_propvals[5];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	*pb_partial = FALSE;
	src_val = rop_util_get_gc_value(src_fid);
	dst_val = rop_util_get_gc_value(dst_fid);
	if (FALSE == common_util_get_folder_type(
		pdb->psqlite, src_val, &folder_type)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (TRUE == b_guest) {
		if (FOLDER_TYPE_SEARCH != folder_type) {
			if (FALSE == common_util_check_folder_permission(
				pdb->psqlite, src_val, username, &permission)) {
				db_engine_put_db(pdb);
				return FALSE;
			}
			if ((PERMISSION_FOLDEROWNER & permission) ||
				(PERMISSION_READANY & permission)) {
				b_check = FALSE;
			} else {
				b_check = TRUE;
			}
		} else {
			b_check = TRUE;
		}
	} else {
		b_check = FALSE;
	}
	if (pmessage_ids->count >= MIN_BATCH_MESSAGE_NUM) {
		b_batch = TRUE;
	} else {
		b_batch = FALSE;
	}
	if (TRUE == b_batch) {
		db_engine_begin_batch_mode(pdb);
	}
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sql_len = sprintf(sql_string, "SELECT parent_fid, "
		"is_associated FROM messages WHERE message_id=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		if (TRUE == b_batch) {
			db_engine_cancel_batch_mode(pdb);
		}
		db_engine_put_db(pdb);
		return FALSE;
	}
	b_update = TRUE;
	if (FALSE == b_copy) {
		if (TRUE == exmdb_server_check_private()) {
			sql_len = sprintf(sql_string, "DELETE FROM "
						"messages WHERE message_id=?");
			b_update = FALSE;
		} else {
			sql_len = sprintf(sql_string, "UPDATE messages"
					" SET is_deleted=1 WHERE message_id=?");
		}
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
			sql_string, sql_len, &pstmt1, NULL)) {
			sqlite3_finalize(pstmt);
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			if (TRUE == b_batch) {
				db_engine_cancel_batch_mode(pdb);
			}
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	fai_size = 0;
	del_count = 0;
	normal_size = 0;
	for (i=0; i<pmessage_ids->count; i++) {
		tmp_val = rop_util_get_gc_value(pmessage_ids->pids[i]);
		sqlite3_bind_int64(pstmt, 1, tmp_val);
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			*pb_partial = TRUE;
			continue;
		}
		parent_fid = sqlite3_column_int64(pstmt, 0);
		is_associated = sqlite3_column_int64(pstmt, 1);
		sqlite3_reset(pstmt);
		if (FOLDER_TYPE_SEARCH == folder_type) {
			if (TRUE == b_check) {
				if (FALSE == common_util_check_folder_permission(
					pdb->psqlite, parent_fid, username, &permission)) {
					goto MVCP_FAILURE;
				}
				if (0 == (permission & PERMISSION_FOLDEROWNER) &&
					0 == (permission & PERMISSION_READANY)) {
					if (FALSE == common_util_check_message_owner(
						pdb->psqlite, tmp_val, username, &b_owner)) {
						goto MVCP_FAILURE;
					}
					if (FALSE == b_owner) {
						*pb_partial = TRUE;
						continue;
					}
				}
			}
		} else {
			if (parent_fid != src_val) {
				*pb_partial = TRUE;
				continue;
			}
			if (TRUE == b_check) {
				if (FALSE == common_util_check_message_owner(
					pdb->psqlite, tmp_val, username, &b_owner)) {
					goto MVCP_FAILURE;
				}
				if (FALSE == b_owner) {
					*pb_partial = TRUE;
					continue;
				}
			}
		}
		if (FALSE == b_copy) {
			db_engine_proc_dynmaic_event(pdb, cpid,
				DYNAMIC_EVENT_DELETE_MESSAGE,
				parent_fid, tmp_val, 0);
		}
		tmp_val1 = 0;
		if (FALSE == common_util_copy_message(
			pdb->psqlite, account_id, tmp_val, dst_val,
			&tmp_val1, &b_result, &message_size)) {
			sqlite3_finalize(pstmt);
			if (FALSE == b_copy) {
				sqlite3_finalize(pstmt1);
			}
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			if (TRUE == b_batch) {
				db_engine_cancel_batch_mode(pdb);
			}
			db_engine_put_db(pdb);
			return FALSE;
		}
		if (FALSE == b_result) {
			*pb_partial = TRUE;
			continue;
		}
		if (0 == is_associated) {
			normal_size += message_size;
		} else {
			fai_size += message_size;
		}
		db_engine_proc_dynmaic_event(pdb, cpid,
			DYNAMIC_EVENT_NEW_MESSAGE,
			dst_val, tmp_val1, 0);
		db_engine_notify_message_movecopy(pdb, b_copy,
				dst_val, tmp_val1, src_val, tmp_val);
		if (FALSE == b_copy) {
			del_count ++;
			sqlite3_bind_int64(pstmt1, 1, tmp_val);
			if (SQLITE_DONE != sqlite3_step(pstmt1)) {
				goto MVCP_FAILURE;
			}
			sqlite3_reset(pstmt1);
			if (FALSE == exmdb_server_check_private()) {
				sprintf(sql_string, "DELETE FROM read_states"
					" WHERE message_id=%llu", tmp_val);
				if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					goto MVCP_FAILURE;
				}
			}
		}
	}
	sqlite3_finalize(pstmt);
	if (FALSE == b_copy) {
		sqlite3_finalize(pstmt1);
	}
	if (TRUE == b_update && normal_size + fai_size > 0) {
		if (FALSE == common_util_increase_store_size(
			pdb->psqlite, normal_size, fai_size)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			if (TRUE == b_batch) {
				db_engine_cancel_batch_mode(pdb);
			}
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	nt_time = rop_util_current_nttime();
	if (FALSE == b_copy) {
		propvals.count = 5;
		propvals.ppropval = tmp_propvals;
		if (FALSE == common_util_allocate_cn(pdb->psqlite, &change_num)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
		tmp_cn = rop_util_make_eid_ex(1, change_num);
		tmp_propvals[0].proptag = PROP_TAG_CHANGENUMBER;
		tmp_propvals[0].pvalue = &tmp_cn;
		if (TRUE == exmdb_server_check_private()) {
			tmp_xid.guid = rop_util_make_user_guid(account_id);
		} else {
			tmp_xid.guid = rop_util_make_domain_guid(account_id);
		}
		rop_util_value_to_gc(change_num, tmp_xid.local_id);
		tmp_propvals[1].proptag = PROP_TAG_CHANGEKEY;
		tmp_propvals[1].pvalue = common_util_xid_to_binary(22, &tmp_xid);
		if (NULL == tmp_propvals[1].pvalue ||
			FALSE == common_util_get_property(
			FOLDER_PROPERTIES_TABLE, parent_fid, 0,
			pdb->psqlite, PROP_TAG_PREDECESSORCHANGELIST,
			&pvalue)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
		tmp_propvals[2].proptag = PROP_TAG_PREDECESSORCHANGELIST;
		tmp_propvals[2].pvalue = common_util_pcl_append(
						pvalue, tmp_propvals[1].pvalue);
		if (NULL == tmp_propvals[2].pvalue) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
		nt_time = rop_util_current_nttime();
		tmp_propvals[3].proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
		tmp_propvals[3].pvalue = &nt_time;
		tmp_propvals[4].proptag = PROP_TAG_LASTMODIFICATIONTIME;
		tmp_propvals[4].pvalue = &nt_time;
		common_util_set_properties(FOLDER_PROPERTIES_TABLE,
			parent_fid, 0, pdb->psqlite, &propvals, &problems);
		common_util_increase_deleted_count(
			pdb->psqlite, parent_fid, del_count);
	}
	tmp_propval.proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
	tmp_propval.pvalue = &nt_time;
	common_util_set_property(FOLDER_PROPERTIES_TABLE,
		dst_val, 0, pdb->psqlite, &tmp_propval, &b_result);
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	if (TRUE == b_batch) {
		db_engine_commit_batch_mode(pdb);
	} else {
		db_engine_put_db(pdb);
	}
	return TRUE;

MVCP_FAILURE:
	sqlite3_finalize(pstmt);
	if (FALSE == b_copy) {
		sqlite3_finalize(pstmt1);
	}
	sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
	if (TRUE == b_batch) {
		db_engine_cancel_batch_mode(pdb);
	}
	db_engine_put_db(pdb);
	return FALSE;
}

BOOL exmdb_server_delete_messages(const char *dir,
	int account_id, uint32_t cpid, const char *username,
	uint64_t folder_id, const EID_ARRAY *pmessage_ids,
	BOOL b_hard, BOOL *pb_partial)
{
	int i;
	int sql_len;
	XID tmp_xid;
	DB_ITEM *pdb;
	void *pvalue;
	BOOL b_batch;
	BOOL b_check;
	BOOL b_owner;
	BOOL b_result;
	int del_count;
	uint64_t tmp_cn;
	uint64_t nt_time;
	uint64_t src_val;
	uint64_t tmp_val;
	uint64_t fai_size;
	uint32_t permission;
	uint64_t parent_fid;
	uint64_t change_num;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	char sql_string[256];
	uint32_t folder_type;
	uint64_t normal_size;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	TAGGED_PROPVAL tmp_propvals[5];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	*pb_partial = FALSE;
	if (TRUE == exmdb_server_check_private()) {
		b_hard = TRUE;
	}
	src_val = rop_util_get_gc_value(folder_id);
	if (FALSE == common_util_get_folder_type(
		pdb->psqlite, src_val, &folder_type)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (NULL != username) {
		if (FOLDER_TYPE_SEARCH != folder_type) {
			if (FALSE == common_util_check_folder_permission(
				pdb->psqlite, src_val, username, &permission)) {
				db_engine_put_db(pdb);
				return FALSE;
			}
			if ((PERMISSION_FOLDEROWNER & permission) ||
				(PERMISSION_DELETEANY & permission)) {
				b_check = FALSE;
			} else {
				b_check = TRUE;
			}
		} else {
			b_check = TRUE;
		}
	} else {
		b_check = FALSE;
	}
	if (pmessage_ids->count >= MIN_BATCH_MESSAGE_NUM) {
		b_batch = TRUE;
	} else {
		b_batch = FALSE;
	}
	if (TRUE == b_batch) {
		db_engine_begin_batch_mode(pdb);
	}
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sql_len = sprintf(sql_string, "SELECT parent_fid, is_associated, "
					"message_size FROM messages WHERE message_id=?");
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		if (TRUE == b_batch) {
			db_engine_cancel_batch_mode(pdb);
		}
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (TRUE == b_hard) {
		sql_len = sprintf(sql_string, "DELETE FROM "
					"messages WHERE message_id=?");
	} else {
		sql_len = sprintf(sql_string, "UPDATE messages"
				" SET is_deleted=1 WHERE message_id=?");
	}
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_exec(pdb->psqlite,
			"ROLLBACK", NULL, NULL, NULL);
		if (TRUE == b_batch) {
			db_engine_cancel_batch_mode(pdb);
		}
		db_engine_put_db(pdb);
		return FALSE;
	}
	fai_size = 0;
	del_count = 0;
	normal_size = 0;
	for (i=0; i<pmessage_ids->count; i++) {
		tmp_val = rop_util_get_gc_value(pmessage_ids->pids[i]);
		sqlite3_bind_int64(pstmt, 1, tmp_val);
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			continue;
		}
		parent_fid = sqlite3_column_int64(pstmt, 0);
		if (0 == sqlite3_column_int64(pstmt, 1)) {
			normal_size += sqlite3_column_int64(pstmt, 2);
		} else {
			fai_size += sqlite3_column_int64(pstmt, 2);
		}
		sqlite3_reset(pstmt);
		if (FOLDER_TYPE_SEARCH == folder_type) {
			if (TRUE == b_check) {
				if (FALSE == common_util_check_folder_permission(
					pdb->psqlite, parent_fid, username, &permission)) {
					sqlite3_finalize(pstmt);
					sqlite3_finalize(pstmt1);
					sqlite3_exec(pdb->psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					if (TRUE == b_batch) {
						db_engine_cancel_batch_mode(pdb);
					}
					db_engine_put_db(pdb);
					return FALSE;
				}
				if (0 == (permission & PERMISSION_FOLDEROWNER) &&
					0 == (permission & PERMISSION_DELETEANY)) {
					if (FALSE == common_util_check_message_owner(
						pdb->psqlite, tmp_val, username, &b_owner)) {
						sqlite3_finalize(pstmt);
						sqlite3_finalize(pstmt1);
						sqlite3_exec(pdb->psqlite,
							"ROLLBACK", NULL, NULL, NULL);
						if (TRUE == b_batch) {
							db_engine_cancel_batch_mode(pdb);
						}
						db_engine_put_db(pdb);
						return FALSE;
					}
					if (FALSE == b_owner) {
						*pb_partial = TRUE;
						continue;
					}
				}
			}
		} else {
			if (parent_fid != src_val) {
				*pb_partial = TRUE;
				continue;
			}
			if (TRUE == b_check) {
				if (FALSE == common_util_check_message_owner(
					pdb->psqlite, tmp_val, username, &b_owner)) {
					sqlite3_finalize(pstmt);
					sqlite3_finalize(pstmt1);
					sqlite3_exec(pdb->psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					if (TRUE == b_batch) {
						db_engine_cancel_batch_mode(pdb);
					}
					db_engine_put_db(pdb);
					return FALSE;
				}
				if (FALSE == b_owner) {
					*pb_partial = TRUE;
					continue;
				}
			}
		}
		del_count ++;
		db_engine_proc_dynmaic_event(pdb, cpid,
			DYNAMIC_EVENT_DELETE_MESSAGE,
			parent_fid, tmp_val, 0);
		if (FOLDER_TYPE_SEARCH == folder_type) {
			db_engine_notify_link_deletion(pdb, src_val, tmp_val);
		} else {
			db_engine_notify_message_deletion(pdb, src_val, tmp_val);
		}
		sqlite3_bind_int64(pstmt1, 1, tmp_val);
		if (SQLITE_DONE != sqlite3_step(pstmt1)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			sqlite3_exec(pdb->psqlite,
				"ROLLBACK", NULL, NULL, NULL);
			if (TRUE == b_batch) {
				db_engine_cancel_batch_mode(pdb);
			}
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_reset(pstmt1);
		if (FALSE == b_hard) {
			sprintf(sql_string, "DELETE FROM read_states"
				" WHERE message_id=%llu", tmp_val);
			if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				sqlite3_exec(pdb->psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				if (TRUE == b_batch) {
					db_engine_cancel_batch_mode(pdb);
				}
				db_engine_put_db(pdb);
				return FALSE;
			}
		}
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	if (TRUE == b_hard) {
		if (FALSE == common_util_decrease_store_size(
			pdb->psqlite, normal_size, fai_size)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			if (TRUE == b_batch) {
				db_engine_cancel_batch_mode(pdb);
			}
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	propvals.count = 5;
	propvals.ppropval = tmp_propvals;
	if (FALSE == common_util_allocate_cn(pdb->psqlite, &change_num)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	tmp_cn = rop_util_make_eid_ex(1, change_num);
	tmp_propvals[0].proptag = PROP_TAG_CHANGENUMBER;
	tmp_propvals[0].pvalue = &tmp_cn;
	if (TRUE == exmdb_server_check_private()) {
		tmp_xid.guid = rop_util_make_user_guid(account_id);
	} else {
		tmp_xid.guid = rop_util_make_domain_guid(account_id);
	}
	rop_util_value_to_gc(change_num, tmp_xid.local_id);
	tmp_propvals[1].proptag = PROP_TAG_CHANGEKEY;
	tmp_propvals[1].pvalue = common_util_xid_to_binary(22, &tmp_xid);
	if (NULL == tmp_propvals[1].pvalue ||
		FALSE == common_util_get_property(
		FOLDER_PROPERTIES_TABLE, src_val, 0,
		pdb->psqlite, PROP_TAG_PREDECESSORCHANGELIST,
		&pvalue)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	tmp_propvals[2].proptag = PROP_TAG_PREDECESSORCHANGELIST;
	tmp_propvals[2].pvalue = common_util_pcl_append(
					pvalue, tmp_propvals[1].pvalue);
	if (NULL == tmp_propvals[2].pvalue) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	nt_time = rop_util_current_nttime();
	tmp_propvals[3].proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
	tmp_propvals[3].pvalue = &nt_time;
	tmp_propvals[4].proptag = PROP_TAG_LASTMODIFICATIONTIME;
	tmp_propvals[4].pvalue = &nt_time;
	common_util_set_properties(FOLDER_PROPERTIES_TABLE,
		src_val, 0, pdb->psqlite, &propvals, &problems);
	common_util_increase_deleted_count(
		pdb->psqlite, src_val, del_count);
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	if (TRUE == b_batch) {
		db_engine_commit_batch_mode(pdb);
	} else {
		db_engine_put_db(pdb);
	}
	return TRUE;
}

static BOOL message_get_message_rcpts(sqlite3 *psqlite,
	uint64_t message_id, TARRAY_SET *pset)
{
	int sql_len;
	uint32_t row_id;
	uint64_t rcpt_id;
	uint32_t rcpt_num;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	char sql_string[256];
	PROPTAG_ARRAY proptags;
	TAGGED_PROPVAL *ppropval;
	uint32_t tmp_proptags[0x8000];
	
	sql_len = sprintf(sql_string, "SELECT count(*) FROM"
		" recipients WHERE message_id=%llu", message_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	rcpt_num = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	pset->count = 0;
	if (0 == rcpt_num) {
		pset->pparray = NULL;
		return TRUE;
	}
	pset->pparray = common_util_alloc(sizeof(TPROPVAL_ARRAY*)*rcpt_num);
	if (NULL == pset->pparray) {
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT recipient_id FROM"
			" recipients WHERE message_id=%llu", message_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT proptag FROM"
		" recipients_properties WHERE recipient_id=?");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	row_id = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		rcpt_id = sqlite3_column_int64(pstmt, 0);
		sqlite3_bind_int64(pstmt1, 1, rcpt_id);
		proptags.count = 0;
		proptags.pproptag = tmp_proptags;
		while (SQLITE_ROW == sqlite3_step(pstmt1)) {
			tmp_proptags[proptags.count] = 
				sqlite3_column_int64(pstmt1, 0);
			proptags.count ++;
		}
		tmp_proptags[proptags.count] = PROP_TAG_ROWID;
		proptags.count ++;
		sqlite3_reset(pstmt1);
		pset->pparray[pset->count] =
			common_util_alloc(sizeof(TPROPVAL_ARRAY));
		if (NULL == pset->pparray[pset->count] ||
			FALSE == common_util_get_properties(
			RECIPIENT_PROPERTIES_TABLE,
			rcpt_id, 0, psqlite, &proptags,
			pset->pparray[pset->count])) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		/* PROP_TAG_ROWID MUST be the first */
		memmove(pset->pparray[pset->count]->ppropval + 1,
			pset->pparray[pset->count]->ppropval, sizeof(
			TAGGED_PROPVAL)*pset->pparray[pset->count]->count);
		ppropval = pset->pparray[pset->count]->ppropval;
		pset->pparray[pset->count]->count ++;
		ppropval->proptag = PROP_TAG_ROWID;
		ppropval->pvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == ppropval->pvalue) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		*(uint32_t*)ppropval->pvalue = row_id;
		row_id ++;
		pset->count ++;
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	return TRUE;
}

BOOL exmdb_server_get_message_brief(const char *dir, uint32_t cpid,
	uint64_t message_id, MESSAGE_CONTENT **ppbrief)
{
	int sql_len;
	DB_ITEM *pdb;
	uint32_t count;
	uint64_t mid_val;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	PROPTAG_ARRAY proptags;
	uint64_t attachment_id;
	uint32_t proptag_buff[16];
	ATTACHMENT_CONTENT *pattachment;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	mid_val = rop_util_get_gc_value(message_id);
	sql_len = sprintf(sql_string, "SELECT message_id FROM"
			" messages WHERE message_id=%llu", mid_val);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		*ppbrief = NULL;
		db_engine_put_db(pdb);
		return TRUE;
	}
	sqlite3_finalize(pstmt);
	*ppbrief = common_util_alloc(sizeof(MESSAGE_CONTENT));
	if (NULL == *ppbrief) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	proptags.count = 9;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_SUBJECT;
	proptag_buff[1] = PROP_TAG_SENTREPRESENTINGNAME;
	proptag_buff[2] = PROP_TAG_SENTREPRESENTINGSMTPADDRESS;
	proptag_buff[3] = PROP_TAG_CLIENTSUBMITTIME;
	proptag_buff[4] = PROP_TAG_MESSAGESIZE;
	proptag_buff[5] = PROP_TAG_INTERNETCODEPAGE;
	proptag_buff[6] = PROP_TAG_INTERNETMESSAGEID;
	proptag_buff[7] = PROP_TAG_PARENTKEY;
	proptag_buff[8] = PROP_TAG_CONVERSATIONINDEX;
	if (FALSE == common_util_get_properties(
		MESSAGE_PROPERTIES_TABLE, mid_val, cpid,
		pdb->psqlite, &proptags, &(*ppbrief)->proplist)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	(*ppbrief)->children.prcpts =
		common_util_alloc(sizeof(TARRAY_SET));
	if (NULL == (*ppbrief)->children.prcpts) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == message_get_message_rcpts(pdb->psqlite,
		mid_val, (*ppbrief)->children.prcpts)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	(*ppbrief)->children.pattachments =
		common_util_alloc(sizeof(ATTACHMENT_LIST));
	if (NULL == (*ppbrief)->children.pattachments) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT count(*) FROM "
		"attachments WHERE message_id=%llu", mid_val);
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
	count = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	(*ppbrief)->children.pattachments->count = 0;
	(*ppbrief)->children.pattachments->pplist =
		common_util_alloc(count*sizeof(ATTACHMENT_CONTENT*));
	if (NULL == (*ppbrief)->children.pattachments->pplist) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT attachment_id FROM "
			"attachments WHERE message_id=%llu", mid_val);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	proptags.count = 1;
	proptag_buff[0] = PROP_TAG_ATTACHLONGFILENAME;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		attachment_id = sqlite3_column_int64(pstmt, 0);
		pattachment = common_util_alloc(sizeof(ATTACHMENT_CONTENT));
		if (NULL == pattachment) {
			sqlite3_finalize(pstmt);
			db_engine_put_db(pdb);
			return FALSE;
		}
		if (FALSE == common_util_get_properties(
			ATTACHMENT_PROPERTIES_TABLE, attachment_id, cpid,
			pdb->psqlite, &proptags, &pattachment->proplist)) {
			sqlite3_finalize(pstmt);
			db_engine_put_db(pdb);
			return FALSE;
		}
		pattachment->pembedded = NULL;
		(*ppbrief)->children.pattachments->pplist[
			(*ppbrief)->children.pattachments->count] = pattachment;
		(*ppbrief)->children.pattachments->count ++;
	}
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_check_message(const char *dir,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_exist)
{
	int sql_len;
	DB_ITEM *pdb;
	uint64_t tmp_val;
	uint64_t fid_val;
	uint64_t mid_val;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	uint32_t folder_type;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	fid_val = rop_util_get_gc_value(folder_id);
	mid_val = rop_util_get_gc_value(message_id);
	if (FALSE == common_util_get_folder_type(
		pdb->psqlite, fid_val, &folder_type)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FOLDER_TYPE_SEARCH == folder_type) {
		sql_len = sprintf(sql_string, "SELECT folder_id FROM"
					" search_result WHERE folder_id=%llu AND"
					" message_id=%llu", fid_val, mid_val);
	} else {
		sql_len = sprintf(sql_string, "SELECT parent_fid FROM"
					" messages WHERE message_id=%llu", mid_val);
	}
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		*pb_exist = FALSE;
		return TRUE;
	}
	tmp_val = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	if (tmp_val == fid_val) {
		*pb_exist = TRUE;
	} else {
		*pb_exist = FALSE;
	}
	return TRUE;
}

BOOL exmdb_server_check_message_deleted(const char *dir,
	uint64_t message_id, BOOL *pb_del)
{
	int sql_len;
	DB_ITEM *pdb;
	uint64_t mid_val;
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
	mid_val = rop_util_get_gc_value(message_id);
	if (TRUE == exmdb_server_check_private()) {
		sql_len = sprintf(sql_string, "SELECT message_id "
			"FROM messages WHERE message_id=%llu", mid_val);
	} else {
		sql_len = sprintf(sql_string, "SELECT is_deleted "
			"FROM messages WHERE message_id=%llu", mid_val);
	}
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		*pb_del = TRUE;
		return TRUE;
	}
	if (FALSE == exmdb_server_check_private()) {
		if (0 != sqlite3_column_int64(pstmt, 0)) {
			sqlite3_finalize(pstmt);
			db_engine_put_db(pdb);
			*pb_del = TRUE;
			return TRUE;
		}
	}
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	*pb_del = FALSE;
	return TRUE;
}

BOOL exmdb_server_get_message_rcpts(const char *dir,
	uint64_t message_id, TARRAY_SET *pset)
{
	int sql_len;
	DB_ITEM *pdb;
	uint64_t mid_val;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	mid_val = rop_util_get_gc_value(message_id);
	if (FALSE == message_get_message_rcpts(
		pdb->psqlite, mid_val, pset)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_get_message_properties(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
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
	if (FALSE == exmdb_server_check_private()) {
		exmdb_server_set_public_username(username);
	}
	if (FALSE == common_util_get_properties(MESSAGE_PROPERTIES_TABLE,
		rop_util_get_gc_value(message_id), cpid, pdb->psqlite,
		pproptags, ppropvals)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_put_db(pdb);
	return TRUE;
}

/* message_size will not be updated in the function! */
BOOL exmdb_server_set_message_properties(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	const TPROPVAL_ARRAY *pproperties, PROBLEM_ARRAY *pproblems)
{
	DB_ITEM *pdb;
	BOOL b_result;
	uint64_t nt_time;
	uint64_t fid_val;
	uint64_t mid_val;
	TAGGED_PROPVAL tmp_propval;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == exmdb_server_check_private()) {
		exmdb_server_set_public_username(username);
	}
	mid_val = rop_util_get_gc_value(message_id);
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == common_util_set_properties(
		MESSAGE_PROPERTIES_TABLE, mid_val, cpid,
		pdb->psqlite, pproperties, pproblems)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == common_util_get_message_parent_folder(
		pdb->psqlite, mid_val, &fid_val) || 0 == fid_val) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	nt_time = rop_util_current_nttime();
	tmp_propval.proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
	tmp_propval.pvalue = &nt_time;
	common_util_set_property(FOLDER_PROPERTIES_TABLE,
		fid_val, 0, pdb->psqlite, &tmp_propval, &b_result);
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	db_engine_proc_dynmaic_event(pdb,
		cpid, DYNAMIC_EVENT_MODIFY_MESSAGE,
		fid_val, mid_val, 0);
	db_engine_notify_message_modification(
		pdb, fid_val, mid_val);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_remove_message_properties(
	const char *dir, uint32_t cpid, uint64_t message_id,
	const PROPTAG_ARRAY *pproptags)
{
	DB_ITEM *pdb;
	BOOL b_result;
	uint64_t nt_time;
	uint64_t fid_val;
	uint64_t mid_val;
	TAGGED_PROPVAL tmp_propval;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	mid_val = rop_util_get_gc_value(message_id);
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == common_util_remove_properties(
		MESSAGE_PROPERTIES_TABLE, mid_val,
		pdb->psqlite, pproptags)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == common_util_get_message_parent_folder(
		pdb->psqlite, mid_val, &fid_val) || 0 == fid_val) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	nt_time = rop_util_current_nttime();
	tmp_propval.proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
	tmp_propval.pvalue = &nt_time;
	common_util_set_property(FOLDER_PROPERTIES_TABLE,
		fid_val, 0, pdb->psqlite, &tmp_propval, &b_result);
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	db_engine_proc_dynmaic_event(pdb,
		cpid, DYNAMIC_EVENT_MODIFY_MESSAGE,
		fid_val, mid_val, 0);
	db_engine_notify_message_modification(
		pdb, fid_val, mid_val);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_set_message_read_state(const char *dir,
	const char *username, uint64_t message_id,
	uint8_t mark_as_read, uint64_t *pread_cn)
{
	int sql_len;
	DB_ITEM *pdb;
	BOOL b_result;
	uint64_t nt_time;
	uint64_t mid_val;
	uint64_t fid_val;
	uint64_t read_cn;
	sqlite3_stmt *pstmt;
	char sql_string[128];
	TAGGED_PROPVAL tmp_propval;
	
	mid_val = rop_util_get_gc_value(message_id);
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == common_util_allocate_cn(pdb->psqlite, &read_cn)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
	}
	if (FALSE == exmdb_server_check_private()) {
		exmdb_server_set_public_username(username);
		common_util_set_message_read(pdb->psqlite,
			mid_val, mark_as_read);
		sql_len = sprintf(sql_string, "REPLACE INTO "
				"read_cns VALUES (%llu, ?, %llu)",
				mid_val, read_cn);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_finalize(pstmt);
	} else {
		common_util_set_message_read(pdb->psqlite,
			mid_val, mark_as_read);
		sprintf(sql_string, "UPDATE messages SET "
			"read_cn=%llu WHERE message_id=%llu",
			read_cn, mid_val);
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	if (FALSE == common_util_get_message_parent_folder(
		pdb->psqlite, mid_val, &fid_val)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	nt_time = rop_util_current_nttime();
	tmp_propval.proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
	tmp_propval.pvalue = &nt_time;
	common_util_set_property(FOLDER_PROPERTIES_TABLE,
		fid_val, 0, pdb->psqlite, &tmp_propval, &b_result);
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	db_engine_proc_dynmaic_event(pdb,
		0, DYNAMIC_EVENT_MODIFY_MESSAGE,
		fid_val, mid_val, 0);
	db_engine_notify_message_modification(
		pdb, fid_val, mid_val);
	db_engine_put_db(pdb);
	*pread_cn = rop_util_make_eid_ex(1, read_cn);
	return TRUE;
}

/* if folder_id is 0, it means embedded message */
BOOL exmdb_server_allocate_message_id(const char *dir,
	uint64_t folder_id, uint64_t *pmessage_id)
{
	int sql_len;
	DB_ITEM *pdb;
	uint64_t eid_val;
	uint64_t fid_val;
	sqlite3_stmt *pstmt;
	char sql_string[128];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (0 == folder_id) {
		if (FALSE == common_util_allocate_eid(
			pdb->psqlite, &eid_val)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		*pmessage_id = rop_util_make_eid_ex(1, eid_val);
		db_engine_put_db(pdb);
		return TRUE;
	}
	fid_val = rop_util_get_gc_value(folder_id);
	if (FALSE == common_util_allocate_eid_from_folder(
		pdb->psqlite, fid_val, &eid_val)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	*pmessage_id = rop_util_make_eid_ex(1, eid_val);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_get_message_group_id(const char *dir,
	uint64_t message_id, uint32_t **ppgroup_id)
{
	int sql_len;
	DB_ITEM *pdb;
	sqlite3_stmt *pstmt;
	char sql_string[128];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT group_id "
				"FROM messages WHERE message_id=%llu",
				rop_util_get_gc_value(message_id));
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
		SQLITE_NULL == sqlite3_column_type(pstmt, 0)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		*ppgroup_id = NULL;
		return TRUE;
	}
	*ppgroup_id = common_util_alloc(sizeof(uint32_t));
	if (NULL == *ppgroup_id) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return FALSE;
	}
	**ppgroup_id = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_set_message_group_id(const char *dir,
	uint64_t message_id, uint32_t group_id)
{
	DB_ITEM *pdb;
	char sql_string[128];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sprintf(sql_string, "UPDATE messages SET"
		" group_id=%u WHERE message_id=%llu",
		group_id, rop_util_get_gc_value(message_id));
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_put_db(pdb);
	return TRUE;
}

/* if count of indices and ungroup_proptags are both 0 means full change */
BOOL exmdb_server_save_change_indices(const char *dir,
	uint64_t message_id, uint64_t cn, const INDEX_ARRAY *pindices,
	const PROPTAG_ARRAY *pungroup_proptags)
{
	int sql_len;
	DB_ITEM *pdb;
	uint64_t mid_val;
	EXT_PUSH ext_push;
	sqlite3_stmt *pstmt;
	char sql_string[128];
	uint8_t indices_buff[0x8000];
	uint8_t proptags_buff[0x8000];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	mid_val = rop_util_get_gc_value(message_id);
	if (0 == pindices->count && 0 == pungroup_proptags->count) {
		sql_len = sprintf(sql_string, "UPDATE messages SET "
				"group_id=? WHERE message_id=%llu", mid_val);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_bind_null(pstmt, 1);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return TRUE;
	}
	sql_len = sprintf(sql_string, "INSERT INTO"
		" message_changes VALUES (?, ?, ?, ?)");
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_bind_int64(pstmt, 1, mid_val);
	sqlite3_bind_int64(pstmt, 2, rop_util_get_gc_value(cn));
	ext_buffer_push_init(&ext_push,
		indices_buff, sizeof(indices_buff), 0);
	if (EXT_ERR_SUCCESS != ext_buffer_push_proptag_array(
		&ext_push, pindices)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_bind_blob(pstmt, 3, ext_push.data,
			ext_push.offset, SQLITE_STATIC);
	ext_buffer_push_init(&ext_push,
		proptags_buff, sizeof(proptags_buff), 0);
	if (EXT_ERR_SUCCESS != ext_buffer_push_proptag_array(
		&ext_push, pungroup_proptags)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_bind_blob(pstmt, 4, ext_push.data,
			ext_push.offset, SQLITE_STATIC);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	return TRUE;
}

/* if count of indices and ungroup_proptags are both 0 means full change */
BOOL exmdb_server_get_change_indices(const char *dir,
	uint64_t message_id, uint64_t cn, INDEX_ARRAY *pindices,
	PROPTAG_ARRAY *pungroup_proptags)
{
	int i;
	int sql_len;
	DB_ITEM *pdb;
	uint64_t cn_val;
	uint64_t mid_val;
	EXT_PULL ext_pull;
	sqlite3_stmt *pstmt;
	char sql_string[128];
	INDEX_ARRAY tmp_indices;
	INDEX_ARRAY *ptmp_indices;
	PROPTAG_ARRAY tmp_proptags;
	PROPTAG_ARRAY *ptmp_proptags;
	
	cn_val = rop_util_get_gc_value(cn);
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	mid_val = rop_util_get_gc_value(message_id);
	ptmp_indices = proptag_array_init();
	if (NULL == ptmp_indices) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	ptmp_proptags = proptag_array_init();
	if (NULL == ptmp_proptags) {
		proptag_array_free(ptmp_indices);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT change_number,"
				" indices, proptags FROM message_changes"
				" WHERE message_id=%llu", mid_val);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		proptag_array_free(ptmp_indices);
		proptag_array_free(ptmp_proptags);
		db_engine_put_db(pdb);
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		if (sqlite3_column_int64(pstmt, 0) <= cn_val) {
			continue;
		}
		if (sqlite3_column_bytes(pstmt, 1) > 0) {
			ext_buffer_pull_init(&ext_pull,
				sqlite3_column_blob(pstmt, 1),
				sqlite3_column_bytes(pstmt, 1),
				common_util_alloc, 0);
			if (EXT_ERR_SUCCESS != ext_buffer_pull_proptag_array(
				&ext_pull, &tmp_indices)) {
				sqlite3_finalize(pstmt);
				proptag_array_free(ptmp_indices);
				proptag_array_free(ptmp_proptags);
				db_engine_put_db(pdb);
				return FALSE;
			}
			for (i=0; i<tmp_indices.count; i++) {
				if (FALSE == proptag_array_append(ptmp_indices,
					tmp_indices.pproptag[i])) {
					sqlite3_finalize(pstmt);
					proptag_array_free(ptmp_indices);
					proptag_array_free(ptmp_proptags);
					db_engine_put_db(pdb);
					return FALSE;
				}
			}
		}
		if (sqlite3_column_bytes(pstmt, 2) > 0) {
			ext_buffer_pull_init(&ext_pull,
				sqlite3_column_blob(pstmt, 2),
				sqlite3_column_bytes(pstmt, 2),
				common_util_alloc, 0);
			if (EXT_ERR_SUCCESS != ext_buffer_pull_proptag_array(
				&ext_pull, &tmp_proptags)) {
				sqlite3_finalize(pstmt);
				proptag_array_free(ptmp_indices);
				proptag_array_free(ptmp_proptags);
				db_engine_put_db(pdb);
				return FALSE;
			}
			for (i=0; i<tmp_proptags.count; i++) {
				if (FALSE == proptag_array_append(ptmp_proptags,
					tmp_proptags.pproptag[i])) {
					sqlite3_finalize(pstmt);
					proptag_array_free(ptmp_indices);
					proptag_array_free(ptmp_proptags);
					db_engine_put_db(pdb);
					return FALSE;
				}
			}
		}
	}
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	pindices->count = ptmp_indices->count;
	if (ptmp_indices->count > 0) {
		pindices->pproptag = common_util_alloc(
			sizeof(uint32_t)*ptmp_indices->count);
		if (NULL == pindices->pproptag) {
			proptag_array_free(ptmp_indices);
			proptag_array_free(ptmp_proptags);
			return FALSE;
		}
		memcpy(pindices->pproptag, ptmp_indices->pproptag,
			sizeof(uint32_t)*ptmp_indices->count);
	}
	proptag_array_free(ptmp_indices);
	if (ptmp_proptags->count > 0) {
		pungroup_proptags->count = ptmp_proptags->count;
		pungroup_proptags->pproptag = common_util_alloc(
			sizeof(uint32_t)*ptmp_proptags->count);
		if (NULL == pungroup_proptags->pproptag) {
			proptag_array_free(ptmp_proptags);
			return FALSE;
		}
		memcpy(pungroup_proptags->pproptag, ptmp_proptags->pproptag,
			sizeof(uint32_t)*ptmp_proptags->count);
	} else {
		pungroup_proptags->count = 0;
		pungroup_proptags->pproptag = NULL;
	}
	proptag_array_free(ptmp_proptags);
	return TRUE;
}

BOOL exmdb_server_mark_modified(const char *dir, uint64_t message_id)
{
	DB_ITEM *pdb;
	BOOL b_result;
	uint64_t mid_val;
	TAGGED_PROPVAL propval;
	uint32_t *pmessage_flags;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	mid_val = rop_util_get_gc_value(message_id);
	if (FALSE == common_util_get_message_flags(
		pdb->psqlite, mid_val, TRUE, &pmessage_flags)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (0 == (MESSAGE_FLAG_UNMODIFIED & (*pmessage_flags))) {
		db_engine_put_db(pdb);
		return TRUE;
	}
	*pmessage_flags &= ~MESSAGE_FLAG_UNMODIFIED;
	propval.proptag = PROP_TAG_MESSAGEFLAGS;
	propval.pvalue = pmessage_flags;
	if (FALSE == common_util_set_property(MESSAGE_PROPERTIES_TABLE,
		mid_val, 0, pdb->psqlite, &propval, &b_result)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_put_db(pdb);
	return TRUE;
}

/* add MESSAGE_FLAG_SUBMITTED and clear
	MESSAGE_FLAG_UNSENT in message_flags */
BOOL exmdb_server_try_mark_submit(const char *dir,
	uint64_t message_id, BOOL *pb_marked)
{
	DB_ITEM *pdb;
	uint64_t mid_val;
	TAGGED_PROPVAL propval;
	uint32_t *pmessage_flags;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	mid_val = rop_util_get_gc_value(message_id);
	if (FALSE == common_util_get_message_flags(
		pdb->psqlite, mid_val, TRUE, &pmessage_flags)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (MESSAGE_FLAG_SUBMITTED & (*pmessage_flags)) {
		db_engine_put_db(pdb);
		*pb_marked = FALSE;
		return TRUE;
	}
	*pmessage_flags |= MESSAGE_FLAG_SUBMITTED;
	*pmessage_flags &= ~MESSAGE_FLAG_UNSENT;
	propval.proptag = PROP_TAG_MESSAGEFLAGS;
	propval.pvalue = pmessage_flags;
	if (FALSE == common_util_set_property(MESSAGE_PROPERTIES_TABLE,
		mid_val, 0, pdb->psqlite, &propval, pb_marked)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_put_db(pdb);
	return TRUE;
}

/* clear MESSAGE_FLAG_SUBMITTED set by
	exmdb_server_try_submit, clear timer_id,
	set/clear MESSAGE_FLAG_UNSENT by b_unsent */
BOOL exmdb_server_clear_submit(const char *dir,
	uint64_t message_id, BOOL b_unsent)
{
	int sql_len;
	DB_ITEM *pdb;
	BOOL b_result;
	uint64_t mid_val;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	TAGGED_PROPVAL propval;
	uint32_t *pmessage_flags;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	mid_val = rop_util_get_gc_value(message_id);
	if (FALSE == common_util_get_message_flags(
		pdb->psqlite, mid_val, TRUE, &pmessage_flags)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	*pmessage_flags &= ~MESSAGE_FLAG_SUBMITTED;
	if (TRUE == b_unsent) {
		*pmessage_flags |= MESSAGE_FLAG_UNSENT;
	} else {
		*pmessage_flags &= ~MESSAGE_FLAG_UNSENT;
	}
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	propval.proptag = PROP_TAG_MESSAGEFLAGS;
	propval.pvalue = pmessage_flags;
	if (FALSE == common_util_set_property(MESSAGE_PROPERTIES_TABLE,
		mid_val, 0, pdb->psqlite, &propval, &b_result)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == b_result) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return TRUE;
	}
	sql_len = sprintf(sql_string, "UPDATE messages SET"
		" timer_id=? WHERE message_id=%llu", mid_val);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_bind_null(pstmt, 1);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_finalize(pstmt);
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	db_engine_put_db(pdb);
	return TRUE;
}

/* private only */
BOOL exmdb_server_link_message(const char *dir, uint32_t cpid,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_result)
{
	int sql_len;
	DB_ITEM *pdb;
	uint64_t fid_val;
	uint64_t mid_val;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	uint32_t folder_type;
	
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
	fid_val = rop_util_get_gc_value(folder_id);
	mid_val = rop_util_get_gc_value(message_id);
	if (FALSE == common_util_get_folder_type(
		pdb->psqlite, fid_val, &folder_type)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FOLDER_TYPE_SEARCH != folder_type) {
		db_engine_put_db(pdb);
		*pb_result = FALSE;
		return TRUE;
	}	
	sql_len = sprintf(sql_string, "SELECT message_id FROM "
				"messages WHERE message_id=%llu", mid_val);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		*pb_result = FALSE;
		return TRUE;
	}
	sqlite3_finalize(pstmt);
	sprintf(sql_string, "INSERT INTO search_result"
		" VALUES (%llu, %llu)", fid_val, mid_val);
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_proc_dynmaic_event(pdb,
		cpid, DYNAMIC_EVENT_NEW_MESSAGE,
		fid_val, mid_val, 0);
	db_engine_notify_link_creation(pdb, fid_val, mid_val);
	db_engine_put_db(pdb);
	*pb_result = TRUE;
	return TRUE;
}

/* private only */
BOOL exmdb_server_unlink_message(const char *dir,
	uint32_t cpid, uint64_t folder_id, uint64_t message_id)
{
	DB_ITEM *pdb;
	uint64_t fid_val;
	uint64_t mid_val;
	char sql_string[256];
	
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
	fid_val = rop_util_get_gc_value(folder_id);
	mid_val = rop_util_get_gc_value(message_id);
	sprintf(sql_string, "DELETE FROM search_result"
		" WHERE folder_id=%llu AND message_id=%llu",
		fid_val, mid_val);
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_proc_dynmaic_event(pdb,
		cpid, DYNAMIC_EVENT_DELETE_MESSAGE,
		fid_val, mid_val, 0);
	db_engine_notify_link_deletion(pdb, fid_val, mid_val);
	db_engine_put_db(pdb);
	return TRUE;
}

/* private only */
BOOL exmdb_server_set_message_timer(const char *dir,
	uint64_t message_id, uint32_t timer_id)
{
	DB_ITEM *pdb;
	char sql_string[256];
	
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
	sprintf(sql_string, "UPDATE messages SET"
		" timer_id=%u WHERE message_id=%llu",
		timer_id, rop_util_get_gc_value(message_id));
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_put_db(pdb);
	return TRUE;
}

/* private only */
BOOL exmdb_server_get_message_timer(const char *dir,
	uint64_t message_id, uint32_t **pptimer_id)
{
	int sql_len;
	DB_ITEM *pdb;
	uint64_t mid_val;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	
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
	mid_val = rop_util_get_gc_value(message_id);
	sql_len = sprintf(sql_string, "SELECT timer_id FROM "
				"messages WHERE message_id=%llu", mid_val);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		*pptimer_id = NULL;
		return TRUE;
	}
	if (SQLITE_NULL == sqlite3_column_type(pstmt, 0)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		*pptimer_id = NULL;
		return TRUE;
	}
	*pptimer_id = common_util_alloc(sizeof(uint32_t));
	if (NULL == *pptimer_id) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return FALSE;
	}
	**pptimer_id = sqlite3_column_int64(pstmt, 1);
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	return TRUE;
}

static BOOL message_read_message(sqlite3 *psqlite, uint32_t cpid,
	uint64_t message_id, MESSAGE_CONTENT **ppmsgctnt)
{
	int i;
	int sql_len;
	uint32_t count;
	uint32_t attach_num;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	char sql_string[256];
	PROPTAG_ARRAY proptags;
	uint64_t attachment_id;
	TAGGED_PROPVAL *ppropval;
	PROPTAG_ARRAY tmp_proptags;
	uint32_t proptag_buff[0x8000];
	ATTACHMENT_CONTENT *pattachment;
	
	sql_len = sprintf(sql_string, "SELECT message_id FROM"
			" messages WHERE message_id=%llu", message_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		*ppmsgctnt = NULL;
		return TRUE;
	}
	sqlite3_finalize(pstmt);
	*ppmsgctnt = common_util_alloc(sizeof(MESSAGE_CONTENT));
	if (NULL == *ppmsgctnt) {
		return FALSE;
	}
	if (FALSE == common_util_get_proptags(
		MESSAGE_PROPERTIES_TABLE, message_id,
		psqlite, &tmp_proptags)) {
		return FALSE;	
	}
	proptags.count = 0;
	proptags.pproptag = proptag_buff;
	for (i=0; i<tmp_proptags.count; i++) {
		switch (tmp_proptags.pproptag[i]) {
		case PROP_TAG_DISPLAYTO:
		case PROP_TAG_DISPLAYTO_STRING8:
		case PROP_TAG_DISPLAYCC:
		case PROP_TAG_DISPLAYCC_STRING8:
		case PROP_TAG_DISPLAYBCC:
		case PROP_TAG_DISPLAYBCC_STRING8:
		case PROP_TAG_HASATTACHMENTS:
			continue;
		}
		proptag_buff[proptags.count] = tmp_proptags.pproptag[i];
		proptags.count ++;
	}
	if (FALSE == common_util_get_properties(
		MESSAGE_PROPERTIES_TABLE, message_id, cpid,
		psqlite, &proptags, &(*ppmsgctnt)->proplist)) {
		return FALSE;
	}
	(*ppmsgctnt)->children.prcpts =
		common_util_alloc(sizeof(TARRAY_SET));
	if (NULL == (*ppmsgctnt)->children.prcpts) {
		return FALSE;
	}
	if (FALSE == message_get_message_rcpts(psqlite,
		message_id, (*ppmsgctnt)->children.prcpts)) {
		return FALSE;
	}
	(*ppmsgctnt)->children.pattachments =
		common_util_alloc(sizeof(ATTACHMENT_LIST));
	if (NULL == (*ppmsgctnt)->children.pattachments) {
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT count(*) FROM "
		"attachments WHERE message_id=%llu", message_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	count = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	(*ppmsgctnt)->children.pattachments->count = 0;
	(*ppmsgctnt)->children.pattachments->pplist =
		common_util_alloc(count*sizeof(ATTACHMENT_CONTENT*));
	if (NULL == (*ppmsgctnt)->children.pattachments->pplist) {
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT attachment_id FROM "
			"attachments WHERE message_id=%llu", message_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT message_id"
			" FROM messages WHERE parent_attid=?");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	attach_num = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		attachment_id = sqlite3_column_int64(pstmt, 0);
		if (FALSE == common_util_get_proptags(
			ATTACHMENT_PROPERTIES_TABLE, attachment_id,
			psqlite, &tmp_proptags)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		pattachment = common_util_alloc(sizeof(ATTACHMENT_CONTENT));
		if (NULL == pattachment) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		proptags.count = tmp_proptags.count;
		proptags.pproptag = proptag_buff;
		memcpy(proptag_buff, tmp_proptags.pproptag,
			sizeof(uint32_t)*tmp_proptags.count);
		proptag_buff[proptags.count] = PROP_TAG_ATTACHNUMBER;
		proptags.count ++;
		if (FALSE == common_util_get_properties(
			ATTACHMENT_PROPERTIES_TABLE, attachment_id, cpid,
			psqlite, &proptags, &pattachment->proplist)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		/* PROP_TAG_ATTACHNUMBER MUST be the first */
		memmove(pattachment->proplist.ppropval + 1,
			pattachment->proplist.ppropval, sizeof(
			TAGGED_PROPVAL)*pattachment->proplist.count);
		ppropval = pattachment->proplist.ppropval;
		pattachment->proplist.count ++;
		ppropval->proptag = PROP_TAG_ATTACHNUMBER;
		ppropval->pvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == ppropval->pvalue) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		*(uint32_t*)ppropval->pvalue = attach_num;
		attach_num ++;
		sqlite3_bind_int64(pstmt1, 1, attachment_id);
		if (SQLITE_ROW == sqlite3_step(pstmt1)) {
			if (FALSE == message_read_message(psqlite, cpid,
				sqlite3_column_int64(pstmt1, 0),
				&pattachment->pembedded) ||
				NULL == pattachment->pembedded) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				return FALSE;
			}
		} else {
			pattachment->pembedded = NULL;
		}
		sqlite3_reset(pstmt1);
		(*ppmsgctnt)->children.pattachments->pplist[
			(*ppmsgctnt)->children.pattachments->count] = pattachment;
		(*ppmsgctnt)->children.pattachments->count ++;
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	return TRUE;
}

static void message_md5_string(const char *string, uint8_t *pdgt)
{
	int i;
	uint64_t b;
	MD5_CTX ctx;
	char tmp_string[256];
	uint8_t dgt_buff[MD5_DIGEST_LENGTH];
	
	strncpy(tmp_string, string, 255);
	tmp_string[255] = '\0';
	upper_string(tmp_string);
	MD5_Init(&ctx);
	MD5_Update(&ctx, tmp_string, strlen(tmp_string));
	MD5_Final(dgt_buff, &ctx);
	memcpy(pdgt, dgt_buff, 16);
}

static BOOL message_rectify_message(const char *account,
	const MESSAGE_CONTENT *pmsgctnt, MESSAGE_CONTENT *pmsgctnt1)
{
	int i;
	void *pvalue;
	BINARY *pbin;
	BINARY *pbin1;
	GUID tmp_guid;
	uint64_t nt_time;
	EXT_PUSH ext_push;
	char cid_string[256];
	MESSAGE_CONTENT *pembedded;
	static uint8_t fake_true = 1;
	static uint8_t fake_false = 0;
	static uint32_t fake_int32 = 0;
	static uint32_t fake_flags = MESSAGE_FLAG_UNMODIFIED;
	
	pmsgctnt1->proplist.count = 0;
	pmsgctnt1->proplist.ppropval = common_util_alloc(sizeof(
			TAGGED_PROPVAL)*(pmsgctnt->proplist.count + 20));
	if (NULL == pmsgctnt1->proplist.ppropval) {
		return FALSE;
	}
	for (i=0; i<pmsgctnt->proplist.count; i++) {
		switch (pmsgctnt->proplist.ppropval[i].proptag) {
		case PROP_TAG_MID:
		case PROP_TAG_ASSOCIATED:
		case PROP_TAG_CHANGENUMBER:
		case PROP_TAG_MESSAGESTATUS:
			continue;
		case PROP_TAG_SUBJECT:
		case PROP_TAG_SUBJECT_STRING8:
			if (NULL != common_util_get_propvals(&pmsgctnt->proplist,
				PROP_TAG_NORMALIZEDSUBJECT) ||
				NULL != common_util_get_propvals(&pmsgctnt->proplist,
				PROP_TAG_NORMALIZEDSUBJECT_STRING8)) {
				continue;	
			}
			break;
		}
		pmsgctnt1->proplist.ppropval[pmsgctnt1->proplist.count] =
									pmsgctnt->proplist.ppropval[i];
		pmsgctnt1->proplist.count ++;
	}
	pmsgctnt1->proplist.ppropval[
		pmsgctnt1->proplist.count].proptag =
		PROP_TAG_MESSAGESTATUS;
	pmsgctnt1->proplist.ppropval[
		pmsgctnt1->proplist.count].pvalue = &fake_int32;
	pmsgctnt1->proplist.count ++;
	if (NULL == common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_MESSAGEFLAGS)) {
		pmsgctnt1->proplist.ppropval[
			pmsgctnt1->proplist.count].proptag =
			PROP_TAG_MESSAGEFLAGS;
		pmsgctnt1->proplist.ppropval[
			pmsgctnt1->proplist.count].pvalue = &fake_flags;
		pmsgctnt1->proplist.count ++;
	}
	if (NULL == common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_SEARCHKEY)) {
		pbin = common_util_alloc(sizeof(BINARY));
		if (NULL == pbin) {
			return FALSE;
		}
		pbin->cb = 16;
		pbin->pb = common_util_alloc(16);
		if (NULL == pbin->pb) {
			return FALSE;
		}
		tmp_guid = guid_random_new();
		ext_buffer_push_init(&ext_push, pbin->pb, 16, 0);
		ext_buffer_push_guid(&ext_push, &tmp_guid);
		pmsgctnt1->proplist.ppropval[
			pmsgctnt1->proplist.count].proptag =
			PROP_TAG_SEARCHKEY;
		pmsgctnt1->proplist.ppropval[
			pmsgctnt1->proplist.count].pvalue = pbin;
		pmsgctnt1->proplist.count ++;
	}
	if (NULL == common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_BODYCONTENTID)) {
		tmp_guid = guid_random_new();
		ext_buffer_push_init(&ext_push, cid_string, 256, 0);
		ext_buffer_push_guid(&ext_push, &tmp_guid);
		encode_hex_binary(cid_string, 16, cid_string + 16, 64);
		memmove(cid_string, cid_string + 16, 32);
		cid_string[32] = '@';
		pvalue = strchr(account, '@');
		if (NULL == pvalue) {
			pvalue = (void*)account;
		} else {
			pvalue ++;
		}
		strncpy(cid_string + 33, pvalue, 128);
		pvalue = common_util_dup(cid_string);
		if (NULL == pvalue) {
			return FALSE;
		}
		pmsgctnt1->proplist.ppropval[
			pmsgctnt1->proplist.count].proptag =
			PROP_TAG_BODYCONTENTID;
		pmsgctnt1->proplist.ppropval[
			pmsgctnt1->proplist.count].pvalue = pvalue;
		pmsgctnt1->proplist.count ++;
	}
	if (NULL == common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_CREATORNAME)) {
		pvalue = common_util_get_propvals(
			&pmsgctnt->proplist, PROP_TAG_SENDERNAME);
		if (NULL == pvalue) {
			pvalue = common_util_get_propvals(
				&pmsgctnt->proplist, PROP_TAG_SENTREPRESENTINGNAME);
		}
		if (NULL != pvalue) {
			pmsgctnt1->proplist.ppropval[
				pmsgctnt1->proplist.count].proptag =
				PROP_TAG_CREATORNAME;
			pmsgctnt1->proplist.ppropval[
				pmsgctnt1->proplist.count].pvalue = pvalue;
			pmsgctnt1->proplist.count ++;
		}
	}
	if (NULL == common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_CREATORENTRYID)) {
		pvalue = common_util_get_propvals(
			&pmsgctnt->proplist, PROP_TAG_SENDERENTRYID);
		if (NULL == pvalue) {
			pvalue = common_util_get_propvals(
				&pmsgctnt->proplist, PROP_TAG_SENTREPRESENTINGENTRYID);
		}
		if (NULL != pvalue) {
			pmsgctnt1->proplist.ppropval[
				pmsgctnt1->proplist.count].proptag =
				PROP_TAG_CREATORENTRYID;
			pmsgctnt1->proplist.ppropval[
				pmsgctnt1->proplist.count].pvalue = pvalue;
			pmsgctnt1->proplist.count ++;
		}
	}
	if (NULL == common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_LASTMODIFIERNAME)) {
		pvalue = common_util_get_propvals(
			&pmsgctnt->proplist, PROP_TAG_SENDERNAME);
		if (NULL == pvalue) {
			pvalue = common_util_get_propvals(
				&pmsgctnt->proplist, PROP_TAG_SENTREPRESENTINGNAME);
		}
		if (NULL != pvalue) {
			pmsgctnt1->proplist.ppropval[
				pmsgctnt1->proplist.count].proptag =
				PROP_TAG_LASTMODIFIERNAME;
			pmsgctnt1->proplist.ppropval[
				pmsgctnt1->proplist.count].pvalue = pvalue;
			pmsgctnt1->proplist.count ++;
		}
	}
	if (NULL == common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_LASTMODIFIERENTRYID)) {
		pvalue = common_util_get_propvals(
			&pmsgctnt->proplist, PROP_TAG_SENDERENTRYID);
		if (NULL == pvalue) {
			pvalue = common_util_get_propvals(
				&pmsgctnt->proplist, PROP_TAG_SENTREPRESENTINGENTRYID);
		}
		if (NULL != pvalue) {
			pmsgctnt1->proplist.ppropval[
				pmsgctnt1->proplist.count].proptag =
				PROP_TAG_LASTMODIFIERENTRYID;
			pmsgctnt1->proplist.ppropval[
				pmsgctnt1->proplist.count].pvalue = pvalue;
			pmsgctnt1->proplist.count ++;
		}
	}
	if (NULL == common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_READ)) {
		pmsgctnt1->proplist.ppropval[
			pmsgctnt1->proplist.count].proptag =
			PROP_TAG_READ;
		pmsgctnt1->proplist.ppropval[
			pmsgctnt1->proplist.count].pvalue = &fake_false;
		pmsgctnt1->proplist.count ++;
	}
	pbin1 = common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_CONVERSATIONINDEX);
	pbin = common_util_alloc(sizeof(BINARY));
	if (NULL == pbin) {
		return FALSE;
	}
	pbin->cb = 16;
	if (NULL != pbin1 && pbin1->cb >= 22) {
		pbin->pb = pbin1->pb + 6;
	} else {
		pbin->pb = common_util_alloc(16);
		if (NULL == pbin->pb) {
			return FALSE;
		}
		pvalue = common_util_get_propvals(
			&pmsgctnt->proplist, PROP_TAG_CONVERSATIONTOPIC);
		if (NULL != pvalue && '\0' != ((uint8_t*)pvalue)[0]) {
			message_md5_string(pvalue, pbin->pb);
		} else {
			tmp_guid = guid_random_new();
			ext_buffer_push_init(&ext_push, pbin->pb, 16, 0);
			ext_buffer_push_guid(&ext_push, &tmp_guid);
		}
	}
	pmsgctnt1->proplist.ppropval[
		pmsgctnt1->proplist.count].proptag =
		PROP_TAG_CONVERSATIONID;
	pmsgctnt1->proplist.ppropval[
		pmsgctnt1->proplist.count].pvalue = pbin;
	pmsgctnt1->proplist.count ++;
	pmsgctnt1->proplist.ppropval[
		pmsgctnt1->proplist.count].proptag =
		PROP_TAG_CONVERSATIONINDEXTRACKING;
	pmsgctnt1->proplist.ppropval[
		pmsgctnt1->proplist.count].pvalue = &fake_true;
	pmsgctnt1->proplist.count ++;
	if (NULL == pbin1) {
		pbin1 = common_util_alloc(sizeof(BINARY));
		if (NULL == pbin1) {
			return FALSE;
		}
		pbin1->pb = common_util_alloc(27);
		if (NULL == pbin1->pb) {
			return FALSE;
		}
		nt_time = rop_util_current_nttime();
		ext_buffer_push_init(&ext_push, pbin1->pb, 27, 0);
		ext_buffer_push_uint8(&ext_push, 1);
		ext_buffer_push_uint32(&ext_push, nt_time >> 32);
		ext_buffer_push_uint8(&ext_push,
			(nt_time & 0xFFFFFFFF) >> 24);
		ext_buffer_push_bytes(&ext_push, pbin->pb, 16);
		ext_buffer_push_uint32(&ext_push, 0xFFFFFFFF);
		ext_buffer_push_uint8(&ext_push, nt_time & 0xFF);
		pbin1->cb = 27;
		pmsgctnt1->proplist.ppropval[
			pmsgctnt1->proplist.count].proptag =
			PROP_TAG_CONVERSATIONINDEX;
		pmsgctnt1->proplist.ppropval[
			pmsgctnt1->proplist.count].pvalue = pbin1;
		pmsgctnt1->proplist.count ++;
	}
	pvalue = common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_CONVERSATIONTOPIC);
	if (NULL == pvalue) {
		pvalue = common_util_get_propvals(&pmsgctnt->proplist,
						PROP_TAG_CONVERSATIONTOPIC_STRING8);
	}
	if (NULL == pvalue) {
		pvalue = common_util_get_propvals(
			&pmsgctnt->proplist, PROP_TAG_NORMALIZEDSUBJECT);
		if (NULL == pvalue) {
			pvalue = common_util_get_propvals(&pmsgctnt->proplist,
							PROP_TAG_NORMALIZEDSUBJECT_STRING8);
			if (NULL != pvalue) {
				pmsgctnt1->proplist.ppropval[
					pmsgctnt1->proplist.count].proptag =
					PROP_TAG_CONVERSATIONTOPIC_STRING8;
				pmsgctnt1->proplist.ppropval[
					pmsgctnt1->proplist.count].pvalue = pvalue;
				pmsgctnt1->proplist.count ++;
			}
		} else {
			pmsgctnt1->proplist.ppropval[
				pmsgctnt1->proplist.count].proptag =
				PROP_TAG_CONVERSATIONTOPIC;
			pmsgctnt1->proplist.ppropval[
				pmsgctnt1->proplist.count].pvalue = pvalue;
			pmsgctnt1->proplist.count ++;
		}
	}
	pmsgctnt1->children.prcpts = pmsgctnt->children.prcpts;
	if (NULL == pmsgctnt->children.pattachments ||
		0 == pmsgctnt->children.pattachments->count) {
		pmsgctnt1->children.pattachments = NULL;
		return TRUE;
	}
	pmsgctnt1->children.pattachments =
		common_util_alloc(sizeof(ATTACHMENT_LIST));
	if (NULL == pmsgctnt1->children.pattachments) {
		return FALSE;
	}
	pmsgctnt1->children.pattachments->count =
		pmsgctnt->children.pattachments->count;
	pmsgctnt1->children.pattachments->pplist =
		common_util_alloc(sizeof(void*)*
		pmsgctnt->children.pattachments->count);
	if (NULL == pmsgctnt1->children.pattachments->pplist) {
		return FALSE;
	}
	for (i=0; i<pmsgctnt->children.pattachments->count; i++) {
		if (NULL == pmsgctnt->children.pattachments->pplist[i]->pembedded) {
			pmsgctnt1->children.pattachments->pplist[i] =
				pmsgctnt->children.pattachments->pplist[i];
		} else {
			pmsgctnt1->children.pattachments->pplist[i] =
				common_util_alloc(sizeof(ATTACHMENT_CONTENT));
			if (NULL == pmsgctnt1->children.pattachments->pplist[i]) {
				return FALSE;
			}
			pmsgctnt1->children.pattachments->pplist[i]->proplist =
				pmsgctnt->children.pattachments->pplist[i]->proplist;
			pembedded = common_util_alloc(sizeof(MESSAGE_CONTENT));
			if (NULL == pembedded) {
				return FALSE;
			}
			if (FALSE == message_rectify_message(account,
				pmsgctnt->children.pattachments->pplist[i]->pembedded,
				pembedded)) {
				return FALSE;	
			}
			pmsgctnt1->children.pattachments->pplist[i]->pembedded =
															pembedded;
		}
	}
	return TRUE;
}
	
static BOOL message_write_message(BOOL b_internal, sqlite3 *psqlite,
	const char *account, uint32_t cpid, BOOL b_embedded,
	uint64_t parent_id, const MESSAGE_CONTENT *pmsgctnt,
	uint64_t *pmessage_id)
{
	int i;
	BOOL b_cn;
	XID tmp_xid;
	int sql_len;
	int tmp_int;
	int tmp_int1;
	void *pvalue;
	BINARY *pbin;
	BOOL b_exist;
	BOOL b_result;
	uint32_t next;
	uint64_t tmp_id;
	uint64_t nt_time;
	uint8_t tmp_byte;
	int is_associated;
	uint64_t change_num;
	uint64_t message_id;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	char sql_string[256];
	uint32_t message_size;
	uint32_t original_size;
	MESSAGE_CONTENT msgctnt;
	TAGGED_PROPVAL tmp_propval;
	PROBLEM_ARRAY tmp_problems;
	static uint32_t fake_uid = 1;
	const TPROPVAL_ARRAY *pproplist;
	
	pproplist = &pmsgctnt->proplist;
	pvalue = common_util_get_propvals(
		pproplist, PROP_TAG_CHANGENUMBER);
	if (NULL == pvalue) {
		if (FALSE == common_util_allocate_cn(psqlite, &change_num)) {
			return FALSE;
		}
		b_cn = FALSE;
	} else {
		change_num = rop_util_get_gc_value(*(uint64_t*)pvalue);
		b_cn = TRUE;
	}
	if (FALSE == b_internal) {
		if (FALSE == message_rectify_message(
			account, pmsgctnt, &msgctnt)) {
			return FALSE;
		}
		if (FALSE == b_embedded && FALSE == b_cn) {
			if (TRUE == exmdb_server_check_private()) {
				if (FALSE == common_util_get_id_from_username(
					account, &tmp_int)) {
					return FALSE;
				}
				tmp_xid.guid = rop_util_make_user_guid(tmp_int);
			} else {
				if (FALSE == common_util_get_domain_ids(
					account, &tmp_int, &tmp_int1)) {
					return FALSE;
				}
				tmp_xid.guid = rop_util_make_domain_guid(tmp_int);
			}
			rop_util_value_to_gc(change_num, tmp_xid.local_id);
			pvalue = common_util_xid_to_binary(22, &tmp_xid);
			if (NULL == pvalue) {
				return FALSE;
			}
			msgctnt.proplist.ppropval[msgctnt.proplist.count].proptag =
													PROP_TAG_CHANGEKEY;
			msgctnt.proplist.ppropval[msgctnt.proplist.count].pvalue =
																pvalue;
			msgctnt.proplist.count ++;
			pvalue = common_util_pcl_append(NULL, pvalue);
			if (NULL == pvalue) {
				return FALSE;
			}
			msgctnt.proplist.ppropval[msgctnt.proplist.count].proptag =
										PROP_TAG_PREDECESSORCHANGELIST;
			msgctnt.proplist.ppropval[msgctnt.proplist.count].pvalue =
																pvalue;
			msgctnt.proplist.count ++;
		}
		pmsgctnt = &msgctnt;
	}
	original_size = 0;
	message_size = common_util_calculate_message_size(pmsgctnt);
	if (FALSE == b_embedded) {
		pvalue = common_util_get_propvals(
			pproplist, PROP_TAG_ASSOCIATED);
		if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
			is_associated = 0;
		} else {
			is_associated = 1;
		}
		if (TRUE == exmdb_server_check_private()) {
			sql_len = sprintf(sql_string, "SELECT is_search FROM "
						"folders WHERE folder_id=%llu", parent_id);
		} else {
			sql_len = sprintf(sql_string, "SELECT is_deleted FROM"
						" folders WHERE folder_id=%llu", parent_id);
		}
		if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			return FALSE;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			*pmessage_id = 0;
			return TRUE;
		}
		tmp_byte = sqlite3_column_int64(pstmt, 0);
		sqlite3_finalize(pstmt);
		if (0 != tmp_byte) {
			*pmessage_id = 0;
			return TRUE;
		}
		b_exist = FALSE;
		pvalue = common_util_get_propvals(pproplist, PROP_TAG_MID);
		if (NULL == pvalue) {
			if (FALSE == common_util_allocate_eid_from_folder(
				psqlite, parent_id, pmessage_id)) {
				return FALSE;
			}
		} else {
			*pmessage_id = rop_util_get_gc_value(*(uint64_t*)pvalue);
			sql_len = sprintf(sql_string, "SELECT parent_fid, message_size"
					" FROM messages WHERE message_id=%llu", *pmessage_id);
			if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				return FALSE;
			}
			if (SQLITE_ROW != sqlite3_step(pstmt)) {
				if (FALSE == common_util_check_allocated_eid(
					psqlite, *pmessage_id, &b_result)) {
					sqlite3_finalize(pstmt);
					return FALSE;
				}
				if (FALSE == b_result) {
					sqlite3_finalize(pstmt);
					*pmessage_id = 0;
					return TRUE;
				}
			} else {
				if (parent_id != sqlite3_column_int64(pstmt, 0)) {
					sqlite3_finalize(pstmt);
					*pmessage_id = 0;
					return TRUE;
				}
				b_exist = TRUE;
				original_size = sqlite3_column_int64(pstmt, 1);
			}
			sqlite3_finalize(pstmt);
		}
		if (TRUE == b_exist) {
			sprintf(sql_string, "DELETE FROM message_properties"
				" WHERE message_id=%llu", *pmessage_id);
			if (SQLITE_OK != sqlite3_exec(psqlite,
				sql_string, NULL, NULL, NULL)) {
				return FALSE;
			}
			sprintf(sql_string, "DELETE FROM recipients"
				" WHERE message_id=%llu", *pmessage_id);
			if (SQLITE_OK != sqlite3_exec(psqlite,
				sql_string, NULL, NULL, NULL)) {
				return FALSE;
			}
			sprintf(sql_string, "DELETE FROM attachments"
				" WHERE message_id=%llu", *pmessage_id);
			if (SQLITE_OK != sqlite3_exec(psqlite,
				sql_string, NULL, NULL, NULL)) {
				return FALSE;
			}
			sprintf(sql_string, "DELETE FROM message_changes"
				"  WHERE message_id=%llu", *pmessage_id);
			if (SQLITE_OK != sqlite3_exec(psqlite,
				sql_string, NULL, NULL, NULL)) {
				return FALSE;
			}
			sprintf(sql_string, "UPDATE messages SET change_number=%llu,"
				" message_size=%u, group_id=NULL WHERE message_id=%llu",
				change_num, message_size, *pmessage_id);
			if (SQLITE_OK != sqlite3_exec(psqlite,
				sql_string, NULL, NULL, NULL)) {
				return FALSE;
			}
		} else {
			sprintf(sql_string, "INSERT INTO messages (message_id,"
				" parent_fid, parent_attid, is_associated, "
				"change_number, message_size) VALUES (%llu, %llu, "
				"NULL, %d, %llu, %u)", *pmessage_id, parent_id,
				is_associated, change_num, message_size);
			if (SQLITE_OK != sqlite3_exec(psqlite,
				sql_string, NULL, NULL, NULL)) {
				return FALSE;
			}
		}
	} else {
		sql_len = sprintf(sql_string, "SELECT count(*) FROM "
			"attachments WHERE attachment_id=%llu", parent_id);
		if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			return FALSE;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		if (1 != sqlite3_column_int64(pstmt, 0)) {
			sqlite3_finalize(pstmt);
			*pmessage_id = 0;
			return TRUE;
		}
		sqlite3_finalize(pstmt);
		b_exist = FALSE;
		sql_len = sprintf(sql_string, "SELECT message_id, message_size"
				" FROM messages WHERE parent_attid=%llu", parent_id);
		if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			return FALSE;
		}
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			*pmessage_id = sqlite3_column_int64(pstmt, 0);
			original_size = sqlite3_column_int64(pstmt, 1);
			b_exist = TRUE;
		}
		sqlite3_finalize(pstmt);
		if (FALSE == b_exist) {
			if (FALSE == common_util_allocate_eid(
				psqlite, pmessage_id)) {
				return FALSE;
			}
		} else {
			sprintf(sql_string, "DELETE FROM messages"
				" WHERE message_id=%llu", *pmessage_id);
			if (SQLITE_OK != sqlite3_exec(psqlite,
				sql_string, NULL, NULL, NULL)) {
				return FALSE;
			}
		}
		sprintf(sql_string, "INSERT INTO messages (message_id,"
			" parent_fid, parent_attid, change_number, "
			"message_size) VALUES (%llu, NULL, %llu, %llu, %u)",
			*pmessage_id, parent_id, change_num, message_size);
		if (SQLITE_OK != sqlite3_exec(psqlite,
			sql_string, NULL, NULL, NULL)) {
			return FALSE;
		}
	}
	if (FALSE == common_util_set_properties(
		MESSAGE_PROPERTIES_TABLE, *pmessage_id, cpid,
		psqlite, &pmsgctnt->proplist, &tmp_problems)) {
		return FALSE;
	}
	if (FALSE == b_embedded) {
		if (FALSE == common_util_get_property(FOLDER_PROPERTIES_TABLE,
			parent_id, 0, psqlite, PROP_TAG_ARTICLENUMBERNEXT, &pvalue)) {
			return FALSE;
		}
		if (NULL == pvalue) {
			pvalue = &fake_uid;
		}
		next = *(uint32_t*)pvalue + 1;
		tmp_propval.proptag = PROP_TAG_ARTICLENUMBERNEXT;
		tmp_propval.pvalue = &next;
		if (FALSE == common_util_set_property(FOLDER_PROPERTIES_TABLE,
			parent_id, 0, psqlite, &tmp_propval, &b_result)) {
			return FALSE;	
		}
		tmp_propval.proptag = PROP_TAG_INTERNETARTICLENUMBER;
		tmp_propval.pvalue = pvalue;
		if (FALSE == common_util_set_property(MESSAGE_PROPERTIES_TABLE,
			*pmessage_id, 0, psqlite, &tmp_propval, &b_result)) {
			return FALSE;	
		}
	}
	if (NULL != pmsgctnt->children.prcpts) {
		sql_len = sprintf(sql_string, "INSERT INTO recipients "
					"(message_id) VALUES (%llu)", *pmessage_id);
		if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			return FALSE;
		}
		for (i=0; i<pmsgctnt->children.prcpts->count; i++) {
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				sqlite3_finalize(pstmt);
				return FALSE;
			}
			tmp_id = sqlite3_last_insert_rowid(psqlite);
			if (FALSE == common_util_set_properties(
				RECIPIENT_PROPERTIES_TABLE, tmp_id, cpid, psqlite,
				pmsgctnt->children.prcpts->pparray[i], &tmp_problems)) {
				sqlite3_finalize(pstmt);
				return FALSE;
			}
		}
		sqlite3_finalize(pstmt);
	}
	if (NULL != pmsgctnt->children.pattachments) {
		sql_len = sprintf(sql_string, "INSERT INTO attachments"
					" (message_id) VALUES (%llu)", *pmessage_id);
		if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			return FALSE;
		}
		for (i=0; i<pmsgctnt->children.pattachments->count; i++) {
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				sqlite3_finalize(pstmt);
				return FALSE;
			}
			tmp_id = sqlite3_last_insert_rowid(psqlite);
			if (FALSE == common_util_set_properties(
				ATTACHMENT_PROPERTIES_TABLE, tmp_id, cpid, psqlite,
				&pmsgctnt->children.pattachments->pplist[i]->proplist,
				&tmp_problems)) {
				sqlite3_finalize(pstmt);
				return FALSE;
			}
			if (NULL != pmsgctnt->children.pattachments->pplist[i]->pembedded) {
				if (FALSE == message_write_message(TRUE,
					psqlite, account, cpid, TRUE, tmp_id,
					pmsgctnt->children.pattachments->pplist[i]->pembedded,
					&message_id)) {
					sqlite3_finalize(pstmt);
					return FALSE;
				}
				if (0 == message_id) {
					*pmessage_id = 0;
					sqlite3_finalize(pstmt);
					return TRUE;
				}
			}
		}
		sqlite3_finalize(pstmt);
	}
	if (TRUE == b_internal) {
		return TRUE;
	}
	if (TRUE == b_embedded) {
		if (original_size > message_size) {
			sql_len = sprintf(sql_string, "UPDATE messages set "
				"message_size=message_size-%u WHERE message_id=?",
				original_size - message_size);
		} else {
			sql_len = sprintf(sql_string, "UPDATE messages set "
				"message_size=message_size+%u WHERE message_id=?",
				message_size - original_size);
		}
		if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			return FALSE;
		}
		sql_len = sprintf(sql_string, "SELECT message_id FROM"
						" attachments WHERE attachment_id=?");
		if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
			sql_string, sql_len, &pstmt1, NULL)) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		sql_len = sprintf(sql_string, "SELECT parent_attid, "
			"is_associated FROM messages WHERE message_id=?");
		if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
			sql_string, sql_len, &pstmt2, NULL)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		while (TRUE) {
			sqlite3_bind_int64(pstmt1, 1, parent_id);
			if (SQLITE_ROW != sqlite3_step(pstmt1)) {
				*pmessage_id = 0;
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				sqlite3_finalize(pstmt2);
				return FALSE;
			}
			message_id = sqlite3_column_int64(pstmt1, 0);
			sqlite3_bind_int64(pstmt, 1, message_id);
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				sqlite3_finalize(pstmt2);
				return FALSE;
			}
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt2, 1, message_id);
			if (SQLITE_ROW != sqlite3_step(pstmt2)) {
				*pmessage_id = 0;
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				sqlite3_finalize(pstmt2);
				return FALSE;
			}
			if (SQLITE_NULL == sqlite3_column_type(pstmt2, 0)) {
				is_associated = sqlite3_column_int64(pstmt2, 1);
				break;
			}
			parent_id = sqlite3_column_int64(pstmt2, 0);
		}
		sqlite3_finalize(pstmt);
		sqlite3_finalize(pstmt1);
		sqlite3_finalize(pstmt2);
	}
	if (original_size > message_size) {
		if (0 == is_associated) {
			if (FALSE == common_util_decrease_store_size(
				psqlite, original_size - message_size, 0)) {
				return FALSE;	
			}
		} else {
			if (FALSE == common_util_decrease_store_size(
				psqlite, 0, original_size - message_size)) {
				return FALSE;	
			}
		}
	} else {
		if (0 == is_associated) {
			if (FALSE == common_util_increase_store_size(
				psqlite, message_size - original_size, 0)) {
				return FALSE;	
			}
		} else {
			if (FALSE == common_util_increase_store_size(
				psqlite, 0, message_size - original_size)) {
				return FALSE;	
			}
		}
	}
	if (TRUE == b_embedded) {
		return TRUE;
	}
	nt_time = rop_util_current_nttime();
	tmp_propval.proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
	tmp_propval.pvalue = &nt_time;
	return common_util_set_property(FOLDER_PROPERTIES_TABLE,
			parent_id, 0, psqlite, &tmp_propval, &b_result);
}

static BOOL message_load_folder_rules(BOOL b_oof,
	sqlite3 *psqlite, uint64_t folder_id, DOUBLE_LIST *plist)
{
	int sql_len;
	void *pvalue;
	uint32_t state;
	uint32_t sequence;
	RULE_NODE *prnode;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	DOUBLE_LIST_NODE *pnode;
	
	sql_len = sprintf(sql_string, "SELECT state, rule_id,"
					" sequence, provider FROM rules WHERE"
					" folder_id=%lld", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		state = sqlite3_column_int64(pstmt, 0);
		if ((state & RULE_STATE_PARSE_ERROR)
			|| (state & RULE_STATE_ERROR)) {
			continue;
		}
		if (state & RULE_STATE_ENABLED) {
			/* do nothing */
		} else if (state & RULE_STATE_ONLY_WHEN_OOF) {
			if (FALSE == b_oof) {
				continue;
			}
		} else {
			continue;
		}
		prnode = common_util_alloc(sizeof(RULE_NODE));
		if (NULL == prnode) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		prnode->node.pdata = prnode;
		prnode->state = state;
		prnode->id = sqlite3_column_int64(pstmt, 1);
		prnode->sequence = sqlite3_column_int64(pstmt, 2);
		pvalue = (void*)sqlite3_column_text(pstmt, 3);
		if (NULL == pvalue) {
			continue;
		}
		prnode->provider = common_util_dup(pvalue);
		if (NULL == prnode->provider) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		for (pnode=double_list_get_head(plist); NULL!=pnode;
			pnode=double_list_get_after(plist, pnode)) {
			if (((RULE_NODE*)pnode->pdata)->sequence >= prnode->sequence) {
				double_list_insert_before(plist, pnode, &prnode->node);
				break;
			}
		}
		if (NULL == pnode) {
			double_list_append_as_tail(plist, &prnode->node);
		}
	}
	sqlite3_finalize(pstmt);
	return TRUE;
}

static BOOL message_load_folder_ext_rules(BOOL b_oof,
	sqlite3 *psqlite, uint64_t folder_id, DOUBLE_LIST *plist)
{
	int count;
	int sql_len;
	void *pvalue;
	int ext_count;
	uint32_t state;
	uint32_t sequence;
	RULE_NODE *prnode;
	uint64_t message_id;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	DOUBLE_LIST_NODE *pnode;
	
	if (TRUE == exmdb_server_check_private()) {
		sql_len = sprintf(sql_string, "SELECT message_id "
				"FROM messages WHERE parent_fid=%llu AND "
				"is_associated=1", folder_id);
	} else {
		sql_len = sprintf(sql_string, "SELECT message_id "
				"FROM messages WHERE parent_fid=%llu AND "
				"is_associated=1 AND is_deleted=0",
				folder_id);
	}
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	count = 0;
	ext_count = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		count ++;
		if (count > MAX_FAI_COUNT) {
			break;
		}
		message_id = sqlite3_column_int64(pstmt, 0);
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, message_id, 0,
			psqlite, PROP_TAG_MESSAGECLASS, &pvalue)) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		if (NULL != pvalue && 0 != strcasecmp(
			pvalue, "IPM.ExtendedRule.Message")) {
			continue;
		}
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, message_id, 0,
			psqlite, PROP_TAG_RULEMESSAGESTATE, &pvalue)) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		if (NULL == pvalue) {
			continue;
		}
		state = *(uint32_t*)pvalue;
		if ((state & RULE_STATE_PARSE_ERROR)
			|| (state & RULE_STATE_ERROR)) {
			continue;
		}
		if (state & RULE_STATE_ENABLED) {
			/* do nothing */
		} else if (state & RULE_STATE_ONLY_WHEN_OOF) {
			if (FALSE == b_oof) {
				continue;
			}
		} else {
			continue;
		}
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, message_id, 0,
			psqlite, PROP_TAG_RULEMESSAGESEQUENCE,
			&pvalue)) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		if (NULL == pvalue) {
			continue;
		}
		sequence = *(uint32_t*)pvalue;
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, message_id, 0,
			psqlite, PROP_TAG_RULEMESSAGEPROVIDER,
			&pvalue)) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		if (NULL == pvalue) {
			continue;
		}
		prnode = common_util_alloc(sizeof(RULE_NODE));
		if (NULL == prnode) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		prnode->node.pdata = prnode;
		prnode->state = state;
		prnode->id = message_id;
		prnode->sequence = sequence;
		prnode->provider = pvalue;
		for (pnode=double_list_get_head(plist); NULL!=pnode;
			pnode=double_list_get_after(plist, pnode)) {
			if (((RULE_NODE*)pnode->pdata)->sequence >= prnode->sequence) {
				double_list_insert_before(plist, pnode, &prnode->node);
				break;
			}
		}
		if (NULL == pnode) {
			double_list_append_as_tail(plist, &prnode->node);
		}
		ext_count ++;
		if (ext_count > common_util_get_param(
			COMMON_UTIL_MAX_EXT_RULE_NUMBER)) {
			break;
		}
	}
	sqlite3_finalize(pstmt);
	return TRUE;
}

static BOOL message_get_real_propid(sqlite3 *psqlite,
	NAMEDPROPERTY_INFOMATION *ppropname_info,
	uint32_t *pproptag, BOOL *pb_replaced)
{
	int i;
	uint16_t propid;
	PROPID_ARRAY propids;
	PROPNAME_ARRAY propnames;
	
	propid = (*pproptag) >> 16;
	*pb_replaced = FALSE;
	if (0 == (propid & 0x8000)) {
		return TRUE;
	}
	for (i=0; i<ppropname_info->count; i++) {
		if (propid == ppropname_info->ppropid[i]) {
			break;
		}
	}
	if (i >= ppropname_info->count) {
		return TRUE;
	}
	propnames.count = 1;
	propnames.ppropname = &ppropname_info->ppropname[i];
	if (FALSE == common_util_get_named_propids(
		psqlite, TRUE, &propnames, &propids)) {
		return FALSE;
	}
	if (1 != propids.count) {
		return TRUE;
	}
	propid = *propids.ppropid;
	if (0 == propid) {
		return TRUE;
	}
	(*pproptag) &= 0xFFFF;
	(*pproptag) |= ((uint32_t)propid) << 16;
	*pb_replaced = TRUE;
	return TRUE;
}

static BOOL message_replace_restriction_propid(sqlite3 *psqlite,
	NAMEDPROPERTY_INFOMATION *ppropname_info, RESTRICTION *pres)
{
	int i;
	BOOL b_replaced;
	
	switch (pres->rt) {
	case RESTRICTION_TYPE_AND:
	case RESTRICTION_TYPE_OR:
		for (i=0; i<((RESTRICTION_AND_OR*)pres->pres)->count; i++) {
			if (FALSE == message_replace_restriction_propid(
				psqlite, ppropname_info, ((RESTRICTION_AND_OR*)
				pres->pres)->pres + i)) {
				return FALSE;
			}
		}
		break;
	case RESTRICTION_TYPE_NOT:
		if (FALSE == message_replace_restriction_propid(psqlite,
			ppropname_info, &((RESTRICTION_NOT*)pres->pres)->res)) {
			return FALSE;
		}
		break;
	case RESTRICTION_TYPE_CONTENT:
		if (FALSE == message_get_real_propid(psqlite, ppropname_info,
			&((RESTRICTION_CONTENT*)pres->pres)->proptag, &b_replaced)) {
			return FALSE;
		}
		if (TRUE == b_replaced) {
			((RESTRICTION_CONTENT*)pres->pres)->propval.proptag =
					((RESTRICTION_CONTENT*)pres->pres)->proptag;
		}
		break;
	case RESTRICTION_TYPE_PROPERTY:
		if (FALSE == message_get_real_propid(psqlite, ppropname_info,
			&((RESTRICTION_PROPERTY*)pres->pres)->proptag, &b_replaced)) {
			return FALSE;
		}
		if (TRUE == b_replaced) {
			((RESTRICTION_PROPERTY*)pres->pres)->propval.proptag =
					((RESTRICTION_PROPERTY*)pres->pres)->proptag;
		}
		break;
	case RESTRICTION_TYPE_PROPCOMPARE:
		if (FALSE == message_get_real_propid(psqlite, ppropname_info,
			&((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag1,
			&b_replaced)) {
			return FALSE;
		}
		if (FALSE == message_get_real_propid(psqlite, ppropname_info,
			&((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag2,
			&b_replaced)) {
			return FALSE;
		}
		break;
	case RESTRICTION_TYPE_BITMASK:
		if (FALSE == message_get_real_propid(psqlite, ppropname_info,
			&((RESTRICTION_BITMASK*)pres->pres)->proptag, &b_replaced)) {
			return FALSE;
		}
		break;
	case RESTRICTION_TYPE_SIZE:
		if (FALSE == message_get_real_propid(psqlite, ppropname_info,
			&((RESTRICTION_SIZE*)pres->pres)->proptag, &b_replaced)) {
			return FALSE;
		}
		break;
	case RESTRICTION_TYPE_EXIST:
		if (FALSE == message_get_real_propid(psqlite, ppropname_info,
			&((RESTRICTION_EXIST*)pres->pres)->proptag, &b_replaced)) {
			return FALSE;
		}
		break;
	case RESTRICTION_TYPE_SUBOBJ:
		if (FALSE == message_replace_restriction_propid(psqlite,
			ppropname_info, &((RESTRICTION_SUBOBJ*)pres->pres)->res)) {
			return FALSE;
		}
		break;
	case RESTRICTION_TYPE_COMMENT:
		for (i=0; i<((RESTRICTION_COMMENT*)pres->pres)->count; i++) {
			if (FALSE == message_get_real_propid(psqlite, ppropname_info,
				&((RESTRICTION_COMMENT*)pres->pres)->ppropval[i].proptag,
				&b_replaced)) {
				return FALSE;
			}
		}
		if (NULL != ((RESTRICTION_COMMENT*)pres->pres)->pres) {
			if (FALSE == message_replace_restriction_propid(psqlite,
				ppropname_info, ((RESTRICTION_COMMENT*)pres->pres)->pres)) {
				return FALSE;
			}
		}
		break;
	case RESTRICTION_TYPE_COUNT:
		if (FALSE == message_replace_restriction_propid(psqlite,
			ppropname_info, &((RESTRICTION_COUNT*)pres->pres)->sub_res)) {
			return FALSE;
		}
		break;
	}
	return TRUE;
}

static BOOL message_replace_actions_propid(sqlite3 *psqlite,
	NAMEDPROPERTY_INFOMATION *ppropname_info, EXT_RULE_ACTIONS *pactions)
{
	int i;
	BOOL b_replaced;
	
	for (i=0; i<pactions->count; i++) {
		if (ACTION_TYPE_OP_TAG == pactions->pblock[i].type) {
			if (FALSE == message_get_real_propid(
				psqlite, ppropname_info, &((TAGGED_PROPVAL*)
				pactions->pblock[i].pdata)->proptag,
				&b_replaced)) {
				return FALSE;
			}
		}
	}
	return TRUE;
}

static BOOL message_make_deferred_error_message(
	const char *username, sqlite3 *psqlite,
	uint64_t folder_id, uint64_t message_id,
	uint64_t rule_id, uint32_t rule_error,
	uint32_t action_type, uint32_t block_index,
	const char *provider, DOUBLE_LIST *pmsg_list)
{
	BOOL b_result;
	BINARY tmp_bin;
	uint64_t tmp_eid;
	uint64_t mid_val;
	uint64_t nt_time;
	char tmp_buff[1024];
	MESSAGE_NODE *pmnode;
	MESSAGE_CONTENT *pmsg;
	TAGGED_PROPVAL propval;
	
	if (FALSE == exmdb_server_check_private()) {
		return TRUE;
	}
	pmsg = message_content_init();
	if (NULL == pmsg) {
		return FALSE;
	}
	nt_time = rop_util_current_nttime();
	propval.proptag = PROP_TAG_CLIENTSUBMITTIME;
	propval.pvalue = &nt_time;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_CREATIONTIME;
	propval.pvalue = &nt_time;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_LASTMODIFICATIONTIME;
	propval.pvalue = &nt_time;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_MESSAGEDELIVERYTIME;
	propval.pvalue = &nt_time;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_MESSAGECLASS;
	propval.pvalue = "IPC.Microsoft Exchange 4.0.Deferred Error";
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_RULEACTIONTYPE;
	propval.pvalue = &action_type;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_RULEACTIONNUMBER;
	propval.pvalue = &block_index;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_DAMORIGINALENTRYID;
	propval.pvalue = common_util_to_private_message_entryid(
				psqlite, username, folder_id, message_id);
	if (NULL == propval.pvalue) {
		message_content_free(pmsg);
		return FALSE;
	}
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_RULEFOLDERENTRYID;
	propval.pvalue = common_util_to_private_folder_entryid(
							psqlite, username, folder_id);
	if (NULL == propval.pvalue) {
		message_content_free(pmsg);
		return FALSE;
	}
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_RULEPROVIDER;
	propval.pvalue = (void*)provider;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	tmp_eid = rop_util_make_eid_ex(1, rule_id);
	propval.proptag = PROP_TAG_RULEID;
	propval.pvalue = &tmp_eid;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	if (FALSE == message_write_message(FALSE, psqlite, username,
		0, FALSE, PRIVATE_FID_DEFERRED_ACTION, pmsg, &mid_val)) {
		message_content_free(pmsg);
		return FALSE;
	}
	message_content_free(pmsg);
	propval.proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
	propval.pvalue = &nt_time;
	common_util_set_property(FOLDER_PROPERTIES_TABLE,
		PRIVATE_FID_DEFERRED_ACTION, 0, psqlite,
		&propval, &b_result);
	pmnode = common_util_alloc(sizeof(MESSAGE_NODE));
	if (NULL == pmnode) {
		return FALSE;
	}
	pmnode->node.pdata = pmnode;
	pmnode->folder_id = PRIVATE_FID_DEFERRED_ACTION;
	pmnode->message_id = mid_val;
	double_list_append_as_tail(pmsg_list, &pmnode->node);
	return TRUE;
}

static BOOL message_disable_rule(sqlite3 *psqlite,
	BOOL b_extended, uint64_t id)
{
	void *pvalue;
	BOOL b_result;
	char sql_string[128];
	TAGGED_PROPVAL propval;
	
	if (FALSE == b_extended) {
		sprintf(sql_string, "UPDATE rules SET state=state|%u "
			"WHERE rule_id=%llu", RULE_STATE_ERROR, id);
		if (SQLITE_OK != sqlite3_exec(psqlite,
			sql_string, NULL, NULL, NULL)) {
			return FALSE;
		}
	} else {
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, id, 0, psqlite,
			PROP_TAG_RULEMESSAGESTATE, &pvalue) ||
			NULL == pvalue) {
			return FALSE;
		}
		*(uint32_t*)pvalue |= RULE_STATE_ERROR;
		propval.proptag = PROP_TAG_RULEMESSAGESTATE;
		propval.pvalue = pvalue;
		if (FALSE == common_util_set_property(
			MESSAGE_PROPERTIES_TABLE, id, 0,
			psqlite, &propval, &b_result)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL message_get_propids(const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids)
{
	sqlite3 *psqlite;
	
	psqlite = (sqlite3*)common_util_get_tls_var();
	if (NULL == psqlite) {
		return FALSE;
	}
	if (FALSE == common_util_get_named_propids(
		psqlite, FALSE, ppropnames, ppropids)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL message_get_propname(uint16_t propid,
	PROPERTY_NAME **pppropname)
{
	sqlite3 *psqlite;
	PROPID_ARRAY propids;
	PROPNAME_ARRAY propnames;
	
	psqlite = (sqlite3*)common_util_get_tls_var();
	if (NULL == psqlite) {
		return FALSE;
	}
	propids.count = 1;
	propids.ppropid = &propid;
	if (FALSE == common_util_get_named_propnames(
		psqlite, &propids, &propnames)) {
		return FALSE;
	}
	if (1 != propnames.count) {
		*pppropname = NULL;
	} else {
		*pppropname = propnames.ppropname;
	}
	return TRUE;
}

static BOOL message_auto_reply(sqlite3 *psqlite,
	uint64_t message_id, const char *from_address,
	const char *account, uint8_t action_type,
	uint32_t action_flavor, uint32_t template_message_id,
	GUID template_guid, BOOL *pb_result)
{
	MAIL imail;
	MIME *pmime;
	void *pvalue;
	GUID tmp_guid;
	BINARY tmp_bin;
	TARRAY_SET *prcpts;
	DOUBLE_LIST tmp_list;
	char content_type[128];
	TAGGED_PROPVAL propval;
	char tmp_buff[256*1024];
	MESSAGE_CONTENT *pmsgctnt;
	
	if (0 == strcasecmp(from_address, "none@none")) {
		*pb_result = TRUE;
		return TRUE;
	}
	if (FALSE == common_util_get_property(
		MESSAGE_PROPERTIES_TABLE, message_id, 0,
		psqlite, PROP_TAG_AUTORESPONSESUPPRESS, &pvalue)) {
		return FALSE;
	}
	if (NULL != pvalue) {
		if (ACTION_TYPE_OP_REPLY == action_type) {
			if ((*(uint32_t*)pvalue) &
				AUTO_RESPONSE_SUPPRESS_AUTOREPLY) {
				*pb_result = TRUE;
				return TRUE;
			}
		} else {
			if ((*(uint32_t*)pvalue) &
				AUTO_RESPONSE_SUPPRESS_OOF) {
				*pb_result = TRUE;
				return TRUE;
			}
		}
	}
	if (FALSE == message_read_message(psqlite,
		0, template_message_id, &pmsgctnt)) {
		return FALSE;
	}
	if (NULL == pmsgctnt) {
		*pb_result = FALSE;
		return TRUE;
	}
	pvalue = common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_MESSAGECLASS);
	if (NULL == pvalue) {
		*pb_result = FALSE;
		return TRUE;
	}
	if (ACTION_TYPE_OP_REPLY == action_type) {
		if (0 != strncasecmp(pvalue,
			"IPM.Note.rules.ReplyTemplate.", 29)) {
			*pb_result = FALSE;
			return TRUE;
		}
	} else {
		if (0 != strncasecmp(pvalue, "IPM.Note.rules.", 15)) {
			*pb_result = FALSE;
			return TRUE;
		}
	}
	pvalue = common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_ASSOCIATED);
	if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
		*pb_result = FALSE;
		return TRUE;
	}
	pvalue = common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_REPLYTEMPLATEID);
	if (NULL == pvalue || 16 != ((BINARY*)pvalue)->cb) {
		*pb_result = FALSE;
		return TRUE;
	}
	tmp_guid = rop_util_binary_to_guid(pvalue);
	if (0 != guid_compare(&tmp_guid, &template_guid)) {
		*pb_result = FALSE;
		return TRUE;
	}
	if (action_flavor & ACTION_FLAVOR_NS) {
		if (NULL == pmsgctnt->children.prcpts ||
			0 == pmsgctnt->children.prcpts->count) {
			*pb_result = FALSE;
			return TRUE;
		}
	} else {
		prcpts = common_util_alloc(sizeof(TARRAY_SET));
		if (NULL == prcpts) {
			return FALSE;
		}
		prcpts->count = 1;
		prcpts->pparray = common_util_alloc(sizeof(void*));
		if (NULL == prcpts->pparray) {
			return FALSE;
		}
		*prcpts->pparray = common_util_alloc(
						sizeof(TPROPVAL_ARRAY));
		if (NULL == *prcpts->pparray) {
			return FALSE;
		}
		(*prcpts->pparray)->ppropval = common_util_alloc(
								sizeof(TAGGED_PROPVAL)*3);
		if (NULL == (*prcpts->pparray)->ppropval) {
			return FALSE;
		}
		(*prcpts->pparray)->ppropval[0].proptag =
							PROP_TAG_SMTPADDRESS;
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, message_id, 0, psqlite,
			PROP_TAG_SENTREPRESENTINGSMTPADDRESS, &pvalue)) {
			return FALSE;
		}
		if (NULL == pvalue) {
			(*prcpts->pparray)->ppropval[0].pvalue =
								(void*)from_address;
		} else {
			(*prcpts->pparray)->ppropval[0].pvalue = pvalue;
		}
		(*prcpts->pparray)->ppropval[1].proptag =
							PROP_TAG_RECIPIENTTYPE;
		pvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == pvalue) {
			return FALSE;
		}
		*(uint32_t*)pvalue = RECIPIENT_TYPE_TO;
		(*prcpts->pparray)->ppropval[1].pvalue = pvalue; 
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, message_id, 0,
			psqlite, PROP_TAG_SENTREPRESENTINGNAME,
			&pvalue)) {
			return FALSE;
		}
		if (NULL == pvalue) {
			(*prcpts->pparray)->count = 2;
		} else {
			(*prcpts->pparray)->count = 3;
			(*prcpts->pparray)->ppropval[2].proptag =
								PROP_TAG_DISPLAYNAME;
			(*prcpts->pparray)->ppropval[2].pvalue = pvalue;
		}
		pmsgctnt->children.prcpts = prcpts;
	}
	if (action_flavor & ACTION_FLAVOR_ST) {
		if (FALSE == bounce_producer_make_content(
			from_address, account, psqlite,
			message_id, BOUNCE_AUTO_RESPONSE, NULL,
			NULL, content_type, tmp_buff)) {
			return FALSE;
		}
		common_util_remove_propvals(
			&pmsgctnt->proplist, PROP_TAG_ASSOCIATED);
		common_util_remove_propvals(
			&pmsgctnt->proplist, PROP_TAG_MID);
		common_util_remove_propvals(
			&pmsgctnt->proplist, PROP_TAG_BODY);
		common_util_remove_propvals(
			&pmsgctnt->proplist, PROP_TAG_HTML);
		common_util_remove_propvals(
			&pmsgctnt->proplist, PROP_TAG_RTFCOMPRESSED);
		if (0 == strcasecmp(content_type, "text/plain")) {
			propval.proptag = PROP_TAG_BODY;
			propval.pvalue = tmp_buff;
			common_util_set_propvals(&pmsgctnt->proplist, &propval);
		} else if (0 == strcasecmp(content_type, "text/html")) {
			propval.proptag = PROP_TAG_HTML;
			propval.pvalue = &tmp_bin;
			pvalue = common_util_get_propvals(
				&pmsgctnt->proplist, PROP_TAG_INTERNETCODEPAGE);
			if (NULL != pvalue && 1200 != *(uint32_t*)pvalue) {
				tmp_bin.pb = common_util_convert_copy(
					FALSE, *(uint32_t*)pvalue, tmp_buff);
			} else {
				tmp_bin.pb = tmp_buff;
			}
			tmp_bin.cb = strlen(tmp_bin.pb);
			common_util_set_propvals(&pmsgctnt->proplist, &propval);
		}
	}
	common_util_set_tls_var(psqlite);
	if (FALSE == oxcmail_export(pmsgctnt, FALSE,
		OXCMAIL_BODY_PLAIN_AND_HTML, common_util_get_mime_pool(),
		&imail, common_util_alloc, message_get_propids,
		message_get_propname)) {
		common_util_set_tls_var(NULL);
		return FALSE;
	}
	common_util_set_tls_var(NULL);
	pmime = mail_get_head(&imail);
	if (NULL == pmime) {
		mail_free(&imail);
		return FALSE;
	}
	mime_set_field(pmime, "X-Auto-Response-Suppress", "All");
	pvalue = strchr(from_address, '@');
	if (NULL == pvalue) {
		pvalue = "system.mail";
	} else {
		pvalue ++;
	}
	sprintf(tmp_buff, "auto-reply@%s", pvalue);
	double_list_init(&tmp_list);
	if (FALSE == common_util_recipients_to_list(
		pmsgctnt->children.prcpts, &tmp_list)) {
		mail_free(&imail);
		return FALSE;
	}
	common_util_send_mail(&imail, tmp_buff, &tmp_list);
	mail_free(&imail);
	*pb_result = TRUE;
	return TRUE;
}

static BOOL message_bounce_message(const char *from_address,
	const char *account, sqlite3 *psqlite,
	uint64_t message_id, uint32_t bounce_code)
{
	MAIL imail;
	void *pvalue;
	int bounce_type;
	char tmp_buff[256];
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	
	if (0 == strcasecmp(from_address, "none@none") ||
		NULL == strchr(account, '@')) {
		return TRUE;
	}
	switch (bounce_code) {
	case BOUNCE_CODE_MESSAGE_TOO_LARGE:
		bounce_type = BOUNCE_MAIL_TOO_LARGE;
		break;
	case BOUNCE_CODE_MESSAGE_NOT_DISPLAYED:
		bounce_type = BOUNCE_CANNOT_DISPLAY;
		break;
	case BOUNCE_CODE_MESSAGE_DENIED:
		bounce_type = BOUNCE_GENERIC_ERROR;
		break;
	default:
		return TRUE;
	}
	double_list_init(&tmp_list);
	pnode = common_util_alloc(sizeof(DOUBLE_LIST_NODE));
	if (NULL == pnode) {
		return FALSE;
	}
	double_list_append_as_tail(&tmp_list, pnode);
	if (FALSE == common_util_get_property(
		MESSAGE_PROPERTIES_TABLE, message_id, 0, psqlite,
		PROP_TAG_SENTREPRESENTINGSMTPADDRESS, &pvalue)) {
		return FALSE;
	}
	if (NULL == pvalue) {
		pnode->pdata = (void*)from_address;
	} else {
		pnode->pdata = pvalue;
	}
	mail_init(&imail, common_util_get_mime_pool());
	if (FALSE == bounce_producer_make(from_address,
		account, psqlite, message_id, bounce_type,
		&imail)) {
		mail_free(&imail);
		return FALSE;
	}
	pvalue = strchr(account, '@') + 1;
	sprintf(tmp_buff, "postmaster@%s", pvalue);
	common_util_send_mail(&imail, tmp_buff, &tmp_list);
	mail_free(&imail);
	return TRUE;
}

static BOOL message_recipient_blocks_to_list(uint32_t count,
	RECIPIENT_BLOCK *pblock, DOUBLE_LIST *prcpt_list)
{
	int i;
	TARRAY_SET rcpts;
	
	double_list_init(prcpt_list);
	rcpts.count = count;
	rcpts.pparray = common_util_alloc(sizeof(void*)*count);
	if (NULL == rcpts.pparray) {
		return FALSE;
	}
	for (i=0; i<count; i++) {
		rcpts.pparray[i] = common_util_alloc(
					sizeof(TPROPVAL_ARRAY));
		if (NULL == rcpts.pparray[i]) {
			return FALSE;
		}
		rcpts.pparray[i]->count = pblock[i].count;
		rcpts.pparray[i]->ppropval = pblock[i].ppropval;
	}
	return common_util_recipients_to_list(&rcpts, prcpt_list);
}

static BOOL message_ext_recipient_blocks_to_list(uint32_t count,
	EXT_RECIPIENT_BLOCK *pblock, DOUBLE_LIST *prcpt_list)
{
	int i;
	TARRAY_SET rcpts;
	
	double_list_init(prcpt_list);
	rcpts.count = count;
	rcpts.pparray = common_util_alloc(sizeof(void*)*count);
	if (NULL == rcpts.pparray) {
		return FALSE;
	}
	for (i=0; i<count; i++) {
		rcpts.pparray[i] = common_util_alloc(
					sizeof(TPROPVAL_ARRAY));
		if (NULL == rcpts.pparray[i]) {
			return FALSE;
		}
		rcpts.pparray[i]->count = pblock[i].count;
		rcpts.pparray[i]->ppropval = pblock[i].ppropval;
	}
	return common_util_recipients_to_list(&rcpts, prcpt_list);
}

static BOOL message_forward_message(const char *from_address,
	const char *username, sqlite3 *psqlite, uint32_t cpid,
	uint64_t message_id, const char *pdigest, uint32_t action_flavor,
	BOOL b_extended, uint32_t count, void *pblock)
{
	int i;
	int fd;
	int num;
	int offset;
	MAIL imail;
	MAIL imail1;
	char *pbuff;
	MIME *pmime;
	void *pvalue;
	int body_type;
	char *pdomain;
	time_t cur_time;
	char tmp_path[256];
	struct tm time_buff;
	char mid_string[128];
	struct stat node_stat;
	DOUBLE_LIST rcpt_list;
	char tmp_buff[64*1024];
	DOUBLE_LIST_NODE *pnode;
	MESSAGE_CONTENT *pmsgctnt;
	
	pdomain = strchr(username, '@');
	if (NULL != pdomain) {
		pdomain ++;
	} else {
		pdomain = "system.mail";
	}
	if (FALSE == b_extended) {
		if (FALSE == message_recipient_blocks_to_list(
			count, pblock, &rcpt_list)) {
			return FALSE;
		}
	} else {
		if (FALSE == message_ext_recipient_blocks_to_list(
			count, pblock, &rcpt_list)) {
			return FALSE;
		}
	}
	if (NULL != pdigest) {
		get_digest(pdigest, "file", mid_string, 128);
		sprintf(tmp_path, "%s/eml/%s",
			exmdb_server_get_dir(), mid_string);
		if (0 != stat(tmp_path, &node_stat)) {
			return FALSE;
		}
		pbuff = malloc(node_stat.st_size);
		if (NULL == pbuff) {
			return FALSE;
		}
		fd = open(tmp_path, O_RDONLY);
		if (-1 == fd) {
			free(pbuff);
			return FALSE;
		}
		if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
			close(fd);
			free(pbuff);
			return FALSE;
		}
		close(fd);
		mail_init(&imail, common_util_get_mime_pool());
		if (FALSE == mail_retrieve(&imail, pbuff, node_stat.st_size)) {
			free(pbuff);
			return FALSE;
		}
		pmime = mail_get_head(&imail);
		if (NULL == pmime) {
			mail_free(&imail);
			free(pbuff);
			return FALSE;
		}
		num = mime_get_field_num(pmime, "Delivered-To");
		for (i=0; i<num; i++) {
			if (TRUE == mime_search_field(pmime,
				"Delivered-To", i, tmp_buff, 256)) {
				if (0 == strcasecmp(tmp_buff, username)) {
					mail_free(&imail);
					free(pbuff);
					return TRUE;
				}
			}
		}
	} else {
		pbuff = NULL;
		if (FALSE == message_read_message(psqlite, cpid,
			message_id, &pmsgctnt) || NULL == pmsgctnt) {
			return FALSE;
		}
		pvalue = common_util_get_propvals(&pmsgctnt->proplist,
						PROP_TAG_INTERNETMAILOVERRIDEFORMAT);
		if (NULL == pvalue) {
			body_type = OXCMAIL_BODY_PLAIN_AND_HTML;
		} else {
			if (*(uint32_t*)pvalue & MESSAGE_FORMAT_PLAIN_AND_HTML) {
				body_type = OXCMAIL_BODY_PLAIN_AND_HTML;
			} else if (*(uint32_t*)pvalue & MESSAGE_FORMAT_HTML_ONLY) {
				body_type = OXCMAIL_BODY_HTML_ONLY;
			} else {
				body_type = OXCMAIL_BODY_PLAIN_ONLY;
			}
		}
		/* try to avoid TNEF message */
		common_util_set_tls_var(psqlite);
		if (FALSE == oxcmail_export(pmsgctnt, FALSE,
			body_type, common_util_get_mime_pool(), &imail,
			common_util_alloc, message_get_propids,
			message_get_propname)) {
			common_util_set_tls_var(NULL);
			return FALSE;
		}
		common_util_set_tls_var(NULL);
	}
	if (action_flavor & ACTION_FLAVOR_AT) {
		mail_init(&imail1, common_util_get_mime_pool());
		pmime = mail_add_head(&imail1);
		if (NULL == pmime) {
			mail_free(&imail);
			if (NULL != pbuff) {
				free(pbuff);
			}
			return FALSE;
		}
		mime_set_content_type(pmime, "message/rfc822");
		if (action_flavor & ACTION_FLAVOR_PR) {
			sprintf(tmp_buff, "<%s>", from_address);
		} else {
			sprintf(tmp_buff, "\"Forwarder\"<forwarder@%s>", pdomain);
		}
		mime_set_field(pmime, "From", tmp_buff);
		offset = 0;
		for (pnode=double_list_get_head(&rcpt_list); NULL!=pnode;
			pnode=double_list_get_after(&rcpt_list, pnode)) {
			if (0 == offset) {
				offset = sprintf(tmp_buff, "<%s>", pnode->pdata);
			} else {
				offset += snprintf(tmp_buff + offset,
					64*1024 - offset, ", <%s>", pnode->pdata);
			}
			mime_append_field(pmime, "Delivered-To", pnode->pdata);
		}
		mime_set_field(pmime, "To", tmp_buff);
		sprintf(tmp_buff, "Automatic forwarded message from %s", username);
		mime_set_field(pmime, "Subject", tmp_buff);
		time(&cur_time);
		strftime(tmp_buff, 128, "%a, %d %b %Y %H:%M:%S %z", 
			localtime_r(&cur_time, &time_buff));
		mime_set_field(pmime, "Date", tmp_buff);
		mime_write_mail(pmime, &imail);
		if (action_flavor & ACTION_FLAVOR_PR) {
			strcpy(tmp_buff, from_address);
		} else {
			sprintf(tmp_buff, "forwarder@%s", pdomain);
		}
		common_util_send_mail(&imail1, tmp_buff, &rcpt_list);
		mail_free(&imail1);
	} else {
		pmime = mail_get_head(&imail);
		if (NULL == pmime) {
			mail_free(&imail);
			if (NULL != pbuff) {
				free(pbuff);
			}
			return FALSE;
		}
		for (pnode=double_list_get_head(&rcpt_list); NULL!=pnode;
			pnode=double_list_get_after(&rcpt_list, pnode)) {
			mime_append_field(pmime, "Delivered-To", pnode->pdata);
		}
		if (action_flavor & ACTION_FLAVOR_PR) {
			strcpy(tmp_buff, from_address);
		} else {
			sprintf(tmp_buff, "forwarder@%s", pdomain);
		}
		common_util_send_mail(&imail, tmp_buff, &rcpt_list);
	}
	mail_free(&imail);
	if (NULL != pbuff) {
		free(pbuff);
	}
	return TRUE;
}

static BOOL message_make_deferred_action_message(
	const char *username, sqlite3 *psqlite,
	uint64_t folder_id, uint64_t message_id,
	const char *provider, DOUBLE_LIST *pdam_list,
	DOUBLE_LIST *pmsg_list)
{
	int i;
	int id_count;
	SVREID svreid;
	BOOL b_result;
	BINARY tmp_bin;
	uint64_t tmp_eid;
	uint64_t mid_val;
	uint64_t nt_time;
	uint8_t tmp_byte;
	DAM_NODE *pdnode;
	EXT_PUSH ext_push;
	MESSAGE_NODE *pmnode;
	RULE_ACTIONS actions;
	MESSAGE_CONTENT *pmsg;
	TAGGED_PROPVAL propval;
	DOUBLE_LIST_NODE *pnode;
	uint64_t tmp_ids[MAX_DAMS_PER_RULE_FOLDER];
	
	pmsg = message_content_init();
	if (NULL == pmsg) {
		return FALSE;
	}
	nt_time = rop_util_current_nttime();
	propval.proptag = PROP_TAG_CLIENTSUBMITTIME;
	propval.pvalue = &nt_time;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_CREATIONTIME;
	propval.pvalue = &nt_time;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_LASTMODIFICATIONTIME;
	propval.pvalue = &nt_time;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_MESSAGEDELIVERYTIME;
	propval.pvalue = &nt_time;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_MESSAGECLASS;
	propval.pvalue = "IPC.Microsoft Exchange 4.0.Deferred Action";
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_DAMBACKPATCHED;
	propval.pvalue = &tmp_byte;
	tmp_byte = 0;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_DAMORIGINALENTRYID;
	propval.pvalue = common_util_to_private_message_entryid(
					psqlite, username, folder_id, message_id);
	if (NULL == propval.pvalue) {
		message_content_free(pmsg);
		return FALSE;
	}
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_DEFERREDACTIONMESSAGEORIGINALENTRYID;
	propval.pvalue = &svreid;
	svreid.pbin = NULL;
	svreid.folder_id = rop_util_make_eid_ex(1, folder_id);
	svreid.message_id = rop_util_make_eid_ex(1, message_id);
	svreid.instance = 0;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_RULEFOLDERFID;
	propval.pvalue = &tmp_eid;
	tmp_eid = rop_util_make_eid_ex(1, folder_id);
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_RULEFOLDERENTRYID;
	propval.pvalue = common_util_to_private_folder_entryid(
							psqlite, username, folder_id);
	if (NULL == propval.pvalue) {
		message_content_free(pmsg);
		return FALSE;
	}
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	propval.proptag = PROP_TAG_RULEPROVIDER;
	propval.pvalue = (void*)provider;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	actions.pblock = common_util_alloc(sizeof(ACTION_BLOCK)*
						double_list_get_nodes_num(pdam_list));
	if (NULL == actions.pblock) {
		message_content_free(pmsg);
		return FALSE;
	}
	actions.count = 0;
	id_count = 0;
	for (pnode=double_list_get_head(pdam_list); NULL!=pnode;
		pnode=double_list_get_after(pdam_list, pnode)) {
		pdnode = (DAM_NODE*)pnode->pdata;
		memcpy(&actions.pblock[actions.count],
			pdnode->pblock, sizeof(ACTION_BLOCK));
		actions.count ++;
		tmp_eid = rop_util_make_eid_ex(1, pdnode->rule_id);
		for (i=0; i<id_count; i++) {
			if (tmp_ids[i] == tmp_eid) {
				break;
			}
		}
		if (i >= id_count) {
			tmp_ids[id_count] = tmp_eid;
			id_count ++;
		}
	}
	if (FALSE == ext_buffer_push_init(
		&ext_push, NULL, 0, EXT_FLAG_UTF16)) {
		message_content_free(pmsg);
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_rule_actions(
		&ext_push, &actions)) {
		ext_buffer_push_free(&ext_push);
		message_content_free(pmsg);
		return FALSE;
	}
	tmp_bin.pb = ext_push.data;
	tmp_bin.cb = ext_push.offset;
	propval.proptag = PROP_TAG_CLIENTACTIONS;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		ext_buffer_push_free(&ext_push);
		message_content_free(pmsg);
		return FALSE;
	}
	ext_buffer_push_free(&ext_push);
	tmp_bin.pb = (void*)tmp_ids;
	tmp_bin.cb = sizeof(uint64_t)*id_count;
	propval.proptag = PROP_TAG_RULEIDS;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return FALSE;
	}
	if (FALSE == message_write_message(FALSE, psqlite, username,
		0, FALSE, PRIVATE_FID_DEFERRED_ACTION, pmsg, &mid_val)) {
		message_content_free(pmsg);
		return FALSE;
	}
	message_content_free(pmsg);
	propval.proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
	propval.pvalue = &nt_time;
	common_util_set_property(FOLDER_PROPERTIES_TABLE,
		PRIVATE_FID_DEFERRED_ACTION, 0, psqlite,
		&propval, &b_result);
	pmnode = common_util_alloc(sizeof(MESSAGE_NODE));
	if (NULL == pmnode) {
		return FALSE;
	}
	pmnode->node.pdata = pmnode;
	pmnode->folder_id = PRIVATE_FID_DEFERRED_ACTION;
	pmnode->message_id = mid_val;
	double_list_append_as_tail(pmsg_list, &pmnode->node);
	return TRUE;
}

static BOOL message_make_deferred_action_messages(
	const char *username, sqlite3 *psqlite,
	uint64_t folder_id, uint64_t message_id,
	DOUBLE_LIST *pdam_list, DOUBLE_LIST *pmsg_list)
{
	DAM_NODE *pdnode;
	DOUBLE_LIST tmp_list;
	const char *provider;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	
	if (FALSE == exmdb_server_check_private()) {
		return TRUE;
	}
	if (double_list_get_nodes_num(pdam_list) >
		MAX_DAMS_PER_RULE_FOLDER) {
		common_util_log_info(0, "user: %s, IP: unknown"
			"  dam error! too many deferred actions "
			"triggered by message %llu under folder "
			"%llu", username, message_id, folder_id);
		return TRUE;
	}
	provider = NULL;
	double_list_init(&tmp_list);
	ptail = double_list_get_tail(pdam_list);
	while (pnode=double_list_get_from_head(pdam_list)) {
		pdnode = (DAM_NODE*)pnode->pdata;
		if (NULL != provider) {
			if (0 == strcasecmp(provider, pdnode->provider)) {
				double_list_append_as_tail(&tmp_list, pnode);
			} else {
				double_list_append_as_tail(pdam_list, pnode);
			}
		} else {
			provider = pdnode->provider;
			double_list_append_as_tail(&tmp_list, pnode);
		}
		if (pnode == ptail) {
			if (FALSE == message_make_deferred_action_message(
				username, psqlite, folder_id, message_id,
				provider, &tmp_list, pmsg_list)) {
				return FALSE;
			}
			provider = NULL;
			double_list_init(&tmp_list);
			ptail = double_list_get_tail(pdam_list);
		}
	}
	return TRUE;
}

/* extended rules do not produce DAM or DEM */
static BOOL message_rule_new_message(BOOL b_oof,
	const char *from_address, const char *account,
	uint32_t cpid, sqlite3 *psqlite, uint64_t folder_id,
	uint64_t message_id, const char *pdigest,
	DOUBLE_LIST *pfolder_list, DOUBLE_LIST *pmsg_list)
{
	int i;
	BOOL b_del;
	int tmp_id;
	int tmp_id1;
	BOOL b_exit;
	int sql_len;
	BOOL b_exist;
	void *pvalue;
	GUID tmp_guid;
	BOOL b_result;
	char *pdigest1;
	uint32_t result;
	uint64_t nt_time;
	uint64_t dst_fid;
	DAM_NODE *pdnode;
	uint64_t dst_mid;
	uint32_t version;
	RULE_NODE *prnode;
	EXT_PULL ext_pull;
	char *pmid_string;
	char maildir[256];
	char tmp_path[256];
	char tmp_path1[256];
	MESSAGE_NODE *pmnode;
	BINARY searchkey_bin;
	char sql_string[128];
	DOUBLE_LIST dam_list;
	REPLY_ACTION *preply;
	char mid_string[128];
	char mid_string1[128];
	char essdn_buff[1280];
	uint32_t message_size;
	DOUBLE_LIST rule_list;
	DOUBLE_LIST rcpt_list;
	TAGGED_PROPVAL propval;
	RULE_ACTIONS *pactions;
	char display_name[1024];
	RESTRICTION restriction;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DOUBLE_LIST ext_rule_list;
	char tmp_buff[MAX_DIGLEN];
	MESSAGE_CONTENT *pmsgctnt;
	MOVECOPY_ACTION *pmovecopy;
	EXT_REPLY_ACTION *pextreply;
	static uint8_t fake_true = 1;
	EXT_RULE_ACTIONS ext_actions;
	EXT_MOVECOPY_ACTION *pextmvcp;
	FORWARDDELEGATE_ACTION *pfwddlgt;
	NAMEDPROPERTY_INFOMATION propname_info;
	EXT_FORWARDDELEGATE_ACTION *pextfwddlgt;
	
	double_list_init(&dam_list);
	double_list_init(&rule_list);
	double_list_init(&ext_rule_list);
	if (FALSE == message_load_folder_rules(
		b_oof, psqlite, folder_id, &rule_list) ||
		FALSE == message_load_folder_ext_rules(
		b_oof, psqlite, folder_id, &ext_rule_list)) {
		return FALSE;
	}
	b_del = FALSE;
	b_exit = FALSE;
	for (pnode=double_list_get_head(&rule_list); NULL!=pnode;
		pnode=double_list_get_after(&rule_list, pnode)) {
		prnode = (RULE_NODE*)pnode->pdata;
		if (TRUE == b_exit && 0 == (prnode->state
			& RULE_STATE_ONLY_WHEN_OOF)) {
			continue;
		}
		if (FALSE == common_util_get_rule_property(prnode->id,
			psqlite, PROP_TAG_RULECONDITION, &pvalue)) {
			return FALSE;
		}
		if (NULL == pvalue || FALSE ==
			common_util_evaluate_message_restriction(
			psqlite, 0, message_id, pvalue)) {
			continue;
		}
		if (prnode->state & RULE_STATE_EXIT_LEVEL) {
			b_exit = TRUE;
		}
		if (FALSE == common_util_get_rule_property(prnode->id,
			psqlite, PROP_TAG_RULEACTIONS, (void**)&pactions)) {
			return FALSE;
		}
		if (NULL == pactions) {
			continue;
		}
		for (i=0; i<pactions->count; i++) {
			switch (pactions->pblock[i].type) {
			case ACTION_TYPE_OP_MOVE:
			case ACTION_TYPE_OP_COPY:
				pmovecopy = pactions->pblock[i].pdata;
				if (0 != pmovecopy->same_store) {
					dst_fid = rop_util_get_gc_value(((SVREID*)
							pmovecopy->pfolder_eid)->folder_id);
					for (pnode1=double_list_get_head(pfolder_list);
						NULL!=pnode1; pnode1=double_list_get_after(
						pfolder_list, pnode1)) {
						if (dst_fid == *(uint64_t*)pnode1->pdata) {
							break;
						}
					}
					if (NULL != pnode1) {
						continue;
					}
					if (FALSE == common_util_check_folder_id(
						psqlite, dst_fid, &b_exist)) {
						return FALSE;
					}
					if (FALSE == b_exist) {
						message_make_deferred_error_message(account,
							psqlite, folder_id, message_id, prnode->id,
							RULE_ERROR_MOVECOPY, pactions->pblock[i].type,
							i, prnode->provider, pmsg_list);
						if (FALSE == message_disable_rule(
							psqlite, FALSE, prnode->id)) {
							return FALSE;
						}
						continue;
					}
					if (TRUE == exmdb_server_check_private()) {
						if (FALSE == common_util_get_id_from_username(
							account, &tmp_id)) {
							return FALSE;
						}
					} else {
						if (FALSE == common_util_get_domain_ids(
							account, &tmp_id, &tmp_id1)) {
							return FALSE;
						}
					}
					dst_mid = 0;
					if (FALSE == common_util_copy_message(
						psqlite, tmp_id, message_id, dst_fid,
						&dst_mid, &b_result, &message_size)) {
						return FALSE;
					}
					if (FALSE == b_result) {
						message_make_deferred_error_message(account,
							psqlite, folder_id, message_id, prnode->id,
							RULE_ERROR_MOVECOPY, pactions->pblock[i].type,
							i, prnode->provider, pmsg_list);
						continue;
					}
					propval.proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
					propval.pvalue = &nt_time;
					nt_time = rop_util_current_nttime();
					common_util_set_property(FOLDER_PROPERTIES_TABLE,
						dst_fid, 0, psqlite, &propval, &b_result);
					if (FALSE == common_util_increase_store_size(
						psqlite, message_size, 0)) {
						return FALSE;
					}
					pnode1 = common_util_alloc(sizeof(DOUBLE_LIST_NODE));
					if (NULL == pnode1) {
						return FALSE;
					}
					pnode1->pdata = common_util_alloc(sizeof(uint64_t));
					if (NULL == pnode1->pdata) {
						return FALSE;
					}
					*(uint64_t*)pnode1->pdata = dst_fid;
					double_list_append_as_tail(pfolder_list, pnode1);
					if (NULL != pdigest && TRUE == common_util_get_mid_string(
						psqlite, dst_mid, &pmid_string) && NULL != pmid_string) {
						strcpy(tmp_buff, pdigest);
						sprintf(mid_string, "\"%s\"", pmid_string);
						set_digest(tmp_buff, MAX_DIGLEN, "file", mid_string);
						pdigest1 = tmp_buff;
					} else {
						pdigest1 = NULL;
					}
					if (FALSE == message_rule_new_message(b_oof,
						from_address, account, cpid, psqlite,
						dst_fid, dst_mid, pdigest1, pfolder_list,
						pmsg_list)) {
						remove(tmp_path);
						return FALSE;
					}
					if (ACTION_TYPE_OP_MOVE == pactions->pblock[i].type) {
						b_del = TRUE;
						common_util_log_info(0, "user: %s, IP: unknown"
							"  message %llu under folder %llu is going"
							" to be moved to %llu under folde %llu by "
							"rule", account, message_id, folder_id,
							dst_mid, dst_fid);
					} else {
						common_util_log_info(0, "user: %s, IP: unknown"
							"  message %llu under folder %llu is going"
							" to be copied to %llu under folde %llu by "
							"rule", account, message_id, folder_id,
							dst_mid, dst_fid);
					}
				} else {
					if (FALSE == exmdb_server_check_private()) {
						continue;
					}
					pdnode = common_util_alloc(sizeof(DAM_NODE));
					if (NULL == pdnode) {
						return FALSE;
					}
					pdnode->node.pdata = pdnode;
					pdnode->rule_id = prnode->id;
					pdnode->folder_id = folder_id;
					pdnode->message_id = message_id;
					pdnode->provider = prnode->provider;
					pdnode->pblock = pactions->pblock + i;
					double_list_append_as_tail(
						&dam_list, &pdnode->node);
				}
				break;
			case ACTION_TYPE_OP_REPLY:
			case ACTION_TYPE_OP_OOF_REPLY:
				preply = pactions->pblock[i].pdata;
				if (FALSE == message_auto_reply(psqlite, message_id,
					from_address, account, pactions->pblock[i].type,
					pactions->pblock[i].flavor, rop_util_get_gc_value(
					preply->template_message_id), preply->template_guid,
					&b_result)) {
					return FALSE;
				}
				if (FALSE == b_result) {
					message_make_deferred_error_message(
						account, psqlite, folder_id, message_id,
						prnode->id, RULE_ERROR_RETRIEVE_TEMPLATE,
						pactions->pblock[i].type, i, prnode->provider,
						pmsg_list);
					if (FALSE == message_disable_rule(
						psqlite, FALSE, prnode->id)) {
						return FALSE;
					}
					continue;
				}
				break;
			case ACTION_TYPE_OP_DEFER_ACTION:
				if (FALSE == exmdb_server_check_private()) {
					continue;
				}
				pdnode = common_util_alloc(sizeof(DAM_NODE));
				if (NULL == pdnode) {
					return FALSE;
				}
				pdnode->node.pdata = pdnode;
				pdnode->rule_id = prnode->id;
				pdnode->folder_id = folder_id;
				pdnode->message_id = message_id;
				pdnode->provider = prnode->provider;
				pdnode->pblock = pactions->pblock + i;
				double_list_append_as_tail(
					&dam_list, &pdnode->node);
				break;
			case ACTION_TYPE_OP_BOUNCE:
				if (FALSE == message_bounce_message(
					from_address, account, psqlite, message_id,
					*(uint32_t*)pactions->pblock[i].pdata)) {
					return FALSE;
				}
				b_del = TRUE;
				common_util_log_info(0, "user: %s, IP: unknown"
					"  message %llu under folder %llu is going"
					" to be deleted by rule", account,
					message_id, folder_id);
				break;
			case ACTION_TYPE_OP_FORWARD:
				if (FALSE == exmdb_server_check_private()) {
					continue;
				}
				pfwddlgt = pactions->pblock[i].pdata;
				if (pfwddlgt->count > MAX_RULE_RECIPIENTS) {
					message_make_deferred_error_message(
						account, psqlite, folder_id,
						message_id, prnode->id,
						RULE_ERROR_TOO_MANY_RCPTS,
						pactions->pblock[i].type, i,
						prnode->provider, pmsg_list);
					if (FALSE == message_disable_rule(
						psqlite, FALSE, prnode->id)) {
						return FALSE;
					}
					continue;
				}
				if (FALSE == message_forward_message(from_address,
					account, psqlite, cpid, message_id, pdigest,
					pactions->pblock[i].flavor, FALSE,
					pfwddlgt->count, pfwddlgt->pblock)) {
					return FALSE;
				}
				break;
			case ACTION_TYPE_OP_DELEGATE:
				pfwddlgt = pactions->pblock[i].pdata;
				if (FALSE == exmdb_server_check_private() ||
					NULL == pdigest || 0 == pfwddlgt->count) {
					continue;
				}
				if (pfwddlgt->count > MAX_RULE_RECIPIENTS) {
					message_make_deferred_error_message(
						account, psqlite, folder_id,
						message_id, prnode->id,
						RULE_ERROR_TOO_MANY_RCPTS,
						pactions->pblock[i].type, i,
						prnode->provider, pmsg_list);
					if (FALSE == message_disable_rule(
						psqlite, FALSE, prnode->id)) {
						return FALSE;
					}
					continue;
				}
				if (FALSE == message_read_message(psqlite, cpid,
					message_id, &pmsgctnt) || NULL == pmsgctnt) {
					return FALSE;
				}
				if (NULL != common_util_get_propvals(
					&pmsgctnt->proplist, PROP_TAG_DELEGATEDBYRULE)) {
					common_util_log_info(0, "user: %s, IP: unknown delegated"
						" message %llu under folder %llu cannot be delegated"
						" again!", account, message_id, folder_id);
					break;	
				}
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_DISPLAYTO);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_DISPLAYTO_STRING8);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_DISPLAYCC);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_DISPLAYCC_STRING8);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_DISPLAYBCC);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_DISPLAYBCC_STRING8);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_MID);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_MESSAGESIZE);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_ASSOCIATED);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_CHANGENUMBER);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_CHANGEKEY);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_READ);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_HASATTACHMENTS);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_PREDECESSORCHANGELIST);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_MESSAGETOME);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_MESSAGECCME);
				if (NULL == common_util_get_propvals(&pmsgctnt->proplist,
					PROP_TAG_RECEIVEDREPRESENTINGENTRYID)) {
					memcpy(essdn_buff, "EX:", 3);
					if (FALSE == common_util_username_to_essdn(
						account, essdn_buff + 3)) {
						return FALSE;
					}
					upper_string(essdn_buff);
					pvalue = common_util_username_to_addressbook_entryid(
																account);
					if (NULL == pvalue) {
						return FALSE;
					}
					propval.proptag = PROP_TAG_RECEIVEDREPRESENTINGENTRYID;
					propval.pvalue = pvalue;
					common_util_set_propvals(&pmsgctnt->proplist, &propval);
					propval.proptag = PROP_TAG_RECEIVEDREPRESENTINGADDRESSTYPE;
					propval.pvalue = "EX";
					common_util_set_propvals(&pmsgctnt->proplist, &propval);
					propval.proptag =
						PROP_TAG_RECEIVEDREPRESENTINGEMAILADDRESS;
					propval.pvalue = essdn_buff + 3;
					common_util_set_propvals(&pmsgctnt->proplist, &propval);
					if (TRUE == common_util_get_user_displayname(
						account, display_name)) {
						propval.proptag = PROP_TAG_RECEIVEDREPRESENTINGNAME;
						propval.pvalue = display_name;
						common_util_set_propvals(
							&pmsgctnt->proplist, &propval);
					}
					searchkey_bin.cb = strlen(essdn_buff) + 1;
					searchkey_bin.pb = essdn_buff;
					propval.proptag = PROP_TAG_RECEIVEDREPRESENTINGSEARCHKEY;
					propval.pvalue = &searchkey_bin;
					common_util_set_propvals(&pmsgctnt->proplist, &propval);
				}
				propval.proptag = PROP_TAG_DELEGATEDBYRULE;
				propval.pvalue = &fake_true;
				common_util_set_propvals(&pmsgctnt->proplist, &propval);
				if (FALSE == message_recipient_blocks_to_list(
					pfwddlgt->count, pfwddlgt->pblock, &rcpt_list)) {
					return FALSE;
				}
				get_digest(pdigest, "file", mid_string1, 128);
				sprintf(tmp_path1, "%s/eml/%s",
					exmdb_server_get_dir(), mid_string1);
				for (pnode1=double_list_get_head(&rcpt_list);
					NULL!=pnode1; pnode1=double_list_get_after(
					&rcpt_list, pnode1)) {
					if (FALSE == common_util_get_maildir(
						pnode1->pdata, maildir)) {
						continue;
					}
					snprintf(mid_string, 128, "%ld.%d.%s", time(NULL),
							common_util_sequence_ID(), get_host_ID());
					sprintf(tmp_path, "%s/eml/%s", maildir, mid_string);
					if (FALSE == common_util_copy_file(
						tmp_path1, tmp_path)) {
						continue;
					}
					strcpy(tmp_buff, pdigest);
					sprintf(mid_string1, "\"%s\"", mid_string);
					set_digest(tmp_buff, MAX_DIGLEN, "file", mid_string1);
					pdigest1 = tmp_buff;
					if (FALSE == exmdb_client_relay_delivery(maildir,
						from_address, pnode1->pdata, cpid, pmsgctnt,
						pdigest1, &result)) {
						return FALSE;
					}
				}
				break;
			case ACTION_TYPE_OP_TAG:
				if (FALSE == common_util_set_property(
					MESSAGE_PROPERTIES_TABLE, message_id, cpid,
					psqlite, pactions->pblock[i].pdata, &b_result)) {
					return FALSE;
				}
				break;
			case ACTION_TYPE_OP_DELETE:
				b_del = TRUE;
				common_util_log_info(0, "user: %s, IP: unknown"
					"  message %llu under folder %llu is going"
					" to be deleted by rule", account,
					message_id, folder_id);
				break;
			case ACTION_TYPE_OP_MARK_AS_READ:
				if (FALSE == exmdb_server_check_private()) {
					continue;
				}
				propval.proptag = PROP_TAG_READ;
				propval.pvalue = &fake_true;
				if (FALSE == common_util_set_property(
					MESSAGE_PROPERTIES_TABLE, message_id,
					0, psqlite, &propval, &b_result)) {
					return FALSE;
				}
				break;
			}
		}
		
	}
	if (double_list_get_nodes_num(&dam_list) > 0) {
		if (FALSE == message_make_deferred_action_messages(
			account, psqlite, folder_id, message_id,
			&dam_list, pmsg_list)) {
			return FALSE;
		}
	}
	b_exist = FALSE;
	for (pnode=double_list_get_head(&ext_rule_list); NULL!=pnode;
		pnode=double_list_get_after(&ext_rule_list, pnode)) {
		prnode = (RULE_NODE*)pnode->pdata;
		if (TRUE == b_exit && 0 == (prnode->state
			& RULE_STATE_ONLY_WHEN_OOF)) {
			continue;
		}
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, prnode->id, 0, psqlite,
			PROP_TAG_EXTENDEDRULEMESSAGECONDITION, &pvalue)) {
			return FALSE;
		}
		if (NULL == pvalue || 0 == ((BINARY*)pvalue)->cb) {
			continue;
		}
		ext_buffer_pull_init(&ext_pull, ((BINARY*)pvalue)->pb,
			((BINARY*)pvalue)->cb, common_util_alloc,
			EXT_FLAG_WCOUNT|EXT_FLAG_UTF16);
		if (EXT_ERR_SUCCESS !=
			ext_buffer_pull_namedproperty_information(
			&ext_pull, &propname_info) || EXT_ERR_SUCCESS !=
			ext_buffer_pull_restriction(&ext_pull, &restriction)) {
			continue;
		}
		if (FALSE == message_replace_restriction_propid(
			psqlite, &propname_info, &restriction)) {
			return FALSE;
		}
		if (FALSE == common_util_evaluate_message_restriction(
			psqlite, 0, message_id, &restriction)) {
			continue;
		}
		if (prnode->state & RULE_STATE_EXIT_LEVEL) {
			b_exit = TRUE;
		}
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, prnode->id, 0, psqlite,
			PROP_TAG_EXTENDEDRULEMESSAGEACTIONS, &pvalue)) {
			return FALSE;
		}
		if (NULL == pvalue) {
			continue;
		}
		ext_buffer_pull_init(&ext_pull, ((BINARY*)pvalue)->pb,
			((BINARY*)pvalue)->cb, common_util_alloc,
			EXT_FLAG_WCOUNT|EXT_FLAG_UTF16);
		if (EXT_ERR_SUCCESS != ext_buffer_pull_namedproperty_information(
			&ext_pull, &propname_info) || EXT_ERR_SUCCESS !=
			ext_buffer_pull_uint32(&ext_pull, &version) || 1 != version ||
			EXT_ERR_SUCCESS != ext_buffer_pull_ext_rule_actions(&ext_pull,
			&ext_actions)) {
			continue;
		}
		if (FALSE == message_replace_actions_propid(
			psqlite, &propname_info, &ext_actions)) {
			return FALSE;
		}
		for (i=0; i<ext_actions.count; i++) {
			switch (ext_actions.pblock[i].type) {
			case ACTION_TYPE_OP_MOVE:
			case ACTION_TYPE_OP_COPY:
				pextmvcp = ext_actions.pblock[i].pdata;
				if (TRUE == exmdb_server_check_private()) {
					if (EITLT_PRIVATE_FOLDER !=
						pextmvcp->folder_eid.folder_type) {
						if (FALSE == message_disable_rule(
							psqlite, TRUE, prnode->id)) {
							return FALSE;
						}
						continue;
					}
					if (FALSE == common_util_get_id_from_username(
						account, &tmp_id)) {
						continue;
					}
					tmp_guid = rop_util_make_user_guid(tmp_id);
					if (0 != guid_compare(&tmp_guid,
						&pextmvcp->folder_eid.database_guid)) {
						if (FALSE == message_disable_rule(
							psqlite, TRUE, prnode->id)) {
							return FALSE;
						}
						continue;
					}
				} else {
					if (EITLT_PUBLIC_FOLDER !=
						pextmvcp->folder_eid.folder_type) {
						if (FALSE == message_disable_rule(
							psqlite, TRUE, prnode->id)) {
							return FALSE;
						}
						continue;
					}
					pvalue = strchr(account, '@');
					if (NULL == pvalue) {
						pvalue = (void*)account;
					} else {
						pvalue ++;
					}
					if (FALSE == common_util_get_domain_ids(
						pvalue, &tmp_id, &tmp_id1)) {
						continue;
					}
					tmp_guid = rop_util_make_domain_guid(tmp_id);
					if (0 != guid_compare(&tmp_guid,
						&pextmvcp->folder_eid.database_guid)) {
						if (FALSE == message_disable_rule(
							psqlite, TRUE, prnode->id)) {
							return FALSE;
						}
						continue;
					}
				}
				dst_fid = rop_util_gc_to_value(
					pextmvcp->folder_eid.global_counter);
				for (pnode1=double_list_get_head(pfolder_list);
					NULL!=pnode1; pnode1=double_list_get_after(
					pfolder_list, pnode1)) {
					if (dst_fid == *(uint64_t*)pnode1->pdata) {
						break;
					}
				}
				if (NULL != pnode1) {
					continue;
				}
				if (FALSE == common_util_check_folder_id(
					psqlite, dst_fid, &b_exist)) {
					return FALSE;
				}
				if (FALSE == b_exist) {
					if (FALSE == message_disable_rule(
						psqlite, TRUE, prnode->id)) {
						return FALSE;
					}
					continue;
				}
				if (TRUE == exmdb_server_check_private()) {
					if (FALSE == common_util_get_id_from_username(
						account, &tmp_id)) {
						return FALSE;
					}
				} else {
					if (FALSE == common_util_get_domain_ids(
						account, &tmp_id, &tmp_id1)) {
						return FALSE;
					}
				}
				dst_mid = 0;
				if (FALSE == common_util_copy_message(
					psqlite, tmp_id, message_id, dst_fid,
					&dst_mid, &b_result, &message_size)) {
					return FALSE;
				}
				if (FALSE == b_result) {
					continue;
				}
				propval.proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
				propval.pvalue = &nt_time;
				nt_time = rop_util_current_nttime();
				common_util_set_property(FOLDER_PROPERTIES_TABLE,
					dst_fid, 0, psqlite, &propval, &b_result);
				if (FALSE == common_util_increase_store_size(
					psqlite, message_size, 0)) {
					return FALSE;
				}
				pnode1 = common_util_alloc(sizeof(DOUBLE_LIST_NODE));
				if (NULL == pnode1) {
					return FALSE;
				}
				pnode1->pdata = common_util_alloc(sizeof(uint64_t));
				if (NULL == pnode1->pdata) {
					return FALSE;
				}
				*(uint64_t*)pnode1->pdata = dst_fid;
				double_list_append_as_tail(pfolder_list, pnode1);
				if (NULL != pdigest && TRUE == common_util_get_mid_string(
					psqlite, dst_mid, &pmid_string) && NULL != pmid_string) {
					strcpy(tmp_buff, pdigest);
					sprintf(mid_string, "\"%s\"", pmid_string);
					set_digest(tmp_buff, MAX_DIGLEN, "file", mid_string);
					pdigest1 = tmp_buff;
				} else {
					pdigest1 = NULL;
				}
				if (FALSE == message_rule_new_message(b_oof,
					from_address, account, cpid, psqlite,
					dst_fid, dst_mid, pdigest1, pfolder_list,
					pmsg_list)) {
					remove(tmp_path);
					return FALSE;
				}
				if (ACTION_TYPE_OP_MOVE == ext_actions.pblock[i].type) {
					b_del = TRUE;
					common_util_log_info(0, "user: %s, IP: unknown"
						"  message %llu under folder %llu is going"
						" to be moved to %llu under folde %llu by "
						"ext rule", account, message_id, folder_id,
						dst_mid, dst_fid);
				} else {
					common_util_log_info(0, "user: %s, IP: unknown"
						"  message %llu under folder %llu is going"
						" to be copied to %llu under folde %llu by "
						"ext rule", account, message_id, folder_id,
						dst_mid, dst_fid);
				}
				break;
			case ACTION_TYPE_OP_REPLY:
			case ACTION_TYPE_OP_OOF_REPLY:
				pextreply = ext_actions.pblock[i].pdata;
				if (TRUE == exmdb_server_check_private()) {
					if (FALSE == common_util_get_id_from_username(
						account, &tmp_id)) {
						continue;
					}
					tmp_guid = rop_util_make_user_guid(tmp_id);
					if (0 != guid_compare(&tmp_guid,
						&pextreply->message_eid.message_database_guid)) {
						if (FALSE == message_disable_rule(
							psqlite, TRUE, prnode->id)) {
							return FALSE;
						}
						continue;
					}
				} else {
					pvalue = strchr(account, '@');
					if (NULL == pvalue) {
						continue;
					}
					pvalue ++;
					if (FALSE == common_util_get_domain_ids(
						pvalue, &tmp_id, &tmp_id1)) {
						continue;
					}
					tmp_guid = rop_util_make_domain_guid(tmp_id);
					if (0 != guid_compare(&tmp_guid,
						&pextreply->message_eid.message_database_guid)) {
						if (FALSE == message_disable_rule(
							psqlite, TRUE, prnode->id)) {
							return FALSE;
						}
						continue;
					}
				}
				dst_mid = rop_util_gc_to_value(
					pextreply->message_eid.message_global_counter);
				if (FALSE == message_auto_reply(
					psqlite, message_id, from_address, account,
					ext_actions.pblock[i].type, ext_actions.pblock[i].flavor,
					dst_mid, pextreply->template_guid, &b_result)) {
					return FALSE;
				}
				if (FALSE == b_result) {
					if (FALSE == message_disable_rule(
						psqlite, TRUE, prnode->id)) {
						return FALSE;
					}
					continue;
				}
				break;
			case ACTION_TYPE_OP_DEFER_ACTION:
				break;
			case ACTION_TYPE_OP_BOUNCE:
				if (FALSE == message_bounce_message(
					from_address, account, psqlite, message_id,
					*(uint32_t*)ext_actions.pblock[i].pdata)) {
					return FALSE;
				}
				b_del = TRUE;
				common_util_log_info(0, "user: %s, IP: unknown"
					"  message %llu under folder %llu is going"
					" to be deleted by ext rule", account,
					message_id, folder_id);
				break;
			case ACTION_TYPE_OP_FORWARD:
				if (pextfwddlgt->count > MAX_RULE_RECIPIENTS) {
					if (FALSE == message_disable_rule(
						psqlite, TRUE, prnode->id)) {
						return FALSE;
					}
					continue;
				}
				pextfwddlgt = pactions->pblock[i].pdata;
				if (FALSE == message_forward_message(from_address,
					account, psqlite, cpid, message_id, pdigest,
					pactions->pblock[i].flavor, TRUE,
					pextfwddlgt->count, pextfwddlgt->pblock)) {
					return FALSE;
				}
				break;
			case ACTION_TYPE_OP_DELEGATE:
				pextfwddlgt = pactions->pblock[i].pdata;
				if (FALSE == exmdb_server_check_private() ||
					NULL == pdigest || 0 == pextfwddlgt->count) {
					continue;
				}
				if (pextfwddlgt->count > MAX_RULE_RECIPIENTS) {
					if (FALSE == message_disable_rule(
						psqlite, TRUE, prnode->id)) {
						return FALSE;
					}
					continue;
				}
				if (FALSE == message_read_message(psqlite, cpid,
					message_id, &pmsgctnt) || NULL == pmsgctnt) {
					return FALSE;
				}
				if (NULL != common_util_get_propvals(
					&pmsgctnt->proplist, PROP_TAG_DELEGATEDBYRULE)) {
					common_util_log_info(0, "user: %s, IP: unknown delegated"
						" message %llu under folder %llu cannot be delegated"
						" again!", account, message_id, folder_id);
					break;	
				}
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_DISPLAYTO);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_DISPLAYTO_STRING8);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_DISPLAYCC);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_DISPLAYCC_STRING8);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_DISPLAYBCC);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_DISPLAYBCC_STRING8);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_MID);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_MESSAGESIZE);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_ASSOCIATED);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_CHANGENUMBER);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_CHANGEKEY);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_READ);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_HASATTACHMENTS);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_PREDECESSORCHANGELIST);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_MESSAGETOME);
				common_util_remove_propvals(
					&pmsgctnt->proplist, PROP_TAG_MESSAGECCME);
				if (NULL == common_util_get_propvals(&pmsgctnt->proplist,
					PROP_TAG_RECEIVEDREPRESENTINGENTRYID)) {
					memcpy(essdn_buff, "EX:", 3);
					if (FALSE == common_util_username_to_essdn(
						account, essdn_buff + 3)) {
						return FALSE;
					}
					pvalue = common_util_username_to_addressbook_entryid(
																account);
					if (NULL == pvalue) {
						return FALSE;
					}
					propval.proptag = PROP_TAG_RECEIVEDREPRESENTINGENTRYID;
					propval.pvalue = pvalue;
					common_util_set_propvals(&pmsgctnt->proplist, &propval);
					propval.proptag = PROP_TAG_RECEIVEDREPRESENTINGADDRESSTYPE;
					propval.pvalue = "EX";
					common_util_set_propvals(&pmsgctnt->proplist, &propval);
					propval.proptag =
						PROP_TAG_RECEIVEDREPRESENTINGEMAILADDRESS;
					propval.pvalue = essdn_buff + 3;
					common_util_set_propvals(&pmsgctnt->proplist, &propval);
					if (TRUE == common_util_get_user_displayname(
						account, display_name)) {
						propval.proptag = PROP_TAG_RECEIVEDREPRESENTINGNAME;
						propval.pvalue = display_name;
						common_util_set_propvals(
							&pmsgctnt->proplist, &propval);
					}
					searchkey_bin.cb = strlen(essdn_buff) + 1;
					searchkey_bin.pb = essdn_buff;
					propval.proptag = PROP_TAG_RECEIVEDREPRESENTINGSEARCHKEY;
					propval.pvalue = &searchkey_bin;
					common_util_set_propvals(&pmsgctnt->proplist, &propval);
				}
				propval.proptag = PROP_TAG_DELEGATEDBYRULE;
				propval.pvalue = &fake_true;
				common_util_set_propvals(&pmsgctnt->proplist, &propval);
				if (FALSE == message_ext_recipient_blocks_to_list(
					pextfwddlgt->count, pextfwddlgt->pblock, &rcpt_list)) {
					return FALSE;
				}
				get_digest(pdigest, "file", mid_string1, 128);
				sprintf(tmp_path1, "%s/eml/%s",
					exmdb_server_get_dir(), mid_string1);
				for (pnode1=double_list_get_head(&rcpt_list);
					NULL!=pnode1; pnode1=double_list_get_after(
					&rcpt_list, pnode1)) {
					if (FALSE == common_util_get_maildir(
						pnode1->pdata, maildir)) {
						continue;
					}
					snprintf(mid_string, 128, "%ld.%d.%s", time(NULL),
							common_util_sequence_ID(), get_host_ID());
					sprintf(tmp_path, "%s/eml/%s", maildir, mid_string);
					if (FALSE == common_util_copy_file(
						tmp_path1, tmp_path)) {
						continue;
					}
					strcpy(tmp_buff, pdigest);
					sprintf(mid_string1, "\"%s\"", mid_string);
					set_digest(tmp_buff, MAX_DIGLEN, "file", mid_string1);
					pdigest1 = tmp_buff;
					if (FALSE == exmdb_client_relay_delivery(maildir,
						from_address, pnode1->pdata, cpid, pmsgctnt,
						pdigest1, &result)) {
						return FALSE;
					}
				}
				break;
			case ACTION_TYPE_OP_TAG:
				if (FALSE == common_util_set_property(
					MESSAGE_PROPERTIES_TABLE, message_id, cpid,
					psqlite, ext_actions.pblock[i].pdata, &b_result)) {
					return FALSE;
				}
				break;
			case ACTION_TYPE_OP_DELETE:
				b_del = TRUE;
				common_util_log_info(0, "user: %s, IP: unknown"
					"  message %llu under folder %llu is going"
					" to be deleted by ext rule", account,
					message_id, folder_id);
				break;
			case ACTION_TYPE_OP_MARK_AS_READ:
				if (FALSE == exmdb_server_check_private()) {
					continue;
				}
				propval.proptag = PROP_TAG_READ;
				propval.pvalue = &fake_true;
				if (FALSE == common_util_set_property(
					MESSAGE_PROPERTIES_TABLE, message_id,
					0, psqlite, &propval, &b_result)) {
					return FALSE;
				}
				break;
			}
		}
	}
	if (TRUE == b_del) {
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, message_id, 0, psqlite,
			PROP_TAG_MESSAGESIZE, &pvalue) || NULL == pvalue) {
			return FALSE;
		}
		message_size = *(uint32_t*)pvalue;
		sprintf(sql_string, "DELETE FROM messages"
			" WHERE message_id=%llu", message_id);
		if (SQLITE_OK != sqlite3_exec(psqlite,
			sql_string, NULL, NULL, NULL)) {
			return FALSE;
		}
		if (FALSE == common_util_decrease_store_size(
			psqlite, message_size, 0)) {
			return FALSE;
		}
		if (NULL != pdigest) {
			get_digest(pdigest, "file", mid_string1, 128);
			sprintf(tmp_path1, "%s/eml/%s",
				exmdb_server_get_dir(), mid_string1);
			remove(tmp_path1);
		}
	} else {
		pmnode = common_util_alloc(sizeof(MESSAGE_NODE));
		if (NULL == pmnode) {
			return FALSE;
		}
		pmnode->node.pdata = pmnode;
		pmnode->folder_id = folder_id;
		pmnode->message_id = message_id;
		double_list_append_as_tail(pmsg_list, &pmnode->node);
	}
	return TRUE;
}

/* 0 means success, 1 means mailbox full, other unkown error */
BOOL exmdb_server_delivery_message(const char *dir,
	const char *from_address, const char *account,
	uint32_t cpid, const MESSAGE_CONTENT *pmsg,
	const char *pdigest, uint32_t *presult)
{
	int i, fd;
	BOOL b_oof;
	BOOL b_to_me;
	BOOL b_cc_me;
	DB_ITEM *pdb;
	void *pvalue;
	uint64_t nt_time;
	uint64_t fid_val;
	BINARY *pentryid;
	char tmp_path[256];
	uint64_t message_id;
	BINARY searchkey_bin;
	DOUBLE_LIST msg_list;
	MESSAGE_NODE *pmnode;
	const char *paccount;
	char mid_string[128];
	char essdn_buff[1280];
	TAGGED_PROPVAL propval;
	char display_name[1024];
	DOUBLE_LIST folder_list;
	DOUBLE_LIST_NODE *pnode;
	MESSAGE_CONTENT tmp_msg;
	char digest_buff[MAX_DIGLEN];
	static uint8_t fake_true = 1;
	
	if (NULL != pdigest && strlen(pdigest) >= MAX_DIGLEN) {
		return FALSE;
	}
	b_to_me = FALSE;
	b_cc_me = FALSE;
	if (NULL != pmsg->children.prcpts) {
		for (i=0; i<pmsg->children.prcpts->count; i++) {
			pvalue = common_util_get_propvals(
				pmsg->children.prcpts->pparray[i],
				PROP_TAG_RECIPIENTTYPE);
			if (NULL == pvalue) {
				continue;
			}
			switch (*(uint32_t*)pvalue) {
			case RECIPIENT_TYPE_TO:
				pvalue = common_util_get_propvals(
					pmsg->children.prcpts->pparray[i],
					PROP_TAG_SMTPADDRESS);
				if (NULL != pvalue && 0 == strcasecmp(
					account, pvalue)) {
					b_to_me = TRUE;	
				}
				break;
			case RECIPIENT_TYPE_CC:
				pvalue = common_util_get_propvals(
					pmsg->children.prcpts->pparray[i],
					PROP_TAG_SMTPADDRESS);
				if (NULL != pvalue && 0 == strcasecmp(
					account, pvalue)) {
					b_cc_me = TRUE;	
				}
				break;
			}
			if (TRUE == b_to_me || TRUE == b_cc_me) {
				break;
			}
		}
	}
	if (TRUE == exmdb_server_check_private()) {
		paccount = account;
	} else {
		paccount = strchr(account, '@');
		if (NULL == paccount) {
			return FALSE;
		}
		paccount ++;
	}
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (TRUE == common_util_check_msgsize_overflow(pdb->psqlite) ||
		TRUE == common_util_check_msgcnt_overflow(pdb->psqlite)) {
		db_engine_put_db(pdb);
		*presult = 1;
		return TRUE;
	}
	if (TRUE == exmdb_server_check_private()) {
		if (FALSE == common_util_get_property(STORE_PROPERTIES_TABLE,
			0, 0, pdb->psqlite, PROP_TAG_OUTOFOFFICESTATE, &pvalue)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
			b_oof = FALSE;
		} else {
			b_oof = TRUE;
		}
		fid_val = PRIVATE_FID_INBOX;
	} else {
		b_oof = FALSE;
		//TODO get public folder id
	}
	double_list_init(&msg_list);
	double_list_init(&folder_list);
	pnode = common_util_alloc(sizeof(DOUBLE_LIST_NODE));
	if (NULL == pnode) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	pnode->pdata = common_util_alloc(sizeof(uint64_t));
	if (NULL == pnode->pdata) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	*(uint64_t*)pnode->pdata = fid_val;
	double_list_append_as_tail(&folder_list, pnode);
	tmp_msg = *pmsg;
	if (TRUE == exmdb_server_check_private()) {
		tmp_msg.proplist.ppropval = common_util_alloc(
			sizeof(TAGGED_PROPVAL)*(pmsg->proplist.count + 15));
		if (NULL == tmp_msg.proplist.ppropval) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		memcpy(tmp_msg.proplist.ppropval, pmsg->proplist.ppropval,
					sizeof(TAGGED_PROPVAL)*pmsg->proplist.count);
		pentryid = common_util_username_to_addressbook_entryid(account);
		if (NULL == pentryid) {
			db_engine_put_db(pdb);
			return FALSE;	
		}
		memcpy(essdn_buff, "EX:", 3);
		if (FALSE == common_util_username_to_essdn(
			account, essdn_buff + 3)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		upper_string(essdn_buff);
		propval.proptag = PROP_TAG_RECEIVEDBYENTRYID;
		propval.pvalue = pentryid;
		common_util_set_propvals(&tmp_msg.proplist, &propval);
		propval.proptag = PROP_TAG_RECEIVEDBYADDRESSTYPE;
		propval.pvalue = "EX";
		common_util_set_propvals(&tmp_msg.proplist, &propval);
		propval.proptag = PROP_TAG_RECEIVEDBYEMAILADDRESS;
		propval.pvalue = essdn_buff + 3;
		common_util_set_propvals(&tmp_msg.proplist, &propval);
		if (TRUE == common_util_get_user_displayname(
			account, display_name)) {
			propval.proptag = PROP_TAG_RECEIVEDBYNAME;
			propval.pvalue = display_name;
			common_util_set_propvals(&tmp_msg.proplist, &propval);
		} else {
			display_name[0] = '\0';
		}
		searchkey_bin.cb = strlen(essdn_buff) + 1;
		searchkey_bin.pb = essdn_buff;
		propval.proptag = PROP_TAG_RECEIVEDBYSEARCHKEY;
		propval.pvalue = &searchkey_bin;
		common_util_set_propvals(&tmp_msg.proplist, &propval);
		if (NULL == common_util_get_propvals(&pmsg->proplist,
			PROP_TAG_RECEIVEDREPRESENTINGENTRYID)) {
			propval.proptag = PROP_TAG_RECEIVEDREPRESENTINGENTRYID;
			propval.pvalue = pentryid;
			common_util_set_propvals(&tmp_msg.proplist, &propval);	
			propval.proptag = PROP_TAG_RECEIVEDREPRESENTINGADDRESSTYPE;
			propval.pvalue = "EX";
			common_util_set_propvals(&tmp_msg.proplist, &propval);
			propval.proptag = PROP_TAG_RECEIVEDREPRESENTINGEMAILADDRESS;
			propval.pvalue = essdn_buff + 3;
			common_util_set_propvals(&tmp_msg.proplist, &propval);
			if ('\0' != display_name[0]) {
				propval.proptag = PROP_TAG_RECEIVEDREPRESENTINGNAME;
				propval.pvalue = display_name;
				common_util_set_propvals(&tmp_msg.proplist, &propval);
			}
			propval.proptag = PROP_TAG_RECEIVEDREPRESENTINGSEARCHKEY;
			propval.pvalue = &searchkey_bin;
			common_util_set_propvals(&tmp_msg.proplist, &propval);
		}
		if (TRUE == b_to_me) {
			propval.proptag = PROP_TAG_MESSAGETOME;
			propval.pvalue = &fake_true;
			common_util_set_propvals(&tmp_msg.proplist, &propval);
		} else if (TRUE == b_cc_me) {
			propval.proptag = PROP_TAG_MESSAGECCME;
			propval.pvalue = &fake_true;
			common_util_set_propvals(&tmp_msg.proplist, &propval);
		}
	}
	nt_time = rop_util_current_nttime();
	pvalue = common_util_get_propvals(&tmp_msg.proplist,
							PROP_TAG_MESSAGEDELIVERYTIME);
	if (NULL != pvalue) {
		*(uint64_t*)pvalue = nt_time;
	}
	pvalue = common_util_get_propvals(&tmp_msg.proplist,
							PROP_TAG_LASTMODIFICATIONTIME);
	if (NULL != pvalue) {
		*(uint64_t*)pvalue = nt_time;
	}
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == message_write_message(FALSE, pdb->psqlite,
		paccount, cpid, FALSE, fid_val, &tmp_msg, &message_id)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (0 == message_id) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		*presult = 2;
		return TRUE;
	}
	if (NULL != pdigest && TRUE == get_digest(
		pdigest, "file", mid_string, 128)) {
		strcpy(digest_buff, pdigest);
		set_digest(digest_buff, MAX_DIGLEN, "file", "\"\"");
		sprintf(tmp_path, "%s/ext/%s", exmdb_server_get_dir(), mid_string);
		fd = open(tmp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (-1 != fd) {
			write(fd, digest_buff, strlen(digest_buff));
			close(fd);
			if (FALSE == common_util_set_mid_string(
				pdb->psqlite, message_id, mid_string)) {
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				db_engine_put_db(pdb);
				return FALSE;
			}
		}
	}
	common_util_log_info(0, "user: %s, IP: unknown"
		"  message %llu is delivered into folder "
		"%llu", account, message_id, fid_val);
	if (FALSE == message_rule_new_message(b_oof,
		from_address, account, cpid, pdb->psqlite,
		fid_val, message_id, pdigest, &folder_list, &msg_list)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION",  NULL, NULL, NULL);
	for (pnode=double_list_get_head(&msg_list); NULL!=pnode;
		pnode=double_list_get_after(&msg_list, pnode)) {
		pmnode = (MESSAGE_NODE*)pnode->pdata;
		db_engine_proc_dynmaic_event(
			pdb, cpid, DYNAMIC_EVENT_NEW_MESSAGE,
			pmnode->folder_id, pmnode->message_id, 0);
		if (message_id == pmnode->message_id) {
			db_engine_notify_new_mail(pdb, 
				pmnode->folder_id, pmnode->message_id);
		} else {
			db_engine_notify_message_creation(pdb,
				pmnode->folder_id, pmnode->message_id);
		}
	}
	db_engine_put_db(pdb);
	*presult = 0;
	return TRUE;
}

/* create or cover message under folder, if message exists
	in somewhere except the folder, result will be FALSE */
BOOL exmdb_server_write_message(const char *dir,
	const char *account, uint32_t cpid, uint64_t folder_id,
	const MESSAGE_CONTENT *pmsgctnt, BOOL *pb_result)
{
	DB_ITEM *pdb;
	BOOL b_exist;
	void *pvalue;
	uint64_t *pmid;
	uint64_t nt_time;
	uint64_t mid_val;
	uint64_t fid_val;
	uint64_t fid_val1;
	
	if (NULL == common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_CHANGENUMBER)) {
		*pb_result = FALSE;
		return TRUE;
	}
	b_exist = FALSE;
	pmid = common_util_get_propvals(
		&pmsgctnt->proplist, PROP_TAG_MID);
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (TRUE == common_util_check_msgsize_overflow(pdb->psqlite) ||
		TRUE == common_util_check_msgcnt_overflow(pdb->psqlite)) {
		db_engine_put_db(pdb);
		*pb_result = FALSE;
		return TRUE;	
	}
	fid_val = rop_util_get_gc_value(folder_id);
	if (NULL != pmid) {
		if (FALSE == common_util_get_message_parent_folder(
			pdb->psqlite, rop_util_get_gc_value(*pmid), &fid_val1)) {
			db_engine_put_db(pdb);
			return FALSE;	
		}
		if (0 != fid_val1) {
			b_exist = TRUE;
			if (fid_val != fid_val1) {
				db_engine_put_db(pdb);
				*pb_result = FALSE;
				return TRUE;
			}
		}
	}
	nt_time = rop_util_current_nttime();
	pvalue = common_util_get_propvals(&pmsgctnt->proplist,
							PROP_TAG_LASTMODIFICATIONTIME);
	if (NULL != pvalue) {
		*(uint64_t*)pvalue = nt_time;
	}
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == message_write_message(FALSE, pdb->psqlite,
		account, cpid, FALSE, fid_val, pmsgctnt, &mid_val)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (0 == mid_val) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		*pb_result = FALSE;
	} else {
		sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
		*pb_result = TRUE;
	}
	if (TRUE == b_exist) {
		db_engine_proc_dynmaic_event(pdb, cpid,
			DYNAMIC_EVENT_MODIFY_MESSAGE, fid_val, mid_val, 0);
		db_engine_notify_message_modification(
			pdb, fid_val, mid_val);
	} else {
		db_engine_proc_dynmaic_event(pdb, cpid,
			DYNAMIC_EVENT_NEW_MESSAGE, fid_val, mid_val, 0);
		db_engine_notify_message_creation(
			pdb, fid_val, mid_val);
	}
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_read_message(const char *dir, const char *username,
	uint32_t cpid, uint64_t message_id, MESSAGE_CONTENT **ppmsgctnt)
{
	DB_ITEM *pdb;
	uint64_t mid_val;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == exmdb_server_check_private()) {
		exmdb_server_set_public_username(username);
	}
	mid_val = rop_util_get_gc_value(message_id);
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == common_util_begin_message_optimize(pdb->psqlite)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == message_read_message(
		pdb->psqlite, cpid, mid_val, ppmsgctnt)) {
		common_util_end_message_optimize();
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	common_util_end_message_optimize();
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_rule_new_message(const char *dir,
	const char *username, const char *account, uint32_t cpid,
	uint64_t folder_id, uint64_t message_id)
{
	int fd, len;
	DB_ITEM *pdb;
	char *pdigest;
	uint64_t fid_val;
	uint64_t mid_val;
	char *pmid_string;
	char tmp_path[256];
	DOUBLE_LIST msg_list;
	MESSAGE_NODE *pmnode;
	DOUBLE_LIST folder_list;
	DOUBLE_LIST_NODE *pnode;
	char digest_buff[MAX_DIGLEN];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == exmdb_server_check_private()) {
		exmdb_server_set_public_username(username);
	}
	fid_val = rop_util_get_gc_value(folder_id);
	mid_val = rop_util_get_gc_value(message_id);
	pdigest = NULL;
	if (FALSE == common_util_get_mid_string(
		pdb->psqlite, mid_val, &pmid_string)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (NULL != pmid_string) {
		sprintf(tmp_path, "%s/ext/%s",
			exmdb_server_get_dir(), pmid_string);
		fd = open(tmp_path, O_RDONLY);
		if (-1 != fd) {
			len = read(fd, digest_buff, MAX_DIGLEN);
			if (len > 0) {
				digest_buff[len] = '\0';
				pdigest = digest_buff;
			}
			close(fd);
		}
	}
	double_list_init(&msg_list);
	double_list_init(&folder_list);
	pnode = common_util_alloc(sizeof(DOUBLE_LIST_NODE));
	if (NULL == pnode) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	pnode->pdata = common_util_alloc(sizeof(uint64_t));
	if (NULL == pnode->pdata) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	*(uint64_t*)pnode->pdata = fid_val;
	double_list_append_as_tail(&folder_list, pnode);
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == message_rule_new_message(FALSE, "none@none",
		account, cpid, pdb->psqlite, fid_val, mid_val,
		pdigest, &folder_list, &msg_list)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION",  NULL, NULL, NULL);
	for (pnode=double_list_get_head(&msg_list); NULL!=pnode;
		pnode=double_list_get_after(&msg_list, pnode)) {
		pmnode = (MESSAGE_NODE*)pnode->pdata;
		if (mid_val == pmnode->message_id) {
			continue;
		}
		db_engine_proc_dynmaic_event(
			pdb, cpid, DYNAMIC_EVENT_NEW_MESSAGE,
			pmnode->folder_id, pmnode->message_id, 0);
		db_engine_notify_message_creation(pdb,
			pmnode->folder_id, pmnode->message_id);
	}
	db_engine_put_db(pdb);
	return TRUE;
}
