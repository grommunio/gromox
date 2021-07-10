// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <libHX/string.h>
#include <gromox/database.h>
#include "exmdb_server.h"
#include "common_util.h"
#include <gromox/ext_buffer.hpp>
#include "db_engine.h"
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/proptags.hpp>
#include <cstring>
#include <cstdio>
#define LLD(x) static_cast<long long>(x)
#define LLU(x) static_cast<unsigned long long>(x)

#define MAXIMUM_RECIEVE_FOLDERS				2000
#define MAXIMUM_STORE_FOLDERS				10000
#define SYSTEM_ALLOCATED_EID_RANGE			10000

using namespace gromox;

/* private only */
BOOL exmdb_server_get_folder_by_class(const char *dir,
	const char *str_class, uint64_t *pid, char *str_explicit)
{
	char *pdot;
	char tmp_class[256];
	char sql_string[1024];
	
	if (FALSE == exmdb_server_check_private()) {
		return FALSE;
	}
	auto class_len = std::min(strlen(str_class), static_cast<size_t>(255));
	memcpy(tmp_class, str_class, class_len);
	tmp_class[class_len] = '\0';
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	sprintf(sql_string, "SELECT folder_id"
				" FROM receive_table WHERE class=?");
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	pdot = tmp_class + class_len;
	do {
		*pdot = '\0';
		sqlite3_bind_text(pstmt, 1, tmp_class, -1, SQLITE_STATIC);
		if (SQLITE_ROW == sqlite3_step(pstmt)) {
			*pid = rop_util_make_eid_ex(1,
				sqlite3_column_int64(pstmt, 0));
			strcpy(str_explicit, tmp_class);
			return TRUE;
		}
		sqlite3_reset(pstmt);
	} while ((pdot = strrchr(tmp_class, '.')) != NULL);
	pstmt.finalize();
	sprintf(sql_string, "SELECT folder_id "
				"FROM receive_table WHERE class=''");
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	*pid = sqlite3_step(pstmt) == SQLITE_ROW ?
	       rop_util_make_eid_ex(1, sqlite3_column_int64(pstmt, 0)) :
	       rop_util_make_eid_ex(1, PRIVATE_FID_INBOX);
	str_explicit[0] = '\0';
	return TRUE;
}

/* private only */
BOOL exmdb_server_set_folder_by_class(const char *dir,
	uint64_t folder_id, const char *str_class, BOOL *pb_result)
{
	char sql_string[1024];
	
	if (FALSE == exmdb_server_check_private()) {
		return FALSE;
	}
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (0 == folder_id) {
		sprintf(sql_string, "DELETE FROM"
					" receive_table WHERE class=?");
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr) {
			return FALSE;
		}
		sqlite3_bind_text(pstmt, 1, str_class, -1, SQLITE_STATIC);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			return FALSE;
		}
		*pb_result = TRUE;
		return TRUE;
	}
	sprintf(sql_string, "SELECT folder_id FROM folders WHERE"
	          " folder_id=%llu", LLU(rop_util_get_gc_value(folder_id)));
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		*pb_result = FALSE;
		return TRUE;
	}
	pstmt.finalize();
	sprintf(sql_string, "SELECT "
			"count(*) FROM receive_table");
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW ||
	    sqlite3_column_int64(pstmt, 0) > MAXIMUM_RECIEVE_FOLDERS)
		return FALSE;
	pstmt.finalize();
	sprintf(sql_string, "REPLACE INTO receive_table"
			" VALUES (?, ?, %lu)", rop_util_current_nttime());
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	sqlite3_bind_text(pstmt, 1, str_class, -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, rop_util_get_gc_value(folder_id));
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	*pb_result = TRUE;
	return TRUE;
}

/* private only */
BOOL exmdb_server_get_folder_class_table(
	const char *dir, TARRAY_SET *ptable)
{
	int total_count;
	char sql_string[256];
	TPROPVAL_ARRAY *ppropvals;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	sprintf(sql_string, "SELECT "
			"count(*) FROM receive_table");
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	total_count = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	if (0 == total_count) {
		ptable->count = 0;
		ptable->pparray = NULL;
		return TRUE;
	}
	ptable->pparray = cu_alloc<TPROPVAL_ARRAY *>(total_count);
	if (NULL == ptable->pparray) {
		return FALSE;
	}
	sprintf(sql_string, "SELECT class, folder_id,"
					" modified_time FROM receive_table");
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	ptable->count = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		ppropvals = cu_alloc<TPROPVAL_ARRAY>();
		if (NULL == ppropvals) {
			return FALSE;
		}
		ppropvals->count = 3;
		ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(3);
		if (NULL == ppropvals->ppropval) {
			return FALSE;
		}
		ppropvals->ppropval[0].proptag = PROP_TAG_FOLDERID;
		ppropvals->ppropval[0].pvalue = cu_alloc<uint64_t>();
		if (NULL == ppropvals->ppropval[0].pvalue) {
			return FALSE;
		}
		*(uint64_t*)ppropvals->ppropval[0].pvalue =
			rop_util_make_eid_ex(1, sqlite3_column_int64(pstmt, 1));
		ppropvals->ppropval[1].proptag = PROP_TAG_MESSAGECLASS_STRING8;
		ppropvals->ppropval[1].pvalue =
			common_util_dup(reinterpret_cast<const char *>(sqlite3_column_text(pstmt, 0)));
		if (NULL == ppropvals->ppropval[1].pvalue) {
			return FALSE;
		}
		ppropvals->ppropval[2].proptag = PR_LAST_MODIFICATION_TIME;
		ppropvals->ppropval[2].pvalue = cu_alloc<uint64_t>();
		if (NULL == ppropvals->ppropval[2].pvalue) {
			return FALSE;
		}
		*(uint64_t*)ppropvals->ppropval[2].pvalue =
					sqlite3_column_int64(pstmt, 2);
		ptable->pparray[ptable->count] = ppropvals;
		ptable->count ++;
	}
	return TRUE;
}

BOOL exmdb_server_check_folder_id(const char *dir,
	uint64_t folder_id, BOOL *pb_exist)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (FALSE == common_util_check_folder_id(pdb->psqlite,
		rop_util_get_gc_value(folder_id), pb_exist)) {
		return FALSE;
	}
	return TRUE;
}

/* this function is only used by midb for query */
BOOL exmdb_server_query_folder_messages(const char *dir,
	uint64_t folder_id, TARRAY_SET *pset)
{
	uint64_t message_id;
	char sql_string[256];
	uint32_t message_flags;
	TPROPVAL_ARRAY *ppropvals;
	
	if (FALSE == exmdb_server_check_private()) {
		return FALSE;
	}
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sprintf(sql_string, "SELECT count(message_id) FROM"
			" messages WHERE parent_fid=%llu AND is_associated=0",
			LLU(rop_util_get_gc_value(folder_id)));
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		pstmt.finalize();
		sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
		return FALSE;
	}
	pset->count = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(pset->count);
	if (NULL == pset->pparray) {
		pset->count = 0;
		sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
		return FALSE;
	}
	sprintf(sql_string, "SELECT message_id, read_state,"
			" mid_string FROM messages WHERE parent_fid=%llu AND "
			"is_associated=0", LLU(rop_util_get_gc_value(folder_id)));
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
		return FALSE;
	}
	sprintf(sql_string, "SELECT propval "
		"FROM message_properties WHERE message_id=?"
		" AND proptag=?");
	auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt1 == nullptr) {
		pstmt.finalize();
		sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
		return FALSE;
	}
	for (size_t i = 0; i < pset->count; ++i) {
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			pstmt.finalize();
			pstmt1.finalize();
			sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
			return FALSE;
		}
		ppropvals = cu_alloc<TPROPVAL_ARRAY>();
		if (NULL == ppropvals) {
			pstmt.finalize();
			pstmt1.finalize();
			sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
			return FALSE;
		}
		pset->pparray[i] = ppropvals;
		ppropvals->count = 0;
		ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(5);
		if (NULL == ppropvals->ppropval) {
			pstmt.finalize();
			pstmt1.finalize();
			sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
			return FALSE;
		}
		message_id = sqlite3_column_int64(pstmt, 0);
		auto *pv = &ppropvals->ppropval[ppropvals->count];
		pv->proptag = PROP_TAG_MID;
		pv->pvalue = cu_alloc<uint64_t>();
		if (pv->pvalue == nullptr) {
			pstmt.finalize();
			pstmt1.finalize();
			sqlite3_exec(pdb->psqlite,
				"COMMIT TRANSACTION", NULL, NULL, NULL);
			return FALSE;
		}
		*static_cast<uint64_t *>(pv->pvalue) = rop_util_make_eid_ex(1, message_id);
		ppropvals->count ++;
		++pv;
		if (SQLITE_NULL != sqlite3_column_type(pstmt, 2)) {
			pv->proptag = PROP_TAG_MIDSTRING;
			pv->pvalue = common_util_dup(reinterpret_cast<const char *>(sqlite3_column_text(pstmt, 2)));
			if (pv->pvalue == nullptr) {
				pstmt.finalize();
				pstmt1.finalize();
				sqlite3_exec(pdb->psqlite,
					"COMMIT TRANSACTION", NULL, NULL, NULL);
				return FALSE;
			}
			ppropvals->count ++;
			++pv;
		}
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, message_id);
		sqlite3_bind_int64(pstmt1, 2, PR_MESSAGE_FLAGS);
		if (SQLITE_ROW == sqlite3_step(pstmt1)) {
			message_flags = sqlite3_column_int64(pstmt1, 0);
			message_flags &= ~(MSGFLAG_READ | MSGFLAG_HASATTACH |
			                 MSGFLAG_FROMME | MSGFLAG_ASSOCIATED |
			                 MSGFLAG_RN_PENDING | MSGFLAG_NRN_PENDING);
			if (0 != sqlite3_column_int64(pstmt, 1)) {
				message_flags |= MSGFLAG_READ;
			}
			pv->proptag = PR_MESSAGE_FLAGS;
			pv->pvalue = cu_alloc<uint32_t>();
			if (pv->pvalue == nullptr) {
				pstmt.finalize();
				pstmt1.finalize();
				sqlite3_exec(pdb->psqlite,
					"COMMIT TRANSACTION", NULL, NULL, NULL);
				return FALSE;
			}
			*static_cast<uint32_t *>(pv->pvalue) = message_flags;
			ppropvals->count ++;
			++pv;
		}
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, message_id);
		sqlite3_bind_int64(pstmt1, 2, PR_LAST_MODIFICATION_TIME);
		if (SQLITE_ROW == sqlite3_step(pstmt1)) {
			pv->proptag = PR_LAST_MODIFICATION_TIME;
			pv->pvalue = cu_alloc<uint64_t>();
			if (pv->pvalue == nullptr) {
				pstmt.finalize();
				pstmt1.finalize();
				sqlite3_exec(pdb->psqlite,
					"COMMIT TRANSACTION", NULL, NULL, NULL);
				return FALSE;
			}
			*static_cast<uint64_t *>(pv->pvalue) = sqlite3_column_int64(pstmt1, 0);
			ppropvals->count ++;
			++pv;
		}
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, message_id);
		sqlite3_bind_int64(pstmt1, 2, PR_LAST_MODIFICATION_TIME);
		if (SQLITE_ROW == sqlite3_step(pstmt1)) {
			pv->proptag = PROP_TAG_MESSAGEDELIVERYTIME;
			pv->pvalue = cu_alloc<uint64_t>();
			if (pv->pvalue == nullptr) {
				pstmt.finalize();
				pstmt1.finalize();
				sqlite3_exec(pdb->psqlite,
					"COMMIT TRANSACTION", NULL, NULL, NULL);
				return FALSE;
			}
			*static_cast<uint64_t *>(pv->pvalue) = sqlite3_column_int64(pstmt1, 0);
			ppropvals->count ++;
			++pv;
		}
	}
	pstmt.finalize();
	pstmt1.finalize();
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	return TRUE;
}

BOOL exmdb_server_check_folder_deleted(const char *dir,
	uint64_t folder_id, BOOL *pb_del)
{
	char sql_string[256];
	
	if (TRUE == exmdb_server_check_private()) {
		*pb_del = FALSE;
		return TRUE;
	}
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	sprintf(sql_string, "SELECT is_deleted "
				"FROM folders WHERE folder_id=%llu",
				LLU(rop_util_get_gc_value(folder_id)));
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	*pb_del = sqlite3_step(pstmt) != SQLITE_ROW || sqlite3_column_int64(pstmt, 0) != 0 ? TRUE : false;
	return TRUE;
}

BOOL exmdb_server_get_folder_by_name(const char *dir,
	uint64_t parent_id, const char *str_name,
	uint64_t *pfolder_id)
{
	uint64_t fid_val;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (FALSE == common_util_get_folder_by_name(pdb->psqlite,
		rop_util_get_gc_value(parent_id), str_name, &fid_val)) {
		return FALSE;
	}
	*pfolder_id = fid_val == 0 ? 0 :
	              (fid_val & 0xFF00000000000000ULL) == 0 ?
	              rop_util_make_eid_ex(1, fid_val) :
	              rop_util_make_eid_ex(fid_val >> 48, fid_val & 0x00FFFFFFFFFFFFFFULL);
	return TRUE;
}

static bool special_name(const char *s)
{
	static const char *const names[] = {
		"Inbox", "Drafts", "Outbox", "Sent Items", "Deleted Items",
		"Contacts", "Calendar", "Journal", "Notes", "Tasks",
		"Junk E-mail", "Sync Issues"
	};
	for (size_t i = 0; i < arsizeof(names); ++i)
		if (strcasecmp(s, names[i]) == 0)
			return true;
	return false;
}

BOOL exmdb_server_create_folder_by_properties(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *pproperties,
	uint64_t *pfolder_id)
{
	void *pvalue;
	uint32_t art;
	uint32_t hcn;
	uint32_t type;
	uint32_t next;
	BOOL b_result;
	uint32_t del_cnt;
	uint64_t nt_time;
	uint64_t cur_eid;
	uint64_t max_eid;
	uint64_t tmp_val;
	uint64_t tmp_fid;
	const char *pname;
	uint64_t parent_id;
	uint64_t folder_id;
	uint64_t change_num;
	char sql_string[128];
	uint32_t parent_type;
	TAGGED_PROPVAL tmp_propval;
	PROBLEM_ARRAY tmp_problems;
	
	pvalue = common_util_get_propvals(pproperties, PROP_TAG_FOLDERID);
	if (NULL == pvalue) {
		tmp_fid = 0;
	} else {
		tmp_fid = *(uint64_t*)pvalue;
		common_util_remove_propvals(
			(TPROPVAL_ARRAY*)pproperties, PROP_TAG_FOLDERID);
	}
	*pfolder_id = 0;
	pvalue = common_util_get_propvals(pproperties, PROP_TAG_PARENTFOLDERID);
	if (pvalue == nullptr || rop_util_get_replid(*static_cast<uint64_t *>(pvalue)) != 1)
		return TRUE;
	parent_id = rop_util_get_gc_value(*(uint64_t*)pvalue);
	common_util_remove_propvals(
		(TPROPVAL_ARRAY*)pproperties, PROP_TAG_PARENTFOLDERID);
	pname = static_cast<char *>(common_util_get_propvals(pproperties, PR_DISPLAY_NAME));
	if (pname == nullptr)
		return TRUE;
	if (exmdb_server_check_private() &&
	    parent_id == PRIVATE_FID_IPMSUBTREE && special_name(pname))
		return TRUE;	
	pvalue = common_util_get_propvals(pproperties, PROP_TAG_CHANGENUMBER);
	if (pvalue == nullptr)
		return TRUE;
	common_util_remove_propvals(
		(TPROPVAL_ARRAY*)pproperties, PROP_TAG_CHANGENUMBER);
	change_num = rop_util_get_gc_value(*(uint64_t*)pvalue);
	if (common_util_get_propvals(pproperties, PR_PREDECESSOR_CHANGE_LIST) == nullptr)
		return TRUE;
	pvalue = common_util_get_propvals(pproperties, PROP_TAG_FOLDERTYPE);
	if (NULL == pvalue) {
		type = FOLDER_TYPE_GENERIC;
	} else {
		type = *(uint32_t*)pvalue;
		switch (type) {
		case FOLDER_TYPE_GENERIC:
			break;
		case FOLDER_TYPE_SEARCH:
			if (!exmdb_server_check_private())
				return TRUE;
			break;
		default:
			return TRUE;
		}
		common_util_remove_propvals((TPROPVAL_ARRAY*)
				pproperties, PROP_TAG_FOLDERTYPE);
	}
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	sprintf(sql_string, "SELECT count(folder_id) FROM folders");
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	if (sqlite3_step(pstmt) != SQLITE_ROW ||
	    sqlite3_column_int64(pstmt, 0) > MAXIMUM_STORE_FOLDERS)
		return TRUE;
	pstmt.finalize();
	if (FALSE == common_util_get_folder_type(
		pdb->psqlite, parent_id, &parent_type)) {
		return FALSE;
	}
	if (parent_type == FOLDER_TYPE_SEARCH)
		return TRUE;
	if (0 != tmp_fid) {
		tmp_val = rop_util_get_gc_value(tmp_fid);
		sprintf(sql_string, "SELECT folder_id FROM"
		          " folders WHERE folder_id=%llu", LLU(tmp_val));
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr) {
			return FALSE;
		}
		if (sqlite3_step(pstmt) == SQLITE_ROW)
			return TRUE;
		pstmt.finalize();
		if (FALSE == common_util_check_allocated_eid(
			pdb->psqlite, tmp_val, &b_result)) {
			return FALSE;
		}
		if (!b_result)
			return TRUE;
	}
	sprintf(sql_string, "SELECT folder_id FROM "
	          "folders WHERE parent_id=%llu", LLU(parent_id));
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	sprintf(sql_string, "SELECT propval "
		"FROM folder_properties WHERE folder_id=?"
	        " AND proptag=%u", PR_DISPLAY_NAME);
	auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt1 == nullptr) {
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		tmp_val = sqlite3_column_int64(pstmt, 0);
		sqlite3_bind_int64(pstmt1, 1, tmp_val);
		if (SQLITE_ROW == sqlite3_step(pstmt1)) {
			if (strcasecmp(pname, reinterpret_cast<const char *>(sqlite3_column_text(pstmt1, 0))) == 0)
				return TRUE;
		}
		sqlite3_reset(pstmt1);
	}
	pstmt1.finalize();
	pstmt.finalize();
	if (FOLDER_TYPE_GENERIC == type) {
		sprintf(sql_string, "SELECT "
			"max(range_end) FROM allocated_eids");
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
			return FALSE;
		max_eid = sqlite3_column_int64(pstmt, 0);
		pstmt.finalize();
		max_eid ++;
		sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
		sprintf(sql_string, "INSERT INTO allocated_eids"
			" VALUES (%llu, %llu, %lld, 1)", LLU(max_eid), LLU(max_eid +
			SYSTEM_ALLOCATED_EID_RANGE - 1), LLD(time(nullptr)));
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			return FALSE;
		}
		if (0 == tmp_fid) {
			folder_id = max_eid;
			cur_eid = max_eid + 1;
		} else {
			folder_id = rop_util_get_gc_value(tmp_fid);
			cur_eid = max_eid;
		}
		max_eid += SYSTEM_ALLOCATED_EID_RANGE;
		sprintf(sql_string, "INSERT INTO folders "
					"(folder_id, parent_id, change_number, "
					"cur_eid, max_eid) VALUES (?, ?, ?, ?, ?)");
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		sqlite3_bind_int64(pstmt, 1, folder_id);
		sqlite3_bind_int64(pstmt, 2, parent_id);
		sqlite3_bind_int64(pstmt, 3, change_num);
		sqlite3_bind_int64(pstmt, 4, cur_eid);
		sqlite3_bind_int64(pstmt, 5, max_eid);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			pstmt.finalize();
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		pstmt.finalize();
		if (FALSE == common_util_set_properties(FOLDER_PROPERTIES_TABLE,
			folder_id, cpid, pdb->psqlite, pproperties, &tmp_problems)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		next = 1;
		tmp_propval.proptag = PROP_TAG_ARTICLENUMBERNEXT;
		tmp_propval.pvalue = &next;
		common_util_set_property(FOLDER_PROPERTIES_TABLE,
			folder_id, 0, pdb->psqlite, &tmp_propval, &b_result);
		del_cnt = 0;
		tmp_propval.proptag = PR_DELETED_COUNT_TOTAL;
		tmp_propval.pvalue = &del_cnt;
		common_util_set_property(FOLDER_PROPERTIES_TABLE,
			folder_id, 0, pdb->psqlite, &tmp_propval, &b_result);
	} else {
		sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
		if (0 == tmp_fid) {
			if (FALSE == common_util_allocate_eid(pdb->psqlite, &max_eid)) {
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				return FALSE;
			}
			folder_id = max_eid;
		} else {
			folder_id = rop_util_get_gc_value(tmp_fid);
		}
		sprintf(sql_string, "INSERT INTO folders (folder_id,"
					" parent_id, change_number, is_search, cur_eid, "
					"max_eid) VALUES (?, ?, ?, 1, 0, 0)");
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		sqlite3_bind_int64(pstmt, 1, folder_id);
		sqlite3_bind_int64(pstmt, 2, parent_id);
		sqlite3_bind_int64(pstmt, 3, change_num);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			pstmt.finalize();
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		pstmt.finalize();
		if (FALSE == common_util_set_properties(FOLDER_PROPERTIES_TABLE,
			folder_id, cpid, pdb->psqlite, pproperties, &tmp_problems)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
	}
	if (FALSE == common_util_allocate_folder_art(pdb->psqlite, &art)) {
		return FALSE;
	}
	tmp_propval.proptag = PROP_TAG_INTERNETARTICLENUMBER;
	tmp_propval.pvalue = &art;
	common_util_set_property(FOLDER_PROPERTIES_TABLE,
		folder_id, 0, pdb->psqlite, &tmp_propval, &b_result);
	nt_time = rop_util_current_nttime();
	tmp_propval.proptag = PROP_TAG_LOCALCOMMITTIMEMAX;
	tmp_propval.pvalue = &nt_time;
	common_util_set_property(FOLDER_PROPERTIES_TABLE,
		parent_id, 0, pdb->psqlite, &tmp_propval, &b_result);
	common_util_set_property(FOLDER_PROPERTIES_TABLE,
		folder_id, 0, pdb->psqlite, &tmp_propval, &b_result);
	hcn = 0;
	tmp_propval.proptag = PROP_TAG_HIERARCHYCHANGENUMBER;
	tmp_propval.pvalue = &hcn;
	common_util_set_property(FOLDER_PROPERTIES_TABLE,
		folder_id, 0, pdb->psqlite, &tmp_propval, &b_result);
	sprintf(sql_string, "UPDATE folder_properties SET"
		" propval=propval+1 WHERE folder_id=%llu AND "
		"proptag=%u", LLU(parent_id), PROP_TAG_HIERARCHYCHANGENUMBER);
	sqlite3_exec(pdb->psqlite, sql_string, NULL, NULL, NULL);
	tmp_propval.proptag = PROP_TAG_HIERREV;
	tmp_propval.pvalue = &nt_time;
	common_util_set_property(FOLDER_PROPERTIES_TABLE,
		parent_id, 0, pdb->psqlite, &tmp_propval, &b_result);
	common_util_set_property(FOLDER_PROPERTIES_TABLE,
		folder_id, 0, pdb->psqlite, &tmp_propval, &b_result);
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	db_engine_notify_folder_creation(pdb, parent_id, folder_id);
	*pfolder_id = rop_util_make_eid_ex(1, folder_id);
	return TRUE;
}

BOOL exmdb_server_get_folder_all_proptags(const char *dir,
	uint64_t folder_id, PROPTAG_ARRAY *pproptags)
{
	int i;
	PROPTAG_ARRAY tmp_proptags;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (FALSE == common_util_get_proptags(FOLDER_PROPERTIES_TABLE,
		rop_util_get_gc_value(folder_id), pdb->psqlite, &tmp_proptags)) {
		return FALSE;
	}
	pdb.reset();
	for (i=0; i<tmp_proptags.count; i++) {
		if (tmp_proptags.pproptag[i] == PR_SOURCE_KEY)
			break;
	}
	if (i < tmp_proptags.count) {
		*pproptags = tmp_proptags;
	} else {
		pproptags->count = tmp_proptags.count + 1;
		pproptags->pproptag = cu_alloc<uint32_t>(pproptags->count);
		if (NULL == pproptags->pproptag) {
			pproptags->count = 0;
			return FALSE;
		}
		memcpy(pproptags->pproptag, tmp_proptags.pproptag,
					sizeof(uint32_t)*tmp_proptags.count);
		pproptags->pproptag[tmp_proptags.count] = PR_SOURCE_KEY;
	}
	return TRUE;
}

BOOL exmdb_server_get_folder_properties(
	const char *dir, uint32_t cpid, uint64_t folder_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (FALSE == common_util_get_properties(FOLDER_PROPERTIES_TABLE,
		rop_util_get_gc_value(folder_id), cpid, pdb->psqlite,
		pproptags, ppropvals)) {
		return FALSE;
	}
	return TRUE;
}

/* no PROPERTY_PROBLEM for PROP_TAG_CHANGENUMBER
	and PROP_TAG_CHANGKEY */
BOOL exmdb_server_set_folder_properties(
	const char *dir, uint32_t cpid, uint64_t folder_id,
	const TPROPVAL_ARRAY *pproperties,
	PROBLEM_ARRAY *pproblems)
{
	int i;
	BOOL b_result;
	uint64_t fid_val;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	fid_val = rop_util_get_gc_value(folder_id);
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (TRUE == exmdb_server_check_private()
		&& PRIVATE_FID_ROOT == fid_val) {
		for (i=0; i<pproperties->count; i++) {
			if (pproperties->ppropval[i].proptag == PR_ADDITIONAL_REN_ENTRYIDS ||
			    pproperties->ppropval[i].proptag == PR_ADDITIONAL_REN_ENTRYIDS_EX ||
			    pproperties->ppropval[i].proptag == PROP_TAG_REMINDERSONLINEENTRYID) {
				if (FALSE == common_util_set_property(
					FOLDER_PROPERTIES_TABLE, PRIVATE_FID_INBOX,
					0, pdb->psqlite, &pproperties->ppropval[i],
					&b_result)) {
					sqlite3_exec(pdb->psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					return FALSE;
				}
			}
		}
	}
	if (FALSE == common_util_set_properties(FOLDER_PROPERTIES_TABLE,
		fid_val, cpid, pdb->psqlite, pproperties, pproblems)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	db_engine_notify_folder_modification(pdb,
		common_util_get_folder_parent_fid(
		pdb->psqlite, fid_val), fid_val);
	return TRUE;
}

BOOL exmdb_server_remove_folder_properties(const char *dir,
	uint64_t folder_id, const PROPTAG_ARRAY *pproptags)
{
	uint64_t fid_val;
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	fid_val = rop_util_get_gc_value(folder_id);
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == common_util_remove_properties(FOLDER_PROPERTIES_TABLE,
		fid_val, pdb->psqlite, pproptags)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	db_engine_notify_folder_modification(pdb,
		common_util_get_folder_parent_fid(
		pdb->psqlite, fid_val), fid_val);
	return TRUE;
}

static BOOL folder_empty_folder(db_item_ptr &pdb, uint32_t cpid,
	const char *username, uint64_t folder_id, BOOL b_hard,
	BOOL b_normal, BOOL b_fai, BOOL b_sub, BOOL *pb_partial,
	uint64_t *pnormal_size, uint64_t *pfai_size,
	uint32_t *pmessage_count, uint32_t *pfolder_count)
{
	BOOL b_check = true, b_owner, b_partial;
	uint32_t folder_type;
	char sql_string[256];
	
	*pb_partial = FALSE;
	uint64_t fid_val = folder_id;
	auto b_private = exmdb_server_check_private();
	if (TRUE == b_private) {
		b_hard = TRUE;
	}
	if (FALSE == common_util_get_folder_type(
		pdb->psqlite, folder_id, &folder_type)) {
		return FALSE;
	}
	if (FOLDER_TYPE_SEARCH == folder_type) {
		/* always in private store, there's only hard deletion */
		if (TRUE == b_normal || TRUE == b_fai) {
			sprintf(sql_string, "SELECT messages.message_id,"
						" messages.parent_fid, messages.message_size, "
						"messages.is_associated FROM messages JOIN "
						"search_result ON messages.message_id="
						"search_result.message_id AND "
						"search_result.folder_id=%llu", LLU(fid_val));
			auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
			if (pstmt == nullptr)
				return FALSE;
			while (SQLITE_ROW == sqlite3_step(pstmt)) {
				bool is_associated = sqlite3_column_int64(pstmt, 3);
				if ((is_associated && !b_fai) ||
				    (!is_associated && !b_normal))
					continue;
				uint64_t message_id = sqlite3_column_int64(pstmt, 0);
				uint64_t parent_fid = sqlite3_column_int64(pstmt, 1);
				if (NULL != username) {
					uint32_t permission;
					if (FALSE == common_util_check_folder_permission(
						pdb->psqlite, parent_fid, username, &permission)) {
						return FALSE;
					}
					if ((PERMISSION_FOLDEROWNER & permission) ||
						(PERMISSION_DELETEANY & permission)) {
						/* do nothing */
					} else if (permission & PERMISSION_DELETEOWNED) {
						if (FALSE == common_util_check_message_owner(
							pdb->psqlite, message_id, username, &b_owner)) {
							return FALSE;
						}
						if (FALSE == b_owner) {
							*pb_partial = TRUE;
							continue;
						}
					} else {
						*pb_partial = TRUE;
						continue;
					}
				}
				if (NULL != pmessage_count) {
					(*pmessage_count) ++;
				}
				if (is_associated && pfai_size != nullptr)
					*pfai_size += sqlite3_column_int64(pstmt, 2);
				else if (!is_associated && pnormal_size != nullptr)
					*pnormal_size += sqlite3_column_int64(pstmt, 2);
				db_engine_proc_dynamic_event(pdb, cpid,
					DYNAMIC_EVENT_DELETE_MESSAGE,
					fid_val, message_id, 0);
				db_engine_proc_dynamic_event(pdb, cpid,
					DYNAMIC_EVENT_DELETE_MESSAGE,
					parent_fid, message_id, 0);
				db_engine_notify_link_deletion(
					pdb, fid_val, message_id);
				db_engine_notify_message_deletion(
					pdb, parent_fid, message_id);
				sprintf(sql_string, "DELETE FROM messages "
				        "WHERE message_id=%llu", LLU(message_id));
				if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					return FALSE;
				}
			}
		}
		return TRUE;
	}
	if (TRUE == b_normal || TRUE == b_fai) {
		if (NULL == username) {
			b_check = FALSE;
		} else {
			uint32_t permission = 0;
			if (FALSE == common_util_check_folder_permission(
				pdb->psqlite, fid_val, username, &permission)) {
				return FALSE;
			}
			if (permission & (PERMISSION_FOLDEROWNER | PERMISSION_DELETEANY)) {
				b_check	= FALSE;
			} else if (permission & PERMISSION_DELETEOWNED) {
				b_check = TRUE;
			} else {
				*pb_partial = TRUE;
				return TRUE;
			}
		}
	}
	if (TRUE == b_normal && TRUE == b_fai) {
		sprintf(sql_string, "SELECT message_id,"
			" message_size, is_associated, is_deleted FROM"
			" messages WHERE parent_fid=%llu", LLU(fid_val));
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			bool is_deleted = b_private ? 0 : sqlite3_column_int64(pstmt, 3);
			if (!b_hard && is_deleted)
				continue;
			uint64_t message_id = sqlite3_column_int64(pstmt, 0);
			bool is_associated = sqlite3_column_int64(pstmt, 2);
			if (TRUE == b_check) {
				if (FALSE == common_util_check_message_owner(
					pdb->psqlite, message_id, username, &b_owner)) {
					return FALSE;
				}
				if (FALSE == b_owner) {
					*pb_partial = TRUE;
					continue;
				}
			}
			if (NULL != pmessage_count && TRUE == b_hard) {
				(*pmessage_count) ++;
			}
			if (b_hard && is_associated && pfai_size != nullptr)
				*pfai_size += sqlite3_column_int64(pstmt, 1);
			else if (b_hard && !is_associated && pnormal_size != nullptr)
				*pnormal_size += sqlite3_column_int64(pstmt, 1);
			if (0 == is_deleted) {
				db_engine_proc_dynamic_event(pdb, cpid,
					DYNAMIC_EVENT_DELETE_MESSAGE, fid_val,
					message_id, 0);
				db_engine_notify_message_deletion(
					pdb, fid_val, message_id);
			}
			if (TRUE == b_check) {
				if (TRUE == b_hard) {
					sprintf(sql_string, "DELETE FROM messages "
					        "WHERE message_id=%llu", LLU(message_id));
				} else {
					sprintf(sql_string, "UPDATE messages SET "
						"is_deleted=1 WHERE message_id=%llu",
						LLU(message_id));
				}
				if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					return FALSE;
				}
			}
			if (FALSE == b_hard) {
				sprintf(sql_string, "DELETE FROM read_states"
				        " WHERE message_id=%llu", LLU(message_id));
				if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					return FALSE;
				}
			}
		}
		pstmt.finalize();
		if (FALSE == b_check) {
			if (TRUE == b_hard) {
				sprintf(sql_string, "DELETE FROM messages WHERE "
				        "parent_fid=%llu", LLU(fid_val));
			} else {
				sprintf(sql_string, "UPDATE messages SET "
				        "is_deleted=1 WHERE parent_fid=%llu", LLU(fid_val));
			}
			if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
				sql_string, NULL, NULL, NULL)) {
				return FALSE;
			}
		}
	} else if (b_normal || b_fai) {
		bool is_associated = !b_normal;
		sprintf(sql_string, "SELECT message_id,"
			" message_size, is_deleted FROM messages "
			"WHERE parent_fid=%llu AND is_associated=%d",
			LLU(fid_val), is_associated);
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			bool is_deleted = b_private ? 0 : sqlite3_column_int64(pstmt, 2);
			if (!b_hard && is_deleted)
				continue;
			uint64_t message_id = sqlite3_column_int64(pstmt, 0);
			if (TRUE == b_check) {
				if (FALSE == common_util_check_message_owner(
					pdb->psqlite, message_id, username, &b_owner)) {
					return FALSE;
				}
				if (FALSE == b_owner) {
					*pb_partial = TRUE;
					continue;
				}
			}
			if (NULL != pmessage_count) {
				(*pmessage_count) ++;
			}
			if (b_hard && is_associated && pfai_size != nullptr)
				*pfai_size += sqlite3_column_int64(pstmt, 1);
			else if (b_hard && !is_associated && pnormal_size != nullptr)
				*pnormal_size += sqlite3_column_int64(pstmt, 1);
			if (0 == is_deleted) {
				db_engine_proc_dynamic_event(pdb, cpid,
					DYNAMIC_EVENT_DELETE_MESSAGE, fid_val,
					message_id, 0);
				db_engine_notify_message_deletion(
					pdb, fid_val, message_id);
			}
			if (TRUE == b_check) {
				if (TRUE == b_hard) {
					sprintf(sql_string, "DELETE FROM messages "
						"WHERE message_id=%llu", LLU(message_id));
				} else {
					sprintf(sql_string, "UPDATE messages SET "
						"is_deleted=1 WHERE message_id=%llu",
						LLU(message_id));
				}
				if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					return FALSE;
				}
			}
			if (FALSE == b_hard) {
				sprintf(sql_string, "DELETE FROM read_states"
					" WHERE message_id=%llu", LLU(message_id));
				if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					return FALSE;
				}
			}
		}
		pstmt.finalize();
		if (FALSE == b_check) {
			if (TRUE == b_hard) {
				sprintf(sql_string, "DELETE FROM messages WHERE"
						" parent_fid=%llu AND is_associated=%d",
						LLU(fid_val), is_associated);
			} else {
				sprintf(sql_string, "UPDATE messages SET is_deleted=1"
						" WHERE parent_fid=%llu AND is_associated=%d",
						LLU(fid_val), is_associated);
			}
			if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
				sql_string, NULL, NULL, NULL)) {
				return FALSE;
			}
		}
	}
	if (!b_sub)
		return TRUE;
	if (TRUE == b_private) {
		sprintf(sql_string, "SELECT folder_id "
			  "FROM folders WHERE parent_id=%llu", LLU(fid_val));
	} else {
		sprintf(sql_string, "SELECT folder_id,"
					" is_deleted FROM folders WHERE "
					"parent_fid=%llu", LLU(fid_val));
	}
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		uint64_t fid_val = sqlite3_column_int64(pstmt, 0);
		if ((TRUE == b_private && fid_val < PRIVATE_FID_CUSTOM) ||
			(FALSE == b_private && fid_val < PUBLIC_FID_CUSTOM)) {
			*pb_partial = TRUE;
			continue;
		}
		bool is_deleted = b_private ? 0 : sqlite3_column_int64(pstmt, 1);
		if (!b_hard && is_deleted)
			continue;
		if (NULL != username) {
			uint32_t permission = 0;
			if (FALSE == common_util_check_folder_permission(
				pdb->psqlite, fid_val, username, &permission)) {
				return FALSE;
			}
			if (0 == (permission & PERMISSION_FOLDEROWNER)) {
				*pb_partial = TRUE;
				continue;
			}
		}
		if (FALSE == folder_empty_folder(pdb, cpid, username,
			fid_val, b_hard, TRUE, TRUE, FALSE, &b_partial,
			pnormal_size, pfai_size, NULL, NULL)) {
			return FALSE;
		}
		if (TRUE == b_partial) {
			*pb_partial = TRUE;
			continue;
		}
		if (FALSE == folder_empty_folder(pdb, cpid, username,
			fid_val, b_hard, FALSE, FALSE, TRUE, &b_partial,
			pnormal_size, pfai_size, NULL, NULL)) {
			return FALSE;
		}
		if (TRUE == b_partial) {
			*pb_partial = TRUE;
			continue;
		}
		if (NULL != pfolder_count && TRUE == b_hard) {
			(*pfolder_count) ++;
		}
		if (TRUE == b_hard) {
			sprintf(sql_string, "DELETE FROM folders "
				"WHERE folder_id=%llu", LLU(fid_val));
		} else {
			sprintf(sql_string, "UPDATE folders SET "
				"is_deleted=1 WHERE folder_id=%llu",
				LLU(fid_val));
		}
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			return FALSE;
		}
		db_engine_notify_folder_deletion(
				pdb, folder_id, fid_val);
	}
	return TRUE;
}

/* only delete empty generic folder or search folder itself, not content */
BOOL exmdb_server_delete_folder(const char *dir, uint32_t cpid,
	uint64_t folder_id, BOOL b_hard, BOOL *pb_result)
{
	BOOL b_search;
	BOOL b_partial;
	uint64_t fid_val;
	uint64_t fai_size;
	uint64_t parent_id;
	char sql_string[256];
	uint64_t normal_size;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	b_search = FALSE;
	fid_val = rop_util_get_gc_value(folder_id);
	if (TRUE == exmdb_server_check_private()) {
		if (fid_val < PRIVATE_FID_CUSTOM) {
			*pb_result = FALSE;
			return TRUE;
		}
		sprintf(sql_string, "SELECT is_search FROM"
		          " folders WHERE folder_id=%llu", LLU(fid_val));
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr) {
			return FALSE;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			return TRUE;
		}
		if (0 != sqlite3_column_int64(pstmt, 0)) {
			b_search = TRUE;
		}
	} else {
		if (fid_val < PUBLIC_FID_CUSTOM) {
			*pb_result = FALSE;
			return TRUE;
		}
	}
	if (FALSE == b_search) {
		sprintf(sql_string, "SELECT count(*) FROM "
		          "folders WHERE parent_id=%llu", LLU(fid_val));
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
			return FALSE;
		if (0 != sqlite3_column_int64(pstmt, 0)) {
			*pb_result = FALSE;
			return TRUE;
		}
		pstmt.finalize();
		if (TRUE == exmdb_server_check_private()) {
			sprintf(sql_string, "SELECT count(*) FROM"
			          " messages WHERE parent_fid=%llu", LLU(fid_val));
		} else {
			sprintf(sql_string, "SELECT count(*) FROM"
							" messages WHERE parent_fid=%llu AND"
							" is_deleted=0", LLU(fid_val));
		}
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
			return FALSE;
		if (0 != sqlite3_column_int64(pstmt, 0)) {
			*pb_result = FALSE;
			return TRUE;
		}
	} else {
		sprintf(sql_string, "SELECT message_id FROM"
		          " search_result WHERE folder_id=%llu", LLU(fid_val));
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr) {
			return FALSE;
		}
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			db_engine_proc_dynamic_event(pdb, cpid,
				DYNAMIC_EVENT_DELETE_MESSAGE, fid_val,
				sqlite3_column_int64(pstmt, 0), 0);
		}
		pstmt.finalize();
		db_engine_delete_dynamic(pdb, fid_val);
	}
	parent_id = common_util_get_folder_parent_fid(
							pdb->psqlite, fid_val);
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (TRUE == exmdb_server_check_private()) {
		sprintf(sql_string, "DELETE FROM folders"
		        " WHERE folder_id=%llu", LLU(fid_val));
	} else {
		if (TRUE == b_hard) {
			if (FALSE == folder_empty_folder(pdb, cpid,
				NULL, fid_val, TRUE, TRUE, TRUE, TRUE,
				&b_partial, &normal_size, &fai_size,
				NULL, NULL) || TRUE == b_partial ||
				FALSE == common_util_decrease_store_size(
				pdb->psqlite, normal_size, fai_size)) {
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				return FALSE;
			}
			sprintf(sql_string, "DELETE FROM folders"
			        " WHERE folder_id=%llu", LLU(fid_val));
		} else {
			sprintf(sql_string, "UPDATE folders SET"
				" is_deleted=1 WHERE folder_id=%llu",
				LLU(fid_val));
		}
	}
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	db_engine_notify_folder_deletion(
		pdb, parent_id, fid_val);
	sprintf(sql_string, "UPDATE folder_properties SET"
		" propval=propval+1 WHERE folder_id=%llu AND "
	        "proptag=%u", LLU(parent_id), PR_DELETED_FOLDER_COUNT);
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	sprintf(sql_string, "UPDATE folder_properties SET"
		" propval=propval+1 WHERE folder_id=%llu AND "
		"proptag=%u", LLU(parent_id), PROP_TAG_HIERARCHYCHANGENUMBER);
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	sprintf(sql_string, "UPDATE folder_properties "
		"SET propval=%llu WHERE folder_id=%llu AND proptag=?",
		LLU(rop_util_current_nttime()), LLU(parent_id));
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	sqlite3_bind_int64(pstmt, 0, PROP_TAG_HIERREV);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		pstmt.finalize();
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 0, PROP_TAG_LOCALCOMMITTIMEMAX);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		pstmt.finalize();
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	pstmt.finalize();
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	*pb_result = TRUE;
	return TRUE;
}

BOOL exmdb_server_empty_folder(const char *dir, uint32_t cpid,
	const char *username, uint64_t folder_id, BOOL b_hard,
	BOOL b_normal, BOOL b_fai, BOOL b_sub, BOOL *pb_partial)
{
	uint64_t fid_val;
	uint64_t fai_size;
	char sql_string[256];
	uint64_t normal_size;
	uint32_t folder_count;
	uint32_t message_count;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	fid_val = rop_util_get_gc_value(folder_id);
	message_count = 0;
	folder_count = 0;
	normal_size = 0;
	fai_size = 0;
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == folder_empty_folder(pdb, cpid, username, fid_val,
		b_hard, b_normal, b_fai, b_sub, pb_partial, &normal_size,
		&fai_size, &message_count, &folder_count)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	if (message_count > 0) {
		sprintf(sql_string, "UPDATE folder_properties SET "
			"propval=propval+%u WHERE folder_id=%llu AND "
			"proptag=%u", message_count, LLU(fid_val),
		        PR_DELETED_COUNT_TOTAL);
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
	}
	if (folder_count > 0) {
		sprintf(sql_string, "UPDATE folder_properties SET "
			"propval=propval+%u WHERE folder_id=%llu AND "
			"proptag=%u", folder_count, LLU(fid_val),
		        PR_DELETED_FOLDER_COUNT);
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		sprintf(sql_string, "UPDATE folder_properties SET "
			"propval=propval+1 WHERE folder_id=%llu AND "
			"proptag=%u", LLU(fid_val), PROP_TAG_HIERARCHYCHANGENUMBER);
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		sprintf(sql_string, "UPDATE folder_properties SET "
			"propval=%llu WHERE folder_id=%llu AND proptag=%u",
			LLU(rop_util_current_nttime()), LLU(fid_val), PROP_TAG_HIERREV);
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
	}
	if (message_count > 0 || folder_count > 0) {
		sprintf(sql_string, "UPDATE folder_properties SET "
			"propval=%llu WHERE folder_id=%llu AND proptag=%u",
			LLU(rop_util_current_nttime()), LLU(fid_val),
			PROP_TAG_LOCALCOMMITTIMEMAX);
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
	}
	if (FALSE == common_util_decrease_store_size(
		pdb->psqlite, normal_size, fai_size)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	return TRUE;
}

BOOL exmdb_server_check_folder_cycle(const char *dir,
	uint64_t src_fid, uint64_t dst_fid, BOOL *pb_cycle)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (!common_util_check_descendant(pdb->psqlite,
	    rop_util_get_gc_value(dst_fid), rop_util_get_gc_value(src_fid),
	    pb_cycle)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL folder_copy_generic_folder(sqlite3 *psqlite,
	BOOL b_guest, const char *username, uint64_t src_fid,
	uint64_t dst_pid, uint64_t *pdst_fid)
{
	uint32_t art;
	uint64_t nt_time;
	uint64_t last_eid;
	uint64_t change_num;
	char sql_string[256];
	
	if (FALSE == common_util_allocate_cn(
		psqlite, &change_num)) {
		return FALSE;
	}
	sprintf(sql_string, "SELECT "
		"max(range_end) FROM allocated_eids");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	last_eid = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	sprintf(sql_string, "INSERT INTO allocated_eids"
			" VALUES (%llu, %llu, %lld, 1)", LLU(last_eid + 1),
			LLU(last_eid + ALLOCATED_EID_RANGE), LLD(time(nullptr)));
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	sprintf(sql_string, "INSERT INTO folders "
				"(folder_id, parent_id, change_number, "
				"cur_eid, max_eid) VALUES (?, ?, ?, ?, ?)");
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, last_eid + 1);
	sqlite3_bind_int64(pstmt, 2, dst_pid);
	sqlite3_bind_int64(pstmt, 3, change_num);
	sqlite3_bind_int64(pstmt, 4, last_eid + 2);
	sqlite3_bind_int64(pstmt, 5, last_eid + ALLOCATED_EID_RANGE);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	pstmt.finalize();
	sprintf(sql_string, "INSERT INTO folder_properties "
		"(folder_id, proptag, propval) SELECT %llu, proptag,"
		" propval FROM folder_properties WHERE folder_id=%llu",
		LLU(last_eid + 1), LLU(src_fid));
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	if (TRUE == b_guest) {
		sprintf(sql_string, "INSERT INTO permissions "
					"(folder_id, username, permission) VALUES "
					"(%llu, ?, ?)", LLU(last_eid + 1));
		pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
		sqlite3_bind_int64(pstmt, 2, PERMISSION_FOLDEROWNER);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			return FALSE;
		}
		pstmt.finalize();
	}
	if (FALSE == common_util_allocate_folder_art(psqlite, &art)) {
		return FALSE;
	}
	nt_time = rop_util_current_nttime();
	sprintf(sql_string, "UPDATE folder_properties"
				" SET propval=? WHERE folder_id=%llu AND "
				"proptag=?", LLU(last_eid + 1));
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, art);
	sqlite3_bind_int64(pstmt, 2, PROP_TAG_INTERNETARTICLENUMBER);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, 1);
	sqlite3_bind_int64(pstmt, 2, PROP_TAG_ARTICLENUMBERNEXT);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, nt_time);
	sqlite3_bind_int64(pstmt, 2, PR_LAST_MODIFICATION_TIME);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, nt_time);
	sqlite3_bind_int64(pstmt, 2, PROP_TAG_LOCALCOMMITTIMEMAX);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, 0);
	sqlite3_bind_int64(pstmt, 2, PROP_TAG_HIERARCHYCHANGENUMBER);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, nt_time);
	sqlite3_bind_int64(pstmt, 2, PROP_TAG_HIERREV);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	*pdst_fid = last_eid + 1;
	return TRUE;
}

static BOOL folder_copy_search_folder(db_item_ptr &pdb,
	uint32_t cpid, BOOL b_guest, const char *username,
	uint64_t src_fid, uint64_t dst_pid, uint64_t *pdst_fid)
{
	uint32_t art;
	uint64_t nt_time;
	uint64_t last_eid;
	uint64_t change_num;
	char sql_string[256];
	
	if (FALSE == common_util_allocate_cn(
		pdb->psqlite, &change_num)) {
		return FALSE;
	}
	if (FALSE == common_util_allocate_eid(
		pdb->psqlite, &last_eid)) {
		return FALSE;
	}
	sprintf(sql_string, "INSERT INTO folders (folder_id, "
		"parent_id, change_number, is_search, search_flags,"
		" search_criteria, cur_eid, max_eid) SELECT %llu, "
		"%llu, %llu, 1, search_flags, search_criteria, 0, 0"
		" FROM folders WHERE folder_id=%llu", LLU(last_eid),
		LLU(dst_pid), LLU(change_num), LLU(src_fid));
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	sprintf(sql_string, "INSERT INTO folder_properties "
		"(folder_id, proptag, propval) SELECT %llu, proptag,"
		" propval FROM folder_properties WHERE folder_id=%llu",
		LLU(last_eid), LLU(src_fid));
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	if (TRUE == b_guest) {
		sprintf(sql_string, "INSERT INTO permissions "
					"(folder_id, username, permission) VALUES "
					"(%llu, ?, ?)", LLU(last_eid));
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
		sqlite3_bind_int64(pstmt, 2, PERMISSION_FOLDEROWNER);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			return FALSE;
		}
	}
	if (FALSE == common_util_allocate_folder_art(pdb->psqlite, &art)) {
		return FALSE;
	}
	nt_time = rop_util_current_nttime();
	sprintf(sql_string, "UPDATE folder_properties"
				" SET propval=? WHERE folder_id=%llu AND "
				"proptag=?", LLU(last_eid));
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, art);
	sqlite3_bind_int64(pstmt, 2, PROP_TAG_INTERNETARTICLENUMBER);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, nt_time);
	sqlite3_bind_int64(pstmt, 2, PR_LAST_MODIFICATION_TIME);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, nt_time);
	sqlite3_bind_int64(pstmt, 2, PROP_TAG_LOCALCOMMITTIMEMAX);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, 0);
	sqlite3_bind_int64(pstmt, 2, PROP_TAG_HIERARCHYCHANGENUMBER);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, nt_time);
	sqlite3_bind_int64(pstmt, 2, PROP_TAG_HIERREV);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
	pstmt.finalize();
	sprintf(sql_string, "INSERT INTO search_result (folder_id, "
		"message_id) SELECT %llu, message_id WHERE folder_id=%llu",
		LLU(last_eid), LLU(src_fid));
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	sprintf(sql_string, "SELECT message_id FROM "
	          "search_result WHERE folder_id=%llu", LLU(last_eid));
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		db_engine_proc_dynamic_event(pdb, cpid,
			DYNAMIC_EVENT_NEW_MESSAGE, last_eid,
			sqlite3_column_int64(pstmt, 0), 0);
	}
	*pdst_fid = last_eid;
	return TRUE;
}

static BOOL folder_copy_folder_internal(db_item_ptr &pdb, int account_id,
    uint32_t cpid, BOOL b_guest,
	const char *username, uint64_t src_fid, BOOL b_normal,
	BOOL b_fai, BOOL b_sub, uint64_t dst_fid, BOOL *pb_partial,
	uint64_t *pnormal_size, uint64_t *pfai_size, uint32_t *pfolder_count)
{
	BOOL b_check = true, b_owner, b_result, b_private, b_partial;
	uint64_t fid_val;
	uint64_t src_fid1;
	int is_associated;
	uint64_t message_id;
	uint64_t parent_fid;
	uint64_t message_id1;
	uint32_t folder_type;
	char sql_string[256];
	uint32_t message_size, permission = 0;
	
	*pb_partial = FALSE;
	fid_val = src_fid;
	b_private = exmdb_server_check_private();
	if (FALSE == common_util_get_folder_type(
		pdb->psqlite, fid_val, &folder_type)) {
		return FALSE;
	}
	if (FOLDER_TYPE_SEARCH == folder_type) {
		if (TRUE == b_guest) {
			if (FALSE == common_util_check_folder_permission(
				pdb->psqlite, dst_fid, username, &permission)) {
				return FALSE;
			}
			if (0 == (permission & PERMISSION_CREATE)) {
				*pb_partial = TRUE;
				return TRUE;
			}
		}
		if (TRUE == b_normal || TRUE == b_fai) {
			sprintf(sql_string, "SELECT messages.message_id,"
						" messages.parent_fid, messages.is_associated "
						"FROM messages JOIN search_result ON "
						"messages.message_id=search_result.message_id"
						" AND search_result.folder_id=%llu", LLU(fid_val));
			auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
			if (pstmt == nullptr)
				return FALSE;
			while (SQLITE_ROW == sqlite3_step(pstmt)) {
				is_associated = sqlite3_column_int64(pstmt, 2);
				if (0 == is_associated) {
					if (FALSE == b_normal) {
						continue;
					}
				} else {
					if (FALSE == b_fai) {
						continue;
					}
				}
				message_id = sqlite3_column_int64(pstmt, 0);
				parent_fid = sqlite3_column_int64(pstmt, 1);
				if (TRUE == b_guest) {
					if (FALSE == common_util_check_folder_permission(
						pdb->psqlite, parent_fid, username, &permission)) {
						return FALSE;
					}
					if ((PERMISSION_FOLDEROWNER & permission) ||
						(PERMISSION_READANY & permission)) {
						/* do nothing */
					} else {
						if (FALSE == common_util_check_message_owner(
							pdb->psqlite, message_id, username, &b_owner)) {
							return FALSE;
						}
						if (FALSE == b_owner) {
							*pb_partial = TRUE;
							continue;
						}
					}
				}
				message_id1 = 0;
				if (FALSE == common_util_copy_message(pdb->psqlite,
					account_id, message_id, dst_fid, &message_id1,
					&b_result, &message_size)) {
					return FALSE;
				}
				if (FALSE == b_result) {
					*pb_partial = TRUE;
					continue;
				}
				if (0 == is_associated) {
					if (NULL != pnormal_size) {
						*pnormal_size += message_size;
					}
				} else {
					if (NULL != pfai_size) {
						*pfai_size += message_size;
					}
				}
				db_engine_proc_dynamic_event(pdb, cpid,
					DYNAMIC_EVENT_NEW_MESSAGE,
					dst_fid, message_id1, 0);
			}
		}
		return TRUE;
	}
	if (TRUE == b_normal || TRUE == b_fai) {
		if (FALSE == b_guest) {
			b_check = FALSE;
		} else {
			if (0 == (permission & PERMISSION_CREATE)) {
				*pb_partial = FALSE;
				return TRUE;
			}
			if (FALSE == common_util_check_folder_permission(
				pdb->psqlite, fid_val, username, &permission)) {
				return FALSE;
			}
			b_check	= (permission & (PERMISSION_FOLDEROWNER | PERMISSION_READANY)) ? false : TRUE;
			if (FALSE == common_util_check_folder_permission(
				pdb->psqlite, dst_fid, username, &permission)) {
				return FALSE;
			}
			if (0 == (permission & PERMISSION_CREATE)) {
				*pb_partial = TRUE;
				goto COPY_SUBFOLDER;
			}
		}
	}
	if (TRUE == b_normal && TRUE == b_fai) {
		if (TRUE == b_private) {
			sprintf(sql_string, "SELECT message_id,"
						" is_associated FROM messages WHERE "
						"parent_fid=%llu", LLU(fid_val));
		} else {
			sprintf(sql_string, "SELECT message_id,"
						" is_associated FROM messages WHERE "
						"parent_fid=%llu AND is_deleted=0", LLU(fid_val));
		}
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			message_id = sqlite3_column_int64(pstmt, 0);
			is_associated = sqlite3_column_int64(pstmt, 1);
			if (TRUE == b_check) {
				if (FALSE == common_util_check_message_owner(
					pdb->psqlite, message_id, username, &b_owner)) {
					return FALSE;
				}
				if (FALSE == b_owner) {
					*pb_partial = TRUE;
					continue;
				}
			}
			message_id1 = 0;
			if (FALSE == common_util_copy_message(pdb->psqlite,
				account_id, message_id, dst_fid, &message_id1,
				&b_result, &message_size)) {
				return FALSE;
			}
			if (FALSE == b_result) {
				*pb_partial = TRUE;
				continue;
			}
			if (0 == is_associated) {
				if (NULL != pnormal_size) {
					*pnormal_size += message_size;
				}
			} else {
				if (NULL != pfai_size) {
					*pfai_size += message_size;
				}
			}
			db_engine_proc_dynamic_event(pdb, cpid,
				DYNAMIC_EVENT_NEW_MESSAGE, dst_fid,
				message_id1, 0);
		}
	} else {
		if (TRUE == b_normal || TRUE == b_fai) {
			is_associated = !b_normal;
			if (TRUE == b_private) {
				sprintf(sql_string, "SELECT message_id,"
							" FROM messages WHERE parent_fid=%llu"
							" AND is_associated=%d", LLU(fid_val),
							is_associated);
			} else {
				sprintf(sql_string, "SELECT message_id,"
							" is_deleted FROM messages WHERE "
							"parent_fid=%llu AND is_associated=%d",
							LLU(fid_val), is_associated);
			}
			auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
			if (pstmt == nullptr)
				return FALSE;
			while (SQLITE_ROW == sqlite3_step(pstmt)) {
				if (FALSE == b_private) {
					if (0 != sqlite3_column_int64(pstmt, 1)) {
						continue;
					}
				}
				message_id = sqlite3_column_int64(pstmt, 0);
				if (TRUE == b_check) {
					if (FALSE == common_util_check_message_owner(
						pdb->psqlite, message_id, username, &b_owner)) {
						return FALSE;
					}
					if (FALSE == b_owner) {
						*pb_partial = TRUE;
						continue;
					}
				}
				message_id1 = 0;
				if (FALSE == common_util_copy_message(pdb->psqlite,
					account_id, message_id, dst_fid, &message_id1,
					&b_result, &message_size)) {
					return FALSE;
				}
				if (FALSE == b_result) {
					*pb_partial = TRUE;
					continue;
				}
				if (0 == is_associated) {
					if (NULL != pnormal_size) {
						*pnormal_size += message_size;
					}
				} else {
					if (NULL != pfai_size) {
						*pfai_size += message_size;
					}
				}
				db_engine_proc_dynamic_event(pdb, cpid,
					DYNAMIC_EVENT_NEW_MESSAGE, dst_fid,
					message_id1, 0);
			}
		}
 COPY_SUBFOLDER:
		if (TRUE == b_sub) {
			if (TRUE == b_guest) {
				if (FALSE == common_util_check_folder_permission(
					pdb->psqlite, dst_fid, username, &permission)) {
					return FALSE;
				}
				if (0 == (permission & PERMISSION_CREATESUBFOLDER)) {
					*pb_partial = TRUE;
					return TRUE;
				}
			}
			sprintf(sql_string, "SELECT folder_id "
			          "FROM folders WHERE parent_id=%llu", LLU(fid_val));
			auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
			if (pstmt == nullptr)
				return FALSE;
			while (SQLITE_ROW == sqlite3_step(pstmt)) {
				src_fid1 = sqlite3_column_int64(pstmt, 0);
				fid_val = src_fid1;
				if (TRUE == b_check) {
					if (FALSE == common_util_check_folder_permission(
						pdb->psqlite, fid_val, username, &permission)) {
						return FALSE;
					}
					if (0 == (permission & PERMISSION_READANY) &&
						0 == (permission & PERMISSION_FOLDERVISIBLE)) {
						*pb_partial = TRUE;
						continue;
					}
				}
				if (FALSE == common_util_get_folder_type(
					pdb->psqlite, fid_val, &folder_type)) {
					return FALSE;
				}
				if (FOLDER_TYPE_SEARCH == folder_type) {
					if (FALSE == folder_copy_search_folder(pdb, cpid,
						b_guest, username, fid_val, dst_fid, &fid_val)) {
						return FALSE;
					}
				} else {
					if (FALSE == folder_copy_generic_folder(pdb->psqlite,
						b_guest, username, fid_val, dst_fid, &fid_val)) {
						return FALSE;
					}
				}
				if (0 == fid_val) {
					*pb_partial = TRUE;
					continue;
				}
				if (NULL != pfolder_count) {
					(*pfolder_count) ++;
				}
				if (FOLDER_TYPE_SEARCH == folder_type) {
					continue;
				}
				if (FALSE == folder_copy_folder_internal(pdb, account_id,
					cpid, b_guest, username, src_fid1, TRUE, TRUE, TRUE,
					fid_val, &b_partial, pnormal_size, pfai_size, NULL)) {
					return FALSE;
				}
				if (TRUE == b_partial) {
					*pb_partial = TRUE;
					continue;
				}
			}
		}
	}
	return TRUE;
}

/* set hierarchy change number when finish action */
BOOL exmdb_server_copy_folder_internal(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest, const char *username,
	uint64_t src_fid, BOOL b_normal, BOOL b_fai, BOOL b_sub,
	uint64_t dst_fid, BOOL *pb_collid, BOOL *pb_partial)
{
	BOOL b_partial;
	uint64_t src_val;
	uint64_t dst_val;
	uint64_t fai_size;
	char sql_string[256];
	uint64_t normal_size;
	uint32_t folder_count;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	src_val = rop_util_get_gc_value(src_fid);
	dst_val = rop_util_get_gc_value(dst_fid);
	if (!common_util_check_descendant(pdb->psqlite, dst_fid,
	    src_val, pb_collid)) {
		return FALSE;
	}
	if (TRUE == *pb_collid) {
		return TRUE;
	}
	folder_count = 0;
	normal_size = 0;
	fai_size = 0;
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == folder_copy_folder_internal(pdb, account_id, cpid,
		b_guest, username, src_val, b_normal, b_fai, b_sub, dst_val,
		&b_partial, &normal_size, &fai_size, &folder_count)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	if (folder_count > 0) {
		sprintf(sql_string, "UPDATE folder_properties SET "
			"propval=propval+1 WHERE folder_id=%llu AND "
			"proptag=%u", LLU(dst_val), PROP_TAG_HIERARCHYCHANGENUMBER);
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		sprintf(sql_string, "UPDATE folder_properties SET "
			"propval=%llu WHERE folder_id=%llu AND proptag=%u",
			LLU(rop_util_current_nttime()), LLU(dst_val), PROP_TAG_HIERREV);
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
	}
	if (normal_size + fai_size > 0 || folder_count > 0) {
		sprintf(sql_string, "UPDATE folder_properties SET "
			"propval=%llu WHERE folder_id=%llu AND proptag=%u",
			LLU(rop_util_current_nttime()), LLU(dst_val),
			PROP_TAG_LOCALCOMMITTIMEMAX);
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
	}
	if (FALSE == common_util_increase_store_size(
		pdb->psqlite, normal_size, fai_size)) {
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
	}
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	return TRUE;
}

/* set hierarchy change number when finish action */
BOOL exmdb_server_movecopy_folder(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest, const char *username,
	uint64_t src_pid, uint64_t src_fid, uint64_t dst_fid,
	const char *str_new, BOOL b_copy, BOOL *pb_exist,
	BOOL *pb_partial)
{
	BOOL b_partial;
	BOOL b_included;
	uint64_t nt_time;
	uint64_t tmp_fid;
	uint64_t fid_val;
	uint64_t src_val;
	uint64_t dst_val;
	uint64_t fai_size;
	uint64_t parent_val;
	char sql_string[256];
	uint64_t normal_size;
	uint32_t folder_type;
	
	src_val = rop_util_get_gc_value(src_fid);
	dst_val = rop_util_get_gc_value(dst_fid);
	parent_val = rop_util_get_gc_value(src_pid);
	*pb_exist = FALSE;
	*pb_partial = FALSE;
	if (FALSE == b_copy) {
		if (TRUE == exmdb_server_check_private()) {
			if (src_val < PRIVATE_FID_CUSTOM) {
				*pb_partial = TRUE;
				return TRUE;
			}
		} else {
			if (src_val < PUBLIC_FID_CUSTOM) {
				*pb_partial = TRUE;
				return TRUE;
			}
		}
	}
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (TRUE == b_copy &&
	    cu_check_msgsize_overflow(pdb->psqlite, PROP_TAG_STORAGEQUOTALIMIT) &&
		TRUE == common_util_check_msgcnt_overflow(pdb->psqlite)) {
		*pb_partial = TRUE;
		return TRUE;		
	}
	if (FALSE == common_util_get_folder_by_name(
		pdb->psqlite, dst_val, str_new, &tmp_fid)) {
		return FALSE;
	}
	if (0 != tmp_fid) {
		*pb_exist = TRUE;
		return TRUE;
	}
	if (FALSE == b_copy) {
		if (!common_util_check_descendant(pdb->psqlite, dst_val,
		    src_val, &b_included)) {
			return FALSE;
		}
		if (TRUE == b_included) {
			*pb_partial = TRUE;
			return TRUE;
		}
	}
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (FALSE == b_copy) {
		sprintf(sql_string, "UPDATE folders SET parent_id=%llu"
		        " WHERE folder_id=%llu", LLU(dst_val), LLU(src_val));
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		sprintf(sql_string, "UPDATE folder_properties "
			"SET propval=? WHERE folder_id=%llu AND proptag=%u",
		        LLU(src_val), PR_DISPLAY_NAME);
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		sqlite3_bind_text(pstmt, 1, str_new, -1, SQLITE_STATIC);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			pstmt.finalize();
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		pstmt.finalize();
		nt_time = rop_util_current_nttime();
		sprintf(sql_string, "UPDATE folder_properties SET "
			"propval=%llu WHERE folder_id=%llu AND proptag=%u",
			LLU(nt_time), LLU(parent_val), PROP_TAG_LOCALCOMMITTIMEMAX);
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		sprintf(sql_string, "UPDATE folder_properties SET "
			"propval=propval+1 WHERE folder_id=%llu AND "
		        "proptag=%u", LLU(parent_val), PR_DELETED_FOLDER_COUNT);
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		sprintf(sql_string, "UPDATE folder_properties SET "
			"propval=propval+1 WHERE folder_id=%llu AND "
			"proptag=%u", LLU(parent_val), PROP_TAG_HIERARCHYCHANGENUMBER);
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		sprintf(sql_string, "UPDATE folder_properties SET "
			"propval=%llu WHERE folder_id=%llu AND proptag=%u",
			LLU(nt_time), LLU(parent_val), PROP_TAG_HIERREV);
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		fid_val = src_val;
		db_engine_proc_dynamic_event(pdb,
			cpid, DYNAMIC_EVENT_MOVE_FOLDER,
			parent_val, dst_val, src_val);
	} else {
		if (FALSE == common_util_get_folder_type(
			pdb->psqlite, src_val, &folder_type)) {
			return FALSE;
		}
		if (FOLDER_TYPE_SEARCH == folder_type) {
			if (FALSE == folder_copy_search_folder(pdb, cpid,
				b_guest, username, src_val, dst_val, &fid_val)) {
				return FALSE;
			}
		} else {
			if (FALSE == folder_copy_generic_folder(pdb->psqlite,
				b_guest, username, src_val, dst_val, &fid_val)) {
				return FALSE;
			}
		}
		sprintf(sql_string, "UPDATE folder_properties "
			"SET propval=? WHERE folder_id=%llu AND proptag=%u",
		        LLU(fid_val), PR_DISPLAY_NAME);
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		sqlite3_bind_text(pstmt, 1, str_new, -1, SQLITE_STATIC);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			pstmt.finalize();
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		pstmt.finalize();
		if (FOLDER_TYPE_SEARCH != folder_type) {
			normal_size = 0;
			fai_size = 0;
			if (FALSE == folder_copy_folder_internal(pdb, account_id,
				cpid, b_guest, username, src_val, TRUE, TRUE, TRUE,
				fid_val, &b_partial, &normal_size, &fai_size, NULL)) {
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				return FALSE;
			}
			if (FALSE == common_util_increase_store_size(
				pdb->psqlite, normal_size, fai_size)) {
				if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
					return FALSE;
				}
			}
		}
	}
	nt_time = rop_util_current_nttime();
	sprintf(sql_string, "UPDATE folder_properties SET "
		"propval=%llu WHERE folder_id=%llu AND proptag=%u",
		LLU(nt_time), LLU(dst_val), PROP_TAG_LOCALCOMMITTIMEMAX);
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	sprintf(sql_string, "UPDATE folder_properties SET "
		"propval=propval+1 WHERE folder_id=%llu AND "
		"proptag=%u", LLU(dst_val), PROP_TAG_HIERARCHYCHANGENUMBER);
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	sprintf(sql_string, "UPDATE folder_properties SET "
		"propval=%llu WHERE folder_id=%llu AND proptag=%u",
		LLU(nt_time), LLU(dst_val), PROP_TAG_HIERREV);
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	db_engine_notify_folder_movecopy(pdb, b_copy,
		dst_val, fid_val, parent_val, src_val);
	return TRUE;
}

BOOL exmdb_server_get_search_criteria(
	const char *dir, uint64_t folder_id, uint32_t *psearch_status,
	RESTRICTION **pprestriction, LONGLONG_ARRAY *pfolder_ids)
{
	uint64_t fid_val;
	EXT_PULL ext_pull;
	char sql_string[256];
	uint32_t search_flags;
	
	if (FALSE == exmdb_server_check_private()) {
		return FALSE;
	}
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	fid_val = rop_util_get_gc_value(folder_id);
	sprintf(sql_string, "SELECT is_search,"
				" search_flags, search_criteria FROM "
				"folders WHERE folder_id=%llu", LLU(fid_val));
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
		0 == sqlite3_column_int64(pstmt, 0) ||
		NULL == sqlite3_column_blob(pstmt, 2) ||
		0 == sqlite3_column_bytes(pstmt, 2)) {
		pstmt.finalize();
		*psearch_status = SEARCH_STATUS_NOT_INITIALIZED;
		if (NULL != pprestriction) {
			*pprestriction = NULL;
		}
		if (NULL != pfolder_ids) {
			pfolder_ids->count = 0;
			pfolder_ids->pll = NULL;
		}
		return TRUE;
	}
	search_flags = sqlite3_column_int64(pstmt, 1);
	if (NULL != pprestriction) {
		ext_buffer_pull_init(&ext_pull,
			sqlite3_column_blob(pstmt, 2),
			sqlite3_column_bytes(pstmt, 2),
			common_util_alloc, 0);
		*pprestriction = cu_alloc<RESTRICTION>();
		if (NULL == *pprestriction) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_restriction(
			&ext_pull, *pprestriction)) {
			return FALSE;
		}
	}
	pstmt.finalize();
	if (NULL != pfolder_ids) {
		if (FALSE == common_util_load_search_scopes(
			pdb->psqlite, fid_val, pfolder_ids)) {
			return FALSE;
		}
	}
	pdb.reset();
	if (NULL != pfolder_ids) {
		for (size_t i = 0; i < pfolder_ids->count; ++i)
			pfolder_ids->pll[i] = rop_util_make_eid_ex(
								1, pfolder_ids->pll[i]);
	}
	*psearch_status = 0;
	if (TRUE == db_engine_check_populating(dir, fid_val)) {
		*psearch_status |= SEARCH_STATUS_REBUILD;
	}
	if (search_flags & SEARCH_FLAG_STATIC) {
		if (search_flags & SEARCH_FLAG_RESTART) {
			*psearch_status |= SEARCH_STATUS_COMPLETE;
		}
	} else {
		if (search_flags & SEARCH_FLAG_RESTART) {
			*psearch_status |= SEARCH_STATUS_RUNNING;
		}
	}
	if (search_flags & SEARCH_FLAG_RECURSIVE) {
		*psearch_status |= SEARCH_STATUS_RECURSIVE;
	}
	if (search_flags & SEARCH_FLAG_CONTENT_INDEXED) {
		*psearch_status |= SEARCH_STATUS_CI_TOTALLY;
	} else {
		*psearch_status |= SEARCH_STATUS_TWIR_TOTALLY;
	}
	return TRUE;
}

static BOOL folder_clear_search_folder(db_item_ptr &pdb,
	uint32_t cpid, uint64_t folder_id)
{
	char sql_string[128];
	
	sprintf(sql_string, "SELECT message_id FROM "
	          "search_result WHERE folder_id=%llu", LLU(folder_id));
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		db_engine_proc_dynamic_event(pdb, cpid,
			DYNAMIC_EVENT_DELETE_MESSAGE, folder_id,
			sqlite3_column_int64(pstmt, 0), 0);
	}
	pstmt.finalize();
	sprintf(sql_string, "DELETE FROM search_result"
	        " WHERE folder_id=%llu", LLU(folder_id));
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_server_set_search_criteria(const char *dir,
	uint32_t cpid, uint64_t folder_id, uint32_t search_flags,
	const RESTRICTION *prestriction, const LONGLONG_ARRAY *pfolder_ids,
	BOOL *pb_result)
{
	BOOL b_update;
	BOOL b_populate;
	BOOL b_included;
	BOOL b_recursive;
	uint64_t fid_val;
	uint64_t fid_val1;
	EXT_PULL ext_pull;
	EXT_PUSH ext_push;
	char sql_string[128];
	uint32_t original_flags;
	uint8_t tmp_buff[0x8000];
	LONGLONG_ARRAY folder_ids;
	
	if (FALSE == exmdb_server_check_private()) {
		return FALSE;
	}
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	fid_val = rop_util_get_gc_value(folder_id);
	if (pfolder_ids->count > 0) {
		for (size_t i = 0; i < pfolder_ids->count; ++i) {
			fid_val1 = rop_util_get_gc_value(pfolder_ids->pll[i]);
			if (!common_util_check_descendant(pdb->psqlite, fid_val,
			    fid_val1, &b_included)) {
				return FALSE;	
			}
			if (TRUE == b_included) {
				*pb_result = FALSE;
				return TRUE;
			}
		}
	}
	sprintf(sql_string, "SELECT search_flags FROM"
	          " folders WHERE folder_id=%llu", LLU(fid_val));
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	original_flags = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sprintf(sql_string, "UPDATE folders SET search_flags=%u "
	        "WHERE folder_id=%llu", search_flags, LLU(fid_val));
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		goto CRITERIA_FAILURE;
	}
	if (NULL != prestriction) {
		if (!ext_push.init(tmp_buff, sizeof(tmp_buff), 0) ||
		    ext_push.p_restriction(prestriction) != EXT_ERR_SUCCESS)
			goto CRITERIA_FAILURE;
		sprintf(sql_string, "UPDATE folders SET "
		          "search_criteria=? WHERE folder_id=%llu", LLU(fid_val));
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			goto CRITERIA_FAILURE;
		sqlite3_bind_blob(pstmt, 1, ext_push.data,
				ext_push.offset, SQLITE_STATIC);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			pstmt.finalize();
			goto CRITERIA_FAILURE;
		}
		pstmt.finalize();
	} else {
		if (0 == original_flags) {
			goto CRITERIA_FAILURE;
		}
		prestriction = cu_alloc<RESTRICTION>();
		if (NULL == prestriction) {
			goto CRITERIA_FAILURE;
		}
		sprintf(sql_string, "SELECT search_criteria FROM"
		          " folders WHERE folder_id=%llu", LLU(fid_val));
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			goto CRITERIA_FAILURE;
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			pstmt.finalize();
			goto CRITERIA_FAILURE;
		}
		ext_buffer_pull_init(&ext_pull,
			sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0),
			common_util_alloc, 0);
		if (EXT_ERR_SUCCESS != ext_buffer_pull_restriction(
			&ext_pull, (RESTRICTION*)prestriction)) {
			pstmt.finalize();
			goto CRITERIA_FAILURE;
		}
		pstmt.finalize();
	}
	if (pfolder_ids->count > 0) {
		folder_ids.count = 0;
		folder_ids.pll = cu_alloc<uint64_t>(pfolder_ids->count);
		if (NULL == folder_ids.pll) {
			goto CRITERIA_FAILURE;
		}
		sprintf(sql_string, "DELETE FROM search_scopes"
		        " WHERE folder_id=%llu", LLU(fid_val));
		if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
			sql_string, NULL, NULL, NULL)) {
			goto CRITERIA_FAILURE;
		}
		sprintf(sql_string, "INSERT INTO "
		          "search_scopes VALUES (%llu, ?)", LLU(fid_val));
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			goto CRITERIA_FAILURE;
		sprintf(sql_string, "SELECT count(*) "
					"FROM folders WHERE folder_id=?");
		auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt1 == nullptr)
			goto CRITERIA_FAILURE;
		for (size_t i = 0; i < pfolder_ids->count; ++i) {
			folder_ids.pll[folder_ids.count] =
				rop_util_get_gc_value(pfolder_ids->pll[i]);
			sqlite3_bind_int64(pstmt1, 1, folder_ids.pll[folder_ids.count]);
			if (SQLITE_ROW != sqlite3_step(pstmt1)) {
				goto CRITERIA_FAILURE;
			}
			if (0 == sqlite3_column_int64(pstmt1, 0)) {
				sqlite3_reset(pstmt);
				sqlite3_reset(pstmt1);
				continue;
			}
			sqlite3_bind_int64(pstmt, 1, folder_ids.pll[folder_ids.count]);
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				goto CRITERIA_FAILURE;
			}
			sqlite3_reset(pstmt);
			sqlite3_reset(pstmt1);
			folder_ids.count ++;
		}
	} else {
		if (0 == original_flags) {
			goto CRITERIA_FAILURE;
		}
		if (FALSE == common_util_load_search_scopes(
			pdb->psqlite, fid_val, &folder_ids)) {
			goto CRITERIA_FAILURE;
		}
	}
	b_recursive = (search_flags & SEARCH_FLAG_RECURSIVE) ? TRUE : false;
	b_update = FALSE;
	b_populate = FALSE;
	if (FALSE == folder_clear_search_folder(pdb, cpid, fid_val)) {
		goto CRITERIA_FAILURE;
	}
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	if (search_flags & SEARCH_FLAG_RESTART) {
		b_populate = TRUE;
		if (0 == (search_flags & SEARCH_FLAG_STATIC)) {
			b_update = TRUE;
		}
	}
	if (TRUE == b_update) {
		db_engine_update_dynamic(pdb, fid_val,
			search_flags, prestriction, &folder_ids);
	} else {
		db_engine_delete_dynamic(pdb, fid_val);
	}
	pdb.reset();
	if (TRUE == b_populate) {
		if (FALSE == db_engine_enqueue_populating_criteria(
			dir, cpid, fid_val, b_recursive, prestriction,
			&folder_ids))  {
			return FALSE;
		}
	}
	*pb_result = TRUE;
	return TRUE;
 CRITERIA_FAILURE:
	sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
	return FALSE;
}

BOOL exmdb_server_check_folder_permission(const char *dir,
	uint64_t folder_id, const char *username,
	uint32_t *ppermission)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (TRUE == common_util_check_folder_permission(pdb->psqlite,
		rop_util_get_gc_value(folder_id), username, ppermission)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

BOOL exmdb_server_empty_folder_permission(
	const char *dir, uint64_t folder_id)
{
	char sql_string[1024];
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	snprintf(sql_string, 1024, "DELETE FROM permissions WHERE"
	         " folder_id=%llu", LLU(rop_util_get_gc_value(folder_id)));
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	return TRUE;
}

/* after updating the database, update the table too! */
BOOL exmdb_server_update_folder_permission(const char *dir,
	uint64_t folder_id, BOOL b_freebusy,
	uint16_t count, const PERMISSION_DATA *prow)
{
	int i;
	void *pvalue;
	uint64_t fid_val;
	uint64_t member_id;
	char username[UADDR_SIZE];
	uint32_t permission = 0;
	xstmt pstmt;
	char sql_string[128];
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	fid_val = rop_util_get_gc_value(folder_id);
	pstmt = NULL;
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	for (i=0; i<count; i++) {
		switch (prow[i].flags) {
		case PERMISSION_DATA_FLAG_ADD_ROW:
			pvalue = common_util_get_propvals(&prow[i].propvals, PR_ENTRYID);
			if (NULL != pvalue) {
				if (!common_util_addressbook_entryid_to_username(static_cast<BINARY *>(pvalue), username, GX_ARRAY_SIZE(username)))
					continue;
			} else {
				pvalue = common_util_get_propvals(&prow[i].propvals, PR_SMTP_ADDRESS);
				if (NULL == pvalue) {
					continue;
				}
				gx_strlcpy(username, static_cast<char *>(pvalue), GX_ARRAY_SIZE(username));
			}
			pvalue = common_util_get_propvals(
				&prow[i].propvals, PROP_TAG_MEMBERRIGHTS);
			if (NULL == pvalue) {
				continue;
			}
			permission = *(uint32_t*)pvalue;
			if (permission & PERMISSION_READANY) {
				permission |= PERMISSION_FOLDERVISIBLE;
			}
			if (permission & PERMISSION_FOLDEROWNER) {
				permission |= PERMISSION_FOLDERVISIBLE;
				permission |= PERMISSION_FOLDERCONTACT;
			}
			if (permission & PERMISSION_DELETEANY) {
				permission |= PERMISSION_DELETEOWNED;
			}
			if (permission & PERMISSION_EDITANY) {
				permission |= PERMISSION_EDITOWNED;
			}
			if (FALSE == b_freebusy ||
				FALSE == exmdb_server_check_private()
				|| fid_val != PRIVATE_FID_CALENDAR) {
				permission &= ~(PERMISSION_FREEBUSYSIMPLE |
								PERMISSION_FREEBUSYDETAILED);
			}
			if (NULL == pstmt) {
				sprintf(sql_string, "INSERT INTO permissions"
							" (folder_id, username, permission) VALUES"
							" (%llu, ?, ?)", LLU(fid_val));
				pstmt = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt == nullptr)
					goto PERMISSION_FAILURE;
			}
			sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
			sqlite3_bind_int64(pstmt, 2, permission);
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				goto PERMISSION_FAILURE;
			}
			sqlite3_reset(pstmt);
			break;
		case PERMISSION_DATA_FLAG_MODIFY_ROW: {
			pvalue = common_util_get_propvals(
				&prow[i].propvals, PROP_TAG_MEMBERID);
			if (NULL == pvalue) {
				continue;
			}
			member_id = *(uint64_t*)pvalue;
			if (0 == member_id) {
				sprintf(sql_string, "SELECT member_id "
					"FROM permissions WHERE folder_id=%llu AND "
					"username=?", LLU(fid_val));
				auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt1 == nullptr)
					goto PERMISSION_FAILURE;
				sqlite3_bind_text(pstmt1, 1, "default", -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt1)) {
					pstmt1.finalize();
					sprintf(sql_string, "SELECT config_value "
						"FROM configurations WHERE config_id=%d",
						CONFIG_ID_DEFAULT_PERMISSION);
					pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
					if (pstmt1 == nullptr)
						goto PERMISSION_FAILURE;
					if (SQLITE_ROW == sqlite3_step(pstmt1)) {
						permission = sqlite3_column_int64(pstmt1, 0);
					}
					pstmt1.finalize();
					sprintf(sql_string, "INSERT INTO permissions"
								" (folder_id, username, permission) VALUES"
								" (%llu, ?, ?)", LLU(fid_val));
					pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
					if (pstmt1 == nullptr)
						goto PERMISSION_FAILURE;
					sqlite3_bind_text(pstmt1, 1, "default", -1, SQLITE_STATIC);
					sqlite3_bind_int64(pstmt1, 2, permission);
					if (SQLITE_DONE != sqlite3_step(pstmt1)) {
						pstmt1.finalize();
						goto PERMISSION_FAILURE;
					}
					member_id = sqlite3_last_insert_rowid(pdb->psqlite);
				} else {
					member_id = sqlite3_column_int64(pstmt1, 0);
				}
				pstmt1.finalize();
			} else if (member_id == 0xFFFFFFFFFFFFFFFF) {
				sprintf(sql_string, "SELECT member_id "
					"FROM permissions WHERE folder_id=%llu AND "
					"username=?", LLU(fid_val));
				auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt1 == nullptr)
					goto PERMISSION_FAILURE;
				sqlite3_bind_text(pstmt1, 1, "", -1, SQLITE_STATIC);
				if (SQLITE_ROW != sqlite3_step(pstmt1)) {
					pstmt1.finalize();
					sprintf(sql_string, "SELECT config_value "
						"FROM configurations WHERE config_id=%d",
						CONFIG_ID_ANONYMOUS_PERMISSION);
					pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
					if (pstmt1 == nullptr)
						goto PERMISSION_FAILURE;
					if (SQLITE_ROW == sqlite3_step(pstmt1)) {
						permission = sqlite3_column_int64(pstmt1, 0);
					}
					pstmt1.finalize();
					sprintf(sql_string, "INSERT INTO permissions"
								" (folder_id, username, permission) VALUES"
								" (%llu, ?, ?)", LLU(fid_val));
					pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
					if (pstmt1 == nullptr)
						goto PERMISSION_FAILURE;
					sqlite3_bind_text(pstmt1, 1, "", -1, SQLITE_STATIC);
					sqlite3_bind_int64(pstmt1, 2, permission);
					if (SQLITE_DONE != sqlite3_step(pstmt1)) {
						pstmt1.finalize();
						goto PERMISSION_FAILURE;
					}
					member_id = sqlite3_last_insert_rowid(pdb->psqlite);
				} else {
					member_id = sqlite3_column_int64(pstmt1, 0);
				}
				pstmt1.finalize();
			}
			sprintf(sql_string, "SELECT folder_id FROM"
			          " permissions WHERE member_id=%llu", LLU(member_id));
			auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
			if (pstmt1 == nullptr)
				goto PERMISSION_FAILURE;
			if (sqlite3_step(pstmt1) != SQLITE_ROW ||
			    gx_sql_col_uint64(pstmt1, 0) != fid_val)
				continue;
			pstmt1.finalize();
			pvalue = common_util_get_propvals(
				&prow[i].propvals, PROP_TAG_MEMBERRIGHTS);
			if (NULL == pvalue) {
				continue;
			}
			permission = *(uint32_t*)pvalue;
			if (permission & PERMISSION_READANY) {
				permission |= PERMISSION_FOLDERVISIBLE;
			}
			if (permission & PERMISSION_FOLDEROWNER) {
				permission |= PERMISSION_FOLDERVISIBLE;
				permission |= PERMISSION_FOLDERCONTACT;
			}
			if (permission & PERMISSION_DELETEANY) {
				permission |= PERMISSION_DELETEOWNED;
			}
			if (permission & PERMISSION_EDITANY) {
				permission |= PERMISSION_EDITOWNED;
			}
			if (FALSE == b_freebusy ||
				FALSE == exmdb_server_check_private()
				|| fid_val != PRIVATE_FID_CALENDAR) {
				permission &= ~(PERMISSION_FREEBUSYSIMPLE |
								PERMISSION_FREEBUSYDETAILED);
			}
			sprintf(sql_string, "UPDATE permissions SET permission=%u"
			        " WHERE member_id=%llu", permission, LLU(member_id));
			if (SQLITE_OK!= sqlite3_exec(pdb->psqlite,
				sql_string, NULL, NULL, NULL)) {
				goto PERMISSION_FAILURE;
			}
			break;
		}
		case PERMISSION_DATA_FLAG_REMOVE_ROW:
			pvalue = common_util_get_propvals(
				&prow[i].propvals, PROP_TAG_MEMBERID);
			if (NULL == pvalue) {
				continue;
			}
			member_id = *(uint64_t*)pvalue;
			if (0 == member_id) {
				sprintf(sql_string, "DELETE FROM permissions WHERE "
				        "folder_id=%llu and username=\"default\"", LLU(fid_val));
				if (SQLITE_OK!= sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					goto PERMISSION_FAILURE;
				}
			} else if (member_id == 0xFFFFFFFFFFFFFFFF) {
				sprintf(sql_string, "DELETE FROM permissions WHERE "
				        "folder_id=%llu and username=\"\"", LLU(fid_val));
				if (SQLITE_OK!= sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					goto PERMISSION_FAILURE;
				}
			} else {
				sprintf(sql_string, "SELECT folder_id FROM"
				          " permissions WHERE member_id=%llu", LLU(member_id));
				auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt1 == nullptr)
					goto PERMISSION_FAILURE;
				if (sqlite3_step(pstmt1) != SQLITE_ROW ||
				    gx_sql_col_uint64(pstmt1, 0) != fid_val)
					continue;
				pstmt1.finalize();
				sprintf(sql_string, "DELETE FROM permissions"
				        " WHERE member_id=%llu", LLU(member_id));
				if (SQLITE_OK!= sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					goto PERMISSION_FAILURE;
				}
			}
			break;
		}
	}
	pstmt.finalize();
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	return TRUE;
	
 PERMISSION_FAILURE:
	sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
	return FALSE;
}

BOOL exmdb_server_empty_folder_rule(
	const char *dir, uint64_t folder_id)
{
	char sql_string[1024];
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	snprintf(sql_string, 1024, "DELETE FROM rules WHERE "
	         "folder_id=%llu", LLU(rop_util_get_gc_value(folder_id)));
	if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	return TRUE;
}

/* after updating the database, update the table too! */
BOOL exmdb_server_update_folder_rule(const char *dir,
	uint64_t folder_id, uint16_t count,
	const RULE_DATA *prow, BOOL *pb_exceed)
{
	int i;
	char *pname;
	void *pvalue;
	int action_len;
	uint32_t state;
	char *pprovider;
	uint32_t seq_id;
	uint64_t fid_val;
	uint64_t rule_id;
	uint32_t *plevel;
	int condition_len;
	EXT_PUSH ext_push;
	char sql_string[256];
	BINARY *pprovider_bin;
	uint32_t *puser_flags;
	RULE_ACTIONS *paction;
	RESTRICTION *pcondition;
	char action_buff[256*1024];
	char condition_buff[256*1024];
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	fid_val = rop_util_get_gc_value(folder_id);
	sprintf(sql_string, "SELECT count(*) "
	          "FROM rules WHERE folder_id=%llu", LLU(fid_val));
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	size_t rule_count = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	*pb_exceed = FALSE;
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	for (i=0; i<count; i++) {
		switch (prow[i].flags) {
		case RULE_DATA_FLAG_ADD_ROW:
			if (rule_count >= common_util_get_param(
				COMMON_UTIL_MAX_RULE_NUMBER)) {
				*pb_exceed = TRUE;
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				return TRUE;
			}
			pname = static_cast<char *>(common_util_get_propvals(
			        &prow[i].propvals, PROP_TAG_RULENAME));
			pprovider = static_cast<char *>(common_util_get_propvals(
			            &prow[i].propvals, PROP_TAG_RULEPROVIDER));
			if (NULL == pprovider) {
				continue;
			}
			pvalue = common_util_get_propvals(
				&prow[i].propvals, PROP_TAG_RULESEQUENCE);
			if (NULL == pvalue) {
				sprintf(sql_string, "SELECT max(sequence)"
				          " FROM rules WHERE folder_id=%llu", LLU(fid_val));
				auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt1 == nullptr)
					continue;
				seq_id = sqlite3_step(pstmt1) != SQLITE_ROW ? 0 :
				         sqlite3_column_int64(pstmt1, 0);
				pstmt1.finalize();
				seq_id ++;
			} else {
				seq_id = *(uint32_t*)pvalue;
			}
			pvalue = common_util_get_propvals(
				&prow[i].propvals, PROP_TAG_RULESTATE);
			state = pvalue == nullptr ? 0 : *static_cast<uint32_t *>(pvalue);
			plevel = static_cast<uint32_t *>(common_util_get_propvals(
			         &prow[i].propvals, PROP_TAG_RULELEVEL));
			puser_flags = static_cast<uint32_t *>(common_util_get_propvals(
			              &prow[i].propvals, PROP_TAG_RULEUSERFLAGS));
			pprovider_bin = static_cast<BINARY *>(common_util_get_propvals(
			                &prow[i].propvals, PROP_TAG_RULEPROVIDERDATA));
			pcondition = static_cast<RESTRICTION *>(common_util_get_propvals(
			             &prow[i].propvals, PROP_TAG_RULECONDITION));
			if (NULL == pcondition) {
				continue;
			}
			if (!ext_push.init(condition_buff, sizeof(condition_buff), 0) ||
			    ext_push.p_restriction(pcondition) != EXT_ERR_SUCCESS)
				goto RULE_FAILURE;
			condition_len = ext_push.offset;
			paction = static_cast<RULE_ACTIONS *>(common_util_get_propvals(
			          &prow[i].propvals, PROP_TAG_RULEACTIONS));
			if (NULL == paction) {
				continue;
			}
			if (!ext_push.init(action_buff, sizeof(action_buff), 0) ||
			    ext_push.p_rule_actions(paction) != EXT_ERR_SUCCESS)
				goto RULE_FAILURE;
			action_len = ext_push.offset;
			if (NULL == pstmt) {
				sprintf(sql_string, "INSERT INTO rules "
					"(name, provider, sequence, state, level, user_flags,"
					" provider_data, condition, actions, folder_id) VALUES"
					" (?, ?, ?, ?, ?, ?, ?, ?, ?, %llu)", LLU(fid_val));
				pstmt = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt == nullptr)
					goto RULE_FAILURE;
			}
			if (NULL != pname) {
				sqlite3_bind_text(pstmt, 1, pname, -1, SQLITE_STATIC);
			} else {
				sqlite3_bind_null(pstmt, 1);
			}
			sqlite3_bind_text(pstmt, 2, pprovider, -1, SQLITE_STATIC);
			sqlite3_bind_int64(pstmt, 3, seq_id);
			sqlite3_bind_int64(pstmt, 4, state);
			sqlite3_bind_int64(pstmt, 5, plevel != nullptr ? *plevel : 0);
			if (NULL != puser_flags) {
				sqlite3_bind_int64(pstmt, 6, *puser_flags);
			} else {
				sqlite3_bind_null(pstmt, 6);
			}
			if (NULL != pprovider_bin && pprovider_bin->cb > 0) {
				sqlite3_bind_blob(pstmt, 7, pprovider_bin->pb,
					pprovider_bin->cb, SQLITE_STATIC);
			} else {
				sqlite3_bind_null(pstmt, 7);
			}
			sqlite3_bind_blob(pstmt, 8, condition_buff,
				condition_len, SQLITE_STATIC);
			sqlite3_bind_blob(pstmt, 9, action_buff,
				action_len, SQLITE_STATIC);
			if (SQLITE_DONE != sqlite3_step(pstmt)) {
				goto RULE_FAILURE;
			}
			sqlite3_reset(pstmt);
			break;
		case RULE_DATA_FLAG_MODIFY_ROW: {
			pvalue = common_util_get_propvals(
				&prow[i].propvals, PROP_TAG_RULEID);
			if (NULL == pvalue) {
				continue;
			}
			rule_id = rop_util_get_gc_value(*(uint64_t*)pvalue);
			sprintf(sql_string, "SELECT folder_id "
			          "FROM rules WHERE rule_id=%llu", LLU(rule_id));
			auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
			if (pstmt1 == nullptr)
				goto RULE_FAILURE;
			if (sqlite3_step(pstmt1) != SQLITE_ROW ||
			    gx_sql_col_uint64(pstmt1, 0) != fid_val)
				continue;
			pstmt1.finalize();
			pprovider = static_cast<char *>(common_util_get_propvals(
			            &prow[i].propvals, PROP_TAG_RULEPROVIDER));
			if (NULL != pprovider) {
				sprintf(sql_string, "UPDATE rules SET"
				          " provider=? WHERE rule_id=%llu", LLU(rule_id));
				pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt1 == nullptr)
					goto RULE_FAILURE;
				sqlite3_bind_text(pstmt1, 1, pprovider, -1, SQLITE_STATIC);
				if (SQLITE_DONE != sqlite3_step(pstmt1)) {
					goto RULE_FAILURE;
				}
				pstmt1.finalize();
			}
			pvalue = common_util_get_propvals(
				&prow[i].propvals, PROP_TAG_RULESEQUENCE);
			if (NULL != pvalue) {
				seq_id = *(uint32_t*)pvalue;
				sprintf(sql_string, "UPDATE rules SET sequence=%u"
				        " WHERE rule_id=%llu", seq_id, LLU(rule_id));
				if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					goto RULE_FAILURE;
				}
			}
			pvalue = common_util_get_propvals(
				&prow[i].propvals, PROP_TAG_RULESTATE);
			if (NULL != pvalue) {
				state = *(uint32_t*)pvalue;
				sprintf(sql_string, "UPDATE rules SET state=%u"
				        " WHERE rule_id=%llu", state, LLU(rule_id));
				if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					goto RULE_FAILURE;
				}
			}
			plevel = static_cast<uint32_t *>(common_util_get_propvals(
			         &prow[i].propvals, PROP_TAG_RULELEVEL));
			if (NULL != plevel) {
				sprintf(sql_string, "UPDATE rules SET level=%u"
				        " WHERE rule_id=%llu", *plevel, LLU(rule_id));
				if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					goto RULE_FAILURE;
				}
			}
			puser_flags = static_cast<uint32_t *>(common_util_get_propvals(
			              &prow[i].propvals, PROP_TAG_RULEUSERFLAGS));
			if (NULL != puser_flags) {
				sprintf(sql_string, "UPDATE rules SET user_flags=%u"
				        " WHERE rule_id=%llu", *puser_flags, LLU(rule_id));
				if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					goto RULE_FAILURE;
				}
			}
			pprovider_bin = static_cast<BINARY *>(common_util_get_propvals(
			                &prow[i].propvals, PROP_TAG_RULEPROVIDERDATA));
			if (NULL != pprovider_bin) {
				sprintf(sql_string, "UPDATE rules SET "
				          "provider_data=? WHERE rule_id=%llu", LLU(rule_id));
				pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt1 == nullptr)
					goto RULE_FAILURE;
				sqlite3_bind_blob(pstmt1, 1, pprovider_bin->pb,
						pprovider_bin->cb, SQLITE_STATIC);
				if (SQLITE_DONE != sqlite3_step(pstmt1)) {
					goto RULE_FAILURE;
				}
				pstmt1.finalize();
			}
			pcondition = static_cast<RESTRICTION *>(common_util_get_propvals(
			             &prow[i].propvals, PROP_TAG_RULECONDITION));
			if (NULL != pcondition) {
				if (!ext_push.init(condition_buff, sizeof(condition_buff), 0) ||
				    ext_push.p_restriction(pcondition) != EXT_ERR_SUCCESS)
					goto RULE_FAILURE;
				condition_len = ext_push.offset;
				sprintf(sql_string, "UPDATE rules SET "
				          "condition=? WHERE rule_id=%llu", LLU(rule_id));
				pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt1 == nullptr)
					goto RULE_FAILURE;
				sqlite3_bind_blob(pstmt1, 1, condition_buff,
						condition_len, SQLITE_STATIC);
				if (SQLITE_DONE != sqlite3_step(pstmt1)) {
					pstmt1.finalize();
					goto RULE_FAILURE;
				}
				pstmt1.finalize();
			}
			paction = static_cast<RULE_ACTIONS *>(common_util_get_propvals(
			          &prow[i].propvals, PROP_TAG_RULEACTIONS));
			if (NULL != paction) {
				if (!ext_push.init(action_buff, sizeof(action_buff), 0) ||
				    ext_push.p_rule_actions(paction) != EXT_ERR_SUCCESS)
					goto RULE_FAILURE;
				action_len = ext_push.offset;
				sprintf(sql_string, "UPDATE rules SET "
				          "actions=? WHERE rule_id=%llu", LLU(rule_id));
				pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt1 == nullptr)
					goto RULE_FAILURE;
				sqlite3_bind_blob(pstmt1, 1, action_buff,
						action_len, SQLITE_STATIC);
				if (SQLITE_DONE != sqlite3_step(pstmt1)) {
					pstmt1.finalize();
					goto RULE_FAILURE;
				}
				pstmt1.finalize();
			}
			break;
		}
		case RULE_DATA_FLAG_REMOVE_ROW: {
			pvalue = common_util_get_propvals(
				&prow[i].propvals, PROP_TAG_RULEID);
			if (NULL == pvalue) {
				continue;
			}
			rule_id = rop_util_get_gc_value(*(uint64_t*)pvalue);
			sprintf(sql_string, "SELECT folder_id "
			          "FROM rules WHERE rule_id=%llu", LLU(rule_id));
			auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
			if (pstmt1 == nullptr)
				goto RULE_FAILURE;
			if (sqlite3_step(pstmt1) != SQLITE_ROW ||
			    gx_sql_col_uint64(pstmt1, 0) != fid_val)
				continue;
			pstmt1.finalize();
			sprintf(sql_string, "DELETE FROM rules"
			        " WHERE rule_id=%llu", LLU(rule_id));
			if (SQLITE_OK!= sqlite3_exec(pdb->psqlite,
				sql_string, NULL, NULL, NULL)) {
				goto RULE_FAILURE;
			}
			break;
		}
		}
	}
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	return TRUE;
	
 RULE_FAILURE:
	sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
	return FALSE;
}

/* public only */
BOOL exmdb_server_get_public_folder_unread_count(const char *dir,
	const char *username, uint64_t folder_id, uint32_t *pcount)
{
	if (TRUE == exmdb_server_check_private()) {
		return FALSE;
	}
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	exmdb_server_set_public_username(username);
	*pcount = common_util_get_folder_unread_count(
		pdb->psqlite, rop_util_get_gc_value(folder_id));
	return TRUE;
	
}
