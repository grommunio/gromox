// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2022 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <libHX/string.h>
#include <gromox/database.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "db_engine.h"
#define MAXIMUM_RECIEVE_FOLDERS				2000
#define SYSTEM_ALLOCATED_EID_RANGE			10000

using namespace gromox;
using LLD = long long;
using LLU = unsigned long long;

unsigned int exmdb_pf_read_per_user, exmdb_pf_read_states;

/* private only */
BOOL exmdb_server::get_folder_by_class(const char *dir,
    const char *str_class, uint64_t *pid, char **str_explicit)
{
	char tmp_class[256];
	char sql_string[1024];
	
	if (!exmdb_server::is_private())
		return FALSE;
	auto class_len = std::min(strlen(str_class), static_cast<size_t>(255));
	memcpy(tmp_class, str_class, class_len);
	tmp_class[class_len] = '\0';
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pstmt = gx_sql_prep(pdb->psqlite, "SELECT folder_id"
	             " FROM receive_table WHERE class=?");
	if (pstmt == nullptr)
		return FALSE;
	auto pdot = tmp_class + class_len;
	do {
		*pdot = '\0';
		sqlite3_bind_text(pstmt, 1, tmp_class, -1, SQLITE_STATIC);
		if (pstmt.step() == SQLITE_ROW) {
			*pid = rop_util_make_eid_ex(1,
				sqlite3_column_int64(pstmt, 0));
			*str_explicit = cu_alloc<char>(strlen(tmp_class) + 1);
			if (*str_explicit == nullptr)
				return false;
			strcpy(*str_explicit, tmp_class);
			return TRUE;
		}
		sqlite3_reset(pstmt);
	} while ((pdot = strrchr(tmp_class, '.')) != NULL);
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id "
				"FROM receive_table WHERE class=''");
	*str_explicit = cu_alloc<char>(1);
	if (*str_explicit == nullptr)
		return false;
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*pid = pstmt.step() == SQLITE_ROW ?
	       rop_util_make_eid_ex(1, sqlite3_column_int64(pstmt, 0)) :
	       rop_util_make_eid_ex(1, PRIVATE_FID_INBOX);
	**str_explicit = '\0';
	return TRUE;
}

/* private only */
BOOL exmdb_server::set_folder_by_class(const char *dir,
	uint64_t folder_id, const char *str_class, BOOL *pb_result)
{
	char sql_string[1024];
	
	if (!exmdb_server::is_private())
		return FALSE;
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (0 == folder_id) {
		auto pstmt = gx_sql_prep(pdb->psqlite, "DELETE FROM"
		             " receive_table WHERE class=?");
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_text(pstmt, 1, str_class, -1, SQLITE_STATIC);
		if (pstmt.step() != SQLITE_DONE)
			return FALSE;
		*pb_result = TRUE;
		return TRUE;
	}
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id FROM folders WHERE"
	          " folder_id=%llu", LLU{rop_util_get_gc_value(folder_id)});
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW) {
		*pb_result = FALSE;
		return TRUE;
	}
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "SELECT "
			"count(*) FROM receive_table");
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW ||
	    sqlite3_column_int64(pstmt, 0) > MAXIMUM_RECIEVE_FOLDERS)
		return FALSE;
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "REPLACE INTO receive_table"
	         " VALUES (?, ?, %llu)", LLU{rop_util_current_nttime()});
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_text(pstmt, 1, str_class, -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, rop_util_get_gc_value(folder_id));
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	*pb_result = TRUE;
	return TRUE;
}

/* private only */
BOOL exmdb_server::get_folder_class_table(
	const char *dir, TARRAY_SET *ptable)
{
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT "
			"count(*) FROM receive_table");
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	auto total_count = std::min(static_cast<uint64_t>(UINT32_MAX), pstmt.col_uint64(0));
	pstmt.finalize();
	if (0 == total_count) {
		ptable->count = 0;
		ptable->pparray = NULL;
		return TRUE;
	}
	ptable->pparray = cu_alloc<TPROPVAL_ARRAY *>(total_count);
	if (ptable->pparray == nullptr)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT class, folder_id,"
					" modified_time FROM receive_table");
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	ptable->count = 0;
	while (pstmt.step() == SQLITE_ROW) {
		auto ppropvals = cu_alloc<TPROPVAL_ARRAY>();
		if (ppropvals == nullptr)
			return FALSE;
		ppropvals->count = 3;
		ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(3);
		if (ppropvals->ppropval == nullptr)
			return FALSE;
		ppropvals->ppropval[0].proptag = PidTagFolderId;
		auto v = cu_alloc<uint64_t>();
		ppropvals->ppropval[0].pvalue = v;
		if (ppropvals->ppropval[0].pvalue == nullptr)
			return FALSE;
		*v = rop_util_make_eid_ex(1, sqlite3_column_int64(pstmt, 1));
		ppropvals->ppropval[1].proptag = PR_MESSAGE_CLASS_A;
		ppropvals->ppropval[1].pvalue =
			common_util_dup(reinterpret_cast<const char *>(sqlite3_column_text(pstmt, 0)));
		if (ppropvals->ppropval[1].pvalue == nullptr)
			return FALSE;
		ppropvals->ppropval[2].proptag = PR_LAST_MODIFICATION_TIME;
		v = cu_alloc<uint64_t>();
		ppropvals->ppropval[2].pvalue = v;
		if (ppropvals->ppropval[2].pvalue == nullptr)
			return FALSE;
		*v = sqlite3_column_int64(pstmt, 2);
		ptable->pparray[ptable->count++] = ppropvals;
	}
	return TRUE;
}

BOOL exmdb_server::check_folder_id(const char *dir,
	uint64_t folder_id, BOOL *pb_exist)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	return common_util_check_folder_id(pdb->psqlite,
	       rop_util_get_gc_value(folder_id), pb_exist);
}

BOOL exmdb_server::check_folder_deleted(const char *dir,
	uint64_t folder_id, BOOL *pb_del)
{
	char sql_string[256];
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT is_deleted "
				"FROM folders WHERE folder_id=%llu",
				LLU{rop_util_get_gc_value(folder_id)});
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*pb_del = pstmt.step() != SQLITE_ROW || sqlite3_column_int64(pstmt, 0) != 0 ? TRUE : false;
	return TRUE;
}

BOOL exmdb_server::get_folder_by_name(const char *dir,
	uint64_t parent_id, const char *str_name,
	uint64_t *pfolder_id)
{
	uint64_t fid_val = 0;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (!common_util_get_folder_by_name(pdb->psqlite,
	    rop_util_get_gc_value(parent_id), str_name, &fid_val))
		return FALSE;
	*pfolder_id = fid_val == 0 ? eid_t(0) :
	              (fid_val & NFID_UPPER_PART) == 0 ?
	              rop_util_make_eid_ex(1, fid_val) :
	              rop_util_make_eid_ex(fid_val >> 48, fid_val & NFID_LOWER_PART);
	return TRUE;
}

BOOL exmdb_server::create_folder_by_properties(const char *dir, cpid_t cpid,
    TPROPVAL_ARRAY *pproperties, uint64_t *pfolder_id)
{
	BOOL b_result;
	uint32_t type = 0, parent_type = 0;
	uint64_t tmp_fid = 0, folder_id = 0;
	char sql_string[128];
	PROBLEM_ARRAY tmp_problems;

	auto folder_id_p = pproperties->get<const eid_t>(PidTagFolderId);
	if (folder_id_p == nullptr) {
		tmp_fid = 0;
	} else {
		tmp_fid = *folder_id_p;
		common_util_remove_propvals(pproperties, PidTagFolderId);
	}
	*pfolder_id = 0;
	auto parent_fid_p = pproperties->get<const eid_t>(PidTagParentFolderId);
	if (parent_fid_p == nullptr || rop_util_get_replid(*parent_fid_p) != 1) {
		mlog(LV_ERR, "E-1581: create_folder_b_p request with no parent or wrong EID");
		return TRUE;
	}
	auto parent_id = rop_util_get_gc_value(*parent_fid_p);
	common_util_remove_propvals(pproperties, PidTagParentFolderId);
	auto pname = pproperties->get<const char>(PR_DISPLAY_NAME);
	if (pname == nullptr) {
		mlog(LV_ERR, "E-1582: create_folder_b_p request with no name");
		return TRUE;
	}
	auto cn_p = pproperties->get<const eid_t>(PidTagChangeNumber);
	if (cn_p == nullptr) {
		mlog(LV_ERR, "E-1583: create_folder_b_p request without CN");
		return TRUE;
	}
	common_util_remove_propvals(pproperties, PidTagChangeNumber);
	auto change_num = rop_util_get_gc_value(*cn_p);
	if (!pproperties->has(PR_PREDECESSOR_CHANGE_LIST)) {
		mlog(LV_ERR, "E-1584: create_folder_b_p request without PCL");
		return TRUE;
	}
	auto folder_type_p = pproperties->get<const uint32_t>(PR_FOLDER_TYPE);
	if (folder_type_p == nullptr) {
		type = FOLDER_GENERIC;
	} else {
		type = *folder_type_p;
		switch (type) {
		case FOLDER_GENERIC:
			break;
		case FOLDER_SEARCH:
			if (exmdb_server::is_private())
				break;
			mlog(LV_ERR, "E-1585: create_folder_b_p request without PCL");
			return TRUE;
		default:
			return TRUE;
		}
		common_util_remove_propvals(pproperties, PR_FOLDER_TYPE);
	}
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (!common_util_get_folder_type(pdb->psqlite, parent_id, &parent_type))
		return FALSE;
	if (parent_type == FOLDER_SEARCH)
		return TRUE;
	if (0 != tmp_fid) {
		auto tmp_val = rop_util_get_gc_value(tmp_fid);
		snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id FROM"
		          " folders WHERE folder_id=%llu", LLU{tmp_val});
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		if (pstmt.step() == SQLITE_ROW)
			return TRUE;
		if (!common_util_check_allocated_eid(pdb->psqlite, tmp_val, &b_result))
			return FALSE;
		if (!b_result)
			return TRUE;
	}
	auto qstr = "SELECT 1 FROM folders AS f INNER JOIN folder_properties AS fp "
	            "ON f.folder_id=fp.folder_id AND fp.proptag=? "
	            "WHERE f.parent_id=? and fp.propval=? COLLATE NOCASE";
	auto pstmt = gx_sql_prep(pdb->psqlite, qstr);
	if (pstmt == nullptr)
		return FALSE;
	pstmt.bind_int64(1, PR_DISPLAY_NAME);
	pstmt.bind_int64(2, parent_id);
	pstmt.bind_text(3, pname);
	if (pstmt.step() == SQLITE_ROW)
		return TRUE;
	pstmt.finalize();

	uint64_t max_eid = 0;
	if (type == FOLDER_GENERIC) {
		snprintf(sql_string, arsizeof(sql_string), "SELECT "
			"max(range_end) FROM allocated_eids");
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
			return FALSE;
		max_eid = sqlite3_column_int64(pstmt, 0);
		pstmt.finalize();
		max_eid ++;
	}
	auto sql_transact = gx_sql_begin_trans(pdb->psqlite);
	if (!sql_transact)
		return false;
	if (type == FOLDER_GENERIC) {
		snprintf(sql_string, arsizeof(sql_string), "INSERT INTO allocated_eids"
			" VALUES (%llu, %llu, %lld, 1)", LLU{max_eid}, LLU{max_eid +
			SYSTEM_ALLOCATED_EID_RANGE - 1}, LLD{time(nullptr)});
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
		uint64_t cur_eid = 0;
		if (0 == tmp_fid) {
			folder_id = max_eid;
			cur_eid = max_eid + 1;
		} else {
			folder_id = rop_util_get_gc_value(tmp_fid);
			cur_eid = max_eid;
		}
		max_eid += SYSTEM_ALLOCATED_EID_RANGE;
		pstmt = gx_sql_prep(pdb->psqlite, "INSERT INTO folders "
		        "(folder_id, parent_id, change_number, "
		        "cur_eid, max_eid) VALUES (?, ?, ?, ?, ?)");
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_int64(pstmt, 1, folder_id);
		sqlite3_bind_int64(pstmt, 2, parent_id);
		sqlite3_bind_int64(pstmt, 3, change_num);
		sqlite3_bind_int64(pstmt, 4, cur_eid);
		sqlite3_bind_int64(pstmt, 5, max_eid);
		if (pstmt.step() != SQLITE_DONE)
			return FALSE;
		pstmt.finalize();
		if (!cu_set_properties(MAPI_FOLDER,
		    folder_id, cpid, pdb->psqlite, pproperties, &tmp_problems))
			return FALSE;
		uint32_t next = 1, del_cnt = 0;
		cu_set_property(MAPI_FOLDER, folder_id, CP_ACP, pdb->psqlite,
			PR_INTERNET_ARTICLE_NUMBER_NEXT, &next, &b_result);
		cu_set_property(MAPI_FOLDER, folder_id, CP_ACP, pdb->psqlite,
			PR_DELETED_COUNT_TOTAL, &del_cnt, &b_result);
	} else {
		if (0 == tmp_fid) {
			if (!common_util_allocate_eid(pdb->psqlite, &max_eid))
				return FALSE;
			folder_id = max_eid;
		} else {
			folder_id = rop_util_get_gc_value(tmp_fid);
		}
		pstmt = gx_sql_prep(pdb->psqlite, "INSERT INTO folders (folder_id,"
		        " parent_id, change_number, is_search, cur_eid, "
		        "max_eid) VALUES (?, ?, ?, 1, 0, 0)");
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_int64(pstmt, 1, folder_id);
		sqlite3_bind_int64(pstmt, 2, parent_id);
		sqlite3_bind_int64(pstmt, 3, change_num);
		if (pstmt.step() != SQLITE_DONE)
			return FALSE;
		pstmt.finalize();
		if (!cu_set_properties(MAPI_FOLDER, folder_id, cpid,
		    pdb->psqlite, pproperties, &tmp_problems))
			return FALSE;
	}
	uint32_t art = 0, hcn = 0;
	if (!common_util_allocate_folder_art(pdb->psqlite, &art))
		return FALSE;
	cu_set_property(MAPI_FOLDER, folder_id, CP_ACP, pdb->psqlite,
		PR_INTERNET_ARTICLE_NUMBER, &art, &b_result);
	auto nt_time = rop_util_current_nttime();
	cu_set_property(MAPI_FOLDER, parent_id, CP_ACP, pdb->psqlite,
		PR_LOCAL_COMMIT_TIME_MAX, &nt_time, &b_result);
	cu_set_property(MAPI_FOLDER, folder_id, CP_ACP, pdb->psqlite,
		PR_LOCAL_COMMIT_TIME_MAX, &nt_time, &b_result);
	cu_set_property(MAPI_FOLDER, folder_id, CP_ACP, pdb->psqlite,
		PR_HIERARCHY_CHANGE_NUM, &hcn, &b_result);
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET"
		" propval=propval+1 WHERE folder_id=%llu AND "
		"proptag=%u", LLU{parent_id}, PR_HIERARCHY_CHANGE_NUM);
	gx_sql_exec(pdb->psqlite, sql_string);
	cu_set_property(MAPI_FOLDER, parent_id, CP_ACP, pdb->psqlite,
		PR_HIER_REV, &nt_time, &b_result);
	cu_set_property(MAPI_FOLDER, folder_id, CP_ACP, pdb->psqlite,
		PR_HIER_REV, &nt_time, &b_result);
	if (sql_transact.commit() != 0)
		return false;
	db_engine_notify_folder_creation(pdb, parent_id, folder_id);
	*pfolder_id = rop_util_make_eid_ex(1, folder_id);
	return TRUE;
}

BOOL exmdb_server::get_folder_all_proptags(const char *dir, uint64_t folder_id,
    PROPTAG_ARRAY *pproptags) try
{
	std::vector<uint32_t> tags;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (!cu_get_proptags(MAPI_FOLDER,
	    rop_util_get_gc_value(folder_id), pdb->psqlite, tags))
		return FALSE;
	pdb.reset();
	if (std::find(tags.cbegin(), tags.cend(), PR_SOURCE_KEY) == tags.cend())
		tags.push_back(PR_SOURCE_KEY);
	pproptags->pproptag = cu_alloc<uint32_t>(tags.size());
	if (pproptags->pproptag == nullptr)
		return FALSE;
	pproptags->count = tags.size();
	memcpy(pproptags->pproptag, tags.data(), sizeof(tags[0]) * pproptags->count);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1164: ENOMEM");
	return false;
}

BOOL exmdb_server::get_folder_properties(const char *dir, cpid_t cpid,
    uint64_t folder_id, const PROPTAG_ARRAY *pproptags,
    TPROPVAL_ARRAY *ppropvals)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	return cu_get_properties(MAPI_FOLDER, rop_util_get_gc_value(folder_id),
	       cpid, pdb->psqlite, pproptags, ppropvals);
}

/* no PROPERTY_PROBLEM for PidTagChangeNumber and PR_CHANGE_KEY */
BOOL exmdb_server::set_folder_properties(const char *dir, cpid_t cpid,
    uint64_t folder_id, const TPROPVAL_ARRAY *pproperties,
    PROBLEM_ARRAY *pproblems)
{
	unsigned int i;
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto fid_val = rop_util_get_gc_value(folder_id);
	auto sql_transact = gx_sql_begin_trans(pdb->psqlite);
	if (!sql_transact)
		return false;
	if (exmdb_server::is_private() && fid_val == PRIVATE_FID_ROOT) {
		for (i=0; i<pproperties->count; i++) {
			if (pproperties->ppropval[i].proptag != PR_ADDITIONAL_REN_ENTRYIDS &&
			    pproperties->ppropval[i].proptag != PR_ADDITIONAL_REN_ENTRYIDS_EX &&
			    pproperties->ppropval[i].proptag != PR_REM_ONLINE_ENTRYID)
				continue;
			TPROPVAL_ARRAY values = {1, &pproperties->ppropval[i]};
			PROBLEM_ARRAY problem;
			if (!cu_set_properties(MAPI_FOLDER, PRIVATE_FID_INBOX,
			    CP_ACP, pdb->psqlite, &values, &problem))
				return FALSE;
		}
	}
	if (!cu_set_properties(MAPI_FOLDER,
	    fid_val, cpid, pdb->psqlite, pproperties, pproblems))
		return FALSE;
	if (sql_transact.commit() != 0)
		return false;
	db_engine_notify_folder_modification(pdb,
		common_util_get_folder_parent_fid(
		pdb->psqlite, fid_val), fid_val);
	return TRUE;
}

BOOL exmdb_server::remove_folder_properties(const char *dir,
	uint64_t folder_id, const PROPTAG_ARRAY *pproptags)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto fid_val = rop_util_get_gc_value(folder_id);
	auto sql_transact = gx_sql_begin_trans(pdb->psqlite);
	if (!sql_transact)
		return false;
	if (!cu_remove_properties(MAPI_FOLDER,
	    fid_val, pdb->psqlite, pproptags))
		return FALSE;
	if (sql_transact.commit() != 0)
		return false;
	db_engine_notify_folder_modification(pdb,
		common_util_get_folder_parent_fid(
		pdb->psqlite, fid_val), fid_val);
	return TRUE;
}

static int need_msg_perm_check(sqlite3 *db, const char *user, uint64_t fid)
{
	if (user == nullptr)
		return false;
	uint32_t perms;
	if (!cu_get_folder_permission(db, fid, user, &perms))
		return -1;
	if (perms & (frightsOwner | frightsDeleteAny))
		return false;
	if (perms & frightsDeleteOwned)
		return true;
	/* Not enouugh perms to act within this folder, so skip it */
	return -1;
}

static int have_delete_perm(sqlite3 *db, const char *user, uint64_t fid,
    uint64_t mid = 0)
{
	if (user == nullptr)
		return true;
	uint32_t perms;
	if (!cu_get_folder_permission(db, fid, user, &perms))
		return -1;
	if (mid == 0)
		/* Whether the folder itself may be deleted */
		return !!(perms & frightsOwner);

	/* For messages inside. */
	if (perms & (frightsOwner | frightsDeleteAny))
		return true;
	if (!(perms & frightsDeleteOwned))
		return false;
	BOOL owner = false;
	if (!common_util_check_message_owner(db, mid, user, &owner))
		return -1;
	return !!owner;
}

static BOOL folder_empty_sf(db_item_ptr &pdb, cpid_t cpid, const char *username,
    uint64_t folder_id, unsigned int del_flags, BOOL *pb_partial,
    uint64_t *pnormal_size, uint64_t *pfai_size, uint32_t *pmessage_count,
    uint32_t *pfolder_count)
{
	bool b_normal = del_flags & DEL_MESSAGES;
	bool b_fai    = del_flags & DEL_ASSOCIATED;
	/* always in private store, there's only hard deletion */
	if (!b_normal && !b_fai)
		return TRUE;
	char sql_string[226];
	snprintf(sql_string, arsizeof(sql_string), "SELECT messages.message_id,"
		 " messages.parent_fid, messages.message_size, "
		 "messages.is_associated FROM messages JOIN "
		 "search_result ON messages.message_id="
		 "search_result.message_id AND "
		 "search_result.folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		bool is_associated = sqlite3_column_int64(pstmt, 3);
		if ((is_associated && !b_fai) ||
		    (!is_associated && !b_normal))
			continue;
		uint64_t message_id = sqlite3_column_int64(pstmt, 0);
		uint64_t parent_fid = sqlite3_column_int64(pstmt, 1);
		auto ret = have_delete_perm(pdb->psqlite, username, parent_fid, message_id);
		if (ret < 0)
			return false;
		if (ret == 0) {
			*pb_partial = TRUE;
			continue;
		}
		if (pmessage_count != nullptr)
			(*pmessage_count) ++;
		if (is_associated && pfai_size != nullptr)
			*pfai_size += sqlite3_column_int64(pstmt, 2);
		else if (!is_associated && pnormal_size != nullptr)
			*pnormal_size += sqlite3_column_int64(pstmt, 2);
		db_engine_proc_dynamic_event(pdb, cpid,
			dynamic_event::del_msg,
			folder_id, message_id, 0);
		db_engine_proc_dynamic_event(pdb, cpid,
			dynamic_event::del_msg,
			parent_fid, message_id, 0);
		db_engine_notify_link_deletion(
			pdb, folder_id, message_id);
		db_engine_notify_message_deletion(
			pdb, parent_fid, message_id);
		snprintf(sql_string, arsizeof(sql_string), "DELETE FROM messages "
			"WHERE message_id=%llu", LLU{message_id});
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	}
	return TRUE;
}

static BOOL folder_empty_folder(db_item_ptr &pdb, cpid_t cpid,
    const char *username, uint64_t folder_id, unsigned int del_flags,
    BOOL *pb_partial, uint64_t *pnormal_size, uint64_t *pfai_size,
	uint32_t *pmessage_count, uint32_t *pfolder_count)
{
	bool b_hard   = del_flags & DELETE_HARD_DELETE;
	bool b_normal = del_flags & DEL_MESSAGES;
	bool b_fai    = del_flags & DEL_ASSOCIATED;
	auto s_normal = b_normal ? "0" : "NULL";
	auto s_fai    = b_fai ? "0" : "NULL";
	BOOL b_check = true;
	uint32_t folder_type;
	char sql_string[256];
	
	*pb_partial = FALSE;
	auto b_private = exmdb_server::is_private();
	if (!common_util_get_folder_type(pdb->psqlite, folder_id, &folder_type))
		return FALSE;
	if (folder_type == FOLDER_SEARCH)
		return folder_empty_sf(pdb, cpid, username, folder_id,
		       del_flags, pb_partial, pnormal_size, pfai_size,
		       pmessage_count, pfolder_count);

	if (b_normal || b_fai) {
		auto ret = need_msg_perm_check(pdb->psqlite, username, folder_id);
		if (ret < 0)
			return false;
		b_check = ret > 0 ? TRUE : false;
		/*
		 * First need to count the sizes before doing a sweeping
		 * removal. When a bulk delete is used (!b_check&&b_hard), we
		 * could also use COUNT() and SUM() to fill in pmessage_count,
		 * pmessage_size, pfai_size. But delete counters are currently
		 * inconsistent (XXX: GXL-407).
		 */
		snprintf(sql_string, std::size(sql_string), "SELECT message_id,"
		         " message_size, is_associated, is_deleted FROM messages "
		         "WHERE parent_fid=%llu AND is_associated IN (%s,%s)",
		         LLU{folder_id}, s_normal, s_fai);
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		while (pstmt.step() == SQLITE_ROW) {
			bool is_deleted = pstmt.col_int64(3);
			if (!b_hard && is_deleted)
				continue;
			uint64_t message_id = sqlite3_column_int64(pstmt, 0);
			bool is_associated = sqlite3_column_int64(pstmt, 2);
			if (b_check) {
				BOOL b_owner = false;
				if (!common_util_check_message_owner(pdb->psqlite,
				    message_id, username, &b_owner))
					return FALSE;
				if (!b_owner) {
					*pb_partial = TRUE;
					continue;
				}
			}
			if (pmessage_count != nullptr && b_hard)
				(*pmessage_count) ++;
			if (b_hard && is_associated && pfai_size != nullptr)
				*pfai_size += sqlite3_column_int64(pstmt, 1);
			else if (b_hard && !is_associated && pnormal_size != nullptr)
				*pnormal_size += sqlite3_column_int64(pstmt, 1);
			if (0 == is_deleted) {
				db_engine_proc_dynamic_event(pdb, cpid,
					dynamic_event::del_msg, folder_id,
					message_id, 0);
				db_engine_notify_message_deletion(
					pdb, folder_id, message_id);
			}
			if (b_check) {
				if (b_hard)
					snprintf(sql_string, arsizeof(sql_string), "DELETE FROM messages "
						"WHERE message_id=%llu", LLU{message_id});
				else
					snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET "
						"is_deleted=1 WHERE message_id=%llu",
						LLU{message_id});
				if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
					return FALSE;
			}
			if (!b_hard && !b_private) {
				snprintf(sql_string, arsizeof(sql_string), "DELETE FROM read_states"
					" WHERE message_id=%llu", LLU{message_id});
				if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
					return FALSE;
			}
		}
		pstmt.finalize();
		if (!b_check) {
			if (b_hard)
				/* Sweep removal */
				snprintf(sql_string, arsizeof(sql_string), "DELETE FROM messages WHERE"
				         " parent_fid=%llu AND is_associated IN (%s,%s)",
				         LLU{folder_id}, s_normal, s_fai);
			else
				snprintf(sql_string, arsizeof(sql_string), "UPDATE messages SET is_deleted=1"
				         " WHERE parent_fid=%llu AND is_associated IN (%s,%s)",
				         LLU{folder_id}, s_normal, s_fai);
			if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
				return FALSE;
		}
	}
	if (!(del_flags & DEL_FOLDERS))
		return TRUE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id,"
	         " is_deleted FROM folders WHERE parent_id=%llu", LLU{folder_id});

	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		uint64_t fid_val = sqlite3_column_int64(pstmt, 0);
		if ((b_private && fid_val < PRIVATE_FID_CUSTOM) ||
		    (!b_private && fid_val < PUBLIC_FID_CUSTOM)) {
			*pb_partial = TRUE;
			continue;
		}
		bool is_deleted = pstmt.col_int64(1);
		if (!b_hard && is_deleted)
			continue;
		auto ret = have_delete_perm(pdb->psqlite, username, fid_val);
		if (ret < 0)
			return false;
		if (ret == 0) {
			*pb_partial = TRUE;
			continue;
		}
		BOOL b_partial = false;
		unsigned int new_flags = (del_flags & DELETE_HARD_DELETE) | DEL_MESSAGES | DEL_ASSOCIATED;
		if (!folder_empty_folder(pdb, cpid, username, fid_val,
		    new_flags, &b_partial, pnormal_size, pfai_size,
		    nullptr, nullptr))
			return FALSE;
		if (b_partial) {
			*pb_partial = TRUE;
			continue;
		}
		new_flags = (del_flags & DELETE_HARD_DELETE) | DEL_FOLDERS;
		if (!folder_empty_folder(pdb, cpid, username, fid_val,
		    new_flags, &b_partial, pnormal_size, pfai_size,
		    nullptr, nullptr))
			return FALSE;
		if (b_partial) {
			*pb_partial = TRUE;
			continue;
		}
		if (pfolder_count != nullptr && b_hard)
			(*pfolder_count) ++;
		if (b_hard)
			snprintf(sql_string, arsizeof(sql_string), "DELETE FROM folders "
				"WHERE folder_id=%llu", LLU{fid_val});
		else
			snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET "
				"is_deleted=1 WHERE folder_id=%llu",
				LLU{fid_val});
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
		db_engine_notify_folder_deletion(
				pdb, folder_id, fid_val);
	}
	return TRUE;
}

/* only delete empty generic folder or search folder itself, not content */
BOOL exmdb_server::delete_folder(const char *dir, cpid_t cpid,
	uint64_t folder_id, BOOL b_hard, BOOL *pb_result)
{
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	BOOL b_search = false;
	auto fid_val = rop_util_get_gc_value(folder_id);
	if (exmdb_server::is_private()) {
		if (!g_exmdb_pvt_folder_softdel)
			b_hard = TRUE;
		if (fid_val < PRIVATE_FID_CUSTOM) {
			*pb_result = FALSE;
			return TRUE;
		}
		snprintf(sql_string, arsizeof(sql_string), "SELECT is_search FROM"
		          " folders WHERE folder_id=%llu", LLU{fid_val});
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		if (pstmt.step() != SQLITE_ROW)
			return TRUE;
		if (pstmt.col_int64(0) != 0)
			b_search = b_hard = TRUE;
	} else if (fid_val < PUBLIC_FID_CUSTOM) {
		*pb_result = FALSE;
		return TRUE;
	}
	if (!b_search) {
		snprintf(sql_string, arsizeof(sql_string), "SELECT count(*) FROM "
		          "folders WHERE parent_id=%llu", LLU{fid_val});
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
			return FALSE;
		if (0 != sqlite3_column_int64(pstmt, 0)) {
			*pb_result = FALSE;
			return TRUE;
		}
		pstmt.finalize();
		snprintf(sql_string, std::size(sql_string), "SELECT count(*) FROM"
		         " messages WHERE parent_fid=%llu AND"
		         " is_deleted=0", LLU{fid_val});
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
			return FALSE;
		if (0 != sqlite3_column_int64(pstmt, 0)) {
			*pb_result = FALSE;
			return TRUE;
		}
	} else {
		snprintf(sql_string, arsizeof(sql_string), "SELECT message_id FROM"
		          " search_result WHERE folder_id=%llu", LLU{fid_val});
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		while (pstmt.step() == SQLITE_ROW)
			db_engine_proc_dynamic_event(pdb, cpid,
				dynamic_event::del_msg, fid_val,
				sqlite3_column_int64(pstmt, 0), 0);
		pstmt.finalize();
		db_engine_delete_dynamic(pdb, fid_val);
	}
	auto parent_id = common_util_get_folder_parent_fid(pdb->psqlite, fid_val);
	auto sql_transact = gx_sql_begin_trans(pdb->psqlite);
	if (!sql_transact)
		return false;
	if (b_search) {
		/* empty_folder is too much for search folders; it would delete not just the links. */
		snprintf(sql_string, std::size(sql_string), "DELETE FROM folders"
		         " WHERE folder_id=%llu", LLU{fid_val});
	} else if (b_hard) {
		BOOL b_partial = false;
		uint64_t normal_size = 0, fai_size = 0;
		if (!folder_empty_folder(pdb, cpid, nullptr, fid_val,
		    DELETE_HARD_DELETE | DEL_MESSAGES | DEL_ASSOCIATED | DEL_FOLDERS,
		    &b_partial, &normal_size, &fai_size,
		    nullptr, nullptr) || b_partial ||
		    !cu_adjust_store_size(pdb->psqlite, ADJ_DECREASE, normal_size, fai_size))
			return FALSE;
		snprintf(sql_string, arsizeof(sql_string), "DELETE FROM folders"
			" WHERE folder_id=%llu", LLU{fid_val});
	} else {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET"
			" is_deleted=1 WHERE folder_id=%llu",
			LLU{fid_val});
	}
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	db_engine_notify_folder_deletion(
		pdb, parent_id, fid_val);
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET"
		" propval=propval+1 WHERE folder_id=%llu AND "
	        "proptag=%u", LLU{parent_id}, PR_DELETED_FOLDER_COUNT);
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET"
		" propval=propval+1 WHERE folder_id=%llu AND "
		 "proptag=%u", LLU{parent_id}, PR_HIERARCHY_CHANGE_NUM);
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties "
		"SET propval=%llu WHERE folder_id=%llu AND proptag=?",
		LLU{rop_util_current_nttime()}, LLU{parent_id});
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 0, PR_HIER_REV);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 0, PR_LOCAL_COMMIT_TIME_MAX);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	pstmt.finalize();
	if (sql_transact.commit() != 0)
		return false;
	*pb_result = TRUE;
	return TRUE;
}

BOOL exmdb_server::empty_folder(const char *dir, cpid_t cpid,
    const char *username, uint64_t folder_id, unsigned int flags,
    BOOL *pb_partial)
{
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto fid_val = rop_util_get_gc_value(folder_id);
	uint32_t message_count = 0, folder_count = 0;
	uint64_t normal_size = 0, fai_size = 0;
	auto sql_transact = gx_sql_begin_trans(pdb->psqlite);
	if (!sql_transact)
		return false;
	if (!folder_empty_folder(pdb, cpid, username, fid_val, flags,
	    pb_partial, &normal_size, &fai_size,
	    &message_count, &folder_count))
		return FALSE;
	if (message_count > 0) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
			"propval=propval+%u WHERE folder_id=%llu AND "
			"proptag=%u", message_count, LLU{fid_val},
		        PR_DELETED_COUNT_TOTAL);
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	}
	if (folder_count > 0) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
			"propval=propval+%u WHERE folder_id=%llu AND "
			"proptag=%u", folder_count, LLU{fid_val},
		        PR_DELETED_FOLDER_COUNT);
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
			"propval=propval+1 WHERE folder_id=%llu AND "
		         "proptag=%u", LLU{fid_val}, PR_HIERARCHY_CHANGE_NUM);
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
			"propval=%llu WHERE folder_id=%llu AND proptag=%u",
		         LLU{rop_util_current_nttime()}, LLU{fid_val}, PR_HIER_REV);
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	}
	if (message_count > 0 || folder_count > 0) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
			"propval=%llu WHERE folder_id=%llu AND proptag=%u",
			LLU{rop_util_current_nttime()}, LLU{fid_val},
		         PR_LOCAL_COMMIT_TIME_MAX);
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	}
	if (!cu_adjust_store_size(pdb->psqlite, ADJ_DECREASE, normal_size, fai_size))
		return FALSE;
	return sql_transact.commit() == 0 ? TRUE : false;
}

BOOL exmdb_server::check_folder_cycle(const char *dir,
	uint64_t src_fid, uint64_t dst_fid, BOOL *pb_cycle)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (!common_util_check_descendant(pdb->psqlite,
	    rop_util_get_gc_value(dst_fid), rop_util_get_gc_value(src_fid),
	    pb_cycle))
		return FALSE;
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
	
	if (!common_util_allocate_cn(psqlite, &change_num))
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT "
		"max(range_end) FROM allocated_eids");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	last_eid = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO allocated_eids"
			" VALUES (%llu, %llu, %lld, 1)", LLU{last_eid + 1},
			LLU{last_eid + ALLOCATED_EID_RANGE}, LLD{time(nullptr)});
	if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	pstmt = gx_sql_prep(psqlite, "INSERT INTO folders "
	        "(folder_id, parent_id, change_number, "
	        "cur_eid, max_eid) VALUES (?, ?, ?, ?, ?)");
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, last_eid + 1);
	sqlite3_bind_int64(pstmt, 2, dst_pid);
	sqlite3_bind_int64(pstmt, 3, change_num);
	sqlite3_bind_int64(pstmt, 4, last_eid + 2);
	sqlite3_bind_int64(pstmt, 5, last_eid + ALLOCATED_EID_RANGE);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO folder_properties "
		"(folder_id, proptag, propval) SELECT %llu, proptag,"
		" propval FROM folder_properties WHERE folder_id=%llu",
		LLU{last_eid + 1}, LLU{src_fid});
	if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	if (b_guest) {
		snprintf(sql_string, arsizeof(sql_string), "INSERT INTO permissions "
					"(folder_id, username, permission) VALUES "
					"(%llu, ?, ?)", LLU{last_eid + 1});
		pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
		sqlite3_bind_int64(pstmt, 2, frightsOwner);
		if (pstmt.step() != SQLITE_DONE)
			return FALSE;
		pstmt.finalize();
	}
	if (!common_util_allocate_folder_art(psqlite, &art))
		return FALSE;
	nt_time = rop_util_current_nttime();
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties"
				" SET propval=? WHERE folder_id=%llu AND "
				"proptag=?", LLU{last_eid + 1});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, art);
	sqlite3_bind_int64(pstmt, 2, PR_INTERNET_ARTICLE_NUMBER);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, 1);
	sqlite3_bind_int64(pstmt, 2, PR_INTERNET_ARTICLE_NUMBER_NEXT);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, nt_time);
	sqlite3_bind_int64(pstmt, 2, PR_LAST_MODIFICATION_TIME);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, nt_time);
	sqlite3_bind_int64(pstmt, 2, PR_LOCAL_COMMIT_TIME_MAX);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, 0);
	sqlite3_bind_int64(pstmt, 2, PR_HIERARCHY_CHANGE_NUM);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, nt_time);
	sqlite3_bind_int64(pstmt, 2, PR_HIER_REV);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	*pdst_fid = last_eid + 1;
	return TRUE;
}

static BOOL folder_copy_search_folder(db_item_ptr &pdb,
    cpid_t cpid, BOOL b_guest, const char *username,
	uint64_t src_fid, uint64_t dst_pid, uint64_t *pdst_fid)
{
	uint32_t art;
	uint64_t nt_time;
	uint64_t last_eid;
	uint64_t change_num;
	char sql_string[256];
	
	if (!common_util_allocate_cn(pdb->psqlite, &change_num))
		return FALSE;
	if (!common_util_allocate_eid(pdb->psqlite, &last_eid))
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO folders (folder_id, "
		"parent_id, change_number, is_search, search_flags,"
		" search_criteria, cur_eid, max_eid) SELECT %llu, "
		"%llu, %llu, 1, search_flags, search_criteria, 0, 0"
		" FROM folders WHERE folder_id=%llu", LLU{last_eid},
		LLU{dst_pid}, LLU{change_num}, LLU{src_fid});
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO folder_properties "
		"(folder_id, proptag, propval) SELECT %llu, proptag,"
		" propval FROM folder_properties WHERE folder_id=%llu",
		LLU{last_eid}, LLU{src_fid});
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	if (b_guest) {
		snprintf(sql_string, arsizeof(sql_string), "INSERT INTO permissions "
					"(folder_id, username, permission) VALUES "
					"(%llu, ?, ?)", LLU{last_eid});
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
		sqlite3_bind_int64(pstmt, 2, frightsOwner);
		if (pstmt.step() != SQLITE_DONE)
			return FALSE;
	}
	if (!common_util_allocate_folder_art(pdb->psqlite, &art))
		return FALSE;
	nt_time = rop_util_current_nttime();
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties"
				" SET propval=? WHERE folder_id=%llu AND "
				"proptag=?", LLU{last_eid});
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, art);
	sqlite3_bind_int64(pstmt, 2, PR_INTERNET_ARTICLE_NUMBER);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, nt_time);
	sqlite3_bind_int64(pstmt, 2, PR_LAST_MODIFICATION_TIME);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, nt_time);
	sqlite3_bind_int64(pstmt, 2, PR_LOCAL_COMMIT_TIME_MAX);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, 0);
	sqlite3_bind_int64(pstmt, 2, PR_HIERARCHY_CHANGE_NUM);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, nt_time);
	sqlite3_bind_int64(pstmt, 2, PR_HIER_REV);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO search_result (folder_id, "
		"message_id) SELECT %llu, message_id WHERE folder_id=%llu",
		LLU{last_eid}, LLU{src_fid});
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT message_id FROM "
	          "search_result WHERE folder_id=%llu", LLU{last_eid});
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW)
		db_engine_proc_dynamic_event(pdb, cpid,
			dynamic_event::new_msg, last_eid,
			sqlite3_column_int64(pstmt, 0), 0);
	*pdst_fid = last_eid;
	return TRUE;
}

static BOOL folder_copy_sf_int(db_item_ptr &pdb, int account_id, cpid_t cpid,
    bool b_guest, const char *username, uint64_t fid_val, bool b_normal,
    bool b_fai, uint64_t dst_fid, BOOL *pb_partial, uint64_t *pnormal_size,
    uint64_t *pfai_size)
{
	if (b_guest) {
		uint32_t permission = rightsNone;
		if (!cu_get_folder_permission(pdb->psqlite,
		    dst_fid, username, &permission))
			return FALSE;
		if (!(permission & frightsCreate)) {
			*pb_partial = TRUE;
			return TRUE;
		}
	}
	if (!b_normal && !b_fai)
		return TRUE;
	char sql_string[202];
	snprintf(sql_string, arsizeof(sql_string), "SELECT messages.message_id,"
	         " messages.parent_fid, messages.is_associated "
	         "FROM messages JOIN search_result ON "
	         "messages.message_id=search_result.message_id"
	         " AND search_result.folder_id=%llu", LLU{fid_val});
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		bool is_associated = pstmt.col_uint64(2);
		if (0 == is_associated) {
			if (!b_normal)
				continue;
		} else {
			if (!b_fai)
				continue;
		}
		auto message_id = pstmt.col_uint64(0);
		auto parent_fid = pstmt.col_uint64(1);
		if (b_guest) {
			uint32_t permission = rightsNone;
			if (!cu_get_folder_permission(pdb->psqlite,
			    parent_fid, username, &permission))
				return FALSE;
			if (permission & (frightsOwner | frightsReadAny)) {
				/* do nothing */
			} else {
				BOOL b_owner = false;
				if (!common_util_check_message_owner(pdb->psqlite,
				    message_id, username, &b_owner))
					return FALSE;
				if (!b_owner) {
					*pb_partial = TRUE;
					continue;
				}
			}
		}
		uint64_t message_id1 = 0;
		uint32_t message_size = 0;
		BOOL b_result = false;
		if (!common_util_copy_message(pdb->psqlite,
		    account_id, message_id, dst_fid, &message_id1,
		    &b_result, &message_size))
			return FALSE;
		if (!b_result) {
			*pb_partial = TRUE;
			continue;
		}
		if (0 == is_associated) {
			if (pnormal_size != nullptr)
				*pnormal_size += message_size;
		} else {
			if (pfai_size != nullptr)
				*pfai_size += message_size;
		}
		db_engine_proc_dynamic_event(pdb, cpid, dynamic_event::new_msg,
			dst_fid, message_id1, 0);
	}
	return TRUE;
}

static BOOL folder_copy_folder_internal(db_item_ptr &pdb, int account_id,
    cpid_t cpid, BOOL b_guest,
	const char *username, uint64_t src_fid, BOOL b_normal,
	BOOL b_fai, BOOL b_sub, uint64_t dst_fid, BOOL *pb_partial,
	uint64_t *pnormal_size, uint64_t *pfai_size, uint32_t *pfolder_count)
{
	uint32_t folder_type = 0;
	*pb_partial = FALSE;
	auto fid_val = src_fid;
	auto b_private = exmdb_server::is_private();
	if (!common_util_get_folder_type(pdb->psqlite, fid_val, &folder_type))
		return FALSE;
	if (folder_type == FOLDER_SEARCH) {
		return folder_copy_sf_int(pdb, account_id, cpid, b_guest,
		       username, fid_val, b_normal, b_fai, dst_fid,
		       pb_partial, pnormal_size, pfai_size);
	}

	BOOL b_check = true, b_result, b_partial;
	char sql_string[132];
	uint32_t message_size, permission = rightsNone;
	
	if (b_normal || b_fai) {
		if (!b_guest) {
			b_check = FALSE;
		} else {
			if (!cu_get_folder_permission(pdb->psqlite,
			    fid_val, username, &permission))
				return FALSE;
			b_check	= (permission & (frightsOwner | frightsReadAny)) ? false : TRUE;
			if (!cu_get_folder_permission(pdb->psqlite,
			    dst_fid, username, &permission))
				return FALSE;
			if (!(permission & frightsCreate)) {
				*pb_partial = TRUE;
				goto COPY_SUBFOLDER;
			}
		}
		auto s_normal = b_normal ? "0" : "NULL";
		auto s_fai    = b_fai ? "1" : "NULL";
		snprintf(sql_string, std::size(sql_string), "SELECT message_id,"
		         " is_associated, is_deleted FROM messages WHERE "
		         "parent_fid=%llu AND is_associated IN (%s,%s)",
		         LLU{fid_val}, s_normal, s_fai);

		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		while (pstmt.step() == SQLITE_ROW) {
			if (!b_private && pstmt.col_uint64(2) != 0)
				continue;
			auto message_id = pstmt.col_uint64(0);
			if (b_check) {
				BOOL b_owner = false;
				if (!common_util_check_message_owner(pdb->psqlite,
				    message_id, username, &b_owner))
					return FALSE;
				if (!b_owner) {
					*pb_partial = TRUE;
					continue;
				}
			}
			uint64_t message_id1 = 0;
			if (!common_util_copy_message(pdb->psqlite, account_id,
			    message_id, dst_fid, &message_id1, &b_result, &message_size))
				return FALSE;
			if (!b_result) {
				*pb_partial = TRUE;
				continue;
			}
			auto is_associated = pstmt.col_uint64(1) != 0;
			if (0 == is_associated) {
				if (pnormal_size != nullptr)
					*pnormal_size += message_size;
			} else {
				if (pfai_size != nullptr)
					*pfai_size += message_size;
			}
			db_engine_proc_dynamic_event(pdb, cpid,
				dynamic_event::new_msg, dst_fid,
				message_id1, 0);
		}
	}
 COPY_SUBFOLDER:
	if (!b_sub)
		return TRUE;
	if (b_guest) {
		if (!cu_get_folder_permission(pdb->psqlite,
		    dst_fid, username, &permission))
			return FALSE;
		if (!(permission & frightsCreateSubfolder)) {
			*pb_partial = TRUE;
			return TRUE;
		}
	}
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id "
		  "FROM folders WHERE parent_id=%llu", LLU{fid_val});
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		auto src_fid1 = pstmt.col_uint64(0);
		fid_val = src_fid1;
		if (b_check) {
			if (!cu_get_folder_permission(pdb->psqlite,
			    fid_val, username, &permission))
				return FALSE;
			if (!(permission & (frightsReadAny | frightsVisible))) {
				*pb_partial = TRUE;
				continue;
			}
		}
		if (!common_util_get_folder_type(pdb->psqlite, fid_val, &folder_type))
			return FALSE;
		if (folder_type == FOLDER_SEARCH) {
			if (!folder_copy_search_folder(pdb, cpid,
			    b_guest, username, fid_val, dst_fid, &fid_val))
				return FALSE;
		} else {
			if (!folder_copy_generic_folder(pdb->psqlite,
			    b_guest, username, fid_val, dst_fid, &fid_val))
				return FALSE;
		}
		if (0 == fid_val) {
			*pb_partial = TRUE;
			continue;
		}
		if (pfolder_count != nullptr)
			(*pfolder_count) ++;
		if (folder_type == FOLDER_SEARCH)
			continue;
		if (!folder_copy_folder_internal(pdb, account_id,
		    cpid, b_guest, username, src_fid1, TRUE, TRUE, TRUE,
		    fid_val, &b_partial, pnormal_size, pfai_size, nullptr))
			return FALSE;
		if (b_partial) {
			*pb_partial = TRUE;
			continue;
		}
	}
	return TRUE;
}

/* set hierarchy change number when finish action */
BOOL exmdb_server::copy_folder_internal(const char *dir,
    int account_id, cpid_t cpid, BOOL b_guest, const char *username,
	uint64_t src_fid, BOOL b_normal, BOOL b_fai, BOOL b_sub,
	uint64_t dst_fid, BOOL *pb_collid, BOOL *pb_partial)
{
	char sql_string[256];
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (account_id == 0)
		account_id = get_account_id();
	auto src_val = rop_util_get_gc_value(src_fid);
	auto dst_val = rop_util_get_gc_value(dst_fid);
	if (!common_util_check_descendant(pdb->psqlite, dst_fid,
	    src_val, pb_collid))
		return FALSE;
	if (*pb_collid)
		return TRUE;

	uint32_t folder_count = 0;
	uint64_t normal_size = 0, fai_size = 0;
	BOOL b_partial = false;
	auto sql_transact = gx_sql_begin_trans(pdb->psqlite);
	if (!sql_transact)
		return false;
	if (!folder_copy_folder_internal(pdb, account_id, cpid,
	    b_guest, username, src_val, b_normal, b_fai, b_sub, dst_val,
	    &b_partial, &normal_size, &fai_size, &folder_count))
		return FALSE;
	if (folder_count > 0) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
			"propval=propval+1 WHERE folder_id=%llu AND "
		         "proptag=%u", LLU{dst_val}, PR_HIERARCHY_CHANGE_NUM);
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
			"propval=%llu WHERE folder_id=%llu AND proptag=%u",
		         LLU{rop_util_current_nttime()}, LLU{dst_val}, PR_HIER_REV);
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	}
	if (normal_size + fai_size > 0 || folder_count > 0) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
			"propval=%llu WHERE folder_id=%llu AND proptag=%u",
			LLU{rop_util_current_nttime()}, LLU{dst_val},
		         PR_LOCAL_COMMIT_TIME_MAX);
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	}
	if (!cu_adjust_store_size(pdb->psqlite, ADJ_INCREASE, normal_size, fai_size))
		return FALSE;
	return sql_transact.commit() == 0 ? TRUE : false;
}

/* set hierarchy change number when finish action */
BOOL exmdb_server::movecopy_folder(const char *dir,
    int account_id, cpid_t cpid, BOOL b_guest, const char *username,
	uint64_t src_pid, uint64_t src_fid, uint64_t dst_fid,
	const char *str_new, BOOL b_copy, BOOL *pb_exist,
	BOOL *pb_partial)
{
	uint64_t tmp_fid = 0, fid_val = 0;
	char sql_string[256];
	uint32_t folder_type;
	
	auto src_val = rop_util_get_gc_value(src_fid);
	auto dst_val = rop_util_get_gc_value(dst_fid);
	auto parent_val = rop_util_get_gc_value(src_pid);
	*pb_exist = FALSE;
	*pb_partial = FALSE;
	if (!b_copy) {
		if (exmdb_server::is_private()) {
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
	if (account_id == 0)
		account_id = get_account_id();
	if (b_copy &&
	    cu_check_msgsize_overflow(pdb->psqlite, PR_STORAGE_QUOTA_LIMIT) &&
	    common_util_check_msgcnt_overflow(pdb->psqlite)) {
		*pb_partial = TRUE;
		return TRUE;		
	}
	if (!common_util_get_folder_by_name(pdb->psqlite, dst_val, str_new, &tmp_fid))
		return FALSE;
	if (0 != tmp_fid) {
		*pb_exist = TRUE;
		return TRUE;
	}
	if (!b_copy) {
		BOOL b_included = false;
		if (!common_util_check_descendant(pdb->psqlite, dst_val,
		    src_val, &b_included))
			return FALSE;
		if (b_included) {
			*pb_partial = TRUE;
			return TRUE;
		}
	}
	auto sql_transact = gx_sql_begin_trans(pdb->psqlite);
	if (!sql_transact)
		return false;
	if (!b_copy) {
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET parent_id=%llu"
		        " WHERE folder_id=%llu", LLU{dst_val}, LLU{src_val});
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties "
			"SET propval=? WHERE folder_id=%llu AND proptag=%u",
		        LLU{src_val}, PR_DISPLAY_NAME);
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_text(pstmt, 1, str_new, -1, SQLITE_STATIC);
		if (pstmt.step() != SQLITE_DONE)
			return FALSE;
		pstmt.finalize();
		auto nt_time = rop_util_current_nttime();
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
			"propval=%llu WHERE folder_id=%llu AND proptag=%u",
		         LLU{nt_time}, LLU{parent_val}, PR_LOCAL_COMMIT_TIME_MAX);
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
			"propval=propval+1 WHERE folder_id=%llu AND "
		        "proptag=%u", LLU{parent_val}, PR_DELETED_FOLDER_COUNT);
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
			"propval=propval+1 WHERE folder_id=%llu AND "
		         "proptag=%u", LLU{parent_val}, PR_HIERARCHY_CHANGE_NUM);
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
			"propval=%llu WHERE folder_id=%llu AND proptag=%u",
		         LLU{nt_time}, LLU{parent_val}, PR_HIER_REV);
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
		fid_val = src_val;
		db_engine_proc_dynamic_event(pdb,
			cpid, dynamic_event::move_folder,
			parent_val, dst_val, src_val);
	} else {
		if (!common_util_get_folder_type(pdb->psqlite, src_val, &folder_type))
			return FALSE;
		if (folder_type == FOLDER_SEARCH) {
			if (!folder_copy_search_folder(pdb, cpid,
			    b_guest, username, src_val, dst_val, &fid_val))
				return FALSE;
		} else {
			if (!folder_copy_generic_folder(pdb->psqlite,
			    b_guest, username, src_val, dst_val, &fid_val))
				return FALSE;
		}
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties "
			"SET propval=? WHERE folder_id=%llu AND proptag=%u",
		        LLU{fid_val}, PR_DISPLAY_NAME);
		auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_text(pstmt, 1, str_new, -1, SQLITE_STATIC);
		if (pstmt.step() != SQLITE_DONE)
			return FALSE;
		pstmt.finalize();
		if (folder_type != FOLDER_SEARCH) {
			uint64_t normal_size = 0, fai_size = 0;
			BOOL b_partial = false;
			if (!folder_copy_folder_internal(pdb, account_id,
			    cpid, b_guest, username, src_val, TRUE, TRUE, TRUE,
			    fid_val, &b_partial, &normal_size, &fai_size, nullptr))
				return FALSE;
			if (!cu_adjust_store_size(pdb->psqlite, ADJ_INCREASE,
			    normal_size, fai_size))
				return FALSE;
		}
	}
	auto nt_time = rop_util_current_nttime();
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
		"propval=%llu WHERE folder_id=%llu AND proptag=%u",
	         LLU{nt_time}, LLU{dst_val}, PR_LOCAL_COMMIT_TIME_MAX);
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
		"propval=propval+1 WHERE folder_id=%llu AND "
	         "proptag=%u", LLU{dst_val}, PR_HIERARCHY_CHANGE_NUM);
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folder_properties SET "
		"propval=%llu WHERE folder_id=%llu AND proptag=%u",
	         LLU{nt_time}, LLU{dst_val}, PR_HIER_REV);
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	if (sql_transact.commit() != 0)
		return false;
	db_engine_notify_folder_movecopy(pdb, b_copy,
		dst_val, fid_val, parent_val, src_val);
	return TRUE;
}

BOOL exmdb_server::get_search_criteria(const char *dir, uint64_t folder_id,
    uint32_t *psearch_status, RESTRICTION **pprestriction,
    LONGLONG_ARRAY *pfolder_ids)
{
	char sql_string[256];
	
	if (!exmdb_server::is_private())
		return FALSE;
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto fid_val = rop_util_get_gc_value(folder_id);
	snprintf(sql_string, arsizeof(sql_string), "SELECT is_search,"
				" search_flags, search_criteria FROM "
				"folders WHERE folder_id=%llu", LLU{fid_val});
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW ||
		0 == sqlite3_column_int64(pstmt, 0) ||
		NULL == sqlite3_column_blob(pstmt, 2) ||
		0 == sqlite3_column_bytes(pstmt, 2)) {
		pstmt.finalize();
		*psearch_status = SEARCH_STATUS_NOT_INITIALIZED;
		if (pprestriction != nullptr)
			*pprestriction = NULL;
		if (NULL != pfolder_ids) {
			pfolder_ids->count = 0;
			pfolder_ids->pll = NULL;
		}
		return TRUE;
	}
	uint32_t search_flags = pstmt.col_uint64(1);
	if (NULL != pprestriction) {
		EXT_PULL ext_pull;
		ext_pull.init(sqlite3_column_blob(pstmt, 2),
			sqlite3_column_bytes(pstmt, 2), common_util_alloc, 0);
		*pprestriction = cu_alloc<RESTRICTION>();
		if (*pprestriction == nullptr ||
		    ext_pull.g_restriction(*pprestriction) != EXT_ERR_SUCCESS)
			return FALSE;
	}
	pstmt.finalize();
	if (pfolder_ids != nullptr &&
	    !common_util_load_search_scopes(pdb->psqlite, fid_val, pfolder_ids))
		return FALSE;
	pdb.reset();
	if (pfolder_ids != nullptr)
		for (size_t i = 0; i < pfolder_ids->count; ++i)
			pfolder_ids->pll[i] = rop_util_make_eid_ex(
								1, pfolder_ids->pll[i]);
	*psearch_status = 0;
	if (db_engine_check_populating(dir, fid_val))
		*psearch_status |= SEARCH_REBUILD;
	if (search_flags & STATIC_SEARCH) {
		if (search_flags & RESTART_SEARCH)
			*psearch_status |= SEARCH_COMPLETE;
	} else {
		if (search_flags & RESTART_SEARCH)
			*psearch_status |= SEARCH_RUNNING;
	}
	if (search_flags & RECURSIVE_SEARCH)
		*psearch_status |= SEARCH_RECURSIVE;
	if (search_flags & CONTENT_INDEXED_SEARCH)
		*psearch_status |= CI_TOTALLY;
	else
		*psearch_status |= TWIR_TOTALLY;
	return TRUE;
}

static BOOL folder_clear_search_folder(db_item_ptr &pdb,
    cpid_t cpid, uint64_t folder_id)
{
	char sql_string[128];
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT message_id FROM "
	          "search_result WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW)
		db_engine_proc_dynamic_event(pdb, cpid,
			dynamic_event::del_msg, folder_id,
			sqlite3_column_int64(pstmt, 0), 0);
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "DELETE FROM search_result"
	        " WHERE folder_id=%llu", LLU{folder_id});
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	return TRUE;
}

BOOL exmdb_server::set_search_criteria(const char *dir, cpid_t cpid,
    uint64_t folder_id, uint32_t search_flags, const RESTRICTION *prestriction,
    const LONGLONG_ARRAY *pfolder_ids, BOOL *pb_result) try
{
	EXT_PULL ext_pull;
	EXT_PUSH ext_push;
	char sql_string[128];
	static constexpr size_t buff_size = 0x8000;
	auto tmp_buff = std::make_unique<uint8_t[]>(buff_size);
	LONGLONG_ARRAY folder_ids{};
	
	if (!exmdb_server::is_private())
		return FALSE;
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto fid_val = rop_util_get_gc_value(folder_id);
	if (pfolder_ids->count > 0) {
		for (size_t i = 0; i < pfolder_ids->count; ++i) {
			auto fid_val1 = rop_util_get_gc_value(pfolder_ids->pll[i]);
			BOOL b_included = false;
			if (!common_util_check_descendant(pdb->psqlite, fid_val,
			    fid_val1, &b_included))
				return FALSE;	
			if (b_included) {
				*pb_result = FALSE;
				return TRUE;
			}
		}
	}
	snprintf(sql_string, arsizeof(sql_string), "SELECT search_flags FROM"
	          " folders WHERE folder_id=%llu", LLU{fid_val});
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	uint32_t original_flags = pstmt.col_uint64(0);
	pstmt.finalize();
	auto sql_transact = gx_sql_begin_trans(pdb->psqlite);
	if (!sql_transact)
		return false;
	snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET search_flags=%u "
	        "WHERE folder_id=%llu", search_flags, LLU{fid_val});
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return false;
	if (NULL != prestriction) {
		if (!ext_push.init(tmp_buff.get(), buff_size, 0) ||
		    ext_push.p_restriction(*prestriction) != EXT_ERR_SUCCESS)
			return false;
		snprintf(sql_string, arsizeof(sql_string), "UPDATE folders SET "
		          "search_criteria=? WHERE folder_id=%llu", LLU{fid_val});
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return false;
		sqlite3_bind_blob(pstmt, 1, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
		if (pstmt.step() != SQLITE_DONE)
			return false;
		pstmt.finalize();
	} else {
		if (original_flags == 0)
			return false;
		prestriction = cu_alloc<RESTRICTION>();
		if (prestriction == nullptr)
			return false;
		snprintf(sql_string, arsizeof(sql_string), "SELECT search_criteria FROM"
		          " folders WHERE folder_id=%llu", LLU{fid_val});
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return false;
		if (pstmt.step() != SQLITE_ROW)
			return false;
		ext_pull.init(sqlite3_column_blob(pstmt, 0),
			sqlite3_column_bytes(pstmt, 0), common_util_alloc, 0);
		if (ext_pull.g_restriction(deconst(prestriction)) != EXT_ERR_SUCCESS)
			return false;
		pstmt.finalize();
	}
	if (pfolder_ids->count > 0) {
		folder_ids.count = 0;
		folder_ids.pll = cu_alloc<uint64_t>(pfolder_ids->count);
		if (folder_ids.pll == nullptr)
			return false;
		snprintf(sql_string, arsizeof(sql_string), "DELETE FROM search_scopes"
		        " WHERE folder_id=%llu", LLU{fid_val});
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return false;
		snprintf(sql_string, arsizeof(sql_string), "INSERT INTO "
		          "search_scopes VALUES (%llu, ?)", LLU{fid_val});
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return false;
		auto pstmt1 = gx_sql_prep(pdb->psqlite, "SELECT COUNT(*) "
		              "FROM folders WHERE folder_id=?");
		if (pstmt1 == nullptr)
			return false;
		for (size_t i = 0; i < pfolder_ids->count; ++i) {
			folder_ids.pll[folder_ids.count] =
				rop_util_get_gc_value(pfolder_ids->pll[i]);
			sqlite3_bind_int64(pstmt1, 1, folder_ids.pll[folder_ids.count]);
			if (pstmt1.step() != SQLITE_ROW)
				return false;
			if (0 == sqlite3_column_int64(pstmt1, 0)) {
				sqlite3_reset(pstmt);
				sqlite3_reset(pstmt1);
				continue;
			}
			sqlite3_bind_int64(pstmt, 1, folder_ids.pll[folder_ids.count]);
			if (pstmt.step() != SQLITE_DONE)
				return false;
			sqlite3_reset(pstmt);
			sqlite3_reset(pstmt1);
			folder_ids.count ++;
		}
	} else {
		if (original_flags == 0 ||
		    !common_util_load_search_scopes(pdb->psqlite, fid_val, &folder_ids))
			return false;
	}
	BOOL b_recursive = (search_flags & RECURSIVE_SEARCH) ? TRUE : false;
	BOOL b_update = false, b_populate = false;
	if (!folder_clear_search_folder(pdb, cpid, fid_val))
		return false;
	if (sql_transact.commit() != 0)
		return false;
	if (search_flags & RESTART_SEARCH) {
		b_populate = TRUE;
		if (!(search_flags & STATIC_SEARCH))
			b_update = TRUE;
	}
	if (b_update)
		db_engine_update_dynamic(pdb, fid_val,
			search_flags, prestriction, &folder_ids);
	else
		db_engine_delete_dynamic(pdb, fid_val);

	pdb.reset();
	if (b_populate && !db_engine_enqueue_populating_criteria(dir,
	    cpid, fid_val, b_recursive, prestriction, &folder_ids))
		return FALSE;
	*pb_result = TRUE;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1161: ENOMEM");
	return false;
}

BOOL exmdb_server::get_folder_perm(const char *dir,
	uint64_t folder_id, const char *username,
	uint32_t *ppermission)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	return cu_get_folder_permission(pdb->psqlite,
	       rop_util_get_gc_value(folder_id), username, ppermission);
}

BOOL exmdb_server::empty_folder_permission(const char *dir, uint64_t folder_id)
{
	char sql_string[1024];
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	snprintf(sql_string, 1024, "DELETE FROM permissions WHERE"
	         " folder_id=%llu", LLU{rop_util_get_gc_value(folder_id)});
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	return TRUE;
}

static bool ufp_add(const TPROPVAL_ARRAY &propvals, db_item_ptr &pdb,
    bool b_freebusy, uint64_t fid_val, xstmt &pstmt)
{
	auto bin = propvals.get<const BINARY>(PR_ENTRYID);
	char username[UADDR_SIZE];
	if (bin != nullptr) {
		if (!common_util_addressbook_entryid_to_username(bin, username, std::size(username)))
			return true;
	} else {
		auto str = propvals.get<const char>(PR_SMTP_ADDRESS);
		if (str == nullptr)
			return true;
		gx_strlcpy(username, str, std::size(username));
	}
	auto num = propvals.get<const uint32_t>(PR_MEMBER_RIGHTS);
	if (num == nullptr)
		return true;
	auto permission = *num;
	if (permission & frightsReadAny)
		permission |= frightsVisible;
	if (permission & frightsOwner)
		permission |= frightsVisible | frightsContact;
	if (permission & frightsDeleteAny)
		permission |= frightsDeleteOwned;
	if (permission & frightsEditAny)
		permission |= frightsEditOwned;
	if (!b_freebusy || !exmdb_server::is_private() ||
	    fid_val != PRIVATE_FID_CALENDAR)
		permission &= ~(frightsFreeBusySimple | frightsFreeBusyDetailed);
	if (NULL == pstmt) {
		char sql_string[128];
		snprintf(sql_string, arsizeof(sql_string), "INSERT INTO permissions"
					" (folder_id, username, permission) VALUES"
					" (%llu, ?, ?)", LLU{fid_val});
		pstmt = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt == nullptr)
			return false;
	}
	sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 2, permission);
	if (pstmt.step() != SQLITE_DONE)
		return false;
	sqlite3_reset(pstmt);
	return true;
}

static bool ufp_modify(const TPROPVAL_ARRAY &propvals, db_item_ptr &pdb,
    bool b_freebusy, uint64_t fid_val)
{
	static constexpr uint64_t DEFAULT = 0, ANONYMOUS = UINT64_MAX;
	auto lnum = propvals.get<const uint64_t>(PR_MEMBER_ID);
	if (lnum == nullptr)
		return true;
	auto member_id = *lnum;
	if (member_id == DEFAULT || member_id == ANONYMOUS) {
		char sql_string[128];
		snprintf(sql_string, arsizeof(sql_string), "SELECT member_id "
			"FROM permissions WHERE folder_id=%llu AND "
			"username=?", LLU{fid_val});
		auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt1 == nullptr)
			return false;
		sqlite3_bind_text(pstmt1, 1, member_id == DEFAULT ? "default" : "", -1, SQLITE_STATIC);
		if (pstmt1.step() != SQLITE_ROW) {
			pstmt1.finalize();
			snprintf(sql_string, arsizeof(sql_string), "SELECT config_value "
				"FROM configurations WHERE config_id=%d",
				member_id == DEFAULT ? CONFIG_ID_DEFAULT_PERMISSION : CONFIG_ID_ANONYMOUS_PERMISSION);
			pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
			if (pstmt1 == nullptr)
				return false;
			uint32_t permission = rightsNone;
			if (pstmt1.step() == SQLITE_ROW)
				permission = sqlite3_column_int64(pstmt1, 0);
			pstmt1.finalize();
			snprintf(sql_string, arsizeof(sql_string), "INSERT INTO permissions"
						" (folder_id, username, permission) VALUES"
						" (%llu, ?, ?)", LLU{fid_val});
			pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
			if (pstmt1 == nullptr)
				return false;
			sqlite3_bind_text(pstmt1, 1, "default", -1, SQLITE_STATIC);
			sqlite3_bind_int64(pstmt1, 2, permission);
			if (pstmt1.step() != SQLITE_DONE)
				return false;
			member_id = sqlite3_last_insert_rowid(pdb->psqlite);
		} else {
			member_id = sqlite3_column_int64(pstmt1, 0);
		}
		pstmt1.finalize();
	}
	char sql_string[128];
	snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id FROM"
		  " permissions WHERE member_id=%llu", LLU{member_id});
	auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt1 == nullptr)
		return false;
	if (pstmt1.step() != SQLITE_ROW ||
	    gx_sql_col_uint64(pstmt1, 0) != fid_val)
		return true;
	pstmt1.finalize();
	auto num = propvals.get<const uint32_t>(PR_MEMBER_RIGHTS);
	if (num == nullptr)
		return true;
	auto permission = *num;
	if (permission & frightsReadAny)
		permission |= frightsVisible;
	if (permission & frightsOwner)
		permission |= frightsVisible | frightsContact;
	if (permission & frightsDeleteAny)
		permission |= frightsDeleteOwned;
	if (permission & frightsEditAny)
		permission |= frightsEditOwned;
	if (!b_freebusy || !exmdb_server::is_private() ||
	    fid_val != PRIVATE_FID_CALENDAR)
		permission &= ~(frightsFreeBusySimple | frightsFreeBusyDetailed);
	snprintf(sql_string, arsizeof(sql_string), "UPDATE permissions SET permission=%u"
		" WHERE member_id=%llu", permission, LLU{member_id});
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return false;
	return true;
}

static bool ufp_remove(const TPROPVAL_ARRAY &propvals, db_item_ptr &pdb,
    uint64_t fid_val)
{
	auto member_id = propvals.get<const uint64_t>(PR_MEMBER_ID);
	if (member_id == nullptr)
		return true;
	if (*member_id == 0) {
		char sql_string[128];
		snprintf(sql_string, arsizeof(sql_string), "DELETE FROM permissions WHERE "
			"folder_id=%llu and username=\"default\"", LLU{fid_val});
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return false;
	} else if (*member_id == UINT64_MAX) {
		char sql_string[128];
		snprintf(sql_string, arsizeof(sql_string), "DELETE FROM permissions WHERE "
			"folder_id=%llu and username=\"\"", LLU{fid_val});
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return false;
	} else {
		char sql_string[128];
		snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id FROM"
			  " permissions WHERE member_id=%llu", LLU{*member_id});
		auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
		if (pstmt1 == nullptr)
			return false;
		if (pstmt1.step() != SQLITE_ROW ||
		    gx_sql_col_uint64(pstmt1, 0) != fid_val)
			return true;
		pstmt1.finalize();
		snprintf(sql_string, arsizeof(sql_string), "DELETE FROM permissions"
			" WHERE member_id=%llu", LLU{*member_id});
		if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
			return false;
	}
	return true;
}

/* after updating the database, update the table too! */
BOOL exmdb_server::update_folder_permission(const char *dir,
	uint64_t folder_id, BOOL b_freebusy,
	uint16_t count, const PERMISSION_DATA *prow)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto fid_val = rop_util_get_gc_value(folder_id);
	xstmt pstmt;
	auto sql_transact = gx_sql_begin_trans(pdb->psqlite);
	if (!sql_transact)
		return false;
	for (unsigned int i = 0; i < count; ++i) {
		bool ret = true;
		switch (prow[i].flags) {
		case ROW_ADD:
			ret = ufp_add(prow[i].propvals, pdb, b_freebusy, fid_val, pstmt);
			break;
		case ROW_MODIFY:
			ret = ufp_modify(prow[i].propvals, pdb, b_freebusy, fid_val);
			break;
		case ROW_REMOVE:
			ret = ufp_remove(prow[i].propvals, pdb, fid_val);
			break;
		}
		if (!ret)
			return false;
	}
	pstmt.finalize();
	return sql_transact.commit() == 0 ? TRUE : false;
}

BOOL exmdb_server::empty_folder_rule(const char *dir, uint64_t folder_id)
{
	char sql_string[1024];
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	snprintf(sql_string, 1024, "DELETE FROM rules WHERE "
	         "folder_id=%llu", LLU{rop_util_get_gc_value(folder_id)});
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	return TRUE;
}

/* after updating the database, update the table too! */
BOOL exmdb_server::update_folder_rule(const char *dir, uint64_t folder_id,
    uint16_t count, const RULE_DATA *prow, BOOL *pb_exceed) try
{
	int i;
	EXT_PUSH ext_push;
	char sql_string[256];
	static constexpr size_t bigbufsiz = 256 << 10;
	auto action_buff = std::make_unique<char[]>(bigbufsiz);
	auto condition_buff = std::make_unique<char[]>(bigbufsiz);
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto fid_val = rop_util_get_gc_value(folder_id);
	snprintf(sql_string, arsizeof(sql_string), "SELECT count(*) "
	          "FROM rules WHERE folder_id=%llu", LLU{fid_val});
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	size_t rule_count = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	*pb_exceed = FALSE;
	auto sql_transact = gx_sql_begin_trans(pdb->psqlite);
	if (!sql_transact)
		return false;
	for (i=0; i<count; i++) {
		switch (prow[i].flags) {
		case ROW_ADD: {
			if (rule_count >= g_max_rule_num) {
				*pb_exceed = TRUE;
				return TRUE;
			}
			auto pname = prow[i].propvals.get<const char>(PR_RULE_NAME);
			auto pprovider = prow[i].propvals.get<const char>(PR_RULE_PROVIDER);
			if (pprovider == nullptr)
				continue;
			uint32_t seq_id;
			auto num = prow[i].propvals.get<const uint32_t>(PR_RULE_SEQUENCE);
			if (num == nullptr) {
				snprintf(sql_string, arsizeof(sql_string), "SELECT max(sequence)"
				          " FROM rules WHERE folder_id=%llu", LLU{fid_val});
				auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt1 == nullptr)
					continue;
				seq_id = pstmt1.step() != SQLITE_ROW ? 0 :
				         sqlite3_column_int64(pstmt1, 0);
				pstmt1.finalize();
				seq_id ++;
			} else {
				seq_id = *num;
			}
			num = prow[i].propvals.get<uint32_t>(PR_RULE_STATE);
			uint32_t state = num == nullptr ? 0 : *num;
			auto plevel = prow[i].propvals.get<const uint32_t>(PR_RULE_LEVEL);
			auto puser_flags = prow[i].propvals.get<const uint32_t>(PR_RULE_USER_FLAGS);
			auto pprovider_bin = prow[i].propvals.get<const BINARY>(PR_RULE_PROVIDER_DATA);
			auto pcondition = prow[i].propvals.get<RESTRICTION>(PR_RULE_CONDITION);
			if (pcondition == nullptr)
				continue;
			if (!ext_push.init(condition_buff.get(), bigbufsiz, 0) ||
			    ext_push.p_restriction(*pcondition) != EXT_ERR_SUCCESS)
				return false;
			int condition_len = ext_push.m_offset;
			auto paction = prow[i].propvals.get<RULE_ACTIONS>(PR_RULE_ACTIONS);
			if (paction == nullptr)
				continue;
			if (!ext_push.init(action_buff.get(), bigbufsiz, 0) ||
			    ext_push.p_rule_actions(*paction) != EXT_ERR_SUCCESS)
				return false;
			int action_len = ext_push.m_offset;
			if (NULL == pstmt) {
				snprintf(sql_string, arsizeof(sql_string), "INSERT INTO rules "
					"(name, provider, sequence, state, level, user_flags,"
					" provider_data, condition, actions, folder_id) VALUES"
					" (?, ?, ?, ?, ?, ?, ?, ?, ?, %llu)", LLU{fid_val});
				pstmt = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt == nullptr)
					return false;
			}
			if (pname != nullptr)
				sqlite3_bind_text(pstmt, 1, pname, -1, SQLITE_STATIC);
			else
				sqlite3_bind_null(pstmt, 1);
			sqlite3_bind_text(pstmt, 2, pprovider, -1, SQLITE_STATIC);
			sqlite3_bind_int64(pstmt, 3, seq_id);
			sqlite3_bind_int64(pstmt, 4, state);
			sqlite3_bind_int64(pstmt, 5, plevel != nullptr ? *plevel : 0);
			if (puser_flags != nullptr)
				sqlite3_bind_int64(pstmt, 6, *puser_flags);
			else
				sqlite3_bind_null(pstmt, 6);
			if (pprovider_bin != nullptr && pprovider_bin->cb > 0)
				sqlite3_bind_blob(pstmt, 7, pprovider_bin->pb,
					pprovider_bin->cb, SQLITE_STATIC);
			else
				sqlite3_bind_null(pstmt, 7);
			sqlite3_bind_blob(pstmt, 8, condition_buff.get(),
				condition_len, SQLITE_STATIC);
			sqlite3_bind_blob(pstmt, 9, action_buff.get(),
				action_len, SQLITE_STATIC);
			if (pstmt.step() != SQLITE_DONE)
				return false;
			sqlite3_reset(pstmt);
			break;
		}
		case ROW_MODIFY: {
			auto lnum = prow[i].propvals.get<const uint64_t>(PR_RULE_ID);
			if (lnum == nullptr)
				continue;
			auto rule_id = rop_util_get_gc_value(*lnum);
			snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id "
			          "FROM rules WHERE rule_id=%llu", LLU{rule_id});
			auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
			if (pstmt1 == nullptr)
				return false;
			if (pstmt1.step() != SQLITE_ROW ||
			    gx_sql_col_uint64(pstmt1, 0) != fid_val)
				continue;
			pstmt1.finalize();
			auto pprovider = prow[i].propvals.get<const char>(PR_RULE_PROVIDER);
			if (NULL != pprovider) {
				snprintf(sql_string, arsizeof(sql_string), "UPDATE rules SET"
				          " provider=? WHERE rule_id=%llu", LLU{rule_id});
				pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt1 == nullptr)
					return false;
				sqlite3_bind_text(pstmt1, 1, pprovider, -1, SQLITE_STATIC);
				if (pstmt1.step() != SQLITE_DONE)
					return false;
				pstmt1.finalize();
			}
			auto num = prow[i].propvals.get<const uint32_t>(PR_RULE_SEQUENCE);
			if (num != nullptr) {
				snprintf(sql_string, arsizeof(sql_string), "UPDATE rules SET sequence=%u"
				        " WHERE rule_id=%llu", *num, LLU{rule_id});
				if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
					return false;
			}
			num = prow[i].propvals.get<uint32_t>(PR_RULE_STATE);
			if (num != nullptr) {
				snprintf(sql_string, arsizeof(sql_string), "UPDATE rules SET state=%u"
				        " WHERE rule_id=%llu", *num, LLU{rule_id});
				if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
					return false;
			}
			auto plevel = prow[i].propvals.get<uint32_t>(PR_RULE_LEVEL);
			if (NULL != plevel) {
				snprintf(sql_string, arsizeof(sql_string), "UPDATE rules SET level=%u"
				        " WHERE rule_id=%llu", *plevel, LLU{rule_id});
				if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
					return false;
			}
			auto puser_flags = prow[i].propvals.get<uint32_t>(PR_RULE_USER_FLAGS);
			if (NULL != puser_flags) {
				snprintf(sql_string, arsizeof(sql_string), "UPDATE rules SET user_flags=%u"
				        " WHERE rule_id=%llu", *puser_flags, LLU{rule_id});
				if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
					return false;
			}
			auto pprovider_bin = prow[i].propvals.get<BINARY>(PR_RULE_PROVIDER_DATA);
			if (NULL != pprovider_bin) {
				snprintf(sql_string, arsizeof(sql_string), "UPDATE rules SET "
				          "provider_data=? WHERE rule_id=%llu", LLU{rule_id});
				pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt1 == nullptr)
					return false;
				sqlite3_bind_blob(pstmt1, 1, pprovider_bin->pb,
						pprovider_bin->cb, SQLITE_STATIC);
				if (pstmt1.step() != SQLITE_DONE)
					return false;
				pstmt1.finalize();
			}
			auto pcondition = prow[i].propvals.get<RESTRICTION>(PR_RULE_CONDITION);
			if (NULL != pcondition) {
				if (!ext_push.init(condition_buff.get(), bigbufsiz, 0) ||
				    ext_push.p_restriction(*pcondition) != EXT_ERR_SUCCESS)
					return false;
				int condition_len = ext_push.m_offset;
				snprintf(sql_string, arsizeof(sql_string), "UPDATE rules SET "
				          "condition=? WHERE rule_id=%llu", LLU{rule_id});
				pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt1 == nullptr)
					return false;
				sqlite3_bind_blob(pstmt1, 1, condition_buff.get(),
						condition_len, SQLITE_STATIC);
				if (pstmt1.step() != SQLITE_DONE)
					return false;
				pstmt1.finalize();
			}
			auto paction = prow[i].propvals.get<RULE_ACTIONS>(PR_RULE_ACTIONS);
			if (NULL != paction) {
				if (!ext_push.init(action_buff.get(), bigbufsiz, 0) ||
				    ext_push.p_rule_actions(*paction) != EXT_ERR_SUCCESS)
					return false;
				int action_len = ext_push.m_offset;
				snprintf(sql_string, arsizeof(sql_string), "UPDATE rules SET "
				          "actions=? WHERE rule_id=%llu", LLU{rule_id});
				pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
				if (pstmt1 == nullptr)
					return false;
				sqlite3_bind_blob(pstmt1, 1, action_buff.get(),
						action_len, SQLITE_STATIC);
				if (pstmt1.step() != SQLITE_DONE)
					return false;
				pstmt1.finalize();
			}
			break;
		}
		case ROW_REMOVE: {
			auto lnum = prow[i].propvals.get<const uint64_t>(PR_RULE_ID);
			if (lnum == nullptr)
				continue;
			auto rule_id = rop_util_get_gc_value(*lnum);
			snprintf(sql_string, arsizeof(sql_string), "SELECT folder_id "
			          "FROM rules WHERE rule_id=%llu", LLU{rule_id});
			auto pstmt1 = gx_sql_prep(pdb->psqlite, sql_string);
			if (pstmt1 == nullptr)
				return false;
			if (pstmt1.step() != SQLITE_ROW ||
			    gx_sql_col_uint64(pstmt1, 0) != fid_val)
				continue;
			pstmt1.finalize();
			snprintf(sql_string, arsizeof(sql_string), "DELETE FROM rules"
			        " WHERE rule_id=%llu", LLU{rule_id});
			if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
				return false;
			break;
		}
		}
	}
	return sql_transact.commit() == 0 ? TRUE : false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1199: ENOMEM");
	return false;
}

/* public only */
BOOL exmdb_server::get_public_folder_unread_count(const char *dir,
	const char *username, uint64_t folder_id, uint32_t *pcount)
{
	if (exmdb_server::is_private())
		return FALSE;
	if (exmdb_pf_read_states == 0) {
		*pcount = 0;
		return TRUE;
	}
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	exmdb_server::set_public_username(username);
	*pcount = cu_folder_unread_count(pdb->psqlite, rop_util_get_gc_value(folder_id));
	exmdb_server::set_public_username(nullptr);
	return TRUE;
	
}

/**
 * @normal_size:	size that the caller should subtract from store size
 * @fai_size:		size that the caller should subtract from store size/FAI
 * @msg_count:		indicator for the caller to update the folder commit time
 */
static bool folder_purge_softdel(db_item_ptr &db, cpid_t cpid,
    const char *username, uint64_t folder_id, unsigned int del_flags,
    bool *partial, uint64_t *normal_size, uint64_t *fai_size,
    uint32_t *msg_count, uint32_t *fld_count, mapitime_t cutoff)
{
	uint32_t folder_type = 0;
	if (!common_util_get_folder_type(db->psqlite, folder_id, &folder_type))
		return false;
	if (folder_type == FOLDER_SEARCH)
		/* Search folders do not have real messages */
		return true;

	auto ret = need_msg_perm_check(db->psqlite, username, folder_id);
	if (ret < 0)
		return false;
	auto b_check = ret > 0;
	if (!b_check) {
		/* With enough permissions, a bulk delete is feasible. */
		char qstr[294];
		snprintf(qstr, sizeof(qstr),
		         "SELECT m.is_associated, COUNT(m.message_id), SUM(m.message_size) "
		         "FROM messages AS m INNER JOIN message_properties AS mp "
		         "ON m.message_id=mp.message_id AND m.is_deleted=1 AND m.parent_fid=%llu AND "
		         "mp.proptag=%u AND mp.propval<=%llu GROUP BY m.is_associated",
		         LLU{folder_id}, PR_LAST_MODIFICATION_TIME, LLU{cutoff});
		if (gx_sql_exec(db->psqlite, qstr) != SQLITE_OK)
			return false;
		auto stm = gx_sql_prep(db->psqlite, qstr);
		if (stm == nullptr)
			return false;
		while (stm.step() == SQLITE_ROW) {
			auto assoc = stm.col_uint64(0);
			auto count = stm.col_uint64(1);
			auto size  = stm.col_uint64(2);
			if (!assoc && normal_size != nullptr)
				*normal_size += size;
			else if (assoc && fai_size != nullptr)
				*fai_size += size;
			if (msg_count != nullptr)
				*msg_count += count;
		}
		snprintf(qstr, sizeof(qstr), "DELETE FROM messages "
		         "WHERE message_id IN (SELECT m.message_id "
		         "FROM messages AS m INNER JOIN message_properties AS mp "
		         "ON m.message_id=mp.message_id AND m.is_deleted=1 AND m.parent_fid=%llu AND "
		         "mp.proptag=%u AND mp.propval<=%llu)",
			 LLU{folder_id}, PR_LAST_MODIFICATION_TIME, LLU{cutoff});
		if (gx_sql_exec(db->psqlite, qstr) != SQLITE_OK)
			return false;
	} else {
		char qstr[257];
		snprintf(qstr, sizeof(qstr), "SELECT m.message_id, m.message_size, m.is_associated "
		         "FROM messages AS m INNER JOIN message_properties AS mp "
		         "ON m.message_id=mp.message_id AND m.is_deleted=1 AND m.parent_fid=%llu AND "
		         "mp.proptag=%u AND mp.propval<=%llu",
			 LLU{folder_id}, PR_LAST_MODIFICATION_TIME, LLU{cutoff});
		auto stmt = gx_sql_prep(db->psqlite, qstr);
		if (stmt == nullptr)
			return false;
		while (stmt.step() == SQLITE_ROW) {
			auto msgid = stmt.col_uint64(0);
			ret = have_delete_perm(db->psqlite, username, folder_id, msgid);
			if (ret < 0)
				return false;
			if (ret == 0) {
				*partial = true;
				continue;
			}
			bool assoc = stmt.col_uint64(2);
			if (msg_count != nullptr)
				++*msg_count;
			if (!assoc && normal_size != nullptr)
				*normal_size += stmt.col_uint64(1);
			else if (assoc && fai_size != nullptr)
				*fai_size += stmt.col_uint64(1);
			snprintf(qstr, sizeof(qstr), "DELETE FROM messages WHERE message_id=%llu", LLU{msgid});
			if (gx_sql_exec(db->psqlite, qstr) != SQLITE_OK)
				return false;
		}
	}

	if (!(del_flags & DEL_FOLDERS))
		return true;

	char qstr[80];
	snprintf(qstr, sizeof(qstr), "SELECT folder_id,"
	         " is_deleted FROM folders WHERE parent_id=%llu", LLU{folder_id});
	auto stm = gx_sql_prep(db->psqlite, qstr);
	if (stm == nullptr)
		return FALSE;
	while (stm.step() == SQLITE_ROW) {
		auto subfld = stm.col_uint64(0);
		bool sub_partial = false;
		if (!folder_purge_softdel(db, cpid, username, subfld,
		    del_flags, &sub_partial, normal_size, fai_size,
		    msg_count, fld_count, cutoff))
			return false;
		if (sub_partial) {
			*partial = true;
			continue;
		}
		/*
		 * Try to delete folder itself if permissible. Do this last,
		 * just like Unix permissions act in a filesystem (deep
		 * directory with no perms can block toplevel dir deletion).
		 */
		bool is_del = stm.col_int64(1);
		if (!is_del)
			continue;
		ret = have_delete_perm(db->psqlite, username, subfld);
		if (ret < 0)
			return false;
		if (ret == 0) {
			*partial = true;
			continue;
		}
		if (sub_partial) {
			*partial = true;
			continue;
		}
		if (fld_count != nullptr)
			++*fld_count;
		snprintf(qstr, sizeof(qstr), "DELETE FROM folders "
		         "WHERE folder_id=%llu", LLU{subfld});
		if (gx_sql_exec(db->psqlite, qstr) != SQLITE_OK)
			return false;
		db_engine_notify_folder_deletion(db, folder_id, subfld);
	}
	return true;
}

/**
 * @folder_id:	use 0 to scan entire store
 * @age:	soft-deleted items older than this age
 */
BOOL exmdb_server::purge_softdelete(const char *dir, const char *username,
    uint64_t folder_id, uint32_t del_flags, mapitime_t cutoff)
{
	del_flags &= DEL_FOLDERS;

	auto db = db_engine_get_db(dir);
	if (db == nullptr || db->psqlite == nullptr)
		return false;
	auto fid_val = rop_util_get_gc_value(folder_id);
	auto xact = gx_sql_begin_trans(db->psqlite);
	if (!xact)
		return false;
	uint64_t normal_size = 0, fai_size = 0;
	uint32_t msg_count = 0, fld_count = 0;
	bool partial = false;
	if (!folder_purge_softdel(db, CP_ACP, username, fid_val, del_flags,
	    &partial, &normal_size, &fai_size, &msg_count, &fld_count, cutoff))
		return false;

	char qstr[116];
	if (msg_count > 0) {
		snprintf(qstr, sizeof(qstr), "UPDATE folder_properties SET "
		         "propval=propval+%u WHERE folder_id=%llu AND "
		         "proptag=%u", msg_count, LLU{fid_val}, PR_DELETED_COUNT_TOTAL);
		if (gx_sql_exec(db->psqlite, qstr) != SQLITE_OK)
			return false;
	}
	if (fld_count > 0) {
		snprintf(qstr, sizeof(qstr), "UPDATE folder_properties SET "
		         "propval=propval+%u WHERE folder_id=%llu AND "
		         "proptag=%u", fld_count, LLU{fid_val}, PR_DELETED_FOLDER_COUNT);
		if (gx_sql_exec(db->psqlite, qstr) != SQLITE_OK)
			return false;
		snprintf(qstr, sizeof(qstr), "UPDATE folder_properties SET "
		         "propval=propval+1 WHERE folder_id=%llu AND "
		         "proptag=%u", LLU{fid_val}, PR_HIERARCHY_CHANGE_NUM);
		if (gx_sql_exec(db->psqlite, qstr) != SQLITE_OK)
			return false;
		snprintf(qstr, sizeof(qstr), "UPDATE folder_properties SET "
		         "propval=%llu WHERE folder_id=%llu AND proptag=%u",
		         LLU{rop_util_current_nttime()}, LLU{fid_val}, PR_HIER_REV);
		if (gx_sql_exec(db->psqlite, qstr) != SQLITE_OK)
			return false;
	}
	if (msg_count > 0 || fld_count > 0) {
		snprintf(qstr, sizeof(qstr), "UPDATE folder_properties SET "
		         "propval=%llu WHERE folder_id=%llu AND proptag=%u",
		         LLU{rop_util_current_nttime()}, LLU{fid_val},
		         PR_LOCAL_COMMIT_TIME_MAX);
		if (gx_sql_exec(db->psqlite, qstr) != SQLITE_OK)
			return false;
	}
	if (!cu_adjust_store_size(db->psqlite, ADJ_DECREASE, normal_size, fai_size))
		return false;
	return xact.commit() == 0 ? TRUE : false;
}
