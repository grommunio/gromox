// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <list>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <fmt/core.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vmime/message.hpp>
#include <gromox/cryptoutil.hpp>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_provider_client.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/proptag_array.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_common.h>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "bounce_producer.hpp"
#include "db_engine.hpp"
#include "parser.hpp"
#define MIN_BATCH_MESSAGE_NUM 20

using XUI = unsigned int;
using LLU = unsigned long long;
using namespace std::string_literals;
using namespace gromox;

namespace {

struct rule_node {
	int32_t sequence = 0;
	uint32_t state = 0;
	uint64_t id = 0;
	std::string provider;
	bool extended = false;

	bool operator<(const rule_node &o) const { return sequence < o.sequence; }
};

struct DAM_NODE {
	uint64_t rule_id = 0, folder_id = 0, message_id = 0;
	const char *provider = nullptr;
	const ACTION_BLOCK *pblock = nullptr;
};

struct message_node {
	uint64_t folder_id = 0, message_id = 0;
};

struct rulexec_in {
	const char *ev_from = nullptr, *ev_to = nullptr;
	cpid_t cpid = CP_ACP;
	bool oof = false;
	sqlite3 *sqlite = nullptr;
	uint64_t folder_id = 0, message_id = 0;
	std::optional<Json::Value> digest;
};

struct seen_list {
	std::vector<uint64_t> fld;
	std::vector<message_node> msg;
};

}

static ec_error_t message_rule_new_message(const rulexec_in &, seen_list &);

static constexpr uint8_t fake_true = true;
static constexpr uint32_t dummy_rcpttype = MAPI_TO;
static constexpr char dummy_addrtype[] = "NONE", dummy_string[] = "";

/* Caution: If a message is soft deleted from a public folder,
	it also should be removed from read_states! if someone's
	read stat is "unread", the item of this user should be
	removed from read_states */

#if defined(FMT_VERSION) && FMT_VERSION >= 90000
namespace {
unsigned int format_as(proptag_t x) { return x; }
}
#endif

/**
 * @username:   Used for permission checks (SFOD & generic folders).
 *
 * Can be used when submitting message.
 */
BOOL exmdb_server::movecopy_message(const char *dir, cpid_t cpid,
    uint64_t message_id, uint64_t dst_fid, uint64_t dst_id, BOOL b_move,
    BOOL *pb_result)
{
	*pb_result = false;
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	if (!b_move &&
	    cu_check_msgsize_overflow(pdb->psqlite, PR_STORAGE_QUOTA_LIMIT) &&
	    common_util_check_msgcnt_overflow(pdb->psqlite))
		return TRUE;		
	auto mid_val = rop_util_get_gc_value(message_id);
	auto fid_val = rop_util_get_gc_value(dst_fid);
	auto dst_val = rop_util_get_gc_value(dst_id);
	BOOL b_result = false;
	if (!common_util_check_allocated_eid(pdb->psqlite, dst_val, &b_result))
		return FALSE;
	if (!b_result)
		return TRUE;
	char sql_string[256];
	snprintf(sql_string, std::size(sql_string), "SELECT message_id "
	          "FROM messages WHERE message_id=%llu", LLU{dst_val});
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() == SQLITE_ROW)
		return TRUE;
	pstmt.finalize();
	snprintf(sql_string, std::size(sql_string), "SELECT parent_fid, is_associated"
	          " FROM messages WHERE message_id=%llu", LLU{mid_val});
	pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW)
		return TRUE;
	uint64_t parent_fid = sqlite3_column_int64(pstmt, 0);
	bool is_associated = sqlite3_column_int64(pstmt, 1);
	pstmt.finalize();

	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	if (b_move)
		pdb->proc_dynamic_event(cpid, dynamic_event::del_msg,
			parent_fid, mid_val, 0, *dbase, notifq);
	uint32_t message_size = 0;
	if (!cu_copy_message(pdb->psqlite, mid_val, fid_val, &dst_val,
	    &b_result, &message_size))
		return FALSE;
	if (!b_result)
		return TRUE;
	pdb->proc_dynamic_event(cpid,
		dynamic_event::new_msg, fid_val, dst_val, 0, *dbase, notifq);
	pdb->notify_message_movecopy(!b_move ? TRUE : false,
		fid_val, dst_val, parent_fid, mid_val, *dbase, notifq);
	BOOL b_update = TRUE;
	if (b_move) {
		if (exmdb_server::is_private()) {
			snprintf(sql_string, std::size(sql_string), "DELETE FROM messages"
			        " WHERE message_id=%llu", LLU{mid_val});
			if (pdb->exec(sql_string) != SQLITE_OK)
				return FALSE;
			mlog(LV_DEBUG, "exmdb-audit: moved message %s:f%llu:m%llu to f%llu:m%llu",
				dir, LLU{parent_fid}, LLU{mid_val}, LLU{fid_val}, LLU{dst_val});
			b_update = FALSE;
		} else {
			snprintf(sql_string, std::size(sql_string), "UPDATE messages SET "
			        "is_deleted=1 WHERE message_id=%llu", LLU{mid_val});
			if (pdb->exec(sql_string) != SQLITE_OK)
				return FALSE;
			mlog(LV_DEBUG, "exmdb-audit: moved(PF) message %s:f%llu:m%llu to f%llu:m%llu",
				dir, LLU{parent_fid}, LLU{mid_val}, LLU{fid_val}, LLU{dst_val});
			snprintf(sql_string, std::size(sql_string), "DELETE FROM "
			          "read_states message_id=%llu", LLU{mid_val});
			if (pdb->exec(sql_string) != SQLITE_OK)
				return FALSE;
		}
	} else {
		mlog(LV_DEBUG, "exmdb-audit: copied message %s:f%llu:m%llu to f%llu:m%llu",
			dir, LLU{parent_fid}, LLU{mid_val}, LLU{fid_val}, LLU{dst_val});
	}
	if (b_update && !cu_adjust_store_size(pdb->psqlite, ADJ_INCREASE,
	    is_associated ? 0 : message_size, is_associated ? message_size : 0))
		return FALSE;
	auto nt_time = rop_util_current_nttime();
	if (b_move) {
		TAGGED_PROPVAL tmp_propvals[5];
		TPROPVAL_ARRAY propvals;
		uint64_t change_num = 0;

		propvals.count = 5;
		propvals.ppropval = tmp_propvals;
		if (cu_allocate_cn(pdb->psqlite, &change_num) != ecSuccess)
			return FALSE;
		auto tmp_cn = rop_util_make_eid_ex(1, change_num);
		auto account_id = exmdb_server::get_account_id();
		tmp_propvals[0].proptag = PidTagChangeNumber;
		tmp_propvals[0].pvalue = &tmp_cn;
		tmp_propvals[1].proptag = PR_CHANGE_KEY;
		tmp_propvals[1].pvalue = cu_xid_to_bin({
			exmdb_server::is_private() ?
				rop_util_make_user_guid(account_id) :
				rop_util_make_domain_guid(account_id),
			tmp_cn});

		void *pvalue = nullptr;
		if (tmp_propvals[1].pvalue == nullptr ||
		    !cu_get_property(MAPI_FOLDER, parent_fid, CP_ACP,
		    pdb->psqlite, PR_PREDECESSOR_CHANGE_LIST, &pvalue))
			return FALSE;
		tmp_propvals[2].proptag = PR_PREDECESSOR_CHANGE_LIST;
		tmp_propvals[2].pvalue = common_util_pcl_append(static_cast<BINARY *>(pvalue),
		                         static_cast<BINARY *>(tmp_propvals[1].pvalue));
		if (tmp_propvals[2].pvalue == nullptr)
			return FALSE;
		nt_time = rop_util_current_nttime();
		tmp_propvals[3].proptag = PR_LOCAL_COMMIT_TIME_MAX;
		tmp_propvals[3].pvalue = &nt_time;
		tmp_propvals[4].proptag = PR_LAST_MODIFICATION_TIME;
		tmp_propvals[4].pvalue = &nt_time;

		PROBLEM_ARRAY problems;
		cu_set_properties(MAPI_FOLDER, parent_fid, CP_ACP, pdb->psqlite,
			&propvals, &problems);
		common_util_increase_deleted_count(pdb->psqlite, parent_fid, 1);
	}
	cu_set_property(MAPI_FOLDER, fid_val, CP_ACP, pdb->psqlite,
		PR_LOCAL_COMMIT_TIME_MAX, &nt_time, &b_result);
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	dg_notify(std::move(notifq));
	*pb_result = TRUE;
	return TRUE;
}

/**
 * @b_guest:    0=acting as store owner (no permission checks),
 *              1=acting as logon_mode::delegate or ::guest.
 *              XXX: This field is redundant because it coincides with
 *              @username==STORE_OWNER_GRANTED.
 * @username:   Used for permission checks (SFOD & generic folders & message
 *              owner).
 * @src_fid:    The folder from which the action was invoked (this way, we know
 *              if it came from a search folder or a generic folder).
 */
BOOL exmdb_server::movecopy_messages(const char *dir, cpid_t cpid, BOOL b_guest,
    const char *username, uint64_t src_fid, uint64_t dst_fid, BOOL b_copy,
    const EID_ARRAY *pmessage_ids, BOOL *pb_partial)
{
	BOOL b_check, b_owner, b_result;
	uint32_t permission, folder_type;
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	*pb_partial = FALSE;
	auto src_val = rop_util_get_gc_value(src_fid);
	auto dst_val = rop_util_get_gc_value(dst_fid);
	if (!common_util_get_folder_type(pdb->psqlite, src_val, &folder_type, dir))
		return FALSE;
	if (!b_guest) {
		b_check = FALSE;
	} else if (folder_type != FOLDER_SEARCH) {
		if (!cu_get_folder_permission(pdb->psqlite,
		    src_val, username, &permission))
			return FALSE;
		b_check = (permission & (frightsOwner | frightsReadAny)) ? false : TRUE;
	} else {
		b_check = TRUE;
	}

	auto b_batch = pmessage_ids->count >= MIN_BATCH_MESSAGE_NUM;
	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	if (b_batch)
		pdb->begin_batch_mode(*dbase);
	auto cl_0 = make_scope_exit([&]() {
		if (b_batch)
			pdb->cancel_batch_mode(*dbase);
	});
	auto stm_find = pdb->prep("SELECT parent_fid, "
	             "is_associated FROM messages WHERE message_id=?");
	if (stm_find == nullptr)
		return FALSE;
	BOOL b_update = TRUE;
	xstmt stm_del;
	if (!b_copy) {
		if (exmdb_server::is_private()) {
			strcpy(sql_string, "DELETE FROM messages WHERE message_id=?");
			b_update = FALSE;
		} else {
			strcpy(sql_string, "UPDATE messages SET is_deleted=1 WHERE message_id=?");
		}
		stm_del = pdb->prep(sql_string);
		if (stm_del == nullptr)
			return FALSE;
	}
	uint64_t fai_size = 0, normal_size = 0;
	uint32_t del_count = 0, message_size = 0;
	std::set<uint64_t> touched_folders;
	for (auto mid : *pmessage_ids) {
		auto tmp_val = rop_util_get_gc_value(mid);
		stm_find.bind_int64(1, tmp_val);
		if (stm_find.step() != SQLITE_ROW) {
			*pb_partial = TRUE;
			continue;
		}
		/*
		 * src_val may be a search folder (MS-OXCFOLD v23.2 §2.2.1.6),
		 * so re-lookup for the real parent of the source.
		 */
		uint64_t parent_fid = stm_find.col_uint64(0);
		bool is_associated = stm_find.col_uint64(1);
		stm_find.reset();
		if (folder_type == FOLDER_SEARCH) {
			if (b_check) {
				if (!cu_get_folder_permission(pdb->psqlite,
				    parent_fid, username, &permission))
					return false;
				if (!(permission & (frightsOwner | frightsReadAny))) {
					if (!common_util_check_message_owner(pdb->psqlite,
					    tmp_val, username, &b_owner))
						return false;
					if (!b_owner) {
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
			if (b_check) {
				if (!common_util_check_message_owner(pdb->psqlite,
				    tmp_val, username, &b_owner))
					return false;
				if (!b_owner) {
					*pb_partial = TRUE;
					continue;
				}
			}
		}
		if (!b_copy)
			pdb->proc_dynamic_event(cpid, dynamic_event::del_msg,
				parent_fid, tmp_val, 0, *dbase, notifq);
		uint64_t tmp_val1 = 0;
		if (!cu_copy_message(pdb->psqlite, tmp_val, dst_val, &tmp_val1,
		    &b_result, &message_size))
			return FALSE;
		if (!b_result) {
			*pb_partial = TRUE;
			continue;
		}
		if (!is_associated)
			normal_size += message_size;
		else
			fai_size += message_size;
		pdb->proc_dynamic_event(cpid, dynamic_event::new_msg,
			dst_val, tmp_val1, 0, *dbase, notifq);
		pdb->notify_message_movecopy(b_copy, dst_val, tmp_val1,
			src_val, tmp_val, *dbase, notifq);
		if (b_copy) {
			mlog(LV_DEBUG, "exmdb-audit: copied(mmv) message %s:f%llu:m%llu to f%llu:m%llu",
				dir, LLU{src_val}, LLU{tmp_val}, LLU{dst_val}, LLU{tmp_val1});
			continue;
		}

		/* Below here = moves */
		del_count ++;
		stm_del.bind_int64(1, tmp_val);
		if (stm_del.step() != SQLITE_DONE)
			return false;
		stm_del.reset();
		mlog(LV_DEBUG, "exmdb-audit: moved(mmv) message %s:f%llu:m%llu to f%llu:m%llu",
			dir, LLU{src_val}, LLU{tmp_val}, LLU{dst_val}, LLU{tmp_val1});
		if (!exmdb_server::is_private()) {
			snprintf(sql_string, std::size(sql_string), "DELETE FROM read_states"
			         " WHERE message_id=%llu", LLU{tmp_val});
			if (pdb->exec(sql_string) != SQLITE_OK)
				return false;
		}

		try {
			/* dst folders' change keys are already updated by common_util_copy_message */
			touched_folders.emplace(parent_fid);
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-2232: ENOMEM");
			return false;
		}
	}
	stm_find.finalize();
	stm_del.finalize();
	if (b_update && normal_size + fai_size > 0 &&
	    !cu_adjust_store_size(pdb->psqlite, ADJ_INCREASE, normal_size, fai_size))
		return FALSE;
	auto nt_time = rop_util_current_nttime();
	if (!b_copy) for (auto parent_fid : touched_folders) {
		TAGGED_PROPVAL tmp_propvals[5];
		TPROPVAL_ARRAY propvals;
		PROBLEM_ARRAY problems;
		void *pvalue = nullptr;
		uint64_t change_num = 0;

		propvals.count = 5;
		propvals.ppropval = tmp_propvals;
		if (cu_allocate_cn(pdb->psqlite, &change_num) != ecSuccess)
			return FALSE;
		auto tmp_cn = rop_util_make_eid_ex(1, change_num);
		auto account_id = exmdb_server::get_account_id();
		tmp_propvals[0].proptag = PidTagChangeNumber;
		tmp_propvals[0].pvalue = &tmp_cn;
		tmp_propvals[1].proptag = PR_CHANGE_KEY;
		tmp_propvals[1].pvalue = cu_xid_to_bin({
			exmdb_server::is_private() ?
				rop_util_make_user_guid(account_id) :
				rop_util_make_domain_guid(account_id),
			tmp_cn});
		if (tmp_propvals[1].pvalue == nullptr ||
		    !cu_get_property(MAPI_FOLDER, parent_fid, CP_ACP,
		    pdb->psqlite, PR_PREDECESSOR_CHANGE_LIST, &pvalue))
			return FALSE;
		tmp_propvals[2].proptag = PR_PREDECESSOR_CHANGE_LIST;
		tmp_propvals[2].pvalue = common_util_pcl_append(static_cast<BINARY *>(pvalue),
		                         static_cast<BINARY *>(tmp_propvals[1].pvalue));
		if (tmp_propvals[2].pvalue == nullptr)
			return FALSE;
		tmp_propvals[3].proptag = PR_LOCAL_COMMIT_TIME_MAX;
		tmp_propvals[3].pvalue = &nt_time;
		tmp_propvals[4].proptag = PR_LAST_MODIFICATION_TIME;
		tmp_propvals[4].pvalue = &nt_time;
		cu_set_properties(MAPI_FOLDER, parent_fid, CP_ACP, pdb->psqlite,
			&propvals, &problems);
		common_util_increase_deleted_count(
			pdb->psqlite, parent_fid, del_count);
	}
	cu_set_property(MAPI_FOLDER, dst_val, CP_ACP, pdb->psqlite,
		PR_LOCAL_COMMIT_TIME_MAX, &nt_time, &b_result);
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	dg_notify(std::move(notifq));
	if (b_batch) {
		b_batch = false;
		db_conn::commit_batch_mode_release(std::move(pdb),std::move(dbase));
	}
	return TRUE;
}

/**
 * @username:   Used for evaluating delete permission.
 */
BOOL exmdb_server::delete_messages(const char *dir, cpid_t cpid,
    const char *username, uint64_t folder_id, const EID_ARRAY *pmessage_ids,
    BOOL b_hard, BOOL *pb_partial)
{
	void *pvalue;
	BOOL b_check;
	BOOL b_owner;
	uint32_t permission;
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	*pb_partial = FALSE;
	auto src_val = rop_util_get_gc_value(folder_id);
	uint32_t folder_type = 0;
	if (!common_util_get_folder_type(pdb->psqlite, src_val, &folder_type))
		return FALSE;
	if (username == STORE_OWNER_GRANTED) {
		b_check = FALSE;
	} else if (folder_type == FOLDER_SEARCH) {
		b_check = TRUE;
	} else {
		if (!cu_get_folder_permission(pdb->psqlite,
		    src_val, username, &permission))
			return FALSE;
		b_check = (permission & (frightsOwner | frightsDeleteAny)) ? false : TRUE;
	}

	auto b_batch = pmessage_ids->count >= MIN_BATCH_MESSAGE_NUM;
	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	if (b_batch)
		pdb->begin_batch_mode(*dbase);
	auto cl_0 = make_scope_exit([&]() {
		if (b_batch)
			pdb->cancel_batch_mode(*dbase);
	});
	auto pstmt = pdb->prep("SELECT parent_fid, is_associated, "
	             "message_size FROM messages WHERE message_id=?");
	if (pstmt == nullptr)
		return FALSE;
	auto pstmt1 = pdb->prep(b_hard ?
	              "DELETE FROM messages WHERE message_id=?" :
	              "UPDATE messages SET is_deleted=1 WHERE message_id=?");
	if (pstmt1 == nullptr)
		return FALSE;
	uint64_t fai_size = 0, normal_size = 0;
	int del_count = 0;
	auto nt_time = rop_util_current_nttime();
	for (auto mid : *pmessage_ids) {
		auto tmp_val = rop_util_get_gc_value(mid);
		sqlite3_bind_int64(pstmt, 1, tmp_val);
		if (pstmt.step() != SQLITE_ROW)
			continue;
		uint64_t parent_fid = sqlite3_column_int64(pstmt, 0);
		auto is_assoc = pstmt.col_int64(1) != 0;
		auto obj_size = pstmt.col_int64(2);
		sqlite3_reset(pstmt);
		if (folder_type == FOLDER_SEARCH) {
			if (b_check) {
				if (!cu_get_folder_permission(pdb->psqlite,
				    parent_fid, username, &permission))
					return FALSE;
				if (!(permission & (frightsOwner | frightsDeleteAny))) {
					if (!common_util_check_message_owner(pdb->psqlite,
					    tmp_val, username, &b_owner))
						return FALSE;
					if (!b_owner) {
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
			if (b_check) {
				if (!common_util_check_message_owner(pdb->psqlite,
				    tmp_val, username, &b_owner))
					return FALSE;
				if (!b_owner) {
					*pb_partial = TRUE;
					continue;
				}
			}
		}
		del_count ++;
		if (is_assoc)
			fai_size += obj_size;
		else
			normal_size += obj_size;
		pdb->proc_dynamic_event(cpid, dynamic_event::del_msg,
			parent_fid, tmp_val, 0, *dbase, notifq);
		if (folder_type == FOLDER_SEARCH)
			pdb->notify_link_deletion(src_val, tmp_val, *dbase, notifq);
		else
			pdb->notify_message_deletion(src_val, tmp_val, *dbase, notifq);
		sqlite3_bind_int64(pstmt1, 1, tmp_val);
		if (pstmt1.step() != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt1);
		mlog(LV_DEBUG, "exmdb-audit: %s-deleted message %s:f%llu:m%llu (actor:%s)",
			b_hard ? "hard" : "soft", dir, LLU{src_val}, LLU{tmp_val},
			username != nullptr ? username : "owner");
		if (!b_hard) {
			uint64_t change_num = 0;
			if (cu_allocate_cn(pdb->psqlite, &change_num) != ecSuccess)
				return false;
			change_num = rop_util_make_eid_ex(1, change_num);
			auto account_id = exmdb_server::get_account_id();
			TAGGED_PROPVAL nprop[5];
			nprop[0].proptag = PidTagChangeNumber;
			nprop[0].pvalue = &change_num;
			nprop[1].proptag = PR_CHANGE_KEY;
			nprop[1].pvalue = cu_xid_to_bin({
				exmdb_server::is_private() ?
					rop_util_make_user_guid(account_id) :
					rop_util_make_domain_guid(account_id),
				change_num});
			if (nprop[1].pvalue == nullptr ||
			    !cu_get_property(MAPI_MESSAGE, tmp_val, CP_ACP,
			    pdb->psqlite, PR_PREDECESSOR_CHANGE_LIST, &pvalue))
				return false;
			nprop[2].proptag = PR_PREDECESSOR_CHANGE_LIST;
			nprop[2].pvalue = common_util_pcl_append(static_cast<BINARY *>(pvalue),
			                  static_cast<const BINARY *>(nprop[1].pvalue));
			if (nprop[2].pvalue == nullptr)
				return false;
			nprop[3].proptag = PR_LAST_MODIFICATION_TIME;
			nprop[3].pvalue = &nt_time;
			/*
			 * Something is weird: EXC2019 does not expose PR_DELETED_ON, and OL
			 * knows to display PR_LAST_MODIFICATION_TIME in the "Recover Items"
			 * dialog instead...
			 */
			nprop[4].proptag = PR_DELETED_ON;
			nprop[4].pvalue = &nt_time;
			PROBLEM_ARRAY problems;
			const TPROPVAL_ARRAY npropds = {std::size(nprop), nprop};
			cu_set_properties(MAPI_MESSAGE, tmp_val, CP_ACP, pdb->psqlite,
				&npropds, &problems);
		}
		if (!b_hard && !is_private()) {
			char sql_string[256];
			snprintf(sql_string, std::size(sql_string), "DELETE FROM read_states"
			        " WHERE message_id=%llu", LLU{tmp_val});
			if (pdb->exec(sql_string) != SQLITE_OK)
				return FALSE;
		}
	}
	pstmt.finalize();
	pstmt1.finalize();
	if (b_hard && !cu_adjust_store_size(pdb->psqlite, ADJ_DECREASE,
	    normal_size, fai_size))
		return FALSE;
	TAGGED_PROPVAL tmp_propvals[5];
	TPROPVAL_ARRAY propvals;
	propvals.count = 5;
	propvals.ppropval = tmp_propvals;
	uint64_t change_num = 0;
	if (cu_allocate_cn(pdb->psqlite, &change_num) != ecSuccess)
		return FALSE;
	auto tmp_cn = rop_util_make_eid_ex(1, change_num);
	auto account_id = exmdb_server::get_account_id();
	tmp_propvals[0].proptag = PidTagChangeNumber;
	tmp_propvals[0].pvalue = &tmp_cn;
	tmp_propvals[1].proptag = PR_CHANGE_KEY;
	tmp_propvals[1].pvalue = cu_xid_to_bin({
		exmdb_server::is_private() ?
			rop_util_make_user_guid(account_id) :
			rop_util_make_domain_guid(account_id),
		tmp_cn});
	if (tmp_propvals[1].pvalue == nullptr ||
	    !cu_get_property(MAPI_FOLDER, src_val, CP_ACP,
	    pdb->psqlite, PR_PREDECESSOR_CHANGE_LIST, &pvalue))
		return FALSE;
	tmp_propvals[2].proptag = PR_PREDECESSOR_CHANGE_LIST;
	tmp_propvals[2].pvalue = common_util_pcl_append(static_cast<BINARY *>(pvalue),
	                         static_cast<BINARY *>(tmp_propvals[1].pvalue));
	if (tmp_propvals[2].pvalue == nullptr)
		return FALSE;
	tmp_propvals[3].proptag = PR_LOCAL_COMMIT_TIME_MAX;
	tmp_propvals[3].pvalue = &nt_time;
	tmp_propvals[4].proptag = PR_LAST_MODIFICATION_TIME;
	tmp_propvals[4].pvalue = &nt_time;
	PROBLEM_ARRAY problems;
	cu_set_properties(MAPI_FOLDER, src_val, CP_ACP, pdb->psqlite,
		&propvals, &problems);
	common_util_increase_deleted_count(
		pdb->psqlite, src_val, del_count);
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	dg_notify(std::move(notifq));
	if (b_batch) {
		b_batch = false;
		db_conn::commit_batch_mode_release(std::move(pdb), std::move(dbase));
	}
	return TRUE;
}

static BOOL message_get_message_rcpts(sqlite3 *psqlite, uint64_t message_id,
    TARRAY_SET *pset) try
{
	char sql_string[256];
	TAGGED_PROPVAL *ppropval;
	
	snprintf(sql_string, std::size(sql_string), "SELECT count(*) FROM"
	          " recipients WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	uint32_t rcpt_num = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	pset->count = 0;
	if (0 == rcpt_num) {
		pset->pparray = NULL;
		return TRUE;
	}
	pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(rcpt_num);
	if (pset->pparray == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT recipient_id FROM"
	          " recipients WHERE message_id=%llu", LLU{message_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	uint32_t row_id = 0;
	while (pstmt.step() == SQLITE_ROW) {
		uint64_t rcpt_id = sqlite3_column_int64(pstmt, 0);
		std::vector<uint32_t> tags;
		if (!cu_get_proptags(MAPI_MAILUSER, rcpt_id, psqlite, tags))
			return false;
		/* Nudge cu_get_properties allocation to make extra room. */
		for (size_t i = 0; i < 5; ++i)
			tags.push_back(PR_NULL);
		PROPTAG_ARRAY proptags = {static_cast<uint16_t>(tags.size()), tags.data()};
		pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
		if (pset->pparray[pset->count] == nullptr ||
		    !cu_get_properties(MAPI_MAILUSER, rcpt_id, CP_ACP,
		    psqlite, &proptags, pset->pparray[pset->count]))
			return FALSE;
		/* PR_ROWID MUST be the first */
		memmove(pset->pparray[pset->count]->ppropval + 1,
			pset->pparray[pset->count]->ppropval, sizeof(
			TAGGED_PROPVAL)*pset->pparray[pset->count]->count);
		ppropval = pset->pparray[pset->count]->ppropval;
		pset->pparray[pset->count]->count ++;
		ppropval->proptag = PR_ROWID;
		auto uv = cu_alloc<uint32_t>();
		ppropval->pvalue = uv;
		if (ppropval->pvalue == nullptr)
			return FALSE;
		*uv = row_id++;
		auto &drcpt = *pset->pparray[pset->count];
		if (drcpt.find(PR_RECIPIENT_TYPE) == nullptr)
			drcpt.emplace_back(PR_RECIPIENT_TYPE, &dummy_rcpttype);
		if (drcpt.find(PR_DISPLAY_NAME) == nullptr &&
		    drcpt.find(PR_DISPLAY_NAME_A) == nullptr)
			drcpt.emplace_back(PR_DISPLAY_NAME, dummy_string);
		if (drcpt.find(PR_ADDRTYPE) == nullptr)
			drcpt.emplace_back(PR_ADDRTYPE, dummy_addrtype);
		if (drcpt.find(PR_EMAIL_ADDRESS) == nullptr)
			drcpt.emplace_back(PR_EMAIL_ADDRESS, dummy_string);
		pset->count ++;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1165: ENOMEM");
	return false;
}

BOOL exmdb_server::get_message_brief(const char *dir, cpid_t cpid,
	uint64_t message_id, MESSAGE_CONTENT **ppbrief)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	auto mid_val = rop_util_get_gc_value(message_id);
	char sql_string[256];
	snprintf(sql_string, std::size(sql_string), "SELECT message_id FROM"
	          " messages WHERE message_id=%llu", LLU{mid_val});
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW) {
		*ppbrief = NULL;
		return TRUE;
	}
	pstmt.finalize();
	*ppbrief = cu_alloc<MESSAGE_CONTENT>();
	if (*ppbrief == nullptr)
		return FALSE;
	static constexpr proptag_t proptag_buff[] = {
		PR_SUBJECT, PR_SENT_REPRESENTING_NAME,
		PR_SENT_REPRESENTING_SMTP_ADDRESS, PR_CLIENT_SUBMIT_TIME,
		PR_MESSAGE_SIZE, PR_INTERNET_CPID, PR_INTERNET_MESSAGE_ID,
		PR_PARENT_KEY, PR_CONVERSATION_INDEX,
	};
	static constexpr PROPTAG_ARRAY proptags =
		{std::size(proptag_buff), deconst(proptag_buff)};
	if (!cu_get_properties(MAPI_MESSAGE, mid_val, cpid,
	    pdb->psqlite, &proptags, &(*ppbrief)->proplist))
		return FALSE;
	(*ppbrief)->children.prcpts = cu_alloc<TARRAY_SET>();
	if ((*ppbrief)->children.prcpts == nullptr)
		return FALSE;
	if (!message_get_message_rcpts(pdb->psqlite, mid_val,
	    (*ppbrief)->children.prcpts))
		return FALSE;
	(*ppbrief)->children.pattachments = cu_alloc<ATTACHMENT_LIST>();
	if ((*ppbrief)->children.pattachments == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT count(*) FROM "
	          "attachments WHERE message_id=%llu", LLU{mid_val});
	pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	uint32_t count = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	(*ppbrief)->children.pattachments->count = 0;
	(*ppbrief)->children.pattachments->pplist = cu_alloc<ATTACHMENT_CONTENT *>(count);
	if ((*ppbrief)->children.pattachments->pplist == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT attachment_id FROM "
	          "attachments WHERE message_id=%llu", LLU{mid_val});
	pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;

	static constexpr proptag_t proptag2_buff[] = {PR_ATTACH_LONG_FILENAME};
	static constexpr PROPTAG_ARRAY proptags2 = {std::size(proptag2_buff), deconst(proptag2_buff)};
	while (pstmt.step() == SQLITE_ROW) {
		uint64_t attachment_id = sqlite3_column_int64(pstmt, 0);
		auto pattachment = cu_alloc<ATTACHMENT_CONTENT>();
		if (pattachment == nullptr)
			return FALSE;
		if (!cu_get_properties(MAPI_ATTACH, attachment_id, cpid,
		    pdb->psqlite, &proptags2, &pattachment->proplist))
			return FALSE;
		pattachment->pembedded = NULL;
		auto &ats = *(*ppbrief)->children.pattachments;
		ats.pplist[ats.count++] = pattachment;
	}
	return TRUE;
}

BOOL exmdb_server::is_msg_present(const char *dir,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_exist)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	auto fid_val = rop_util_get_gc_value(folder_id);
	auto mid_val = rop_util_get_gc_value(message_id);
	uint32_t folder_type = 0;
	if (!common_util_get_folder_type(pdb->psqlite, fid_val, &folder_type))
		return FALSE;
	char sql_string[256];
	if (folder_type == FOLDER_SEARCH)
		snprintf(sql_string, std::size(sql_string), "SELECT folder_id FROM"
					" search_result WHERE folder_id=%llu AND"
					" message_id=%llu", LLU{fid_val}, LLU{mid_val});
	else
		snprintf(sql_string, std::size(sql_string), "SELECT parent_fid FROM"
					" messages WHERE message_id=%llu", LLU{mid_val});

	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW) {
		*pb_exist = FALSE;
		return TRUE;
	}
	uint64_t tmp_val = sqlite3_column_int64(pstmt, 0);
	*pb_exist = tmp_val == fid_val ? TRUE : false;
	return TRUE;
}

BOOL exmdb_server::is_msg_deleted(const char *dir,
	uint64_t message_id, BOOL *pb_del)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	auto mid_val = rop_util_get_gc_value(message_id);
	char sql_string[256];
	snprintf(sql_string, std::size(sql_string), "SELECT is_deleted "
	         "FROM messages WHERE message_id=%llu", LLU{mid_val});
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*pb_del = pstmt.step() != SQLITE_ROW ||
	          (!exmdb_server::is_private() &&
	          sqlite3_column_int64(pstmt, 0) != 0) ? TRUE : false;
	return TRUE;
}

BOOL exmdb_server::get_message_rcpts(const char *dir,
	uint64_t message_id, TARRAY_SET *pset)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	auto mid_val = rop_util_get_gc_value(message_id);
	return message_get_message_rcpts(pdb->psqlite, mid_val, pset);
}

/**
 * @username:   Used for adjusting public store readstates
 */
BOOL exmdb_server::get_message_properties(const char *dir,
    const char *username, cpid_t cpid, uint64_t message_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	if (!exmdb_server::is_private())
		exmdb_server::set_public_username(username);
	auto cl_0 = make_scope_exit([]() { exmdb_server::set_public_username(nullptr); });
	return cu_get_properties(MAPI_MESSAGE,
	       rop_util_get_gc_value(message_id), cpid, pdb->psqlite,
	       pproptags, ppropvals);
}

/**
 * @username:   Used for adjusting public store readstates
 *
 * The message_size will not be updated in the function!
 */
BOOL exmdb_server::set_message_properties(const char *dir,
    const char *username, cpid_t cpid, uint64_t message_id,
	const TPROPVAL_ARRAY *pproperties, PROBLEM_ARRAY *pproblems)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	if (!exmdb_server::is_private())
		exmdb_server::set_public_username(username);
	auto cl_0 = make_scope_exit([]() { exmdb_server::set_public_username(nullptr); });
	auto mid_val = rop_util_get_gc_value(message_id);
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!cu_set_properties(MAPI_MESSAGE, mid_val, cpid,
	    pdb->psqlite, pproperties, pproblems))
		return FALSE;
	uint64_t fid_val = 0;
	if (!common_util_get_message_parent_folder(pdb->psqlite,
	    mid_val, &fid_val) || fid_val == 0)
		return FALSE;
	auto nt_time = rop_util_current_nttime();
	BOOL b_result = false;
	cu_set_property(MAPI_FOLDER, fid_val, CP_ACP, pdb->psqlite,
		PR_LOCAL_COMMIT_TIME_MAX, &nt_time, &b_result);

	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	pdb->proc_dynamic_event(cpid, dynamic_event::modify_msg,
		fid_val, mid_val, 0, *dbase, notifq);
	pdb->notify_message_modification(fid_val, mid_val, *dbase, notifq);
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	dg_notify(std::move(notifq));
	return TRUE;
}

BOOL exmdb_server::remove_message_properties(const char *dir, cpid_t cpid,
    uint64_t message_id, const PROPTAG_ARRAY *pproptags)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto mid_val = rop_util_get_gc_value(message_id);
	mid_val = rop_util_get_gc_value(message_id);
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!cu_remove_properties(MAPI_MESSAGE, mid_val,
	    pdb->psqlite, pproptags))
		return FALSE;
	uint64_t fid_val = 0;
	if (!common_util_get_message_parent_folder(pdb->psqlite,
	    mid_val, &fid_val) || fid_val == 0)
		return FALSE;
	auto nt_time = rop_util_current_nttime();
	BOOL b_result = false;
	cu_set_property(MAPI_FOLDER, fid_val, CP_ACP, pdb->psqlite,
		PR_LOCAL_COMMIT_TIME_MAX, &nt_time, &b_result);

	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	pdb->notify_message_modification(fid_val, mid_val, *dbase, notifq);
	pdb->proc_dynamic_event(cpid, dynamic_event::modify_msg,
		fid_val, mid_val, 0, *dbase, notifq);
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	dg_notify(std::move(notifq));
	return TRUE;
}

/**
 * @username:   Used for adjusting public store readstates
 */
BOOL exmdb_server::set_message_read_state(const char *dir,
	const char *username, uint64_t message_id,
	uint8_t mark_as_read, uint64_t *pread_cn)
{
	auto mid_val = rop_util_get_gc_value(message_id);
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	uint64_t read_cn = 0;
	if (cu_allocate_cn(pdb->psqlite, &read_cn) != ecSuccess)
		return false;
	if (!exmdb_server::is_private()) {
		exmdb_server::set_public_username(username);
		auto cl_0 = make_scope_exit([]() { exmdb_server::set_public_username(nullptr); });
		common_util_set_message_read(pdb->psqlite,
			mid_val, mark_as_read);
		char sql_string[128];
		snprintf(sql_string, std::size(sql_string), "REPLACE INTO "
				"read_cns VALUES (%llu, ?, %llu)",
				LLU{mid_val}, LLU{read_cn});
		auto pstmt = pdb->prep(sql_string);
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
		if (pstmt.step() != SQLITE_DONE)
			return FALSE;
	} else {
		common_util_set_message_read(pdb->psqlite,
			mid_val, mark_as_read);
		char sql_string[128];
		snprintf(sql_string, std::size(sql_string), "UPDATE messages SET "
			"read_cn=%llu WHERE message_id=%llu",
			LLU{read_cn}, LLU{mid_val});
		if (pdb->exec(sql_string) != SQLITE_OK)
			return FALSE;
	}
	uint64_t fid_val = 0;
	if (!common_util_get_message_parent_folder(pdb->psqlite,
	    mid_val, &fid_val))
		return FALSE;
	if (fid_val == 0)
		return TRUE; /* XXX: yield ecObjectDeleted or so */
	auto nt_time = rop_util_current_nttime();
	BOOL b_result = false;
	cu_set_property(MAPI_FOLDER, fid_val, CP_ACP, pdb->psqlite,
		PR_LOCAL_COMMIT_TIME_MAX, &nt_time, &b_result);

	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	pdb->proc_dynamic_event(CP_ACP, dynamic_event::modify_msg,
		fid_val, mid_val, 0, *dbase, notifq);
	pdb->notify_message_modification(fid_val, mid_val, *dbase, notifq);
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	dg_notify(std::move(notifq));
	*pread_cn = rop_util_make_eid_ex(1, read_cn);
	return TRUE;
}

/* if folder_id is 0, it means embedded message */
BOOL exmdb_server::allocate_message_id(const char *dir,
	uint64_t folder_id, uint64_t *pmessage_id)
{
	uint64_t eid_val;
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	if (0 == folder_id) {
		if (!common_util_allocate_eid(pdb->psqlite, &eid_val))
			return FALSE;
		*pmessage_id = rop_util_make_eid_ex(1, eid_val);
		return sql_transact.commit() == SQLITE_OK ? TRUE : false;
	}
	auto fid_val = rop_util_get_gc_value(folder_id);
	if (!common_util_allocate_eid_from_folder(pdb->psqlite, fid_val, &eid_val))
		return FALSE;
	*pmessage_id = rop_util_make_eid_ex(1, eid_val);
	return sql_transact.commit() == SQLITE_OK ? TRUE : false;
}

BOOL exmdb_server::get_message_group_id(const char *dir,
	uint64_t message_id, uint32_t **ppgroup_id)
{
	char sql_string[128];
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	snprintf(sql_string, std::size(sql_string), "SELECT group_id "
				"FROM messages WHERE message_id=%llu",
				LLU{rop_util_get_gc_value(message_id)});
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW ||
		SQLITE_NULL == sqlite3_column_type(pstmt, 0)) {
		*ppgroup_id = NULL;
		return TRUE;
	}
	*ppgroup_id = cu_alloc<uint32_t>();
	if (*ppgroup_id == nullptr)
		return FALSE;
	**ppgroup_id = sqlite3_column_int64(pstmt, 0);
	return TRUE;
}

BOOL exmdb_server::set_message_group_id(const char *dir,
	uint64_t message_id, uint32_t group_id)
{
	char sql_string[128];
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	snprintf(sql_string, std::size(sql_string), "UPDATE messages SET"
		" group_id=%u WHERE message_id=%llu",
		XUI{group_id}, LLU{rop_util_get_gc_value(message_id)});
	if (pdb->exec(sql_string) != SQLITE_OK)
		return FALSE;
	return TRUE;
}

/* if count of indices and ungroup_proptags are both 0 means full change */
BOOL exmdb_server::save_change_indices(const char *dir, uint64_t message_id,
    uint64_t cn, const INDEX_ARRAY *pindices,
    const PROPTAG_ARRAY *pungroup_proptags) try
{
	EXT_PUSH ext_push;
	char sql_string[128];
	static constexpr size_t idbuff_size = 0x8000;
	auto indices_buff = std::make_unique<uint8_t[]>(idbuff_size);
	auto proptags_buff = std::make_unique<uint8_t[]>(idbuff_size);
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	auto mid_val = rop_util_get_gc_value(message_id);
	if (0 == pindices->count && 0 == pungroup_proptags->count) {
		snprintf(sql_string, std::size(sql_string), "UPDATE messages SET "
		          "group_id=? WHERE message_id=%llu", LLU{mid_val});
		auto pstmt = pdb->prep(sql_string);
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_null(pstmt, 1);
		return pstmt.step() == SQLITE_DONE ? TRUE : false;
	}
	auto pstmt = pdb->prep("INSERT INTO"
	             " message_changes VALUES (?, ?, ?, ?)");
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, mid_val);
	sqlite3_bind_int64(pstmt, 2, rop_util_get_gc_value(cn));
	if (!ext_push.init(indices_buff.get(), idbuff_size, 0) ||
	    ext_push.p_proptag_a(*pindices) != EXT_ERR_SUCCESS)
		return false;
	sqlite3_bind_blob(pstmt, 3, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
	if (!ext_push.init(proptags_buff.get(), idbuff_size, 0) ||
	    ext_push.p_proptag_a(*pungroup_proptags) != EXT_ERR_SUCCESS)
		return false;
	sqlite3_bind_blob(pstmt, 4, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
	return pstmt.step() == SQLITE_DONE ? TRUE : false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1162: ENOMEM");
	return false;
}

/* if count of indices and ungroup_proptags are both 0 means full change */
BOOL exmdb_server::get_change_indices(const char *dir,
	uint64_t message_id, uint64_t cn, INDEX_ARRAY *pindices,
	PROPTAG_ARRAY *pungroup_proptags)
{
	EXT_PULL ext_pull;
	INDEX_ARRAY tmp_indices;
	PROPTAG_ARRAY tmp_proptags;
	
	auto cn_val = rop_util_get_gc_value(cn);
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	auto mid_val = rop_util_get_gc_value(message_id);
	std::unique_ptr<INDEX_ARRAY, pta_delete> ptmp_indices(proptag_array_init());
	if (ptmp_indices == nullptr)
		return FALSE;
	std::unique_ptr<PROPTAG_ARRAY, pta_delete> ptmp_proptags(proptag_array_init());
	if (ptmp_proptags == nullptr)
		return FALSE;
	char sql_string[128];
	snprintf(sql_string, std::size(sql_string), "SELECT change_number,"
				" indices, proptags FROM message_changes"
				" WHERE message_id=%llu", LLU{mid_val});
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		if (gx_sql_col_uint64(pstmt, 0) <= cn_val)
			continue;
		if (sqlite3_column_bytes(pstmt, 1) > 0) {
			ext_pull.init(sqlite3_column_blob(pstmt, 1),
				sqlite3_column_bytes(pstmt, 1),
				common_util_alloc, 0);
			if (ext_pull.g_proptag_a(&tmp_indices) != EXT_ERR_SUCCESS)
				return FALSE;
			for (unsigned int i = 0; i < tmp_indices.count; ++i)
				if (!proptag_array_append(ptmp_indices.get(),
				    tmp_indices.pproptag[i]))
					return FALSE;
		}
		if (sqlite3_column_bytes(pstmt, 2) > 0) {
			ext_pull.init(sqlite3_column_blob(pstmt, 2),
				sqlite3_column_bytes(pstmt, 2),
				common_util_alloc, 0);
			if (ext_pull.g_proptag_a(&tmp_proptags) != EXT_ERR_SUCCESS)
				return FALSE;
			for (unsigned int i = 0; i < tmp_proptags.count; ++i)
				if (!proptag_array_append(ptmp_proptags.get(),
				    tmp_proptags.pproptag[i]))
					return FALSE;
		}
	}
	pstmt.finalize();
	pdb.reset();
	pindices->count = ptmp_indices->count;
	if (ptmp_indices->count > 0) {
		pindices->pproptag = cu_alloc<uint32_t>(ptmp_indices->count);
		if (pindices->pproptag == nullptr)
			return FALSE;
		memcpy(pindices->pproptag, ptmp_indices->pproptag,
			sizeof(uint32_t)*ptmp_indices->count);
	}
	ptmp_indices.reset();
	if (ptmp_proptags->count == 0) {
		pungroup_proptags->count = 0;
		pungroup_proptags->pproptag = NULL;
		return TRUE;
	}
	pungroup_proptags->count = ptmp_proptags->count;
	pungroup_proptags->pproptag = cu_alloc<uint32_t>(ptmp_proptags->count);
	if (pungroup_proptags->pproptag == nullptr)
		return FALSE;
	memcpy(pungroup_proptags->pproptag, ptmp_proptags->pproptag,
	       sizeof(uint32_t)*ptmp_proptags->count);
	return TRUE;
}

BOOL exmdb_server::mark_modified(const char *dir, uint64_t message_id)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	auto mid_val = rop_util_get_gc_value(message_id);
	uint32_t *pmessage_flags = nullptr;
	if (!common_util_get_message_flags(pdb->psqlite,
	    mid_val, TRUE, &pmessage_flags))
		return FALSE;
	if (!(*pmessage_flags & MSGFLAG_UNMODIFIED))
		return TRUE;
	*pmessage_flags &= ~MSGFLAG_UNMODIFIED;
	BOOL b_result = false;
	if (!cu_set_property(MAPI_MESSAGE, mid_val, CP_ACP, pdb->psqlite,
	    PR_MESSAGE_FLAGS, pmessage_flags, &b_result))
		return false;
	return sql_transact.commit() == SQLITE_OK ? TRUE : false;
}

/* add MSGFLAG_SUBMITTED and clear
	MSGFLAG_UNSENT in message_flags */
BOOL exmdb_server::try_mark_submit(const char *dir,
	uint64_t message_id, BOOL *pb_marked)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	auto mid_val = rop_util_get_gc_value(message_id);
	uint32_t *pmessage_flags = nullptr;
	if (!common_util_get_message_flags(pdb->psqlite,
	    mid_val, TRUE, &pmessage_flags))
		return FALSE;
	if (*pmessage_flags & MSGFLAG_SUBMITTED) {
		*pb_marked = FALSE;
		return TRUE;
	}
	*pmessage_flags |= MSGFLAG_SUBMITTED;
	*pmessage_flags &= ~MSGFLAG_UNSENT;
	if (!cu_set_property(MAPI_MESSAGE, mid_val, CP_ACP, pdb->psqlite,
	    PR_MESSAGE_FLAGS, pmessage_flags, pb_marked))
		return false;
	return sql_transact.commit() == SQLITE_OK ? TRUE : false;
}

/* clear MSGFLAG_SUBMITTED set by
	exmdb_server::try_submit, clear timer_id,
	set/clear MSGFLAG_UNSENT by b_unsent */
BOOL exmdb_server::clear_submit(const char *dir,
	uint64_t message_id, BOOL b_unsent)
{
	BOOL b_result;
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto mid_val = rop_util_get_gc_value(message_id);
	uint32_t *pmessage_flags = nullptr;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	if (!common_util_get_message_flags(pdb->psqlite,
	    mid_val, TRUE, &pmessage_flags))
		return FALSE;
	*pmessage_flags &= ~MSGFLAG_SUBMITTED;
	if (b_unsent)
		*pmessage_flags |= MSGFLAG_UNSENT;
	else
		*pmessage_flags &= ~MSGFLAG_UNSENT;

	if (!cu_set_property(MAPI_MESSAGE, mid_val, CP_ACP, pdb->psqlite,
	    PR_MESSAGE_FLAGS, pmessage_flags, &b_result))
		return FALSE;
	if (!b_result)
		return TRUE;
	snprintf(sql_string, std::size(sql_string), "UPDATE messages SET"
	          " timer_id=? WHERE message_id=%llu", LLU{mid_val});
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_null(pstmt, 1);
	if (pstmt.step() != SQLITE_DONE)
		return FALSE;
	pstmt.finalize();
	return sql_transact.commit() == SQLITE_OK ? TRUE : false;
}

/* private only */
BOOL exmdb_server::link_message(const char *dir, cpid_t cpid,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_result)
{
	char sql_string[256];
	uint32_t folder_type;
	
	*pb_result = false;
	if (!exmdb_server::is_private())
		return FALSE;
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	auto fid_val = rop_util_get_gc_value(folder_id);
	auto mid_val = rop_util_get_gc_value(message_id);
	if (!common_util_get_folder_type(pdb->psqlite, fid_val, &folder_type))
		return FALSE;
	if (folder_type != FOLDER_SEARCH)
		return TRUE;
	snprintf(sql_string, std::size(sql_string), "SELECT message_id FROM "
	          "messages WHERE message_id=%llu", LLU{mid_val});
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW)
		return TRUE;
	pstmt.finalize();
	snprintf(sql_string, std::size(sql_string), "INSERT INTO search_result"
	        " VALUES (%llu, %llu)", LLU{fid_val}, LLU{mid_val});
	if (pdb->exec(sql_string) != SQLITE_OK)
		return FALSE;

	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	pdb->proc_dynamic_event(cpid, dynamic_event::new_msg,
		fid_val, mid_val, 0, *dbase, notifq);
	pdb->notify_link_creation(fid_val, mid_val, *dbase, notifq);
	if (sql_transact.commit() != SQLITE_OK)
		return FALSE;
	dg_notify(std::move(notifq));
	*pb_result = TRUE;
	return TRUE;
}

/* private only */
BOOL exmdb_server::unlink_message(const char *dir,
    cpid_t cpid, uint64_t folder_id, uint64_t message_id)
{
	char sql_string[256];
	
	if (!exmdb_server::is_private())
		return FALSE;
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	auto fid_val = rop_util_get_gc_value(folder_id);
	auto mid_val = rop_util_get_gc_value(message_id);
	snprintf(sql_string, std::size(sql_string), "DELETE FROM search_result"
		" WHERE folder_id=%llu AND message_id=%llu",
		LLU{fid_val}, LLU{mid_val});

	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	pdb->proc_dynamic_event(cpid, dynamic_event::del_msg,
		fid_val, mid_val, 0, *dbase, notifq);
	pdb->notify_link_deletion(fid_val, mid_val, *dbase, notifq);
	if (pdb->exec(sql_string) != SQLITE_OK)
		return FALSE;
	dg_notify(std::move(notifq));
	return TRUE;
}

/* private only */
BOOL exmdb_server::set_message_timer(const char *dir,
	uint64_t message_id, uint32_t timer_id)
{
	char sql_string[256];
	
	if (!exmdb_server::is_private())
		return FALSE;
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	snprintf(sql_string, std::size(sql_string), "UPDATE messages SET"
		" timer_id=%u WHERE message_id=%llu",
		XUI{timer_id}, LLU{rop_util_get_gc_value(message_id)});
	if (pdb->exec(sql_string) != SQLITE_OK)
		return FALSE;
	return TRUE;
}

/* private only */
BOOL exmdb_server::get_message_timer(const char *dir,
	uint64_t message_id, uint32_t **pptimer_id)
{
	char sql_string[256];
	
	if (!exmdb_server::is_private())
		return FALSE;
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	auto mid_val = rop_util_get_gc_value(message_id);
	snprintf(sql_string, std::size(sql_string), "SELECT timer_id FROM "
	          "messages WHERE message_id=%llu", LLU{mid_val});
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW ||
	    sqlite3_column_type(pstmt, 0) == SQLITE_NULL) {
		*pptimer_id = NULL;
		return TRUE;
	}
	*pptimer_id = cu_alloc<uint32_t>();
	if (*pptimer_id == nullptr)
		return FALSE;
	**pptimer_id = sqlite3_column_int64(pstmt, 0);
	return TRUE;
}

static BOOL message_read_message(sqlite3 *psqlite, cpid_t cpid,
    uint64_t message_id, MESSAGE_CONTENT **ppmsgctnt) try
{
	char sql_string[256];
	snprintf(sql_string, std::size(sql_string), "SELECT message_id FROM"
	          " messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW) {
		*ppmsgctnt = NULL;
		return TRUE;
	}
	pstmt.finalize();
	*ppmsgctnt = cu_alloc<MESSAGE_CONTENT>();
	if (*ppmsgctnt == nullptr)
		return FALSE;
	std::vector<uint32_t> mtags;
	if (!cu_get_proptags(MAPI_MESSAGE, message_id, psqlite, mtags))
		return FALSE;	
	mtags.erase(std::remove_if(mtags.begin(), mtags.end(), [](uint32_t t) {
		return t == PR_DISPLAY_TO || t == PR_DISPLAY_TO_A ||
		       t == PR_DISPLAY_CC || t == PR_DISPLAY_CC_A ||
		       t == PR_DISPLAY_BCC || t == PR_DISPLAY_BCC_A ||
		       t == PR_HASATTACH;
	}), mtags.end());
	PROPTAG_ARRAY proptags;
	proptags.count    = mtags.size();
	proptags.pproptag = mtags.data();
	if (!cu_get_properties(MAPI_MESSAGE, message_id, cpid,
	    psqlite, &proptags, &(*ppmsgctnt)->proplist))
		return FALSE;
	(*ppmsgctnt)->children.prcpts = cu_alloc<TARRAY_SET>();
	if ((*ppmsgctnt)->children.prcpts == nullptr)
		return FALSE;
	if (!message_get_message_rcpts(psqlite, message_id,
	    (*ppmsgctnt)->children.prcpts))
		return FALSE;
	(*ppmsgctnt)->children.pattachments = cu_alloc<ATTACHMENT_LIST>();
	if ((*ppmsgctnt)->children.pattachments == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT count(*) FROM "
	          "attachments WHERE message_id=%llu", LLU{message_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	uint32_t count = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	(*ppmsgctnt)->children.pattachments->count = 0;
	(*ppmsgctnt)->children.pattachments->pplist = cu_alloc<ATTACHMENT_CONTENT *>(count);
	if ((*ppmsgctnt)->children.pattachments->pplist == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT attachment_id FROM "
	          "attachments WHERE message_id=%llu", LLU{message_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	auto pstmt1 = gx_sql_prep(psqlite, "SELECT message_id"
	              " FROM messages WHERE parent_attid=?");
	if (pstmt1 == nullptr)
		return FALSE;
	uint32_t attach_num = 0;
	while (pstmt.step() == SQLITE_ROW) {
		uint64_t attachment_id = sqlite3_column_int64(pstmt, 0);
		std::vector<uint32_t> atags;
		if (!cu_get_proptags(MAPI_ATTACH, attachment_id,
		    psqlite, atags))
			return FALSE;
		auto pattachment = cu_alloc<ATTACHMENT_CONTENT>();
		if (pattachment == nullptr)
			return FALSE;
		atags.push_back(PR_ATTACH_NUM);
		proptags.count    = atags.size();
		proptags.pproptag = atags.data();
		if (!cu_get_properties(MAPI_ATTACH, attachment_id, cpid,
		    psqlite, &proptags, &pattachment->proplist))
			return FALSE;
		/* PR_ATTACH_NUM MUST be the first */
		memmove(pattachment->proplist.ppropval + 1,
			pattachment->proplist.ppropval, sizeof(
			TAGGED_PROPVAL)*pattachment->proplist.count);
		auto ppropval = pattachment->proplist.ppropval;
		pattachment->proplist.count ++;
		ppropval->proptag = PR_ATTACH_NUM;
		ppropval->pvalue = cu_alloc<uint32_t>();
		if (ppropval->pvalue == nullptr)
			return FALSE;
		*static_cast<uint32_t *>(ppropval->pvalue) = attach_num;
		attach_num ++;
		sqlite3_bind_int64(pstmt1, 1, attachment_id);
		if (pstmt1.step() != SQLITE_ROW)
			pattachment->pembedded = NULL;
		else if (!message_read_message(psqlite, cpid,
		    sqlite3_column_int64(pstmt1, 0), &pattachment->pembedded) ||
		    pattachment->pembedded == nullptr)
			return FALSE;
		sqlite3_reset(pstmt1);
		auto &ats = *(*ppmsgctnt)->children.pattachments;
		ats.pplist[ats.count++] = pattachment;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1163: ENOMEM");
	return false;
}

static bool message_md5_string(const char *string, uint8_t *pdgt) __attribute__((warn_unused_result));
static bool message_md5_string(const char *string, uint8_t *pdgt)
{
	char tmp_string[256];
	uint8_t dgt_buff[MD5_DIGEST_LENGTH];
	
	gx_strlcpy(tmp_string, string, std::size(tmp_string));
	HX_strupper(tmp_string);
	std::unique_ptr<EVP_MD_CTX, sslfree> ctx(EVP_MD_CTX_new());
	if (ctx == nullptr ||
	    EVP_DigestInit(ctx.get(), EVP_md5()) <= 0 ||
	    EVP_DigestUpdate(ctx.get(), tmp_string, strlen(tmp_string)) <= 0 ||
	    EVP_DigestFinal(ctx.get(), dgt_buff, nullptr) <= 0)
		return false;
	memcpy(pdgt, dgt_buff, 16);
	return true;
}

static ec_error_t message_rectify_message(const MESSAGE_CONTENT *src,
    MESSAGE_CONTENT *dst)
{
	EXT_PUSH ext_push;
	auto &sprop = src->proplist;
	auto &dprop = dst->proplist;
	
	dprop.count = 0;
	/* 14 in this function, and at least 2 more in the caller.. */
	dprop.ppropval = cu_alloc<TAGGED_PROPVAL>(sprop.count + 21);
	if (dprop.ppropval == nullptr)
		return ecServerOOM;
	for (unsigned int i = 0; i < sprop.count; ++i) {
		switch (sprop.ppropval[i].proptag) {
		case PidTagMid:
		case PR_ASSOCIATED:
		case PidTagChangeNumber:
		case PR_MSG_STATUS:
			continue;
		case PR_SUBJECT:
		case PR_SUBJECT_A:
			if (sprop.has(PR_NORMALIZED_SUBJECT) ||
			    sprop.has(PR_NORMALIZED_SUBJECT_A))
				continue;	
			break;
		}
		auto &sp = sprop.ppropval[i];
		dprop.emplace_back(sp.proptag, sp.pvalue);
	}
	auto v32 = cu_alloc<uint32_t>();
	if (v32 == nullptr)
		return ecServerOOM;
	*v32 = 0;
	dprop.emplace_back(PR_MSG_STATUS, v32);
	auto msgfl = sprop.get<uint32_t>(PR_MESSAGE_FLAGS);
	if (msgfl == nullptr) {
		v32 = cu_alloc<uint32_t>();
		if (v32 == nullptr)
			return ecServerOOM;
		*v32 = MSGFLAG_UNMODIFIED; /* modified by cu_set_properties */
		dprop.emplace_back(PR_MESSAGE_FLAGS, v32);
		if (!sprop.has(PR_READ)) {
			auto x = cu_alloc<uint8_t>();
			if (x == nullptr)
				return ecServerOOM;
			*x = false;
			dprop.emplace_back(PR_READ, x);
		}
	} else if (!sprop.has(PR_READ)) {
		auto x = cu_alloc<uint8_t>();
		if (x == nullptr)
			return ecServerOOM;
		*x = *msgfl & MSGFLAG_READ;
		dprop.emplace_back(PR_READ, x);
	}
	if (!sprop.has(PR_SEARCH_KEY)) {
		auto pbin = cu_alloc<BINARY>();
		if (pbin == nullptr)
			return ecServerOOM;
		pbin->cb = 16;
		pbin->pv = common_util_alloc(16);
		if (pbin->pv == nullptr)
			return ecServerOOM;
		if (!ext_push.init(pbin->pb, 16, 0) ||
		    ext_push.p_guid(GUID::random_new()) != EXT_ERR_SUCCESS)
			return ecError;
		dprop.emplace_back(PR_SEARCH_KEY, pbin);
	}
	if (!sprop.has(PR_BODY_CONTENT_ID)) {
		char cid_string[33+UDOM_SIZE];
		FLATUID ctid = GUID::random_new();
		encode_hex_binary(&ctid, sizeof(ctid), cid_string, 33);
		cid_string[32] = '@';
		cid_string[33] = '\0';
		char account[UDOM_SIZE]{};
		if (!mysql_adaptor_get_username_from_id(exmdb_server::get_account_id(),
		    account, std::size(account)))
			gx_strlcpy(account, "localhost", std::size(account));
		const char *pc = strchr(account, '@'); /* CONST-STRCHR-MARKER */
		if (pc == nullptr)
			pc = account;
		else
			++pc;
		HX_strlcat(cid_string, pc, std::size(cid_string));
		auto pvalue = common_util_dup(cid_string);
		if (pvalue == nullptr)
			return ecServerOOM;
		dprop.emplace_back(PR_BODY_CONTENT_ID, pvalue);
	}
	if (!sprop.has(PR_CREATOR_NAME)) {
		auto pvalue = sprop.get<char>(PR_SENDER_NAME);
		if (pvalue == nullptr)
			pvalue = sprop.get<char>(PR_SENT_REPRESENTING_NAME);
		if (pvalue != nullptr)
			dprop.emplace_back(PR_CREATOR_NAME, pvalue);
	}
	if (!sprop.has(PR_CREATOR_ENTRYID)) {
		auto pvalue = sprop.get<char>(PR_SENDER_ENTRYID);
		if (pvalue == nullptr)
			pvalue = sprop.get<char>(PR_SENT_REPRESENTING_ENTRYID);
		if (pvalue != nullptr)
			dprop.emplace_back(PR_CREATOR_ENTRYID, pvalue);
	}
	if (!sprop.has(PR_LAST_MODIFIER_NAME)) {
		auto pvalue = sprop.get<char>(PR_SENDER_NAME);
		if (pvalue == nullptr)
			pvalue = sprop.get<char>(PR_SENT_REPRESENTING_NAME);
		if (pvalue != nullptr)
			dprop.emplace_back(PR_LAST_MODIFIER_NAME, pvalue);
	}
	if (!sprop.has(PR_LAST_MODIFIER_ENTRYID)) {
		auto pvalue = sprop.get<BINARY>(PR_SENDER_ENTRYID);
		if (pvalue == nullptr)
			pvalue = sprop.get<BINARY>(PR_SENT_REPRESENTING_ENTRYID);
		if (pvalue != nullptr)
			dprop.emplace_back(PR_LAST_MODIFIER_ENTRYID, pvalue);
	}
	if (!sprop.has(PR_LAST_MODIFICATION_TIME)) {
		auto v = cu_alloc<mapitime_t>();
		if (v == nullptr)
			return ecServerOOM;
		*v = rop_util_current_nttime();
		dprop.emplace_back(PR_LAST_MODIFICATION_TIME, v);
	}
	auto old_cvindex = sprop.get<BINARY>(PR_CONVERSATION_INDEX);
	auto new_cvid = cu_alloc<BINARY>();
	if (new_cvid == nullptr)
		return ecServerOOM;
	new_cvid->cb = 16;
	if (old_cvindex != nullptr && old_cvindex->cb >= 22) {
		new_cvid->pb = &old_cvindex->pb[6];
	} else {
		new_cvid->pv = common_util_alloc(16);
		if (new_cvid->pv == nullptr)
			return ecServerOOM;
		auto pvalue = sprop.get<char>(PR_CONVERSATION_TOPIC);
		if (pvalue != nullptr && *pvalue != '\0') {
			if (!message_md5_string(pvalue, new_cvid->pb))
				return ecError;
		} else {
			if (!ext_push.init(new_cvid->pb, 16, 0) ||
			    ext_push.p_guid(GUID::random_new()) != EXT_ERR_SUCCESS)
				return ecError;
		}
	}
	dprop.emplace_back(PR_CONVERSATION_ID, new_cvid);
	dprop.emplace_back(PR_CONVERSATION_INDEX_TRACKING, &fake_true);
	if (old_cvindex == nullptr) {
		auto new_cvindex = cu_alloc<BINARY>();
		if (new_cvindex == nullptr)
			return ecServerOOM;
		new_cvindex->pv = common_util_alloc(27);
		if (new_cvindex->pv == nullptr)
			return ecServerOOM;
		auto nt_time = rop_util_current_nttime();
		if (!ext_push.init(new_cvindex->pb, 27, 0) ||
		    ext_push.p_uint8(1) != EXT_ERR_SUCCESS ||
		    ext_push.p_uint32(nt_time >> 32) != EXT_ERR_SUCCESS ||
		    ext_push.p_uint8((nt_time >> 24) & 0xff) != EXT_ERR_SUCCESS ||
		    ext_push.p_bytes(new_cvid->pb, 16) != EXT_ERR_SUCCESS ||
		    ext_push.p_uint32(0xFFFFFFFF) != EXT_ERR_SUCCESS ||
		    ext_push.p_uint8(nt_time & 0xFF) != EXT_ERR_SUCCESS)
			return ecError;
		new_cvindex->cb = ext_push.m_offset;
		dprop.emplace_back(PR_CONVERSATION_INDEX, new_cvindex);
	}
	auto pvalue = sprop.get<char>(PR_CONVERSATION_TOPIC);
	if (pvalue == nullptr)
		pvalue = sprop.get<char>(PR_CONVERSATION_TOPIC_A);
	if (NULL == pvalue) {
		pvalue = sprop.get<char>(PR_NORMALIZED_SUBJECT);
		if (NULL == pvalue) {
			pvalue = sprop.get<char>(PR_NORMALIZED_SUBJECT_A);
			if (pvalue != nullptr)
				dprop.emplace_back(PR_CONVERSATION_TOPIC_A, pvalue);
		} else {
			dprop.emplace_back(PR_CONVERSATION_TOPIC, pvalue);
		}
	}

	dst->children.prcpts = src->children.prcpts;
	auto sal = src->children.pattachments;
	if (sal == nullptr || sal->count == 0) {
		dst->children.pattachments = nullptr;
		return ecSuccess;
	}
	auto dal = dst->children.pattachments = cu_alloc<ATTACHMENT_LIST>();
	if (dal == nullptr)
		return ecServerOOM;
	dal->count = sal->count;
	dal->pplist = cu_alloc<ATTACHMENT_CONTENT *>(sal->count);
	if (dal->pplist == nullptr)
		return ecServerOOM;
	for (unsigned int i = 0; i < sal->count; ++i) {
		if (sal->pplist[i]->pembedded == nullptr) {
			dal->pplist[i] = sal->pplist[i];
			continue;
		}
		dal->pplist[i] = cu_alloc<ATTACHMENT_CONTENT>();
		if (dal->pplist[i] == nullptr)
			return ecServerOOM;
		dal->pplist[i]->proplist = sal->pplist[i]->proplist;
		auto pembedded = cu_alloc<MESSAGE_CONTENT>();
		if (pembedded == nullptr)
			return ecServerOOM;
		auto err = message_rectify_message(sal->pplist[i]->pembedded, pembedded);
		if (err != ecSuccess)
			return err;
		dal->pplist[i]->pembedded = pembedded;
	}
	return ecSuccess;
}
	
/**
 * Optional properties:
 *
 * - if PidTagChangeNumber is absent, one will be assigned and PR_CHANGE_KEY+PCL generated
 * - if PidTagMid is absent, one will be assigned
 *
 * Side effects:
 *
 * - message's PR_INTERNET_ARTICLE_NUMBER is autoassigned
 * - folder's PR_LOCAL_COMMIT_TIME_MAX is updated
 */
static BOOL message_write_message(BOOL b_internal, sqlite3 *psqlite,
    cpid_t cpid, BOOL b_embedded, uint64_t parent_id,
    const MESSAGE_CONTENT *pmsgctnt, uint64_t *pmessage_id, uint64_t *outcn,
    bool *partial_completion)
{
	BOOL b_cn;
	int is_associated = 0;
	BOOL b_exist;
	BOOL b_result;
	uint64_t change_num;
	char sql_string[256];
	MESSAGE_CONTENT msgctnt;
	PROBLEM_ARRAY tmp_problems;
	static const uint32_t fake_uid = 1;

	*partial_completion = false;
	const TPROPVAL_ARRAY *pproplist = &pmsgctnt->proplist;
	auto cn_p = pproplist->get<const eid_t>(PidTagChangeNumber);
	if (cn_p == nullptr) {
		if (cu_allocate_cn(psqlite, &change_num) != ecSuccess)
			return FALSE;
		*outcn = change_num;
		b_cn = FALSE;
	} else {
		*outcn = change_num = rop_util_get_gc_value(*cn_p);
		b_cn = TRUE;
	}
	if (!b_internal) {
		if (message_rectify_message(pmsgctnt, &msgctnt) != ecSuccess)
			return FALSE;
		if (!b_embedded && !b_cn) {
			auto pvalue = cu_xid_to_bin({exmdb_server::is_private() ?
			              	rop_util_make_user_guid(exmdb_server::get_account_id()) :
			              	rop_util_make_domain_guid(exmdb_server::get_account_id()),
			              change_num});
			if (pvalue == nullptr)
				return FALSE;
			msgctnt.proplist.emplace_back(PR_CHANGE_KEY, pvalue);
			pvalue = common_util_pcl_append(nullptr, pvalue);
			if (pvalue == nullptr)
				return FALSE;
			msgctnt.proplist.emplace_back(PR_PREDECESSOR_CHANGE_LIST, pvalue);
		}
		pmsgctnt = &msgctnt;
	}
	uint32_t original_size = 0, message_size = common_util_calculate_message_size(pmsgctnt);
	if (!b_embedded) {
		auto pbool = pproplist->get<const uint8_t>(PR_ASSOCIATED);
		is_associated = pbool != nullptr && *pbool;
		snprintf(sql_string, std::size(sql_string), exmdb_server::is_private() ?
		         "SELECT is_search FROM folders WHERE folder_id=%llu" :
		         "SELECT is_deleted FROM folders WHERE folder_id=%llu",
		         LLU{parent_id});
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		if (pstmt.step() != SQLITE_ROW) {
			*pmessage_id = 0;
			return TRUE;
		}
		uint8_t tmp_byte = sqlite3_column_int64(pstmt, 0);
		pstmt.finalize();
		if (0 != tmp_byte) {
			*pmessage_id = 0;
			return TRUE;
		}
		b_exist = FALSE;
		auto mid_p = pproplist->get<const eid_t>(PidTagMid);
		if (mid_p == nullptr) {
			if (!common_util_allocate_eid_from_folder(psqlite,
			    parent_id, pmessage_id))
				return FALSE;
		} else {
			*pmessage_id = rop_util_get_gc_value(*mid_p);
			snprintf(sql_string, std::size(sql_string), "SELECT parent_fid, message_size"
			          " FROM messages WHERE message_id=%llu", LLU{*pmessage_id});
			pstmt = gx_sql_prep(psqlite, sql_string);
			if (pstmt == nullptr)
				return FALSE;
			if (pstmt.step() != SQLITE_ROW) {
				if (!common_util_check_allocated_eid(psqlite,
				    *pmessage_id, &b_result))
					return FALSE;
				if (!b_result) {
					*pmessage_id = 0;
					return TRUE;
				}
			} else {
				if (gx_sql_col_uint64(pstmt, 0) != parent_id) {
					*pmessage_id = 0;
					return TRUE;
				}
				b_exist = TRUE;
				original_size = sqlite3_column_int64(pstmt, 1);
			}
			pstmt.finalize();
		}
		if (b_exist) {
			snprintf(sql_string, std::size(sql_string), "DELETE FROM message_properties"
			        " WHERE message_id=%llu", LLU{*pmessage_id});
			if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
				return FALSE;
			snprintf(sql_string, std::size(sql_string), "DELETE FROM recipients"
			        " WHERE message_id=%llu", LLU{*pmessage_id});
			if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
				return FALSE;
			snprintf(sql_string, std::size(sql_string), "DELETE FROM attachments"
			        " WHERE message_id=%llu", LLU{*pmessage_id});
			if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
				return FALSE;
			mlog(LV_DEBUG, "exmdb-audit: truncated message %s:f%llu:m%llu (rewrite)",
				exmdb_server::get_dir(), LLU{parent_id}, LLU{*pmessage_id});
			snprintf(sql_string, std::size(sql_string), "DELETE FROM message_changes"
			        "  WHERE message_id=%llu", LLU{*pmessage_id});
			if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
				return FALSE;
			snprintf(sql_string, std::size(sql_string), "UPDATE messages SET change_number=%llu,"
				" message_size=%u, group_id=NULL WHERE message_id=%llu",
				LLU{change_num}, XUI{message_size}, LLU{*pmessage_id});
			if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
				return FALSE;
		} else {
			snprintf(sql_string, std::size(sql_string), "INSERT INTO messages (message_id,"
				" parent_fid, parent_attid, is_associated, "
				"change_number, message_size) VALUES (%llu, %llu, "
				"NULL, %d, %llu, %u)", LLU{*pmessage_id}, LLU{parent_id},
				is_associated, LLU{change_num}, XUI{message_size});
			if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
				return FALSE;
			mlog(LV_DEBUG, "exmdb-audit: created message %s:f%llu:m%llu",
				exmdb_server::get_dir(), LLU{parent_id}, LLU{*pmessage_id});
		}
	} else {
		snprintf(sql_string, std::size(sql_string), "SELECT count(*) FROM "
		          "attachments WHERE attachment_id=%llu", LLU{parent_id});
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
			return FALSE;
		if (1 != sqlite3_column_int64(pstmt, 0)) {
			*pmessage_id = 0;
			return TRUE;
		}
		pstmt.finalize();
		b_exist = FALSE;
		snprintf(sql_string, std::size(sql_string), "SELECT message_id, message_size"
		          " FROM messages WHERE parent_attid=%llu", LLU{parent_id});
		pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		if (pstmt.step() == SQLITE_ROW) {
			*pmessage_id = sqlite3_column_int64(pstmt, 0);
			original_size = sqlite3_column_int64(pstmt, 1);
			b_exist = TRUE;
		}
		pstmt.finalize();
		if (b_exist) {
			snprintf(sql_string, std::size(sql_string), "DELETE FROM messages"
			        " WHERE message_id=%llu", LLU{*pmessage_id});
			if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
				return FALSE;
			mlog(LV_DEBUG, "exmdb-audit: deleted message %s:a%llu:m%llu",
				exmdb_server::get_dir(), LLU{parent_id}, LLU{*pmessage_id});
		} else if (!common_util_allocate_eid(psqlite, pmessage_id)) {
			return FALSE;
		}
		snprintf(sql_string, std::size(sql_string), "INSERT INTO messages (message_id,"
			" parent_fid, parent_attid, change_number, "
			"message_size) VALUES (%llu, NULL, %llu, %llu, %u)",
			LLU{*pmessage_id}, LLU{parent_id}, LLU{change_num}, XUI{message_size});
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return FALSE;
		mlog(LV_DEBUG, "exmdb-audit: created message %s:a%llu:m%llu",
			exmdb_server::get_dir(), LLU{parent_id}, LLU{*pmessage_id});
	}
	if (!cu_set_properties(MAPI_MESSAGE, *pmessage_id, cpid,
	    psqlite, &pmsgctnt->proplist, &tmp_problems))
		return FALSE;
	if (pmsgctnt->proplist.has(PR_BODY) && tmp_problems.has(PR_BODY))
		*partial_completion = true;
	if (pmsgctnt->proplist.has(PR_HTML) && tmp_problems.has(PR_HTML))
		*partial_completion = true;
	if (!b_embedded) {
		void *pvalue = nullptr;
		if (!cu_get_property(MAPI_FOLDER, parent_id, CP_ACP,
		    psqlite, PR_INTERNET_ARTICLE_NUMBER_NEXT, &pvalue))
			return FALSE;
		if (pvalue == nullptr)
			pvalue = deconst(&fake_uid);
		auto next = *static_cast<uint32_t *>(pvalue) + 1;
		if (!cu_set_property(MAPI_FOLDER, parent_id, CP_ACP, psqlite,
		    PR_INTERNET_ARTICLE_NUMBER_NEXT, &next, &b_result))
			return FALSE;	
		if (!cu_set_property(MAPI_MESSAGE, *pmessage_id, CP_ACP, psqlite,
		    PR_INTERNET_ARTICLE_NUMBER, pvalue, &b_result))
			return FALSE;	
	}
	if (NULL != pmsgctnt->children.prcpts) {
		snprintf(sql_string, std::size(sql_string), "INSERT INTO recipients "
		          "(message_id) VALUES (%llu)", LLU{*pmessage_id});
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		for (auto &rcpt : *pmsgctnt->children.prcpts) {
			if (pstmt.step() != SQLITE_DONE)
				return FALSE;
			uint64_t tmp_id = sqlite3_last_insert_rowid(psqlite);
			if (!cu_set_properties(MAPI_MAILUSER, tmp_id, cpid, psqlite,
			    &rcpt, &tmp_problems))
				return FALSE;
		}
	}
	if (NULL != pmsgctnt->children.pattachments) {
		snprintf(sql_string, std::size(sql_string), "INSERT INTO attachments"
		          " (message_id) VALUES (%llu)", LLU{*pmessage_id});
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		for (auto &at : *pmsgctnt->children.pattachments) {
			if (pstmt.step() != SQLITE_DONE)
				return FALSE;
			uint64_t tmp_id = sqlite3_last_insert_rowid(psqlite);
			mlog(LV_DEBUG, "exmdb-audit: created attachment %s:m%llu:a%llu",
				exmdb_server::get_dir(), LLU{*pmessage_id}, LLU{tmp_id});
			auto &atxprops = at.proplist;
			if (!cu_set_properties(MAPI_ATTACH, tmp_id, cpid, psqlite,
			    &atxprops, &tmp_problems))
				return FALSE;
			if (atxprops.has(PR_ATTACH_DATA_BIN) &&
			    tmp_problems.has(PR_ATTACH_DATA_BIN))
				*partial_completion = true;
			if (at.pembedded == nullptr)
				continue;
			uint64_t message_id = 0;
			if (!message_write_message(TRUE, psqlite, cpid, TRUE,
			    tmp_id, at.pembedded, &message_id, &change_num,
			    partial_completion))
				return FALSE;
			if (0 == message_id) {
				*pmessage_id = 0;
				return TRUE;
			}
		}
	}
	if (b_internal)
		return TRUE;
	if (b_embedded) {
		if (original_size > message_size)
			snprintf(sql_string, std::size(sql_string), "UPDATE messages set "
				"message_size=message_size-%u WHERE message_id=?",
				original_size - message_size);
		else
			snprintf(sql_string, std::size(sql_string), "UPDATE messages set "
				"message_size=message_size+%u WHERE message_id=?",
				message_size - original_size);

		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		auto pstmt1 = gx_sql_prep(psqlite, "SELECT message_id FROM"
		              " attachments WHERE attachment_id=?");
		if (pstmt1 == nullptr)
			return FALSE;
		auto pstmt2 = gx_sql_prep(psqlite, "SELECT parent_attid, "
		              "is_associated FROM messages WHERE message_id=?");
		if (pstmt2 == nullptr)
			return FALSE;
		while (true) {
			sqlite3_bind_int64(pstmt1, 1, parent_id);
			if (pstmt1.step() != SQLITE_ROW) {
				*pmessage_id = 0;
				return FALSE;
			}
			uint64_t message_id = sqlite3_column_int64(pstmt1, 0);
			sqlite3_bind_int64(pstmt, 1, message_id);
			if (pstmt.step() != SQLITE_DONE)
				return FALSE;
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt2, 1, message_id);
			if (pstmt2.step() != SQLITE_ROW) {
				*pmessage_id = 0;
				return FALSE;
			}
			if (SQLITE_NULL == sqlite3_column_type(pstmt2, 0)) {
				is_associated = sqlite3_column_int64(pstmt2, 1);
				break;
			}
			parent_id = sqlite3_column_int64(pstmt2, 0);
		}
	}
	if (original_size > message_size) {
		auto d = original_size - message_size;
		if (!cu_adjust_store_size(psqlite, ADJ_DECREASE,
		    is_associated ? 0 : d, is_associated ? d : 0))
			return FALSE;
	} else {
		auto d = message_size - original_size;
		if (!cu_adjust_store_size(psqlite, ADJ_INCREASE,
		    is_associated ? 0 : d, is_associated ? d : 0))
			return FALSE;
	}
	if (b_embedded)
		return TRUE;
	auto nt_time = rop_util_current_nttime();
	return cu_set_property(MAPI_FOLDER, parent_id, CP_ACP, psqlite,
	       PR_LOCAL_COMMIT_TIME_MAX, &nt_time, &b_result);
}

static BOOL message_load_folder_rules(const rulexec_in &rp,
    std::vector<rule_node> &plist) try
{
	char sql_string[256];
	
	snprintf(sql_string, std::size(sql_string), "SELECT state, rule_id, "
	         "sequence, provider FROM rules WHERE folder_id=%lld "
	         "AND provider IS NOT NULL", LLU{rp.folder_id});
	auto pstmt = gx_sql_prep(rp.sqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		uint32_t state = sqlite3_column_int64(pstmt, 0);
		if (state & (ST_PARSE_ERROR | ST_ERROR))
			continue;
		if (state & ST_ENABLED) {
			/* do nothing */
		} else if (state & ST_ONLY_WHEN_OOF) {
			if (!rp.oof)
				continue;
		} else {
			continue;
		}
		uint64_t msg_id = sqlite3_column_int64(pstmt, 1);
		int32_t seq = pstmt.col_int64(2);
		plist.push_back(rule_node{seq, state, msg_id, pstmt.col_text(3)});
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1561: ENOMEM");
	return false;
}

static BOOL message_load_folder_ext_rules(const rulexec_in &rp,
    std::vector<rule_node> &plist) try
{
	size_t num_rules = 0;
	auto qstr = fmt::format(
		"SELECT m.message_id, p2.propval AS state, p3.propval AS seq, "
		"p4.propval AS prov FROM messages AS m "
		"INNER JOIN message_properties AS p1 "
		"ON m.message_id=p1.message_id AND m.parent_fid={} AND "
		"m.is_associated=1 AND m.is_deleted=0 AND p1.proptag={} AND "
		"(p1.propval='IPM.ExtendedRule.Message' COLLATE NOCASE OR "
		"p1.propval LIKE 'IPM.ExtendedRule.Message.')"
		"LEFT JOIN message_properties AS p2 "
		"ON m.message_id=p2.message_id AND p2.proptag={} "
		"LEFT JOIN message_properties AS p3 "
		"ON m.message_id=p3.message_id AND p3.proptag={} "
		"LEFT JOIN message_properties AS p4 "
		"ON m.message_id=p4.message_id AND p4.proptag={}",
		rp.folder_id, PR_MESSAGE_CLASS, PR_RULE_MSG_STATE,
		PR_RULE_MSG_SEQUENCE, PR_RULE_MSG_PROVIDER);
	auto pstmt = gx_sql_prep(rp.sqlite, qstr.c_str());
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		uint64_t message_id = sqlite3_column_int64(pstmt, 0);
		uint32_t state = pstmt.col_uint64(1);
		if (state & (ST_PARSE_ERROR | ST_ERROR))
			continue;
		if (state & ST_ENABLED) {
			/* do nothing */
		} else if (state & ST_ONLY_WHEN_OOF) {
			if (!rp.oof)
				continue;
		} else {
			continue;
		}
		int32_t seq = pstmt.col_int64(2);
		plist.push_back(rule_node{seq, state, message_id, pstmt.col_text(3), true});
		if (++num_rules >= g_max_extrule_num)
			break;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1507: ENOMEM");
	return false;
}

static BOOL message_get_real_propid(sqlite3 *psqlite,
    NAMEDPROPERTY_INFO *ppropname_info, uint32_t *pproptag, BOOL *pb_replaced)
{
	int i;
	PROPID_ARRAY propids;
	PROPNAME_ARRAY propnames;
	
	uint16_t propid = PROP_ID(*pproptag);
	*pb_replaced = FALSE;
	if (!is_nameprop_id(propid))
		return TRUE;
	for (i = 0; i < ppropname_info->count; ++i)
		if (propid == ppropname_info->ppropid[i])
			break;
	if (i >= ppropname_info->count)
		return TRUE;
	propnames.count = 1;
	propnames.ppropname = &ppropname_info->ppropname[i];
	if (!common_util_get_named_propids(psqlite, TRUE, &propnames, &propids))
		return FALSE;
	if (propids.size() != 1)
		return TRUE;
	if (propids[0] == 0)
		return TRUE;
	*pproptag = PROP_TAG(PROP_TYPE(*pproptag), propids[0]);
	*pb_replaced = TRUE;
	return TRUE;
}

static BOOL message_replace_restriction_propid(sqlite3 *psqlite,
    NAMEDPROPERTY_INFO *ppropname_info, RESTRICTION *pres)
{
	BOOL b_replaced;
	
	switch (pres->rt) {
	case RES_AND:
	case RES_OR:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (!message_replace_restriction_propid(psqlite,
			    ppropname_info, &pres->andor->pres[i]))
				return FALSE;
		break;
	case RES_NOT:
		if (!message_replace_restriction_propid(psqlite,
		    ppropname_info, &pres->xnot->res))
			return FALSE;
		break;
	case RES_CONTENT: {
		auto rcon = pres->cont;
		if (!message_get_real_propid(psqlite, ppropname_info,
		    &rcon->proptag, &b_replaced))
			return FALSE;
		if (b_replaced)
			rcon->propval.proptag = rcon->proptag;
		break;
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		if (!message_get_real_propid(psqlite, ppropname_info,
		    &rprop->proptag, &b_replaced))
			return FALSE;
		if (b_replaced)
			rprop->propval.proptag = rprop->proptag;
		break;
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (!message_get_real_propid(psqlite, ppropname_info,
		    &rprop->proptag1, &b_replaced))
			return FALSE;
		if (!message_get_real_propid(psqlite, ppropname_info,
		    &rprop->proptag2, &b_replaced))
			return FALSE;
		break;
	}
	case RES_BITMASK:
		if (!message_get_real_propid(psqlite, ppropname_info,
		    &pres->bm->proptag, &b_replaced))
			return FALSE;
		break;
	case RES_SIZE:
		if (!message_get_real_propid(psqlite, ppropname_info,
		    &pres->size->proptag, &b_replaced))
			return FALSE;
		break;
	case RES_EXIST:
		if (!message_get_real_propid(psqlite, ppropname_info,
		    &pres->exist->proptag, &b_replaced))
			return FALSE;
		break;
	case RES_SUBRESTRICTION:
		if (!message_replace_restriction_propid(psqlite,
		    ppropname_info, &pres->sub->res))
			return FALSE;
		break;
	case RES_COMMENT:
	case RES_ANNOTATION: {
		auto rcom = pres->comment;
		for (size_t i = 0; i < rcom->count; ++i)
			if (!message_get_real_propid(psqlite, ppropname_info,
			    &rcom->ppropval[i].proptag, &b_replaced))
				return FALSE;
		if (rcom->pres != nullptr)
			if (!message_replace_restriction_propid(psqlite,
			    ppropname_info, rcom->pres))
				return FALSE;
		break;
	}
	case RES_COUNT:
		if (!message_replace_restriction_propid(psqlite,
		    ppropname_info, &pres->count->sub_res))
			return FALSE;
		break;
	default:
		return TRUE;
	}
	return TRUE;
}

static BOOL message_replace_actions_propid(sqlite3 *psqlite,
    NAMEDPROPERTY_INFO *ppropname_info, EXT_RULE_ACTIONS *pactions)
{
	BOOL b_replaced;
	
	for (auto &a : *pactions)
		if (a.type == OP_TAG &&
		    !message_get_real_propid(psqlite, ppropname_info,
		    &static_cast<TAGGED_PROPVAL *>(a.pdata)->proptag,
		    &b_replaced))
			return FALSE;
	return TRUE;
}

/**
 * @username:   Used for production of DEM message properties that refer
 *              back to the original message
 */
static BOOL message_make_dem(const char *username,
    sqlite3 *psqlite, uint64_t folder_id, uint64_t message_id, uint64_t rule_id,
    uint32_t rule_error, uint32_t action_type, uint32_t block_index,
    const char *provider, seen_list &seen) try
{
	if (!g_enable_dam)
		return TRUE;
	if (!exmdb_server::is_private())
		return TRUE;
	std::unique_ptr<message_content, mc_delete> pmsg(message_content_init());
	if (pmsg == nullptr)
		return FALSE;
	auto nt_time = rop_util_current_nttime();
	if (pmsg->proplist.set(PR_CLIENT_SUBMIT_TIME, &nt_time) != 0 ||
	    pmsg->proplist.set(PR_CREATION_TIME, &nt_time) != 0 ||
	    pmsg->proplist.set(PR_LAST_MODIFICATION_TIME, &nt_time) != 0 ||
	    pmsg->proplist.set(PR_MESSAGE_DELIVERY_TIME, &nt_time) != 0 ||
	    pmsg->proplist.set(PR_MESSAGE_CLASS, "IPC.Microsoft Exchange 4.0.Deferred Error") != 0 ||
	    pmsg->proplist.set(PR_RULE_ACTION_TYPE, &action_type) != 0 ||
	    pmsg->proplist.set(PR_RULE_ACTION_NUMBER, &block_index) != 0 ||
	    pmsg->proplist.set(PR_RULE_ERROR, &rule_error) != 0)
		return FALSE;
	auto newval = common_util_to_private_message_entryid(
				psqlite, username, folder_id, message_id);
	if (newval == nullptr ||
	    pmsg->proplist.set(PR_DAM_ORIGINAL_ENTRYID, newval) != 0)
		return FALSE;
	newval = common_util_to_private_folder_entryid(psqlite, username, folder_id);
	if (newval == nullptr ||
	    pmsg->proplist.set(PR_RULE_FOLDER_ENTRYID, newval) != 0 ||
	    pmsg->proplist.set(PR_RULE_PROVIDER, provider) != 0)
		return FALSE;
	auto tmp_eid = rop_util_make_eid_ex(1, rule_id);
	if (pmsg->proplist.set(PR_RULE_ID, &tmp_eid) != 0)
		return FALSE;
	uint64_t mid_val = 0, cn_val = 0;
	bool partial = false;
	if (!message_write_message(false, psqlite, CP_ACP, false,
	    PRIVATE_FID_DEFERRED_ACTION, pmsg.get(), &mid_val, &cn_val, &partial))
		return FALSE;
	pmsg.reset();
	BOOL b_result = false;
	cu_set_property(MAPI_FOLDER, PRIVATE_FID_DEFERRED_ACTION, CP_ACP,
		psqlite, PR_LOCAL_COMMIT_TIME_MAX, &nt_time, &b_result);
	seen.msg.emplace_back(message_node{PRIVATE_FID_DEFERRED_ACTION, mid_val});
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2026: ENOMEM");
	return false;
}

static ec_error_t message_disable_rule(sqlite3 *psqlite,
	BOOL b_extended, uint64_t id)
{
	void *pvalue;
	BOOL b_result;
	char sql_string[128];
	
	if (!b_extended) {
		snprintf(sql_string, std::size(sql_string), "UPDATE rules SET state=state|%u "
		         "WHERE rule_id=%llu", ST_ERROR, LLU{id});
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return ecError;
		return ecSuccess;
	}
	if (!cu_get_property(MAPI_MESSAGE, id, CP_ACP, psqlite,
	    PR_RULE_MSG_STATE, &pvalue))
		return ecError;
	uint32_t newflags = pvalue != nullptr ? *static_cast<uint32_t *>(pvalue) : 0;
	newflags |= ST_ERROR;
	if (!cu_set_property(MAPI_MESSAGE, id, CP_ACP, psqlite,
	    PR_RULE_MSG_STATE, &newflags, &b_result))
		return ecError;
	return ecSuccess;
}

static BOOL message_get_propids(const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids)
{
	auto psqlite = g_sqlite_for_oxcmail;
	if (psqlite == nullptr)
		return FALSE;
	return common_util_get_named_propids(psqlite, false, ppropnames, ppropids);
}

static BOOL message_get_propname(uint16_t propid,
	PROPERTY_NAME **pppropname) try
{
	PROPNAME_ARRAY propnames;
	
	auto psqlite = g_sqlite_for_oxcmail;
	if (psqlite == nullptr)
		return FALSE;
	if (!common_util_get_named_propnames(psqlite, {propid}, &propnames) ||
	    propnames.size() != 1)
		return FALSE;
	*pppropname = propnames.ppropname;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2227: ENOMEM");
	return false;
}

static bool cu_rcpt_to_list(const TPROPVAL_ARRAY &props,
    std::vector<std::string> &list) try
{
	auto str = props.get<const char>(PR_SMTP_ADDRESS);
	if (str != nullptr) {
		list.emplace_back(str);
		return true;
	}
	auto addrtype = props.get<const char>(PR_ADDRTYPE);
	auto emaddr   = props.get<const char>(PR_EMAIL_ADDRESS);
	if (addrtype != nullptr) {
		std::string es_result;
		auto ret = cvt_genaddr_to_smtpaddr(addrtype, emaddr,
		           g_exmdb_org_name, cu_id2user, es_result);
		if (ret == ecSuccess) {
			list.emplace_back(std::move(es_result));
			return true;
		} else if (ret != ecNullObject) {
			return false;
		}
	}
	auto entryid = props.get<const BINARY>(PR_ENTRYID);
	if (entryid == nullptr)
		return false;
	std::string es_result;
	auto ret = cvt_entryid_to_smtpaddr(entryid, g_exmdb_org_name,
	           cu_id2user, es_result);
	if (ret == ecSuccess)
		list.emplace_back(std::move(es_result));
	return ret == ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2036: ENOMEM");
	return false;
}

static BOOL message_auto_reply(const rulexec_in &rp, uint8_t action_type,
    uint32_t action_flavor, uint32_t template_message_id, GUID template_guid,
    BOOL *pb_result) try
{
	void *pvalue;
	/* Buffers above may be referenced by pmsgctnt (cu_set_propvals) */
	MESSAGE_CONTENT *pmsgctnt;
	
	*pb_result = TRUE;
	if (strcasecmp(rp.ev_from, ENVELOPE_FROM_NULL) == 0)
		return TRUE;
	if (!cu_get_property(MAPI_MESSAGE, rp.message_id, CP_ACP,
	    rp.sqlite, PR_AUTO_RESPONSE_SUPPRESS, &pvalue))
		return FALSE;
	if (NULL != pvalue) {
		if (action_type == OP_REPLY) {
			if (*static_cast<uint32_t *>(pvalue) & AUTO_RESPONSE_SUPPRESS_AUTOREPLY)
				return TRUE;
		} else {
			if (*static_cast<uint32_t *>(pvalue) & AUTO_RESPONSE_SUPPRESS_OOF)
				return TRUE;
		}
	}
	if (!message_read_message(rp.sqlite, CP_ACP, template_message_id, &pmsgctnt))
		return FALSE;
	*pb_result = false;
	if (pmsgctnt == nullptr)
		return TRUE;
	auto msgclass = pmsgctnt->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (msgclass == nullptr)
		return TRUE;
	if (action_type == OP_REPLY) {
		if (class_match_prefix(msgclass, "IPM.Note.rules.ReplyTemplate") != 0)
			return TRUE;
	} else {
		if (class_match_prefix(msgclass, "IPM.Note.rules") != 0)
			return TRUE;
	}
	auto flag = pmsgctnt->proplist.get<const uint8_t>(PR_ASSOCIATED);
	if (flag == nullptr || *flag == 0)
		return TRUE;
	if (template_guid != GUID_NULL) {
		auto bin = pmsgctnt->proplist.get<const BINARY>(PR_REPLY_TEMPLATE_ID);
		if (bin == nullptr || bin->cb != 16)
			return TRUE;
		auto tmp_guid = rop_util_binary_to_guid(bin);
		if (tmp_guid != template_guid)
			return TRUE;
	}
	if (action_flavor & DO_NOT_SEND_TO_ORIGINATOR) {
		if (pmsgctnt->children.prcpts  == nullptr ||
		    pmsgctnt->children.prcpts->count == 0)
			return TRUE;
	} else {
		auto prcpts = cu_alloc<TARRAY_SET>();
		if (prcpts == nullptr)
			return FALSE;
		prcpts->count = 1;
		prcpts->pparray = cu_alloc<TPROPVAL_ARRAY *>(1);
		if (prcpts->pparray == nullptr)
			return FALSE;
		*prcpts->pparray = cu_alloc<TPROPVAL_ARRAY>();
		if (*prcpts->pparray == nullptr)
			return FALSE;
		(*prcpts->pparray)->ppropval = cu_alloc<TAGGED_PROPVAL>(3);
		if ((*prcpts->pparray)->ppropval == nullptr)
			return FALSE;
		(*prcpts->pparray)->ppropval[0].proptag = PR_SMTP_ADDRESS;
		if (!cu_get_property(MAPI_MESSAGE, rp.message_id, CP_ACP,
		    rp.sqlite, PR_SENT_REPRESENTING_SMTP_ADDRESS, &pvalue))
			return FALSE;
		(*prcpts->pparray)->ppropval[0].pvalue = pvalue == nullptr ?
			deconst(rp.ev_from) : pvalue;
		(*prcpts->pparray)->ppropval[1].proptag = PR_RECIPIENT_TYPE;
		auto uv = cu_alloc<uint32_t>();
		if (uv == nullptr)
			return FALSE;
		*uv = MAPI_TO;
		(*prcpts->pparray)->ppropval[1].pvalue = uv;
		if (!cu_get_property(MAPI_MESSAGE, rp.message_id, CP_ACP,
		    rp.sqlite, PR_SENT_REPRESENTING_NAME, &pvalue))
			return FALSE;
		if (NULL == pvalue) {
			(*prcpts->pparray)->count = 2;
		} else {
			(*prcpts->pparray)->count = 3;
			(*prcpts->pparray)->ppropval[2].proptag = PR_DISPLAY_NAME;
			(*prcpts->pparray)->ppropval[2].pvalue = pvalue;
		}
		pmsgctnt->children.prcpts = prcpts;
	}
	std::string subject, content_buff;
	if (action_flavor & STOCK_REPLY_TEMPLATE) {
		if (!exmdb_bouncer_make_content(rp.ev_from, rp.ev_to,
		    rp.sqlite, rp.message_id, "BOUNCE_AUTO_RESPONSE",
		    subject, content_buff))
			return false;
		common_util_remove_propvals(&pmsgctnt->proplist, PR_ASSOCIATED);
		common_util_remove_propvals(&pmsgctnt->proplist, PidTagMid);
		common_util_remove_propvals(&pmsgctnt->proplist, PR_BODY);
		common_util_remove_propvals(&pmsgctnt->proplist, PR_HTML);
		common_util_remove_propvals(&pmsgctnt->proplist, PR_RTF_COMPRESSED);
		cu_set_propval(&pmsgctnt->proplist, PR_BODY, content_buff.c_str());
	}
	g_sqlite_for_oxcmail = rp.sqlite;
	auto log_id = rp.ev_to + ":m"s + std::to_string(rop_util_get_gc_value(template_message_id));
	MAIL imail;
	if (!oxcmail_export(pmsgctnt, log_id.c_str(), false, oxcmail_body::plain_and_html,
	    &imail, common_util_alloc, message_get_propids, message_get_propname)) {
		g_sqlite_for_oxcmail = nullptr;
		return FALSE;
	}
	g_sqlite_for_oxcmail = nullptr;
	auto pmime = imail.get_head();
	if (pmime == nullptr)
		return FALSE;
	pmime->set_field("X-Auto-Response-Suppress", "All");
	pmime->set_field("From", rp.ev_to);
	std::vector<std::string> rcpt_list;
	for (auto &r : *pmsgctnt->children.prcpts) {
		TPROPVAL_ARRAY pv = {r.count, r.ppropval};
		if (!cu_rcpt_to_list(std::move(pv), rcpt_list))
			return false;
	}
	auto ret = ems_send_mail(&imail, rp.ev_to, rcpt_list);
	if (ret != ecSuccess)
		mlog(LV_ERR, "E-1188: ems_send_mail: %s", mapi_strerror(ret));
	*pb_result = TRUE;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2551: ENOMEM");
	return false;
}

static ec_error_t message_bounce_message(const char *from_address,
	const char *account, sqlite3 *psqlite,
	uint64_t message_id, uint32_t bounce_code)
{
	void *pvalue;
	const char *bounce_type = nullptr;
	char tmp_buff[256];
	
	if (strcasecmp(from_address, ENVELOPE_FROM_NULL) == 0 ||
	    strchr(account, '@') == nullptr)
		return ecSuccess;
	switch (bounce_code) {
	case BOUNCE_CODE_MESSAGE_TOO_LARGE:
		bounce_type = "BOUNCE_MAIL_TOO_LARGE";
		break;
	case BOUNCE_CODE_MESSAGE_NOT_DISPLAYED:
		bounce_type = "BOUNCE_CANNOT_DISPLAY";
		break;
	case BOUNCE_CODE_MESSAGE_DENIED:
		bounce_type = "BOUNCE_GENERIC_ERROR";
		break;
	default:
		return ecSuccess;
	}
	if (!cu_get_property(MAPI_MESSAGE, message_id, CP_ACP,
	    psqlite, PR_SENT_REPRESENTING_SMTP_ADDRESS, &pvalue))
		return ecServerOOM;
	std::vector<std::string> rcpt_list;
	try {
		rcpt_list.emplace_back(pvalue == nullptr ? from_address : static_cast<char *>(pvalue));
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-2037: ENOMEM");
		return ecServerOOM;
	}

	vmime::shared_ptr<vmime::message> imail;
	if (!exmdb_bouncer_make(from_address, account, psqlite, message_id,
	    bounce_type, imail))
		return ecServerOOM;
	const char *pvalue2 = strchr(account, '@');
	snprintf(tmp_buff, sizeof(tmp_buff), "postmaster@%s",
	         pvalue2 == nullptr ? "system.mail" : pvalue2 + 1);
	auto ret = ems_send_vmail(std::move(imail), tmp_buff, rcpt_list);
	if (ret != ecSuccess)
		mlog(LV_ERR, "E-1187: ems_send_vmail: %s", mapi_strerror(ret));
	return ecSuccess;
}

template<typename T> static bool msg_rcpt_blocks_to_list(const T &fwd,
    std::vector<std::string> &rcpt_list)
{
	for (auto &rcptprops : fwd) {
		TPROPVAL_ARRAY pv;
		pv.count = rcptprops.count;
		pv.ppropval = rcptprops.ppropval;
		if (!cu_rcpt_to_list(std::move(pv), rcpt_list))
			return false;
	}
	return true;
}

static ec_error_t message_forward_message(const rulexec_in &rp,
    uint32_t action_flavor, std::vector<std::string> &&rcpt_list) try
{
	int offset;
	char tmp_path[256];
	struct tm time_buff;
	char mid_string[128];
	struct stat node_stat;
	char tmp_buff[64*1024];
	MESSAGE_CONTENT *pmsgctnt;

	std::unique_ptr<char[], stdlib_delete> pbuff;
	MAIL imail;
	if (rp.digest.has_value()) {
		if (!get_digest(*rp.digest, "file", mid_string, std::size(mid_string)))
			return ecError;
		snprintf(tmp_path, std::size(tmp_path), "%s/eml/%s",
		         exmdb_server::get_dir(), mid_string);
		wrapfd fd = open(tmp_path, O_RDONLY);
		if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0)
			return ecNotFound;
		if (!S_ISREG(node_stat.st_mode)) {
			errno = ENOENT;
			return ecNotFound;
		}
		pbuff.reset(me_alloc<char>(node_stat.st_size));
		if (pbuff == nullptr)
			return ecServerOOM;
		if (read(fd.get(), pbuff.get(), node_stat.st_size) != node_stat.st_size)
			return ecError;
		imail.clear();
		if (!imail.load_from_str_move(pbuff.get(), node_stat.st_size))
			return ecError;
		auto pmime = imail.get_head();
		if (pmime == nullptr)
			return ecError;
		auto num = pmime->get_field_num("Delivered-To");
		for (int i = 0; i < num; ++i) {
			std::string dvto;
			if (pmime->search_field("Delivered-To", i, dvto) &&
			    strcasecmp(dvto.c_str(), rp.ev_to) == 0)
				return ecSuccess;
		}
	} else {
		if (!message_read_message(rp.sqlite, rp.cpid, rp.message_id,
		    &pmsgctnt) || pmsgctnt == nullptr)
			return ecError;
		auto body_type = get_override_format(*pmsgctnt);
		/* try to avoid TNEF message */
		g_sqlite_for_oxcmail = rp.sqlite;
		auto log_id = rp.ev_to + ":m"s + std::to_string(rop_util_get_gc_value(rp.message_id));
		if (!oxcmail_export(pmsgctnt, log_id.c_str(), false, body_type,
		    &imail, common_util_alloc,
		    message_get_propids, message_get_propname)) {
			g_sqlite_for_oxcmail = nullptr;
			return ecError;
		}
		g_sqlite_for_oxcmail = nullptr;
	}
	int ret = ecSuccess;
	if (action_flavor & FWD_AS_ATTACHMENT) {
		MAIL imail1;
		auto pmime = imail1.add_head();
		if (pmime == nullptr)
			return ecServerOOM;
		pmime->set_content_type("message/rfc822");
		/*
		 * OXORULE v21 §2.2.5.1.1 specifies FWD_AS_ATTACHMENT is
		 * exclusive, so FWD_PRESERVE_SENDER is not evaluated to build
		 * the From line.
		 */
		snprintf(tmp_buff, std::size(tmp_buff), "<%s>", rp.ev_to);
		pmime->set_field("From", tmp_buff);
		offset = 0;
		for (const auto &eaddr : rcpt_list) {
			if (offset == 0)
				offset = gx_snprintf(tmp_buff, std::size(tmp_buff),
				         "<%s>", eaddr.c_str());
			else
				offset += gx_snprintf(tmp_buff + offset,
				          std::size(tmp_buff) - offset, ", <%s>",
				          eaddr.c_str());
			pmime->append_field("Delivered-To", eaddr.c_str());
		}
		pmime->set_field("To", tmp_buff);

		auto pmime_old = imail.get_head();
		memset(tmp_buff, '\0', std::size(tmp_buff));
		if (pmime_old == nullptr ||
		    !pmime_old->get_field("Subject", tmp_buff + 5, std::size(tmp_buff) - 5))
			snprintf(tmp_buff, std::size(tmp_buff), "Fwd: (no subject)");
		else
			memcpy(tmp_buff, "Fwd: ", 5);
		pmime->set_field("Subject", tmp_buff);
		auto cur_time = time(nullptr);
		strftime(tmp_buff, 128, "%a, %d %b %Y %H:%M:%S %z", 
			localtime_r(&cur_time, &time_buff));
		pmime->set_field("Date", tmp_buff);
		pmime->write_mail(&imail);
		/* Set new envelope FROM */
		gx_strlcpy(tmp_buff, (action_flavor & FWD_PRESERVE_SENDER) ?
		           rp.ev_from : rp.ev_to, std::size(tmp_buff));
		ret = ems_send_mail(&imail1, tmp_buff, rcpt_list);
	} else {
		auto pmime = imail.get_head();
		if (pmime == nullptr)
			return ecError;
		for (const auto &eaddr : rcpt_list)
			pmime->append_field("Delivered-To", eaddr.c_str());
		/* Set new envelope FROM */
		gx_strlcpy(tmp_buff, (action_flavor & FWD_PRESERVE_SENDER) ?
		           rp.ev_from : rp.ev_to, std::size(tmp_buff));
		ret = ems_send_mail(&imail, tmp_buff, rcpt_list);
	}
	if (ret != ecSuccess)
		mlog(LV_ERR, "E-1186: ems_send_mail: %s", mapi_strerror(ret));
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2550: ENOMEM");
	return ecServerOOM;
}

static BOOL message_make_dam(const rulexec_in &rp,
    const char *provider, std::list<DAM_NODE> &&dam_list, seen_list &seen) try
{
	if (!g_enable_dam)
		return TRUE;
	EXT_PUSH ext_push;
	uint64_t tmp_ids[MAX_DAMS_PER_RULE_FOLDER];
	
	std::unique_ptr<message_content, mc_delete> pmsg(message_content_init());
	if (pmsg == nullptr)
		return FALSE;
	auto nt_time = rop_util_current_nttime();
	uint8_t tmp_byte = 0;
	if (pmsg->proplist.set(PR_CLIENT_SUBMIT_TIME, &nt_time) != 0 ||
	    pmsg->proplist.set(PR_CREATION_TIME, &nt_time) != 0 ||
	    pmsg->proplist.set(PR_LAST_MODIFICATION_TIME, &nt_time) != 0 ||
	    pmsg->proplist.set(PR_MESSAGE_DELIVERY_TIME, &nt_time) != 0 ||
	    pmsg->proplist.set(PR_MESSAGE_CLASS, "IPC.Microsoft Exchange 4.0.Deferred Action") != 0 ||
	    pmsg->proplist.set(PR_DAM_BACK_PATCHED, &tmp_byte) != 0)
		return FALSE;
	auto pvalue = common_util_to_private_message_entryid(
	              rp.sqlite, rp.ev_to, rp.folder_id, rp.message_id);
	if (pvalue == nullptr ||
	    pmsg->proplist.set(PR_DAM_ORIGINAL_ENTRYID, pvalue) != 0)
		return FALSE;
	SVREID svreid;
	svreid.pbin = NULL;
	svreid.folder_id  = rop_util_make_eid_ex(1, rp.folder_id);
	svreid.message_id = rop_util_make_eid_ex(1, rp.message_id);
	svreid.instance = 0;
	auto tmp_eid = rop_util_make_eid_ex(1, rp.folder_id);
	if (pmsg->proplist.set(PR_DAM_ORIG_MSG_SVREID, &svreid) != 0 ||
	    pmsg->proplist.set(PR_RULE_FOLDER_FID, &tmp_eid) != 0)
		return FALSE;
	pvalue = common_util_to_private_folder_entryid(
	         rp.sqlite, rp.ev_to, rp.folder_id);
	if (pvalue == nullptr ||
	    pmsg->proplist.set(PR_RULE_FOLDER_ENTRYID, pvalue) != 0 ||
	    pmsg->proplist.set(PR_RULE_PROVIDER, provider) != 0)
		return FALSE;
	RULE_ACTIONS actions;
	actions.pblock = static_cast<ACTION_BLOCK *>(common_util_alloc(sizeof(ACTION_BLOCK) *
	                 dam_list.size()));
	if (actions.pblock == nullptr)
		return FALSE;
	actions.count = 0;
	unsigned int id_count = 0;
	for (auto &&node : dam_list) {
		actions.pblock[actions.count++] = *node.pblock;
		tmp_eid = rop_util_make_eid_ex(1, node.rule_id);
		unsigned int i;
		for (i = 0; i < id_count; ++i)
			if (tmp_ids[i] == tmp_eid)
				break;
		if (i >= id_count && id_count < std::size(tmp_ids))
			tmp_ids[id_count++] = tmp_eid;
	}
	if (!ext_push.init(nullptr, 0, EXT_FLAG_UTF16) ||
	    ext_push.p_rule_actions(actions) != EXT_ERR_SUCCESS)
		return FALSE;
	BINARY tmp_bin;
	tmp_bin.pb = ext_push.m_udata;
	tmp_bin.cb = ext_push.m_offset;
	if (pmsg->proplist.set(PR_CLIENT_ACTIONS, &tmp_bin) != 0)
		return FALSE;
	tmp_bin.pv = tmp_ids;
	tmp_bin.cb = sizeof(uint64_t)*id_count;
	uint64_t mid_val = 0, cn_val = 0;
	bool partial = false;
	if (pmsg->proplist.set(PR_RULE_IDS, &tmp_bin) != 0 ||
	    !message_write_message(false, rp.sqlite, CP_ACP, false,
	    PRIVATE_FID_DEFERRED_ACTION, pmsg.get(), &mid_val, &cn_val, &partial))
		return FALSE;
	pmsg.reset();
	BOOL b_result = false;
	cu_set_property(MAPI_FOLDER, PRIVATE_FID_DEFERRED_ACTION, CP_ACP,
		rp.sqlite, PR_LOCAL_COMMIT_TIME_MAX, &nt_time, &b_result);
	seen.msg.emplace_back(message_node{PRIVATE_FID_DEFERRED_ACTION, mid_val});
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2027: ENOMEM");
	return false;
}

static BOOL message_make_dams(const rulexec_in &rp,
    std::list<DAM_NODE> &&dam_list, seen_list &seen) try
{
	if (!g_enable_dam)
		return TRUE;
	const char *provider;
	
	if (!exmdb_server::is_private())
		return TRUE;
	if (dam_list.size() > MAX_DAMS_PER_RULE_FOLDER) {
		mlog(LV_NOTICE, "user=%s host=unknown  "
			"DAM error: Too many Deferred Actions "
			"triggered by message %llu in folder "
			"%llu", rp.ev_to, LLU{rp.message_id}, LLU{rp.folder_id});
		return TRUE;
	}
	provider = NULL;
	std::list<DAM_NODE> tmp_list;
	auto tail = dam_list.size() > 0 ? &dam_list.back() : nullptr;
	while (dam_list.size() > 0) {
		auto pdnode = &dam_list.front();
		if (provider == nullptr) {
			provider = pdnode->provider;
			tmp_list.splice(tmp_list.end(), dam_list, dam_list.begin());
		} else if (strcasecmp(provider, pdnode->provider) == 0) {
			tmp_list.splice(tmp_list.end(), dam_list, dam_list.begin());
		} else {
			dam_list.splice(dam_list.end(), dam_list, dam_list.begin());
		}
		if (pdnode == tail) {
			if (!message_make_dam(rp, provider,
			    std::move(tmp_list), seen))
				return FALSE;
			provider = NULL;
			tmp_list.clear();
			tail = dam_list.size() > 0 ? &dam_list.back() : nullptr;
		}
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2028: ENOMEM");
	return false;
}

static ec_error_t op_move_same(const rulexec_in &rp,
    seen_list &seen, const rule_node &rule, const ACTION_BLOCK &block,
    size_t act_idx, uint64_t &dst_fid, uint64_t &dst_mid, BOOL &b_del) try
{
	auto pmovecopy = static_cast<MOVECOPY_ACTION *>(block.pdata);
	dst_fid = rop_util_get_gc_value(static_cast<SVREID *>(
		       pmovecopy->pfolder_eid)->folder_id);
	if (std::find(seen.fld.cbegin(), seen.fld.cend(), dst_fid) != seen.fld.cend())
		/* Already moved to this folder once. */
		return ecSuccess;
	BOOL b_exist = false;
	if (!cu_is_folder_present(rp.sqlite, dst_fid, &b_exist))
		return ecError;
	if (!b_exist) {
		mlog(LV_WARN, "W-1978: inbox \"%s\": while processing msgid %llxh (folder %llxh), "
		        "an OP_MOVE/OP_COPY rule was disabled "
		        "because target folder %llxh does not exist",
		        znul(rp.ev_to), LLU{rp.message_id}, LLU{rp.folder_id}, LLU{dst_fid});
		message_make_dem(rp.ev_to,
			rp.sqlite, rp.folder_id, rp.message_id, rule.id,
			RULE_ERROR_MOVECOPY, block.type,
			act_idx, rule.provider.c_str(), seen);
		return message_disable_rule(rp.sqlite, false, rule.id);
	}
	uint32_t message_size = 0;
	BOOL b_result = false;
	if (!cu_copy_message(rp.sqlite, rp.message_id, dst_fid,
	    &dst_mid, &b_result, &message_size))
		return ecError;
	if (!b_result) {
		message_make_dem(rp.ev_to, rp.sqlite, rp.folder_id,
			rp.message_id, rule.id, RULE_ERROR_MOVECOPY, block.type,
			act_idx, rule.provider.c_str(), seen);
		return ecSuccess;
	}
	auto nt_time = rop_util_current_nttime();
	cu_set_property(MAPI_FOLDER, dst_fid, CP_ACP, rp.sqlite,
		PR_LOCAL_COMMIT_TIME_MAX, &nt_time, &b_result);
	if (!cu_adjust_store_size(rp.sqlite, ADJ_INCREASE, message_size, 0))
		return ecError;
	seen.fld.emplace_back(dst_fid);

	rulexec_in rex = rp;
	char *pmid_string = nullptr;
	rex.folder_id = dst_fid;
	rex.message_id = dst_mid;
	if (exmdb_server::is_private() && rp.digest.has_value() &&
	    common_util_get_mid_string(rp.sqlite, dst_mid, &pmid_string) &&
	    pmid_string != nullptr) {
		(*rex.digest)["file"] = pmid_string;
	}
	auto ec = message_rule_new_message(std::move(rex), seen);
	if (ec != ecSuccess)
		return ec;
	if (block.type == OP_MOVE) {
		b_del = TRUE;
		mlog(LV_DEBUG, "user=%s host=unknown  "
			"OP_MOVE: message f-%llu.m-%llu is going to be moved "
			"and become f-%llu.m-%llu",
			rp.ev_to, LLU{rp.folder_id}, LLU{rp.message_id},
			LLU{dst_fid}, LLU{dst_mid});
	} else {
		mlog(LV_DEBUG, "user=%s host=unknown  "
			"OP_COPY: message f-%llu.m-%llu is going to be copied "
			" and become f-%llu.m-%llu",
			rp.ev_to, LLU{rp.folder_id}, LLU{rp.message_id},
			LLU{dst_fid}, LLU{dst_mid});
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2033: ENOMEM");
	return ecServerOOM;
}

static ec_error_t op_reply(const rulexec_in &rp, seen_list &seen,
    const rule_node &rule, const ACTION_BLOCK &block, size_t act_idx)
{
	auto preply = static_cast<REPLY_ACTION *>(block.pdata);
	BOOL b_result = false;
	if (!message_auto_reply(rp,
	    block.type, block.flavor, rop_util_get_gc_value(
	    preply->template_message_id), preply->template_guid,
	    &b_result))
		return ecError;
	if (b_result)
		return ecSuccess;
	message_make_dem(rp.ev_to, rp.sqlite, rp.folder_id,
		rp.message_id, rule.id, RULE_ERROR_RETRIEVE_TEMPLATE,
		block.type, act_idx, rule.provider.c_str(), seen);
	return message_disable_rule(rp.sqlite, false, rule.id);
}

static ec_error_t op_defer(const rulexec_in &rp, const rule_node &rule,
    const ACTION_BLOCK &block, std::list<DAM_NODE> &dam_list) try
{
	if (!exmdb_server::is_private())
		return ecSuccess;
	dam_list.emplace_back();
	auto pdnode = &dam_list.back();
	pdnode->rule_id = rule.id;
	pdnode->folder_id = rp.folder_id;
	pdnode->message_id = rp.message_id;
	pdnode->provider = rule.provider.c_str();
	pdnode->pblock = &block;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

static ec_error_t op_forward(const rulexec_in &rp, seen_list &seen,
    const rule_node &rule, const ACTION_BLOCK &block, size_t act_idx)
{
	if (!exmdb_server::is_private())
		return ecSuccess;
	auto pfwddlgt = static_cast<const FORWARDDELEGATE_ACTION *>(block.pdata);
	if (pfwddlgt->count > MAX_RULE_RECIPIENTS) {
		message_make_dem(rp.ev_to, rp.sqlite, rp.folder_id,
			rp.message_id, rule.id, RULE_ERROR_TOO_MANY_RCPTS,
			block.type, act_idx, rule.provider.c_str(), seen);
		return message_disable_rule(rp.sqlite, false, rule.id);
	}
	std::vector<std::string> rcpt_list;
	if (!msg_rcpt_blocks_to_list(*pfwddlgt, rcpt_list))
		return ecError;
	return message_forward_message(rp, block.flavor, std::move(rcpt_list));
}

static ec_error_t op_delegate(const rulexec_in &rp, seen_list &seen,
    const rule_node &rule, const ACTION_BLOCK &block, size_t act_idx) try
{
	auto pfwddlgt = static_cast<const FORWARDDELEGATE_ACTION *>(block.pdata);
	if (!exmdb_server::is_private() || !rp.digest.has_value() ||
	    pfwddlgt->count == 0)
		return ecSuccess;
	if (pfwddlgt->count > MAX_RULE_RECIPIENTS) {
		message_make_dem(rp.ev_to, rp.sqlite, rp.folder_id,
			rp.message_id, rule.id, RULE_ERROR_TOO_MANY_RCPTS,
			block.type, act_idx, rule.provider.c_str(), seen);
		return message_disable_rule(rp.sqlite, false, rule.id);
	}

	std::string essdn_buff;
	char display_name[1024];
	BINARY searchkey_bin;
	/* Buffers above may be referenced by pmsgctnt (cu_set_propvals) */
	MESSAGE_CONTENT *pmsgctnt = nullptr;

	if (!message_read_message(rp.sqlite, rp.cpid, rp.message_id, &pmsgctnt) ||
	    pmsgctnt == nullptr)
		return ecError;
	if (pmsgctnt->proplist.has(PR_DELEGATED_BY_RULE)) {
		mlog(LV_DEBUG, "user=%s host=unknown  Delegated"
			" message %llu in folder %llu cannot be delegated"
			" again", rp.ev_to, LLU{rp.message_id}, LLU{rp.folder_id});
		return ecSuccess;
	}
	static constexpr uint32_t tags[] = {
		PR_DISPLAY_TO, PR_DISPLAY_TO_A,
		PR_DISPLAY_CC, PR_DISPLAY_CC_A,
		PR_DISPLAY_BCC, PR_DISPLAY_BCC_A, PidTagMid, PR_MESSAGE_SIZE,
		PR_ASSOCIATED, PidTagChangeNumber,
		PR_CHANGE_KEY, PR_READ, PR_HASATTACH,
		PR_PREDECESSOR_CHANGE_LIST,
		PR_MESSAGE_TO_ME, PR_MESSAGE_CC_ME,
	};
	for (auto t : tags)
		common_util_remove_propvals(&pmsgctnt->proplist, t);
	if (!pmsgctnt->proplist.has(PR_RCVD_REPRESENTING_ENTRYID)) {
		auto err = cvt_username_to_essdn(rp.ev_to, g_exmdb_org_name,
		           mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
		           essdn_buff);
		if (err != ecSuccess)
			return err;
		HX_strupper(essdn_buff.data());
		essdn_buff.insert(0, "EX:");
		auto pvalue = common_util_username_to_addressbook_entryid(rp.ev_to);
		if (pvalue == nullptr)
			return ecError;
		cu_set_propval(&pmsgctnt->proplist, PR_RCVD_REPRESENTING_ENTRYID, pvalue);
		cu_set_propval(&pmsgctnt->proplist, PR_RCVD_REPRESENTING_ADDRTYPE, "EX");
		cu_set_propval(&pmsgctnt->proplist, PR_RCVD_REPRESENTING_EMAIL_ADDRESS, &essdn_buff[3]);
		if (mysql_adaptor_get_user_displayname(rp.ev_to, display_name,
		    std::size(display_name)))
			cu_set_propval(&pmsgctnt->proplist, PR_RCVD_REPRESENTING_NAME, display_name);
		searchkey_bin.cb = essdn_buff.size() + 1;
		searchkey_bin.pv = deconst(essdn_buff.c_str());
		cu_set_propval(&pmsgctnt->proplist, PR_RCVD_REPRESENTING_SEARCH_KEY, &searchkey_bin);
	}
	cu_set_propval(&pmsgctnt->proplist, PR_DELEGATED_BY_RULE, &fake_true);

	std::vector<std::string> rcpt_list;
	if (!msg_rcpt_blocks_to_list(*pfwddlgt, rcpt_list))
		return ecError;
	char mid_string1[128], tmp_path1[256];
	get_digest(*rp.digest, "file", mid_string1, std::size(mid_string1));
	snprintf(tmp_path1, std::size(tmp_path1), "%s/eml/%s",
		 exmdb_server::get_dir(), mid_string1);
	for (const auto &eaddr : rcpt_list) {
		sql_meta_result mres;
		if (mysql_adaptor_meta(eaddr.c_str(), WANTPRIV_METAONLY, mres) != 0)
			continue;
		auto maildir = mres.maildir.c_str();
		if (*maildir == '\0') {
			mlog(LV_ERR, "E-1740: copy from %s to delegate %s not possible: no homedir",
				tmp_path1, eaddr.c_str());
			continue;
		}
		auto mid_string = std::to_string(time(nullptr)) + "." +
				  std::to_string(common_util_sequence_ID()) + "." +
				  get_host_ID();
		auto eml_path = maildir + "/eml/"s + mid_string;
		auto ret = HX_copy_file(tmp_path1, eml_path.c_str(), 0);
		if (ret < 0) {
			mlog(LV_ERR, "E-1606: HX_copy_file %s -> %s: %s",
			        tmp_path1, eml_path.c_str(), strerror(-ret));
			continue;
		}
		Json::Value newdigest = *rp.digest;
		newdigest["file"] = std::move(mid_string);
		auto djson = json_to_str(newdigest);
		uint32_t result = 0;
		if (!exmdb_client_relay_delivery(maildir, rp.ev_from,
		    eaddr.c_str(), rp.cpid, pmsgctnt, djson.c_str(), &result))
			return ecError;
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1130: ENOMEM");
	return ecServerOOM;
}

static ec_error_t op_switch(const rulexec_in &rp, seen_list &seen,
    const rule_node &rule, const ACTION_BLOCK &block, size_t act_idx,
    BOOL &b_del, std::list<DAM_NODE> &dam_list)
{
	switch (block.type) {
	case OP_MOVE:
	case OP_COPY: {
		uint64_t dst_fid, dst_mid = 0;
		auto pmovecopy = static_cast<MOVECOPY_ACTION *>(block.pdata);
		return pmovecopy->same_store ?
		       op_move_same(rp, seen, rule, block, act_idx, dst_fid, dst_mid, b_del) :
		       op_defer(rp, rule, block, dam_list);
	}
	case OP_REPLY:
	case OP_OOF_REPLY:
		return op_reply(rp, seen, rule, block, act_idx);
	case OP_DEFER_ACTION:
		return op_defer(rp, rule, block, dam_list);
	case OP_BOUNCE: {
		auto ec = message_bounce_message(rp.ev_from, rp.ev_to,
		          rp.sqlite, rp.message_id,
		          *static_cast<uint32_t *>(block.pdata));
		if (ec != ecSuccess)
			return ec;
		b_del = TRUE;
		mlog(LV_DEBUG, "user=%s host=unknown  "
			"Message %llu in folder %llu is going"
			" to be deleted by rule", rp.ev_to,
			LLU{rp.message_id}, LLU{rp.folder_id});
		break;
	}
	case OP_FORWARD:
		return op_forward(rp, seen, rule, block, act_idx);
	case OP_DELEGATE:
		return op_delegate(rp, seen, rule, block, act_idx);
	case OP_TAG: {
		PROBLEM_ARRAY problems{};
		const TPROPVAL_ARRAY vals = {1, static_cast<TAGGED_PROPVAL *>(block.pdata)};
		if (!cu_set_properties(MAPI_MESSAGE, rp.message_id, rp.cpid,
		    rp.sqlite, &vals, &problems))
			return ecError;
		break;
	}
	case OP_DELETE:
		b_del = TRUE;
		mlog(LV_DEBUG, "user=%s host=unknown  "
			"Message %llu in folder %llu is going"
			" to be deleted by rule", rp.ev_to,
			LLU{rp.message_id}, LLU{rp.folder_id});
		break;
	case OP_MARK_AS_READ: {
		if (!exmdb_server::is_private())
			return ecSuccess;
		BOOL b_result = false;
		if (!cu_set_property(MAPI_MESSAGE, rp.message_id, CP_ACP, rp.sqlite,
		    PR_READ, &fake_true, &b_result))
			return ecError;
		break;
	}
	}
	return ecSuccess;
}

static ec_error_t op_process(const rulexec_in &rp,
    seen_list &seen, const rule_node &rule, BOOL &b_del, BOOL &b_exit,
    std::list<DAM_NODE> &dam_list)
{
	if (b_exit && !(rule.state & ST_ONLY_WHEN_OOF))
		return ecSuccess;
	void *pvalue = nullptr;
	if (!common_util_get_rule_property(rule.id, rp.sqlite,
	    PR_RULE_CONDITION, &pvalue))
		return ecError;
	if (pvalue == nullptr || !cu_eval_msg_restriction(rp.sqlite,
	    CP_ACP, rp.message_id, static_cast<RESTRICTION *>(pvalue)))
		return ecSuccess;
	if (rule.state & ST_EXIT_LEVEL)
		b_exit = TRUE;
	RULE_ACTIONS *pactions = nullptr;
	if (!common_util_get_rule_property(rule.id, rp.sqlite,
	    PR_RULE_ACTIONS, reinterpret_cast<void **>(&pactions)))
		return ecError;
	if (pactions == nullptr)
		return ecSuccess;
	for (size_t i = 0; i < pactions->count; ++i) {
		auto ret = op_switch(rp, seen,
		           rule, pactions->pblock[i], i, b_del, dam_list);
		if (ret != ecSuccess)
			return ret;
	}
	return ecSuccess;
}

/* This is for moves within one private store */
static ec_error_t opx_move_private(sqlite3 *psqlite, const rule_node &rule,
    const EXT_MOVECOPY_ACTION *pextmvcp)
{
	if (pextmvcp->folder_eid.folder_type != EITLT_PRIVATE_FOLDER)
		return message_disable_rule(psqlite, TRUE, rule.id);
	if (pextmvcp->folder_eid.database_guid !=
	    rop_util_make_user_guid(exmdb_server::get_account_id()))
		return message_disable_rule(psqlite, TRUE, rule.id);
	return ecSuccess;
}

/* This is for moves within one public store */
static ec_error_t opx_move_public(sqlite3 *psqlite, const rule_node &rule,
    const EXT_MOVECOPY_ACTION *pextmvcp)
{
	if (pextmvcp->folder_eid.folder_type != EITLT_PUBLIC_FOLDER)
		return message_disable_rule(psqlite, TRUE, rule.id);
	if (pextmvcp->folder_eid.database_guid !=
	    rop_util_make_domain_guid(exmdb_server::get_account_id()))
		return message_disable_rule(psqlite, TRUE, rule.id);
	return ecSuccess;
}

static ec_error_t opx_move(const rulexec_in &rp,
    seen_list &seen, const rule_node &rule, const EXT_ACTION_BLOCK &block,
    BOOL &b_del) try
{
	auto pextmvcp = static_cast<EXT_MOVECOPY_ACTION *>(block.pdata);
	auto ec = exmdb_server::is_private() ?
	          opx_move_private(rp.sqlite, rule, pextmvcp) :
	          opx_move_public(rp.sqlite, rule, pextmvcp);
	if (ec != ecSuccess)
		return ec;
	auto dst_fid = rop_util_gc_to_value(
		       pextmvcp->folder_eid.global_counter);
	if (std::find(seen.fld.cbegin(), seen.fld.cend(), dst_fid) != seen.fld.cend())
		/* Already moved to this folder once. */
		return ecSuccess;
	BOOL b_exist = false;
	if (!cu_is_folder_present(rp.sqlite, dst_fid, &b_exist))
		return ecError;
	if (!b_exist)
		return message_disable_rule(rp.sqlite, TRUE, rule.id);
	uint64_t dst_mid = 0;
	uint32_t message_size = 0;
	BOOL b_result = 0;
	if (!cu_copy_message(rp.sqlite, rp.message_id, dst_fid,
	    &dst_mid, &b_result, &message_size))
		return ecError;
	if (!b_result)
		return ecSuccess;
	auto nt_time = rop_util_current_nttime();
	cu_set_property(MAPI_FOLDER, dst_fid, CP_ACP, rp.sqlite,
		PR_LOCAL_COMMIT_TIME_MAX, &nt_time, &b_result);
	if (!cu_adjust_store_size(rp.sqlite, ADJ_INCREASE, message_size, 0))
		return ecError;
	seen.fld.emplace_back(dst_fid);

	rulexec_in rex = rp;
	char *pmid_string = nullptr;
	if (exmdb_server::is_private() && rp.digest.has_value() &&
	    common_util_get_mid_string(rp.sqlite, dst_mid, &pmid_string) &&
	    pmid_string != nullptr)
		(*rex.digest)["file"] = pmid_string;
	ec = message_rule_new_message(std::move(rex), seen);
	if (ec != ecSuccess)
		return ec;
	if (block.type == OP_MOVE) {
		b_del = TRUE;
		mlog(LV_DEBUG, "user=%s host=unknown  "
			"Message %llu in folder %llu is going"
			" to be moved to %llu in folder %llu by "
			"ext rule", rp.ev_to, LLU{rp.message_id},
			LLU{rp.folder_id}, LLU{dst_mid}, LLU{dst_fid});
	} else {
		mlog(LV_DEBUG, "user=%s host=unknown  "
			"Message %llu in folder %llu is going"
			" to be copied to %llu in folder %llu by "
			"ext rule", rp.ev_to, LLU{rp.message_id},
			LLU{rp.folder_id}, LLU{dst_mid}, LLU{dst_fid});
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2031: ENOMEM");
	return ecServerOOM;
}

static ec_error_t opx_reply(const rulexec_in &rp, const rule_node &rule,
    const EXT_ACTION_BLOCK &block)
{
	auto pextreply = static_cast<EXT_REPLY_ACTION *>(block.pdata);
	auto exp_guid = exmdb_server::is_private() ?
	                rop_util_make_user_guid(exmdb_server::get_account_id()) :
	                rop_util_make_domain_guid(exmdb_server::get_account_id());
	if (exp_guid != pextreply->message_eid.message_database_guid)
		return message_disable_rule(rp.sqlite, TRUE, rule.id);
	auto dst_mid = rop_util_gc_to_value(
		       pextreply->message_eid.message_global_counter);
	BOOL b_result = false;
	if (!message_auto_reply(rp, block.type, block.flavor,
	    dst_mid, pextreply->template_guid, &b_result))
		return ecError;
	if (!b_result)
		return message_disable_rule(rp.sqlite, TRUE, rule.id);
	return ecSuccess;
}

static ec_error_t opx_delegate(const rulexec_in &rp, const rule_node &rule,
    const EXT_ACTION_BLOCK &block) try
{
	auto pextfwddlgt = static_cast<const EXT_FORWARDDELEGATE_ACTION *>(block.pdata);
	if (!exmdb_server::is_private() || !rp.digest.has_value() ||
	    pextfwddlgt->count == 0)
		return ecSuccess;
	if (pextfwddlgt->count > MAX_RULE_RECIPIENTS)
		return message_disable_rule(rp.sqlite, TRUE, rule.id);

	std::string essdn_buff;
	char display_name[1024];
	BINARY searchkey_bin;
	/* Buffers above may be referenced by pmsgctnt (cu_set_propvals) */
	MESSAGE_CONTENT *pmsgctnt = nullptr;

	if (!message_read_message(rp.sqlite, rp.cpid,
	    rp.message_id, &pmsgctnt) || pmsgctnt == nullptr)
		return ecError;
	if (pmsgctnt->proplist.has(PR_DELEGATED_BY_RULE)) {
		mlog(LV_DEBUG, "user=%s host=unknown  Delegated"
			" message %llu in folder %llu cannot be delegated"
			" again", rp.ev_to, LLU{rp.message_id}, LLU{rp.folder_id});
		return ecSuccess;
	}
	static constexpr uint32_t tags[] = {
		PR_DISPLAY_TO, PR_DISPLAY_TO_A,
		PR_DISPLAY_CC, PR_DISPLAY_CC_A,
		PR_DISPLAY_BCC, PR_DISPLAY_BCC_A, PidTagMid, PR_MESSAGE_SIZE,
		PR_ASSOCIATED, PidTagChangeNumber,
		PR_CHANGE_KEY, PR_READ, PR_HASATTACH,
		PR_PREDECESSOR_CHANGE_LIST,
		PR_MESSAGE_TO_ME, PR_MESSAGE_CC_ME,
	};
	for (auto t : tags)
		common_util_remove_propvals(&pmsgctnt->proplist, t);
	if (!pmsgctnt->proplist.has(PR_RCVD_REPRESENTING_ENTRYID)) {
		auto err = cvt_username_to_essdn(rp.ev_to, g_exmdb_org_name,
		           mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
		           essdn_buff);
		if (err != ecSuccess)
			return err;
		HX_strupper(essdn_buff.data());
		essdn_buff.insert(0, "EX:");
		auto pvalue = common_util_username_to_addressbook_entryid(rp.ev_to);
		if (pvalue == nullptr)
			return ecError;
		cu_set_propval(&pmsgctnt->proplist, PR_RCVD_REPRESENTING_ENTRYID, pvalue);
		cu_set_propval(&pmsgctnt->proplist, PR_RCVD_REPRESENTING_ADDRTYPE, "EX");
		cu_set_propval(&pmsgctnt->proplist, PR_RCVD_REPRESENTING_EMAIL_ADDRESS, &essdn_buff[3]);
		if (mysql_adaptor_get_user_displayname(rp.ev_to, display_name,
		    std::size(display_name)))
			cu_set_propval(&pmsgctnt->proplist, PR_RCVD_REPRESENTING_NAME, display_name);
		searchkey_bin.cb = essdn_buff.size() + 1;
		searchkey_bin.pv = deconst(essdn_buff.c_str());
		cu_set_propval(&pmsgctnt->proplist, PR_RCVD_REPRESENTING_SEARCH_KEY, &searchkey_bin);
	}
	cu_set_propval(&pmsgctnt->proplist, PR_DELEGATED_BY_RULE, &fake_true);

	std::vector<std::string> rcpt_list;
	if (!msg_rcpt_blocks_to_list(*pextfwddlgt, rcpt_list))
		return ecError;
	char mid_string1[128], tmp_path1[256];
	get_digest(*rp.digest, "file", mid_string1, std::size(mid_string1));
	snprintf(tmp_path1, std::size(tmp_path1), "%s/eml/%s",
	         exmdb_server::get_dir(), mid_string1);
	for (const auto &eaddr : rcpt_list) {
		sql_meta_result mres;
		if (mysql_adaptor_meta(eaddr.c_str(), WANTPRIV_METAONLY, mres) != 0)
			continue;
		auto maildir = mres.maildir.c_str();
		auto mid_string = std::to_string(time(nullptr)) + "." +
				  std::to_string(common_util_sequence_ID()) + "." +
				  get_host_ID();
		auto eml_path = maildir + "/eml/"s + mid_string;
		auto ret = HX_copy_file(tmp_path1, eml_path.c_str(), 0);
		if (ret < 0) {
			mlog(LV_ERR, "E-1607: HX_copy_file %s -> %s: %s",
			        tmp_path1, eml_path.c_str(), strerror(-ret));
			continue;
		}
		Json::Value newdigest = *rp.digest;
		newdigest["file"] = std::move(mid_string);
		auto djson = json_to_str(newdigest);
		uint32_t result = 0;
		if (!exmdb_client_relay_delivery(maildir, rp.ev_from,
		    eaddr.c_str(), rp.cpid, pmsgctnt, djson.c_str(), &result))
			return ecError;
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1128: ENOMEM");
	return ecServerOOM;
}

static ec_error_t opx_switch(const rulexec_in &rp,
    seen_list &seen, const rule_node &rule, const EXT_ACTION_BLOCK &block,
    size_t act_idx, BOOL &b_del)
{
	switch (block.type) {
	case OP_MOVE:
	case OP_COPY:
		return opx_move(rp, seen, rule, block, b_del);
	case OP_REPLY:
	case OP_OOF_REPLY:
		return opx_reply(rp, rule, block);
	case OP_DEFER_ACTION:
		break;
	case OP_BOUNCE: {
		auto ec = message_bounce_message(rp.ev_from, rp.ev_to, rp.sqlite,
		          rp.message_id, *static_cast<uint32_t *>(block.pdata));
		if (ec != ecSuccess)
			return ec;
		b_del = TRUE;
		mlog(LV_DEBUG, "user=%s host=unknown  "
			"Message %llu in folder %llu is going"
			" to be deleted by ext rule", rp.ev_to,
			LLU{rp.message_id}, LLU{rp.folder_id});
		break;
	}
	case OP_FORWARD: {
		auto pextfwddlgt = static_cast<const EXT_FORWARDDELEGATE_ACTION *>(block.pdata);
		if (pextfwddlgt->count > MAX_RULE_RECIPIENTS)
			return message_disable_rule(rp.sqlite, TRUE, rule.id);
		std::vector<std::string> rcpt_list;
		if (!msg_rcpt_blocks_to_list(*pextfwddlgt, rcpt_list))
			return ecError;
		return message_forward_message(rp, block.flavor, std::move(rcpt_list));
	}
	case OP_DELEGATE:
		return opx_delegate(rp, rule, block);
	case OP_TAG: {
		PROBLEM_ARRAY problems{};
		TPROPVAL_ARRAY vals = {1, static_cast<TAGGED_PROPVAL *>(block.pdata)};
		if (!cu_set_properties(MAPI_MESSAGE, rp.message_id, rp.cpid,
		    rp.sqlite, &vals, &problems))
			return ecError;
		break;
	}
	case OP_DELETE:
		b_del = TRUE;
		mlog(LV_DEBUG, "user=%s host=unknown  "
			"Message %llu in folder %llu is going"
			" to be deleted by ext rule", rp.ev_to,
			LLU{rp.message_id}, LLU{rp.folder_id});
		break;
	case OP_MARK_AS_READ: {
		if (!exmdb_server::is_private())
			return ecSuccess;
		BOOL b_result = false;
		if (!cu_set_property(MAPI_MESSAGE, rp.message_id, CP_ACP, rp.sqlite,
		    PR_READ, &fake_true, &b_result))
			return ecError;
		break;
	}
	}
	return ecSuccess;
}

static ec_error_t opx_process(const rulexec_in &rp,
    seen_list &seen, const rule_node &rule, BOOL &b_del, BOOL &b_exit)
{
	if (b_exit && !(rule.state & ST_ONLY_WHEN_OOF))
		return ecSuccess;
	void *pvalue = nullptr;
	if (!cu_get_property(MAPI_MESSAGE, rule.id, CP_ACP, rp.sqlite,
	    PR_EXTENDED_RULE_MSG_CONDITION, &pvalue))
		return ecError;
	auto bv = static_cast<BINARY *>(pvalue);
	if (pvalue == nullptr || bv->cb == 0)
		return ecSuccess;
	EXT_PULL ext_pull;
	ext_pull.init(bv->pb, bv->cb, common_util_alloc,
		EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
	NAMEDPROPERTY_INFO propname_info;
	RESTRICTION restriction;
	if (ext_pull.g_namedprop_info(&propname_info) != EXT_ERR_SUCCESS ||
	    ext_pull.g_restriction(&restriction) != EXT_ERR_SUCCESS)
		return ecSuccess;
	if (!message_replace_restriction_propid(rp.sqlite, &propname_info, &restriction))
		return ecError;
	if (!cu_eval_msg_restriction(rp.sqlite, CP_ACP, rp.message_id, &restriction))
		return ecSuccess;
	if (rule.state & ST_EXIT_LEVEL)
		b_exit = TRUE;
	if (!cu_get_property(MAPI_MESSAGE, rule.id, CP_ACP, rp.sqlite,
	    PR_EXTENDED_RULE_MSG_ACTIONS, &pvalue))
		return ecError;
	if (pvalue == nullptr)
		return ecSuccess;
	ext_pull.init(bv->pb, bv->cb, common_util_alloc,
		EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
	EXT_RULE_ACTIONS ext_actions;
	uint32_t version = 0;
	if (ext_pull.g_namedprop_info(&propname_info) != EXT_ERR_SUCCESS ||
	    ext_pull.g_uint32(&version) != EXT_ERR_SUCCESS ||
	    version != 1 ||
	    ext_pull.g_ext_rule_actions(&ext_actions) != EXT_ERR_SUCCESS)
		return ecSuccess;
	if (!message_replace_actions_propid(rp.sqlite, &propname_info, &ext_actions))
		return ecError;
	for (size_t i = 0; i < ext_actions.count; ++i) {
		auto ret = opx_switch(rp, seen,
		           rule, ext_actions.pblock[i], i, b_del);
		if (ret != ecSuccess)
			return ret;
	}
	return ecSuccess;
}

/* extended rules do not produce DAM or DEM */
static ec_error_t message_rule_new_message(const rulexec_in &rp, seen_list &seen)
{
	std::vector<rule_node> rule_list;
	std::list<DAM_NODE> dam_list;
	
	if (!message_load_folder_rules(rp, rule_list) ||
	    !message_load_folder_ext_rules(rp, rule_list))
		return ecError;
	std::sort(rule_list.begin(), rule_list.end());
	BOOL b_del = false, b_exit = false;
	for (const auto &rnode : rule_list) {
		auto ec = rnode.extended ?
		          opx_process(rp, seen, rnode, b_del, b_exit) :
		          op_process(rp, seen, rnode, b_del, b_exit, dam_list);
		if (ec != ecSuccess)
			return ec;
	}
	if (dam_list.size() > 0 && !message_make_dams(rp, std::move(dam_list), seen))
		return ecError;
	if (!b_del) try {
		seen.msg.emplace_back(message_node{rp.folder_id, rp.message_id});
		return ecSuccess;
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-2029: ENOMEM");
		return ecServerOOM;
	}
	void *pvalue = nullptr;
	if (!cu_get_property(MAPI_MESSAGE, rp.message_id, CP_ACP, rp.sqlite,
	    PR_MESSAGE_SIZE, &pvalue))
		return ecError;
	auto message_size = pvalue != nullptr ? *static_cast<uint32_t *>(pvalue) : 0;
	char sql_string[128];
	snprintf(sql_string, std::size(sql_string), "DELETE FROM messages"
		" WHERE message_id=%llu", LLU{rp.message_id});
	if (gx_sql_exec(rp.sqlite, sql_string) != SQLITE_OK)
		return ecError;
	mlog(LV_DEBUG, "exmdb-audit: hard-deleted message %s:f%llu:m%llu (rule:OP_DELETE)",
		exmdb_server::get_dir(), LLU{rp.folder_id}, LLU{rp.message_id});
	if (!cu_adjust_store_size(rp.sqlite, ADJ_DECREASE, message_size, 0))
		return ecError;
	if (!rp.digest.has_value())
		return ecSuccess;
	char mid_string1[128], tmp_path1[256];
	get_digest(*rp.digest, "file", mid_string1, std::size(mid_string1));
	snprintf(tmp_path1, std::size(tmp_path1), "%s/eml/%s",
	         exmdb_server::get_dir(), mid_string1);
	if (::remove(tmp_path1) != 0 && errno != ENOENT)
		mlog(LV_WARN, "W-1345: remove %s: %s", tmp_path1, strerror(errno));
	return ecSuccess;
}

static unsigned int detect_rcpt_type(const char *account, const TARRAY_SET *rcpts)
{
	if (rcpts == nullptr)
		return MAPI_BCC;
	for (size_t i = 0; i < rcpts->count; ++i) {
		auto rcpt = rcpts->pparray[i];
		auto smtpaddr = rcpt->get<const char>(PR_SMTP_ADDRESS);
		if (smtpaddr == nullptr || strcasecmp(account, smtpaddr) != 0)
			continue;
		auto type = rcpt->get<const uint32_t>(PR_RECIPIENT_TYPE);
		if (type == nullptr)
			continue;
		if (*type == MAPI_TO || *type == MAPI_CC)
			return *type;
	}
	return MAPI_BCC;
}

/* 0 means success, 1 means mailbox full, other unknown error */
BOOL exmdb_server::deliver_message(const char *dir, const char *from_address,
    const char *, cpid_t cpid, uint32_t dlflags,
    const MESSAGE_CONTENT *pmsg, const char *pdigest, uint64_t *new_folder_id,
    uint64_t *new_msg_id, uint32_t *presult) try
{
	bool b_oof;
	uint64_t fid_val;
	char tmp_path[256];
	BINARY searchkey_bin;
	char mid_string[128], display_name[1024], account[UDOM_SIZE];

	if (exmdb_server::is_private()) {
		if (!mysql_adaptor_get_username_from_id(exmdb_server::get_account_id(),
		    account, std::size(account)))
			return false;
	} else {
		sql_domain dinfo;
		if (!mysql_adaptor_get_domain_info(exmdb_server::get_account_id(), dinfo))
			return false;
		gx_strlcpy(account, dinfo.name.c_str(), std::size(account));
	}
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	if (cu_check_msgsize_overflow(pdb->psqlite, PR_PROHIBIT_RECEIVE_QUOTA)) {
		*presult = static_cast<uint32_t>(deliver_message_result::mailbox_full_bysize);
		return TRUE;
	} else if (common_util_check_msgcnt_overflow(pdb->psqlite)) {
		*presult = static_cast<uint32_t>(deliver_message_result::mailbox_full_bymsg);
		return TRUE;
	}
	if (exmdb_server::is_private()) {
		void *pvalue;
		if (!cu_get_property(MAPI_STORE, 0, CP_ACP,
		    pdb->psqlite, PR_OOF_STATE, &pvalue))
			return FALSE;
		b_oof = pvb_disabled(pvalue);
		fid_val = PRIVATE_FID_INBOX;
	} else {
		b_oof = false;
		//TODO get public folder id
		mlog(LV_ERR, "%s - public folder not implemented", __PRETTY_FUNCTION__);
		return false;
	}
	seen_list seen{{fid_val}};

	MESSAGE_CONTENT tmp_msg = *pmsg; /* may reference buffers (vars above) */
	std::string essdn_buff;
	if (exmdb_server::is_private()) {
		tmp_msg.proplist.ppropval = cu_alloc<TAGGED_PROPVAL>(pmsg->proplist.count + 15);
		if (tmp_msg.proplist.ppropval == nullptr)
			return FALSE;
		memcpy(tmp_msg.proplist.ppropval, pmsg->proplist.ppropval,
					sizeof(TAGGED_PROPVAL)*pmsg->proplist.count);
		auto pentryid = common_util_username_to_addressbook_entryid(account);
		if (pentryid == nullptr)
			return FALSE;	
		if (cvt_username_to_essdn(account, g_exmdb_org_name,
		    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
		    essdn_buff) != ecSuccess)
			return FALSE;
		HX_strupper(essdn_buff.data());
		essdn_buff.insert(0, "EX:");
		cu_set_propval(&tmp_msg.proplist, PR_RECEIVED_BY_ENTRYID, pentryid);
		cu_set_propval(&tmp_msg.proplist, PR_RECEIVED_BY_ADDRTYPE, "EX");
		cu_set_propval(&tmp_msg.proplist, PR_RECEIVED_BY_EMAIL_ADDRESS, &essdn_buff[3]);
		if (mysql_adaptor_get_user_displayname(account, display_name,
		    std::size(display_name)))
			cu_set_propval(&tmp_msg.proplist, PR_RECEIVED_BY_NAME, display_name);
		else
			display_name[0] = '\0';
		searchkey_bin.cb = essdn_buff.size() + 1;
		searchkey_bin.pv = deconst(essdn_buff.c_str());
		cu_set_propval(&tmp_msg.proplist, PR_RECEIVED_BY_SEARCH_KEY, &searchkey_bin);
		if (!pmsg->proplist.has(PR_RCVD_REPRESENTING_ENTRYID)) {
			cu_set_propval(&tmp_msg.proplist, PR_RCVD_REPRESENTING_ENTRYID, pentryid);
			cu_set_propval(&tmp_msg.proplist, PR_RCVD_REPRESENTING_ADDRTYPE, "EX");
			cu_set_propval(&tmp_msg.proplist, PR_RCVD_REPRESENTING_EMAIL_ADDRESS, &essdn_buff[3]);
			if (*display_name != '\0')
				cu_set_propval(&tmp_msg.proplist, PR_RCVD_REPRESENTING_NAME, display_name);
			cu_set_propval(&tmp_msg.proplist, PR_RCVD_REPRESENTING_SEARCH_KEY, &searchkey_bin);
		}
		auto rcpt_type = detect_rcpt_type(account, pmsg->children.prcpts);
		if (rcpt_type != MAPI_BCC)
			cu_set_propval(&tmp_msg.proplist, rcpt_type == MAPI_TO ?
				PR_MESSAGE_TO_ME : PR_MESSAGE_CC_ME, &fake_true);
	}
	auto nt_time = rop_util_current_nttime();
	auto ts = tmp_msg.proplist.get<uint64_t>(PR_MESSAGE_DELIVERY_TIME);
	if (ts != nullptr)
		*ts = nt_time;
	ts = tmp_msg.proplist.get<uint64_t>(PR_LAST_MODIFICATION_TIME);
	if (ts != nullptr)
		*ts = nt_time;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	bool partial = false;
	uint64_t message_id = 0, new_cn = 0;
	if (!message_write_message(false, pdb->psqlite, cpid, false,
	    fid_val, &tmp_msg, &message_id, &new_cn, &partial))
		return FALSE;
	if (0 == message_id) {
		*presult = static_cast<uint32_t>(deliver_message_result::result_error);
		return TRUE;
	}
	std::optional<Json::Value> digest;
	if (pdigest != nullptr) {
		digest.emplace();
		if (!json_from_str(pdigest, *digest))
			digest.reset();
	}
	if (digest.has_value() &&
	    get_digest(*digest, "file", mid_string, std::size(mid_string))) {
		Json::Value newdigest = *digest;
		newdigest["file"] = "";
		snprintf(tmp_path, std::size(tmp_path), "%s/ext/%s",
		         exmdb_server::get_dir(), mid_string);
		auto djson = json_to_str(std::move(newdigest));
		wrapfd fd = open(tmp_path, O_CREAT | O_TRUNC | O_WRONLY, FMODE_PRIVATE);
		if (fd.get() >= 0) {
			if (HXio_fullwrite(fd.get(), djson.c_str(), djson.size()) < 0 ||
			    fd.close_wr() != 0) {
				mlog(LV_ERR, "E-1319: write %s: %s", tmp_path, strerror(errno));
				return false;
			}
			if (!common_util_set_mid_string(pdb->psqlite,
			    message_id, mid_string))
				return FALSE;
		}
	}
	mlog(LV_DEBUG, "to=%s from=%s fid=%llu delivery mid=%llu (%s)", account,
		znul(from_address), LLU{fid_val}, LLU{message_id},
		partial ? " (partial only)" : "");
	if (dlflags & DELIVERY_DO_RULES) {
		auto ec = message_rule_new_message({from_address, account, cpid, b_oof,
		          pdb->psqlite, fid_val, message_id, std::move(digest)}, seen);
		if (ec != ecSuccess)
			return FALSE;
	}

	if (dlflags & DELIVERY_DO_NOTIF) {
		auto dbase = pdb->lock_base_wr();
		db_conn::NOTIFQ notifq;
		for (const auto &mn : seen.msg) {
			pdb->proc_dynamic_event(cpid, dynamic_event::new_msg,
				mn.folder_id, mn.message_id, 0, *dbase, notifq);
			if (message_id == mn.message_id)
				pdb->notify_new_mail(mn.folder_id,
					mn.message_id, *dbase, notifq);
			else
				pdb->notify_message_creation(mn.folder_id,
					mn.message_id, *dbase, notifq);
		}
		if (sql_transact.commit() != SQLITE_OK)
			return false;
		dg_notify(std::move(notifq));
	} else {
		if (sql_transact.commit() != SQLITE_OK)
			return false;
	}
	*new_folder_id = rop_util_make_eid_ex(1, fid_val);
	*new_msg_id = rop_util_make_eid_ex(1, message_id);
	*presult = static_cast<uint32_t>(partial ?
	           deliver_message_result::partial_completion :
	           deliver_message_result::result_ok);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2032: ENOMEM");
	return false;
}

/**
 * Required properties:
 *
 * - if PidTagChangeNumber is set, so should PR_CHANGE_KEY+PCL
 *
 * Optional properties:
 *
 * - If PidTagMid is set, that MID is used or (if it exists) the message
 *   replaced.
 * - If PR_LAST_MODIFICATION_TIME is not present, it will be set to now().
 */
BOOL exmdb_server::write_message_v2(const char *dir, cpid_t cpid,
    uint64_t folder_id, const MESSAGE_CONTENT *pmsgctnt,
    uint64_t *outmid, uint64_t *outcn, ec_error_t *pe_result)
{
	BOOL b_exist;
	uint64_t mid_val = 0, cn_val = 0, fid_val1 = 0;
	
	b_exist = FALSE;
	auto pmid = pmsgctnt->proplist.get<uint64_t>(PidTagMid);
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	if (cu_check_msgsize_overflow(pdb->psqlite, PR_STORAGE_QUOTA_LIMIT) ||
	    common_util_check_msgcnt_overflow(pdb->psqlite)) {
		*pe_result = MAPI_E_STORE_FULL;
		return TRUE;	
	}
	auto fid_val = rop_util_get_gc_value(folder_id);
	if (NULL != pmid) {
		if (!common_util_get_message_parent_folder(pdb->psqlite,
		    rop_util_get_gc_value(*pmid), &fid_val1))
			return FALSE;	
		if (0 != fid_val1) {
			b_exist = TRUE;
			if (fid_val != fid_val1) {
				*pe_result = ecRpcFailed;
				return TRUE;
			}
		}
	}
	auto nt_time = rop_util_current_nttime();
	auto pvalue = /*mutable*/ deconst(pmsgctnt)->proplist.get<uint64_t>(PR_LAST_MODIFICATION_TIME);
	if (pvalue != nullptr)
		*pvalue = nt_time;

	bool partial = false;
	if (!message_write_message(false, pdb->psqlite, cpid, false,
	    fid_val, pmsgctnt, &mid_val, &cn_val, &partial))
		return FALSE;
	if (0 == mid_val) {
		// auto rollback at end of scope
		*pe_result = ecRpcFailed;
		return false;
	}

	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	if (b_exist) {
		pdb->proc_dynamic_event(cpid, dynamic_event::modify_msg,
			fid_val, mid_val, 0, *dbase, notifq);
		pdb->notify_message_modification(fid_val, mid_val, *dbase, notifq);
	} else {
		pdb->proc_dynamic_event(cpid, dynamic_event::new_msg, fid_val,
			mid_val, 0, *dbase, notifq);
		pdb->notify_message_creation(fid_val, mid_val, *dbase, notifq);
	}
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	dg_notify(std::move(notifq));
	*pe_result = ecSuccess;
	return TRUE;
}

BOOL exmdb_server::write_message(const char *dir, cpid_t cpid,
    uint64_t folder_id, const MESSAGE_CONTENT *ctnt, ec_error_t *e_result)
{
	if (!ctnt->proplist.has(PidTagChangeNumber)) {
		*e_result = ecRpcFailed;
		return TRUE;
	}
	uint64_t outmid = 0, outcn = 0;
	return write_message_v2(dir, cpid, folder_id, ctnt,
	       &outmid, &outcn, e_result);
}

/**
 * @username:   Used for adjusting public store readstates
 */
BOOL exmdb_server::read_message(const char *dir, const char *username,
    cpid_t cpid, uint64_t message_id, MESSAGE_CONTENT **ppmsgctnt)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	if (!exmdb_server::is_private())
		exmdb_server::set_public_username(username);
	auto cl_0 = make_scope_exit([]() { exmdb_server::set_public_username(nullptr); });
	auto mid_val = rop_util_get_gc_value(message_id);
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	auto optim = pdb->begin_optim();
	if (optim == nullptr)
		return FALSE;
	auto ret = message_read_message(pdb->psqlite, cpid, mid_val, ppmsgctnt);
	if (!ret)
		return FALSE;
	optim.reset();
	return sql_transact.commit() == SQLITE_OK ? TRUE : false;
}

/**
 * @dir:        Mailbox where the action occurs
 * @username:   Actor/Rule executor, used for public store readstate tracking only
 */
BOOL exmdb_server::rule_new_message(const char *dir, const char *username,
    cpid_t cpid, uint64_t folder_id, uint64_t message_id) try
{
	char *pmid_string = nullptr, tmp_path[256];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	auto is_pvt = exmdb_server::is_private();
	if (!is_pvt)
		exmdb_server::set_public_username(username);
	auto cl_0 = make_scope_exit([]() { exmdb_server::set_public_username(nullptr); });
	auto fid_val = rop_util_get_gc_value(folder_id);
	auto mid_val = rop_util_get_gc_value(message_id);
	if (is_pvt && !common_util_get_mid_string(pdb->psqlite, mid_val, &pmid_string))
		return FALSE;
	std::optional<Json::Value> digest;
	if (NULL != pmid_string) {
		snprintf(tmp_path, std::size(tmp_path), "%s/ext/%s",
		         exmdb_server::get_dir(), pmid_string);
		size_t slurp_size = 0;
		std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_file(tmp_path, &slurp_size));
		if (slurp_data != nullptr) {
			digest.emplace();
			if (!json_from_str({slurp_data.get(), slurp_size}, *digest))
				digest.reset();
		}
	}
	seen_list seen{{fid_val}};
	char account[UDOM_SIZE];
	if (!mysql_adaptor_get_username_from_id(exmdb_server::get_account_id(),
	    account, std::size(account)))
		return false;
	auto ec = message_rule_new_message({ENVELOPE_FROM_NULL, account, cpid, false,
	          pdb->psqlite, fid_val, mid_val, std::move(digest)}, seen);
	if (ec != ecSuccess)
		return FALSE;
	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	for (const auto &mn : seen.msg) {
		if (mid_val == mn.message_id)
			continue;
		pdb->proc_dynamic_event(cpid, dynamic_event::new_msg,
			mn.folder_id, mn.message_id, 0, *dbase, notifq);
		pdb->notify_message_creation(mn.folder_id, mn.message_id, *dbase, notifq);
	}
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	dg_notify(std::move(notifq));
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2034: ENOMEM");
	return false;
}
