// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2026 grommunio GmbH
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
#include <fmt/format.h>
#include <libHX/endian.h>
#include <libHX/io.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vmime/addressList.hpp>
#include <vmime/dateTime.hpp>
#include <vmime/message.hpp>
#include <vmime/stringContentHandler.hpp>
#include <gromox/algorithm.hpp>
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
#include <gromox/rop_util.hpp>
#include <gromox/ruleproc.hpp>
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

	auto operator<=>(const message_node &) const = default;
};

struct rulexec_in {
	const char *ev_from = nullptr, *ev_to = nullptr;
	cpid_t cpid = CP_ACP;
	bool oof = false;
	const db_conn &db;
	sqlite3 *sqlite = nullptr;
	uint64_t folder_id = 0, message_id = 0;
	std::optional<Json::Value> digest;
};

struct rule_delete_audit {
	const char *subject = nullptr, *folder = nullptr;
	std::string mailbox;
};

struct seen_list {
	std::vector<uint64_t> fld;
	std::vector<message_node> msg;
	std::vector<rule_delete_audit> deletions;
};

static std::string audit_store_location()
{
	if (!exmdb_server::is_private())
		return "public folders";
	std::string account;
	mysql_adaptor_userid_to_name(exmdb_server::get_account_id(), account);
	return "mailbox " + account;
}

}

/*
 * gx_collapse_event_storm: When copying or deleting "lots" of messages,
 * collapse and replace all the new_msg/del_msg event notifications with a
 * single table_change event.
 *
 * Drawback: Upon seeing a table_change event, a MAPI client may re-downloads
 * the MAPI table. If it does, it has *all* rows already. Upon seeing the
 * new_msg event, the client might ― erroneously ― add a message to its local
 * table representation without checking for duplicate entryids.
 *
 * EXC2019 behavior can be selected by using collapse=false (the
 * default).
 */
static bool gx_collapse_event_storm;

/* SF stacking is an unusual usecase and thus disabled for the time being. */
static bool gx_stacked_searches;

static constexpr uint32_t dummy_rcpttype = MAPI_TO;
static constexpr char dummy_addrtype[] = "NONE", dummy_string[] = "";

/* Caution: If a message is soft deleted from a public folder,
	it also should be removed from read_states! if someone's
	read stat is "unread", the item of this user should be
	removed from read_states */

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
	    cu_store_msgsize_limit_reached(*pdb, PR_STORAGE_QUOTA_LIMIT) &&
	    cu_store_msgcount_limit_reached(pdb->psqlite))
		return TRUE;		
	auto mid_val = eid_t(message_id).gcv();
	dst_fid = cu_resolve_folder(pdb->psqlite, dst_fid);
	auto fid_val = eid_t(dst_fid).gcv();
	auto dst_val = eid_t(dst_id).gcv();
	BOOL b_result = false;
	if (!cu_eid_is_allocated(pdb->psqlite, dst_val, &b_result))
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

	// Prepare data for gromox-audit
	void *pv_subject = nullptr, *pv_src_folder = nullptr, *pv_dst_folder = nullptr;
	cu_get_property(MAPI_MESSAGE, mid_val, cpid, *pdb, PR_SUBJECT, &pv_subject);
	cu_get_property(MAPI_FOLDER, parent_fid, CP_ACP, *pdb, PR_DISPLAY_NAME, &pv_src_folder);
	cu_get_property(MAPI_FOLDER, fid_val, CP_ACP, *pdb, PR_DISPLAY_NAME, &pv_dst_folder);
	auto subject = static_cast<const char *>(pv_subject);
	auto src_folder = static_cast<const char *>(pv_src_folder);
	auto dst_folder = static_cast<const char *>(pv_dst_folder);
	auto mailbox = audit_store_location();

	uint32_t message_size = 0;
	if (!cu_copy_message(*pdb, mid_val, fid_val, &dst_val,
	    &b_result, &message_size))
		return FALSE;
	if (!b_result)
		return TRUE;
	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	if (b_move)
		pdb->proc_dynamic_event(cpid, dynamic_event::del_msg,
			parent_fid, mid_val, 0, *dbase, notifq);
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

			mlog(LV_INFO, "exmdb-audit: moved message %s:f%llu:m%llu to f%llu:m%llu",
				dir, LLU{parent_fid}, LLU{mid_val}, LLU{fid_val}, LLU{dst_val});
			b_update = FALSE;
		} else {
			snprintf(sql_string, std::size(sql_string), "UPDATE messages SET "
			        "is_deleted=1 WHERE message_id=%llu", LLU{mid_val});
			if (pdb->exec(sql_string) != SQLITE_OK)
				return FALSE;
			timeindex_delete(pdb->psqlite, parent_fid, mid_val);

			mlog(LV_INFO, "exmdb-audit: moved(PF) message %s:f%llu:m%llu to f%llu:m%llu",
				dir, LLU{parent_fid}, LLU{mid_val}, LLU{fid_val}, LLU{dst_val});

			snprintf(sql_string, std::size(sql_string), "DELETE FROM "
			          "read_states WHERE message_id=%llu", LLU{mid_val});
			if (pdb->exec(sql_string) != SQLITE_OK)
				return FALSE;
		}
	} else {
		mlog(LV_INFO, "exmdb-audit: copied message %s:f%llu:m%llu to f%llu:m%llu",
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
		eid_t tmp_cn(1, change_num);
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
		    *pdb, PR_PREDECESSOR_CHANGE_LIST, &pvalue))
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
	mlog(LV_INFO, "gromox-audit: %s message \"%s\" in %s "
			"from folder \"%s\" to \"%s\"",
			b_move ? "moved" : "copied", txt2cstr(subject).c_str(),
			mailbox.c_str(), txt2cstr(src_folder).c_str(),
			txt2cstr(dst_folder).c_str());
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
    std::span<const eid_t> pmessage_ids, BOOL *pb_partial)
{
	BOOL b_check, b_owner, b_result;
	uint32_t permission, folder_type;
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	*pb_partial = FALSE;
	src_fid = cu_resolve_folder(pdb->psqlite, src_fid);
	dst_fid = cu_resolve_folder(pdb->psqlite, dst_fid);
	auto src_val = eid_t(src_fid).gcv();
	auto dst_val = eid_t(dst_fid).gcv();
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

	// Prepare data for gromox-audit
	auto mailbox = audit_store_location();
	void *pv_src_folder = nullptr, *pv_dst_folder = nullptr;
	cu_get_property(MAPI_FOLDER, src_val, CP_ACP, *pdb, PR_DISPLAY_NAME, &pv_src_folder);
	cu_get_property(MAPI_FOLDER, dst_val, CP_ACP, *pdb, PR_DISPLAY_NAME, &pv_dst_folder);
	auto src_folder = static_cast<const char *>(pv_src_folder);
	auto dst_folder = static_cast<const char *>(pv_dst_folder);

	auto b_batch = gx_collapse_event_storm && pmessage_ids.size() >= MIN_BATCH_MESSAGE_NUM
	/* Table reload in MFCMAPI is ~700msg/sec, whereas event processing is ~100msgevt/sec */
	               /* && table_new_content_count / 7 < pmessage_eids->count */;
	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	if (b_batch)
		pdb->begin_batch_mode(*dbase);
	auto cl_0 = HX::make_scope_exit([&]() {
		if (b_batch)
			pdb->cancel_batch_mode(*dbase);
	});
	auto stm_find = pdb->prep("SELECT parent_fid, "
	             "is_associated FROM messages WHERE message_id=?");
	if (stm_find == nullptr)
		return FALSE;
	bool b_update = true, b_softdel = false;
	xstmt stm_del;
	if (!b_copy) {
		const char *sql_string = nullptr;
		if (exmdb_server::is_private()) {
			sql_string = "DELETE FROM messages WHERE message_id=?";
			b_update = FALSE;
		} else {
			sql_string = "UPDATE messages SET is_deleted=1 WHERE message_id=?";
			b_softdel = true;
		}
		stm_del = pdb->prep(sql_string);
		if (stm_del == nullptr)
			return FALSE;
	}
	uint64_t total_adjust[2]{};
	uint32_t del_count = 0, message_size = 0;
	std::set<uint64_t> touched_folders;
	std::vector<const char *> audit_subjects;
	for (auto mid : pmessage_ids) {
		auto tmp_val = mid.gcv();
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
					if (!cu_msg_test_owner(*pdb,
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
				if (!cu_msg_test_owner(*pdb,
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
		if (!cu_copy_message(*pdb, tmp_val, dst_val, &tmp_val1,
		    &b_result, &message_size))
			return FALSE;
		if (!b_result) {
			*pb_partial = TRUE;
			continue;
		}
		total_adjust[is_associated] += message_size;
		pdb->proc_dynamic_event(cpid, dynamic_event::new_msg,
			dst_val, tmp_val1, 0, *dbase, notifq);
		pdb->notify_message_movecopy(b_copy, dst_val, tmp_val1,
			src_val, tmp_val, *dbase, notifq);

		void *pv_subject = nullptr;
		cu_get_property(MAPI_MESSAGE, tmp_val, cpid, *pdb, PR_SUBJECT, &pv_subject);
		auto subject = static_cast<const char *>(pv_subject);
		try {
			audit_subjects.push_back(subject);
		} catch (...) {
		}
		if (b_copy) {
			mlog(LV_INFO, "exmdb-audit: copied(mmv) message %s:f%llu:m%llu to f%llu:m%llu",
				dir, LLU{src_val}, LLU{tmp_val}, LLU{dst_val}, LLU{tmp_val1});
			continue;
		}

		/* Below here = moves */
		del_count ++;
		stm_del.bind_int64(1, tmp_val);
		if (stm_del.step() != SQLITE_DONE)
			return false;
		stm_del.reset();
		if (!b_copy && b_softdel)
			timeindex_delete(pdb->psqlite, parent_fid, tmp_val);

		mlog(LV_INFO, "exmdb-audit: moved(mmv) message %s:f%llu:m%llu to f%llu:m%llu",
			dir, LLU{src_val}, LLU{tmp_val}, LLU{dst_val}, LLU{tmp_val1});

		if (!exmdb_server::is_private()) {
			char sql_string[63];
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
	if (b_update && total_adjust[0] + total_adjust[1] > 0 &&
	    !cu_adjust_store_size(pdb->psqlite, ADJ_INCREASE, total_adjust[0], total_adjust[1]))
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
		eid_t tmp_cn(1, change_num);
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
		    *pdb, PR_PREDECESSOR_CHANGE_LIST, &pvalue))
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
	for (auto subject : audit_subjects)
		mlog(LV_INFO,
			"gromox-audit: %s%s%s message \"%s\" in %s "
			"from folder \"%s\" to \"%s\"",
			znul(username), username != nullptr ? " " : "",
			b_copy ? "copied" : "moved", txt2cstr(subject).c_str(),
			mailbox.c_str(), txt2cstr(src_folder).c_str(),
			txt2cstr(dst_folder).c_str());
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
    const char *username, uint64_t folder_id, std::span<const eid_t> pmessage_ids,
    BOOL b_hard, BOOL *pb_partial)
{
	/*
	 * When a message is soft-deleted from a EXC2019 Private
	 * Store, and the message is in or beneath IPM_SUBTREE, the
	 * message gets moved to "\Recoverable Items\Deletions"
	 * (new PR_PARENT_ENTRYID, CK/RK/PCL and LastActiveParentEntryId
	 * properties are assigned).
	 *
	 * EXC2019 Public Stores also have \Recoverable Items\Deletions, but
	 * use \NON_IPM_SUBTREE\DUMPSTER_ROOT\DUMPSTER_EXTEND\RESERVED_1\RESERVED_1\<uuid_of_user>.
	 * UUID makes sense, but... who comes up with these paths!?
	 */
	void *pvalue;
	BOOL b_check;
	BOOL b_owner;
	uint32_t permission;
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	if (is_private() && !g_exmdb_pvt_folder_softdel)
		b_hard = true;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	*pb_partial = FALSE;
	folder_id = cu_resolve_folder(pdb->psqlite, folder_id);
	auto src_val = eid_t(folder_id).gcv();
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

	void *pv_src_folder = nullptr;
	cu_get_property(MAPI_FOLDER, src_val, CP_ACP, *pdb, PR_DISPLAY_NAME, &pv_src_folder);
	auto src_folder = static_cast<const char *>(pv_src_folder);
	auto mailbox = audit_store_location();

	auto b_batch = gx_collapse_event_storm && pmessage_ids.size() >= MIN_BATCH_MESSAGE_NUM;
	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	if (b_batch)
		pdb->begin_batch_mode(*dbase);
	auto cl_0 = HX::make_scope_exit([&]() {
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
	uint64_t total_adjust[2]{};
	int del_count = 0;
	std::vector<const char *> audit_subjects;
	auto nt_time = rop_util_current_nttime();
	for (auto mid : pmessage_ids) {
		auto tmp_val = mid.gcv();
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
					if (!cu_msg_test_owner(*pdb,
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
				if (!cu_msg_test_owner(*pdb,
				    tmp_val, username, &b_owner))
					return FALSE;
				if (!b_owner) {
					*pb_partial = TRUE;
					continue;
				}
			}
		}

		void *pv_subject = nullptr;
		cu_get_property(MAPI_MESSAGE, tmp_val, cpid, *pdb, PR_SUBJECT, &pv_subject);
		auto subject = static_cast<const char *>(pv_subject);

		del_count ++;
		total_adjust[is_assoc] += obj_size;
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
		if (!b_hard && !is_assoc)
			timeindex_delete(pdb->psqlite, parent_fid, tmp_val);

		mlog(LV_INFO, "exmdb-audit: %s-deleted message %s:f%llu:m%llu (actor:%s)",
			b_hard ? "hard" : "soft", dir, LLU{src_val}, LLU{tmp_val},
			username != nullptr ? username : "owner");
		try {
			audit_subjects.push_back(subject);
		} catch (...) {
		}

		if (!b_hard) {
			eid_t change_num{};
			if (cu_allocate_cn(pdb->psqlite, &change_num.m_value) != ecSuccess)
				return false;
			change_num = eid_t(1, change_num.m_value);
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
			    *pdb, PR_PREDECESSOR_CHANGE_LIST, &pvalue))
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

			/* For GCT(SHOW_SOFTDELETES), this is a new message now */
			pdb->notify_message_creation(src_val, tmp_val, *dbase, notifq);
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
	    total_adjust[0], total_adjust[1]))
		return FALSE;
	TAGGED_PROPVAL tmp_propvals[5];
	TPROPVAL_ARRAY propvals;
	propvals.count = 5;
	propvals.ppropval = tmp_propvals;
	uint64_t change_num = 0;
	if (cu_allocate_cn(pdb->psqlite, &change_num) != ecSuccess)
		return FALSE;

	eid_t tmp_cn(1, change_num);
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
	    *pdb, PR_PREDECESSOR_CHANGE_LIST, &pvalue))
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
	for (auto subject : audit_subjects)
		mlog(LV_INFO,
			"gromox-audit: %s%s%s-deleted message \"%s\" in %s "
			"from folder \"%s\"",
			znul(username), username != nullptr ? " " : "",
			b_hard ? "hard" : "soft", txt2cstr(subject).c_str(),
			mailbox.c_str(), txt2cstr(src_folder).c_str());
	dg_notify(std::move(notifq));
	if (b_batch) {
		b_batch = false;
		db_conn::commit_batch_mode_release(std::move(pdb), std::move(dbase));
	}
	return TRUE;
}

static bool message_get_message_rcpts(const db_conn &db, uint64_t message_id,
    TARRAY_SET *pset) try
{
	char sql_string[256];
	TAGGED_PROPVAL *ppropval;
	
	snprintf(sql_string, std::size(sql_string), "SELECT count(*) FROM"
	          " recipients WHERE message_id=%llu", LLU{message_id});
	auto &psqlite = db.psqlite;
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
		std::vector<proptag_t> tags;
		if (!cu_get_proptags(MAPI_MAILUSER, rcpt_id, psqlite, tags))
			return false;
		/* Nudge cu_get_properties allocation to make extra room. */
		for (size_t i = 0; i < 5; ++i)
			tags.push_back(PR_NULL);
		pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
		if (pset->pparray[pset->count] == nullptr ||
		    !cu_get_properties(MAPI_MAILUSER, rcpt_id, CP_ACP,
		    db, tags, pset->pparray[pset->count]))
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
	mlog(LV_ERR, "%s: ENOMEM", __func__);
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
	auto mid_val = eid_t(message_id).gcv();
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
	static constexpr proptag_t proptags[] = {
		PR_SUBJECT, PR_SENT_REPRESENTING_NAME,
		PR_SENT_REPRESENTING_SMTP_ADDRESS, PR_CLIENT_SUBMIT_TIME,
		PR_MESSAGE_SIZE, PR_INTERNET_CPID, PR_INTERNET_MESSAGE_ID,
		PR_PARENT_KEY, PR_CONVERSATION_INDEX,
	};
	if (!cu_get_properties(MAPI_MESSAGE, mid_val, cpid,
	    *pdb, proptags, &(*ppbrief)->proplist))
		return FALSE;
	(*ppbrief)->children.prcpts = cu_alloc<TARRAY_SET>();
	if ((*ppbrief)->children.prcpts == nullptr)
		return FALSE;
	if (!message_get_message_rcpts(*pdb, mid_val,
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

	static constexpr proptag_t proptags2[] = {PR_ATTACH_LONG_FILENAME};
	while (pstmt.step() == SQLITE_ROW) {
		uint64_t attachment_id = sqlite3_column_int64(pstmt, 0);
		auto pattachment = cu_alloc<ATTACHMENT_CONTENT>();
		if (pattachment == nullptr)
			return FALSE;
		if (!cu_get_properties(MAPI_ATTACH, attachment_id, cpid,
		    *pdb, proptags2, &pattachment->proplist))
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
	folder_id = cu_resolve_folder(pdb->psqlite, folder_id);
	auto fid_val = eid_t(folder_id).gcv();
	auto mid_val = eid_t(message_id).gcv();
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
	auto mid_val = eid_t(message_id).gcv();
	char sql_string[256];
	snprintf(sql_string, std::size(sql_string), "SELECT is_deleted "
	         "FROM messages WHERE message_id=%llu", LLU{mid_val});
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*pb_del = pstmt.step() != SQLITE_ROW || pstmt.col_uint64(0) ? TRUE : false;
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
	return message_get_message_rcpts(*pdb, eid_t(message_id).gcv(), pset);
}

/**
 * @username:   Used for adjusting public store readstates
 */
BOOL exmdb_server::get_message_properties(const char *dir,
    const char *username, cpid_t cpid, uint64_t message_id,
    proptag_cspan pproptags, TPROPVAL_ARRAY *ppropvals) try
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	if (!exmdb_server::is_private())
		exmdb_server::set_public_username(username);
	auto cl_0 = HX::make_scope_exit([]() STATIC_IN_CXX23 { exmdb_server::set_public_username(nullptr); });
	return cu_get_properties(MAPI_MESSAGE,
	       eid_t(message_id).gcv(), cpid, *pdb,
	       pproptags, ppropvals);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
}

/**
 * @username:   Used for adjusting public store readstates
 *
 * The message_size will not be updated in the function!
 */
BOOL exmdb_server::set_message_properties(const char *dir,
    const char *username, cpid_t cpid, uint64_t message_id,
    const TPROPVAL_ARRAY *pproperties, PROBLEM_ARRAY *pproblems) try
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	if (!exmdb_server::is_private())
		exmdb_server::set_public_username(username);
	auto cl_0 = HX::make_scope_exit([]() STATIC_IN_CXX23 { exmdb_server::set_public_username(nullptr); });
	auto mid_val = eid_t(message_id).gcv();
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	if (!cu_set_properties(MAPI_MESSAGE, mid_val, cpid,
	    pdb->psqlite, pproperties, pproblems))
		return FALSE;
	uint64_t fid_val = 0;
	if (!common_util_get_message_parent_folder(pdb->psqlite,
	    mid_val, &fid_val) || fid_val == 0)
		return FALSE;
	if (std::any_of(pproperties->begin(), pproperties->end(),
	    [](const TAGGED_PROPVAL &p) STATIC_IN_CXX23 { return timeindex_covers(p.proptag); }) &&
	    !timeindex_refresh(pdb->psqlite, fid_val, mid_val))
		return false;
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
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
}

BOOL exmdb_server::remove_message_properties(const char *dir, cpid_t cpid,
    uint64_t message_id, proptag_cspan pproptags)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto mid_val = eid_t(message_id).gcv();
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	if (!cu_remove_properties(MAPI_MESSAGE, mid_val,
	    pdb->psqlite, pproptags))
		return FALSE;
	uint64_t fid_val = 0;
	if (!common_util_get_message_parent_folder(pdb->psqlite,
	    mid_val, &fid_val) || fid_val == 0)
		return FALSE;
	if (std::any_of(pproptags.begin(), pproptags.end(), timeindex_covers) &&
	    !timeindex_refresh(pdb->psqlite, fid_val, mid_val))
		return false;
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
BOOL exmdb_server::set_message_read_state(const char *dir, const char *username,
    uint64_t message_id, uint8_t mark_as_read, uint64_t *pread_cn) try
{
	auto mid_val = eid_t(message_id).gcv();
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
		auto cl_0 = HX::make_scope_exit([]() STATIC_IN_CXX23 { exmdb_server::set_public_username(nullptr); });
		if (cu_set_message_read(pdb->psqlite,
		    mid_val, mark_as_read) != SQLITE_OK)
			return false;
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
		if (cu_set_message_read(pdb->psqlite,
		    mid_val, mark_as_read) != SQLITE_OK)
			return false;
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
	*pread_cn = eid_t(1, read_cn);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
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
		*pmessage_id = eid_t(1, eid_val);
		return sql_transact.commit() == SQLITE_OK ? TRUE : false;
	}
	folder_id = cu_resolve_folder(pdb->psqlite, folder_id);
	auto fid_val = eid_t(folder_id).gcv();
	if (!common_util_allocate_eid_from_folder(pdb->psqlite, fid_val, &eid_val))
		return FALSE;
	*pmessage_id = eid_t(1, eid_val);
	return sql_transact.commit() == SQLITE_OK ? TRUE : false;
}

BOOL exmdb_server::mark_modified(const char *dir, uint64_t message_id)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	auto mid_val = eid_t(message_id).gcv();
	uint32_t *pmessage_flags = nullptr;
	if (!cu_get_msg_flags(*pdb, mid_val, true, &pmessage_flags))
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
	auto mid_val = eid_t(message_id).gcv();
	uint32_t *pmessage_flags = nullptr;
	if (!cu_get_msg_flags(*pdb, mid_val, true, &pmessage_flags))
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
	/* Record the future delivery time for the deferred.cpp scheduler. */
	time_t due = 0;
	if (*pb_marked) {
		static constexpr proptag_t tags[] = {PR_DEFERRED_SEND_TIME,
			PR_DEFERRED_SEND_NUMBER, PR_DEFERRED_SEND_UNITS};
		TPROPVAL_ARRAY pv{};
		if (cu_get_properties(MAPI_MESSAGE, mid_val, CP_ACP, *pdb,
		    tags, &pv)) {
			auto interval = props_to_defer_interval(pv);
			if (interval > 0) {
				due = time(nullptr) + interval;
				char q[160];
				snprintf(q, std::size(q), "INSERT OR REPLACE INTO "
					"deferred_sends (message_id, due_time) VALUES "
					"(%llu, %lld)", LLU{mid_val},
					static_cast<long long>(due));
				if (pdb->exec(q) != SQLITE_OK)
					return false;
			}
		}
	}
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	if (due != 0)
		deferred_sched_arm(dir, mid_val, due);
	return TRUE;
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
	auto mid_val = eid_t(message_id).gcv();
	uint32_t *pmessage_flags = nullptr;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	if (!cu_get_msg_flags(*pdb, mid_val, true, &pmessage_flags))
		return FALSE;
	*pmessage_flags &= ~MSGFLAG_SUBMITTED;
	if (b_unsent)
		*pmessage_flags |= MSGFLAG_UNSENT;
	else
		*pmessage_flags &= ~MSGFLAG_UNSENT;

	if (!cu_set_property(MAPI_MESSAGE, mid_val, CP_ACP, pdb->psqlite,
	    PR_MESSAGE_FLAGS, pmessage_flags, &b_result))
		return FALSE;
	/* Cancel any pending deferred send, even if the flag was already clear. */
	snprintf(sql_string, std::size(sql_string),
		"DELETE FROM deferred_sends WHERE message_id=%llu", LLU{mid_val});
	if (pdb->exec(sql_string) != SQLITE_OK)
		return FALSE;
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	deferred_sched_cancel(dir, mid_val);
	return TRUE;
}

static bool message_read_message(const db_conn &, cpid_t, uint64_t, MESSAGE_CONTENT **);
static BOOL message_get_propids(const PROPNAME_ARRAY *, PROPID_ARRAY *);
static BOOL message_get_propname(propid_t, PROPERTY_NAME **);

/**
 * Re-check at send time that actor may represent delegator. send_as=true for
 * Send-As or self, false for On-Behalf; ecSendAsDenied if revoked.
 */
static ec_error_t defer_check_repr(const char *actor, const char *delegator,
    bool &send_as)
{
	send_as = true;
	if (delegator == nullptr || *delegator == '\0' ||
	    strcasecmp(actor, delegator) == 0)
		return ecSuccess;
	sql_meta_result mres;
	if (mysql_adaptor_meta(delegator, WANTPRIV_METAONLY, mres) != 0)
		return ecSendAsDenied;
	if (strcasecmp(actor, mres.username.c_str()) == 0)
		return ecSuccess;
	/* mode 1 = sendas.txt (Send-As), mode 0 = delegates.txt (On-Behalf) */
	for (uint32_t mode : {uint32_t(1), uint32_t(0)}) {
		std::vector<std::string> dl;
		if (!exmdb_server::read_delegates(mres.maildir.c_str(), mode, &dl))
			continue;
		for (const auto &d : dl)
			if (strcasecmp(d.c_str(), actor) == 0 ||
			    mysql_adaptor_check_mlist_include(d.c_str(), actor)) {
				send_as = mode == 1;
				return ecSuccess;
			}
	}
	return ecSendAsDenied;
}

/**
 * Resolve the represented sender the way oxcmail derives the From header
 * (SMTP, then EX ADDRTYPE+EMAIL, then ENTRYID), so the identity we authorize
 * is the one that goes on the wire. Empty output = no representation. A repr
 * that does not resolve to a local user is refused.
 */
static ec_error_t defer_extract_delegator(const MESSAGE_CONTENT &ctnt,
    std::string &out)
{
	out.clear();
	auto smtp = ctnt.proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (smtp != nullptr && *smtp != '\0') {
		out = smtp;
		return ecSuccess;
	}
	auto addrtype = ctnt.proplist.get<const char>(PR_SENT_REPRESENTING_ADDRTYPE);
	auto emaddr = ctnt.proplist.get<const char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
	if (addrtype != nullptr) {
		auto ret = cvt_genaddr_to_smtpaddr(addrtype, emaddr, g_exmdb_org_name,
		           mysql_adaptor_userid_to_name, out);
		if (ret == ecSuccess)
			return ecSuccess;
		if (ret != ecNullObject && ret != ecUnknownUser)
			return ret;
	}
	auto eid = ctnt.proplist.get<const BINARY>(PR_SENT_REPRESENTING_ENTRYID);
	if (eid == nullptr)
		return ecSuccess; /* no representation requested */
	auto ret = cvt_entryid_to_smtpaddr(eid, g_exmdb_org_name,
	           mysql_adaptor_userid_to_name, out);
	if (ret == ecSuccess)
		return ecSuccess;
	if (ret == ecNullObject) {
		out.clear();
		return ecSuccess;
	}
	return ecSendAsDenied; /* Refuse unresolvable representation */
}

/**
 * Deferred-send second stage (run by deferred.cpp when the time arrives).
 * Build the mime object, submit to the MTA, then file or delete the message.
 */
ec_error_t exmdb_execute_deferred_send(const char *dir, uint64_t mid_val) try
{
	exmdb_server::build_env(EM_PRIVATE, dir);
	auto cl_env = HX::make_scope_exit(exmdb_server::free_env);
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return ecError;

	/*
	 * Claim the job by deleting its row first, so a racing clear_submit
	 * loses and a crash hereafter cannot re-send (at-most-once). Recheck the
	 * message in the same transaction.
	 */
	uint64_t parent_fid = 0;
	bool present = false;
	{
		auto xact = gx_sql_begin(pdb->psqlite, txn_mode::write);
		if (!xact)
			return ecError;
		char q[160];
		snprintf(q, std::size(q), "DELETE FROM deferred_sends "
			"WHERE message_id=%llu", LLU{mid_val});
		if (pdb->exec(q) != SQLITE_OK)
			return ecError;
		if (sqlite3_changes(pdb->psqlite) != 1)
			return ecSuccess; /* cancelled or already claimed */
		snprintf(q, std::size(q), "SELECT parent_fid FROM messages "
			"WHERE message_id=%llu AND is_deleted=0", LLU{mid_val});
		auto st = pdb->prep(q);
		if (st != nullptr && st.step() == SQLITE_ROW) {
			present = true;
			parent_fid = st.col_uint64(0);
		}
		if (xact.commit() != SQLITE_OK)
			return ecError;
	}
	if (!present)
		return ecNotFound;        /* deleted after scheduling */
	if (parent_fid != PRIVATE_FID_OUTBOX)
		return ecSuccess;         /* moved out of the Outbox = cancelled */

	unsigned int uid = 0;
	std::string actor;
	if (!mysql_adaptor_get_id_from_maildir(dir, &uid) ||
	    mysql_adaptor_userid_to_name(uid, actor) != ecSuccess) {
		mlog(LV_ERR, "deferred send %s:m%llu: cannot resolve store owner",
			dir, LLU{mid_val});
		return ecError;
	}

	MESSAGE_CONTENT *ctnt = nullptr;
	if (!message_read_message(*pdb, CP_ACP, mid_val, &ctnt) || ctnt == nullptr)
		return ecError;
	auto prcpts = ctnt->children.prcpts;
	if (prcpts == nullptr || prcpts->count == 0)
		return MAPI_E_NO_RECIPIENTS;

	std::string delegator;
	auto xret = defer_extract_delegator(*ctnt, delegator);
	bool send_as = true;
	auto perr = xret == ecSuccess ?
	            defer_check_repr(actor.c_str(), delegator.c_str(), send_as) : xret;
	if (perr != ecSuccess) {
		mlog(LV_WARN, "deferred send %s:m%llu denied: <%s> may no longer "
			"be represented by <%s>", dir, LLU{mid_val},
			delegator.c_str(), actor.c_str());
		exmdb_server::clear_submit(dir, eid_t(1, mid_val), TRUE);
		return perr;
	}
	const char *ev_from = (send_as && !delegator.empty()) ?
	                      delegator.c_str() : actor.c_str();

	auto msgflags = ctnt->proplist.get<const uint32_t>(PR_MESSAGE_FLAGS);
	bool b_resend = msgflags != nullptr && (*msgflags & MSGFLAG_RESEND);
	std::vector<std::string> rcpt_list;
	for (auto &rcpt : *prcpts) {
		TPROPVAL_ARRAY pv = {rcpt.count, rcpt.ppropval};
		if (cu_rcpt_to_list(std::move(pv), g_exmdb_org_name, rcpt_list,
		    mysql_adaptor_userid_to_name, b_resend) != ecSuccess)
			return ecError;
	}
	if (rcpt_list.empty())
		return MAPI_E_NO_RECIPIENTS;

	auto vmail = vmime::make_shared<vmime::message>();
	g_sqlite_for_oxcmail = pdb->psqlite;
	auto log_id = dir + ":m"s + std::to_string(mid_val);
	oxcmail_converter cvt;
	cvt.log_id = log_id.c_str();
	cvt.alloc = common_util_alloc;
	cvt.get_propids = message_get_propids;
	cvt.get_propname = message_get_propname;
	cvt.use_format_override(*ctnt);
	auto ret = cvt.mapi_to_inet(*ctnt, vmail);
	g_sqlite_for_oxcmail = nullptr;
	if (ret != ecSuccess)
		return ret;

	ret = cu_send_vmail(vmail, g_exmdb_smtp_url.c_str(),
	      ev_from, rcpt_list);
	if (ret != ecSuccess) {
		mlog(LV_ERR, "E-1760: deferred send %s:m%llu via SMTP failed: %s",
			dir, LLU{mid_val}, mapi_strerror(ret));
		exmdb_server::clear_submit(dir, eid_t(1, mid_val), TRUE);
		return ret;
	}
	mlog(LV_INFO, "gromox-audit: deferred message sent from <%s> in mailbox %s",
		ev_from, dir);

	/* Clear MSGFLAG_SUBMITTED on the copy about to be filed. */
	exmdb_server::clear_submit(dir, eid_t(1, mid_val), false);
	auto del_after = ctnt->proplist.get<const uint8_t>(PR_DELETE_AFTER_SUBMIT);
	eid_t mid_eid = eid_t(1, mid_val);
	EID_ARRAY ids = {1, &mid_eid};
	BOOL partial = false;
	if (del_after != nullptr && *del_after != 0)
		exmdb_server::delete_messages(dir, CP_ACP, nullptr,
			eid_t(1, parent_fid), ids, TRUE, &partial);
	else
		/*
		 * NB: Filing always targets Sent Items. PR_SENTMAIL_ENTRYID and the
		 * represented mailbox copy are not honored for deferred sends.
		 */
		exmdb_server::movecopy_messages(dir, CP_ACP, false, nullptr,
			eid_t(1, parent_fid), eid_t(1, PRIVATE_FID_SENT_ITEMS),
			false, ids, &partial);
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
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
	folder_id = cu_resolve_folder(pdb->psqlite, folder_id);
	auto fid_val = eid_t(folder_id).gcv();
	auto mid_val = eid_t(message_id).gcv();
	if (!common_util_get_folder_type(pdb->psqlite, fid_val, &folder_type))
		return FALSE;
	if (folder_type != FOLDER_SEARCH)
		return TRUE;
	snprintf(sql_string, std::size(sql_string), "SELECT message_id FROM "
	          "messages WHERE message_id=%llu", LLU{mid_val});
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return false;
	if (pstmt.step() != SQLITE_ROW)
		return TRUE;
	pstmt.finalize();
	bool b_exist = false;
	if (!cu_srchfld_has_msgresult(pdb->psqlite, fid_val,
	    mid_val, &b_exist))
		return FALSE;
	if (b_exist) {
		/* Already linked; treat re-link as an idempotent success. */
		*pb_result = TRUE;
		return TRUE;
	}
	snprintf(sql_string, std::size(sql_string), "INSERT INTO search_result"
	        " VALUES (%llu, %llu)", LLU{fid_val}, LLU{mid_val});
	if (pdb->exec(sql_string) != SQLITE_OK)
		return FALSE;

	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	if (gx_stacked_searches)
		pdb->proc_dynamic_event(cpid, dynamic_event::new_msg,
			fid_val, mid_val, 0, *dbase, notifq);
	pdb->notify_link_creation(fid_val, mid_val, *dbase, notifq);
	if (sql_transact.commit() != SQLITE_OK)
		return FALSE;
	dg_notify(std::move(notifq));
	*pb_result = TRUE;
	return TRUE;
}

/**
 * Batch variant of link_message which links many messages into a single search
 * folder in one write transaction and one notification flush. This avoids the
 * per-message RPC + transaction + notify overhead that a caller would otherwise
 * incur by calling link_message in a loop (e.g. grommunio-web populating a
 * full-text search folder).
 *
 * @pb_partial: gets set when at least one message could not be linked
 *              (missing or not present). Messages that are already linked are
 *              treated as idempotent/silent successes, matching link_message.
 */
BOOL exmdb_server::link_messages(const char *dir, cpid_t cpid,
    uint64_t folder_id, std::span<const eid_t> message_ids, BOOL *pb_partial)
{
	uint32_t folder_type;

	*pb_partial = false;
	if (!exmdb_server::is_private())
		return false;
	if (message_ids.empty())
		return TRUE;
	auto db = db_engine_get_db(dir);
	if (!db)
		return false;
	folder_id = cu_resolve_folder(db->psqlite, folder_id);
	auto fid_val = eid_t(folder_id).gcv();
	if (!common_util_get_folder_type(db->psqlite, fid_val, &folder_type))
		return false;
	if (folder_type != FOLDER_SEARCH)
		return TRUE;
	auto sql_transact = gx_sql_begin(db->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;

	auto dbase = db->lock_base_wr();
	db_conn::NOTIFQ notifq;
	bool b_partial = false, b_linked = false;
	for (auto a_mid : message_ids) {
		auto mid_val = a_mid.gcv();
		char sql_string[256];
		snprintf(sql_string, std::size(sql_string), "SELECT message_id FROM "
		          "messages WHERE message_id=%llu", LLU{mid_val});
		auto stm = db->prep(sql_string);
		if (stm == nullptr)
			return false;
		if (stm.step() != SQLITE_ROW) {
			/* Message no longer present; record as partial failure. */
			b_partial = true;
			continue;
		}
		stm.finalize();

		bool b_exist = false;
		if (!cu_srchfld_has_msgresult(db->psqlite, fid_val,
		    mid_val, &b_exist))
			return FALSE;
		if (b_exist)
			/* Already linked */
			continue;
		snprintf(sql_string, std::size(sql_string), "INSERT INTO search_result"
		        " VALUES (%llu, %llu)", LLU{fid_val}, LLU{mid_val});
		if (db->exec(sql_string) != SQLITE_OK) {
			b_partial = true;
			continue;
		}
		if (gx_stacked_searches)
			db->proc_dynamic_event(cpid, dynamic_event::new_msg,
				fid_val, mid_val, 0, *dbase, notifq);
		db->notify_link_creation(fid_val, mid_val, *dbase, notifq, false);
		b_linked = true;
	}
	if (b_linked && sql_transact.commit() != SQLITE_OK)
		return false;
	if (b_linked)
		db->notify_folder_modification(
			common_util_get_folder_parent_fid(db->psqlite, fid_val),
			fid_val, *dbase, notifq);
	dg_notify(std::move(notifq));
	*pb_partial = b_partial ? TRUE : false;
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
	/* Only one SQL write, no transaction needed. */
	folder_id = cu_resolve_folder(pdb->psqlite, folder_id);
	auto fid_val = eid_t(folder_id).gcv();
	auto mid_val = eid_t(message_id).gcv();
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

static bool message_read_message(const db_conn &db, cpid_t cpid,
    uint64_t message_id, MESSAGE_CONTENT **ppmsgctnt) try
{
	char sql_string[256];
	snprintf(sql_string, std::size(sql_string), "SELECT message_id FROM"
	          " messages WHERE message_id=%llu", LLU{message_id});
	auto &psqlite = db.psqlite;
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
	std::vector<proptag_t> mtags;
	if (!cu_get_proptags(MAPI_MESSAGE, message_id, psqlite, mtags))
		return FALSE;	
	std::erase_if(mtags, [](proptag_t t) STATIC_IN_CXX23 {
		return t == PR_DISPLAY_TO || t == PR_DISPLAY_TO_A ||
		       t == PR_DISPLAY_CC || t == PR_DISPLAY_CC_A ||
		       t == PR_DISPLAY_BCC || t == PR_DISPLAY_BCC_A ||
		       t == PR_HASATTACH;
	});
	if (!cu_get_properties(MAPI_MESSAGE, message_id, cpid,
	    db, mtags, &(*ppmsgctnt)->proplist))
		return FALSE;
	(*ppmsgctnt)->children.prcpts = cu_alloc<TARRAY_SET>();
	if ((*ppmsgctnt)->children.prcpts == nullptr)
		return FALSE;
	if (!message_get_message_rcpts(db, message_id,
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
		std::vector<proptag_t> atags;
		if (!cu_get_proptags(MAPI_ATTACH, attachment_id,
		    psqlite, atags))
			return FALSE;
		auto pattachment = cu_alloc<ATTACHMENT_CONTENT>();
		if (pattachment == nullptr)
			return FALSE;
		atags.push_back(PR_ATTACH_NUM);
		if (!cu_get_properties(MAPI_ATTACH, attachment_id, cpid,
		    db, atags, &pattachment->proplist))
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
		else if (!message_read_message(db, cpid,
		    sqlite3_column_int64(pstmt1, 0), &pattachment->pembedded) ||
		    pattachment->pembedded == nullptr)
			return FALSE;
		sqlite3_reset(pstmt1);
		auto &ats = *(*ppmsgctnt)->children.pattachments;
		ats.pplist[ats.count++] = pattachment;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
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
    MESSAGE_CONTENT *dst) try
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
		case PR_CONVERSATION_TOPIC:
		case PR_CONVERSATION_TOPIC_A:
			/* Rederived from the subject below. */
			if (*znul(static_cast<const char *>(sprop.ppropval[i].pvalue)) == '\0')
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
		    ext_push.p_guid(GUID::random_new()) != pack_result::ok)
			return ecError;
		dprop.emplace_back(PR_SEARCH_KEY, pbin);
	}
	if (!sprop.has(PR_BODY_CONTENT_ID)) {
		std::string account;
		if (mysql_adaptor_userid_to_name(exmdb_server::get_account_id(), account) != ecSuccess)
			account = "localhost";
		const char *pc = strchr(account.c_str(), '@'); /* CONST-STRCHR-MARKER */
		if (pc == nullptr)
			pc = account.c_str();
		else
			++pc;
		auto pvalue = common_util_dup((bin2hex(FLATUID(GUID::random_new())) + "@" + pc).c_str());
		if (pvalue == nullptr)
			return ecServerOOM;
		dprop.emplace_back(PR_BODY_CONTENT_ID, pvalue);
	}
	if (!sprop.has(PR_CREATOR_NAME)) {
		auto pvalue = sprop.getval(PR_SENDER_NAME);
		if (pvalue == nullptr)
			pvalue = sprop.getval(PR_SENT_REPRESENTING_NAME);
		if (pvalue != nullptr)
			dprop.emplace_back(PR_CREATOR_NAME, pvalue);
	}
	if (!sprop.has(PR_CREATOR_ENTRYID)) {
		auto pvalue = sprop.getval(PR_SENDER_ENTRYID);
		if (pvalue == nullptr)
			pvalue = sprop.getval(PR_SENT_REPRESENTING_ENTRYID);
		if (pvalue != nullptr)
			dprop.emplace_back(PR_CREATOR_ENTRYID, pvalue);
	}
	if (!sprop.has(PR_LAST_MODIFIER_NAME)) {
		auto pvalue = sprop.getval(PR_SENDER_NAME);
		if (pvalue == nullptr)
			pvalue = sprop.getval(PR_SENT_REPRESENTING_NAME);
		if (pvalue != nullptr)
			dprop.emplace_back(PR_LAST_MODIFIER_NAME, pvalue);
	}
	if (!sprop.has(PR_LAST_MODIFIER_ENTRYID)) {
		auto pvalue = sprop.getval(PR_SENDER_ENTRYID);
		if (pvalue == nullptr)
			pvalue = sprop.getval(PR_SENT_REPRESENTING_ENTRYID);
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
	/*
	 * The conversation id is derived from the topic below, so the topic
	 * needs to be resolved before that
	 */
	auto cvtopic = sprop.get<char>(PR_CONVERSATION_TOPIC);
	if (cvtopic == nullptr || *cvtopic == '\0')
		cvtopic = sprop.get<char>(PR_CONVERSATION_TOPIC_A);
	if (cvtopic == nullptr || *cvtopic == '\0') {
		const char *pfx = nullptr;
		proptag_t tag = PR_CONVERSATION_TOPIC;
		auto norm = sprop.get<char>(PR_NORMALIZED_SUBJECT);
		auto subj = sprop.get<char>(PR_SUBJECT);
		if (norm == nullptr && subj == nullptr) {
			norm = sprop.get<char>(PR_NORMALIZED_SUBJECT_A);
			subj = sprop.get<char>(PR_SUBJECT_A);
			tag  = PR_CONVERSATION_TOPIC_A;
		}
		if (norm == nullptr && subj != nullptr &&
		    !cu_rebuild_subjects(subj, pfx, norm))
			return ecServerOOM;
		if (norm != nullptr) {
			cvtopic = norm;
			dprop.emplace_back(tag, cvtopic);
		}
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
		if (cvtopic != nullptr && *cvtopic != '\0') {
			if (!message_md5_string(cvtopic, new_cvid->pb))
				return ecError;
		} else {
			if (!ext_push.init(new_cvid->pb, 16, 0) ||
			    ext_push.p_guid(GUID::random_new()) != pack_result::ok)
				return ecError;
		}
	}
	dprop.emplace_back(PR_CONVERSATION_ID, new_cvid);
	dprop.emplace_back(PR_CONVERSATION_INDEX_TRACKING, &byte_value_one);
	if (old_cvindex == nullptr) {
		auto new_cvindex = cu_alloc<BINARY>();
		if (new_cvindex == nullptr)
			return ecServerOOM;
		new_cvindex->pv = common_util_alloc(27);
		if (new_cvindex->pv == nullptr)
			return ecServerOOM;
		auto nt_time = rop_util_current_nttime();
		if (!ext_push.init(new_cvindex->pb, 27, 0) ||
		    ext_push.p_uint8(1) != pack_result::ok ||
		    ext_push.p_uint32(nt_time >> 32) != pack_result::ok ||
		    ext_push.p_uint8((nt_time >> 24) & 0xff) != pack_result::ok ||
		    ext_push.p_bytes(new_cvid->pb, 16) != pack_result::ok ||
		    ext_push.p_uint32(0xFFFFFFFF) != pack_result::ok ||
		    ext_push.p_uint8(nt_time & 0xFF) != pack_result::ok)
			return ecError;
		new_cvindex->cb = ext_push.m_offset;
		dprop.emplace_back(PR_CONVERSATION_INDEX, new_cvindex);
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
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2752: ENOMEM");
	return ecServerOOM;
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
static bool message_write_message(bool b_internal, const db_conn &db,
    cpid_t cpid, bool b_embedded, uint64_t parent_id,
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
	auto &psqlite = db.psqlite;
	if (cn_p == nullptr) {
		if (cu_allocate_cn(psqlite, &change_num) != ecSuccess)
			return FALSE;
		*outcn = change_num;
		b_cn = FALSE;
	} else {
		*outcn = change_num = cn_p->gcv();
		b_cn = TRUE;
	}
	if (!b_internal) {
		if (message_rectify_message(pmsgctnt, &msgctnt) != ecSuccess)
			return FALSE;
		if (!b_embedded && !b_cn) {
			auto pvalue = cu_xid_to_bin({exmdb_server::is_private() ?
			              	rop_util_make_user_guid(exmdb_server::get_account_id()) :
			              	rop_util_make_domain_guid(exmdb_server::get_account_id()),
			              eid_t(1, change_num)});
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
			*pmessage_id = mid_p->gcv();
			snprintf(sql_string, std::size(sql_string), "SELECT parent_fid, message_size"
			          " FROM messages WHERE message_id=%llu", LLU{*pmessage_id});
			pstmt = gx_sql_prep(psqlite, sql_string);
			if (pstmt == nullptr)
				return FALSE;
			if (pstmt.step() != SQLITE_ROW) {
				if (!cu_eid_is_allocated(psqlite,
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
			if (!b_embedded)
				timeindex_refresh(psqlite, parent_id, *pmessage_id);
			snprintf(sql_string, std::size(sql_string), "DELETE FROM recipients"
			        " WHERE message_id=%llu", LLU{*pmessage_id});
			if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
				return FALSE;
			snprintf(sql_string, std::size(sql_string), "DELETE FROM attachments"
			        " WHERE message_id=%llu", LLU{*pmessage_id});
			if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
				return FALSE;
			mlog(LV_INFO, "exmdb-audit: truncated message %s:f%llu:m%llu (rewrite)",
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
			mlog(LV_INFO, "exmdb-audit: created message %s:f%llu:m%llu",
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
			mlog(LV_INFO, "exmdb-audit: deleted message %s:a%llu:m%llu",
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
		mlog(LV_INFO, "exmdb-audit: created message %s:a%llu:m%llu",
			exmdb_server::get_dir(), LLU{parent_id}, LLU{*pmessage_id});
	}
	if (!cu_set_properties(MAPI_MESSAGE, *pmessage_id, cpid,
	    psqlite, &pmsgctnt->proplist, &tmp_problems))
		return FALSE;
	if (!b_embedded)
		timeindex_refresh(psqlite, parent_id, *pmessage_id);
	if (pmsgctnt->proplist.has(PR_BODY) && tmp_problems.has(PR_BODY))
		*partial_completion = true;
	if (pmsgctnt->proplist.has(PR_HTML) && tmp_problems.has(PR_HTML))
		*partial_completion = true;
	if (!b_embedded) {
		void *pvalue = nullptr;
		if (!cu_get_property(MAPI_FOLDER, parent_id, CP_ACP,
		    db, PR_INTERNET_ARTICLE_NUMBER_NEXT, &pvalue))
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
			mlog(LV_INFO, "exmdb-audit: created attachment %s:m%llu:a%llu",
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
			if (!message_write_message(true, db, cpid, true,
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

static BOOL message_get_propids(const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids)
{
	auto psqlite = g_sqlite_for_oxcmail;
	if (psqlite == nullptr)
		return FALSE;
	return common_util_get_named_propids(psqlite, false, ppropnames, ppropids);
}

static BOOL message_get_propname(propid_t propid,
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
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static unsigned int detect_rcpt_type(const char *account, const TARRAY_SET *rcpts)
{
	if (rcpts == nullptr)
		return MAPI_BCC;
	for (size_t i = 0; i < rcpts->count; ++i) {
		auto &rcpt = *rcpts->pparray[i];
		auto smtpaddr = rcpt.get<const char>(PR_SMTP_ADDRESS);
		if (smtpaddr == nullptr) {
			auto addrtype = rcpt.get<const char>(PR_ADDRTYPE);
			if (addrtype != nullptr && strcasecmp(addrtype, "SMTP") == 0)
				smtpaddr = rcpt.get<const char>(PR_EMAIL_ADDRESS);
		}
		if (smtpaddr == nullptr || strcasecmp(account, smtpaddr) != 0)
			continue;
		auto type = rcpt.get<const uint32_t>(PR_RECIPIENT_TYPE);
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
	uint64_t fid_val;
	BINARY searchkey_bin;
	char mid_string[128];
	std::string account, display_name;

	if (exmdb_server::is_private()) {
		auto err = mysql_adaptor_userid_to_name(exmdb_server::get_account_id(), account);
		if (err != ecSuccess) {
			mlog(LV_DEBUG, "deliver_message %s: userid_to_name: %s",
				dir, mapi_strerror(err));
			return false;
		}
	} else {
		sql_domain dinfo;
		if (!mysql_adaptor_get_domain_info(exmdb_server::get_account_id(), dinfo)) {
			mlog(LV_DEBUG, "deliver_message %s: get_domain_info: failed", dir);
			return false;
		}
		account = std::move(dinfo.name);
	}
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	if (cu_store_msgsize_limit_reached(*pdb, PR_PROHIBIT_RECEIVE_QUOTA)) {
		*presult = static_cast<uint32_t>(deliver_message_result::mailbox_full_bysize);
		return TRUE;
	} else if (cu_store_msgcount_limit_reached(pdb->psqlite)) {
		*presult = static_cast<uint32_t>(deliver_message_result::mailbox_full_bymsg);
		return TRUE;
	}
	if (exmdb_server::is_private()) {
		fid_val = (dlflags & DELIVERY_FORCE_JUNK) ?
		          PRIVATE_FID_JUNK : PRIVATE_FID_INBOX;
	} else {
		//TODO get public folder id
		mlog(LV_ERR, "deliver_message %s: public folder delivery not implemented", dir);
		return false;
	}
	seen_list seen{{fid_val}};

	MESSAGE_CONTENT tmp_msg = *pmsg; /* may reference buffers (vars above) */
	std::string essdn_buff;
	if (exmdb_server::is_private()) {
		tmp_msg.proplist.ppropval = cu_alloc<TAGGED_PROPVAL>(pmsg->proplist.count + 15);
		if (tmp_msg.proplist.ppropval == nullptr) {
			mlog(LV_DEBUG, "deliver_message: ENOMEM");
			return FALSE;
		}
		memcpy(tmp_msg.proplist.ppropval, pmsg->proplist.ppropval,
					sizeof(TAGGED_PROPVAL)*pmsg->proplist.count);
		auto pentryid = common_util_username_to_addressbook_entryid(account.c_str());
		if (pentryid == nullptr) {
			mlog(LV_DEBUG, "deliver_message %s: cu_u_to_abkeid(%s) no result",
				dir, account.c_str());
			return FALSE;	
		}
		auto err = cvt_username_to_essdn(account.c_str(), g_exmdb_org_name,
		           mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
		           essdn_buff);
		if (err != ecSuccess) {
			mlog(LV_DEBUG, "deliver_message %s: cvt_u_to_essdn %s: %s",
				dir, account.c_str(), mapi_strerror(err));
			return FALSE;
		}
		HX_strupper(essdn_buff.data());
		essdn_buff.insert(0, "EX:");
		err = cu_set_propval(&tmp_msg.proplist, PR_RECEIVED_BY_ENTRYID, pentryid);
		if (err != ecSuccess) {
			mlog(LV_DEBUG, "deliver_message %s: set_propval 1: %s", dir, mapi_strerror(err));
			return false;
		}
		err = cu_set_propval(&tmp_msg.proplist, PR_RECEIVED_BY_ADDRTYPE, "EX");
		if (err != ecSuccess) {
			mlog(LV_DEBUG, "deliver_message %s: set_propval 2: %s", dir, mapi_strerror(err));
			return false;
		}
		auto rcv_emaddr = &essdn_buff.c_str()[3]; /* picky cov-scan */
		err = cu_set_propval(&tmp_msg.proplist, PR_RECEIVED_BY_EMAIL_ADDRESS, rcv_emaddr);
		if (err != ecSuccess) {
			mlog(LV_DEBUG, "deliver_message %s: set_propval 3: %s", dir, mapi_strerror(err));
			return false;
		}
		if (mysql_adaptor_get_user_displayname(account.c_str(), display_name)) {
			err = cu_set_propval(&tmp_msg.proplist, PR_RECEIVED_BY_NAME, display_name.c_str());
			if (err != ecSuccess) {
				mlog(LV_DEBUG, "deliver_message %s: set_propval 4: %s", dir, mapi_strerror(err));
				return false;
			}
		} else {
			display_name.clear();
		}
		searchkey_bin.cb = essdn_buff.size() + 1;
		searchkey_bin.pv = deconst(essdn_buff.c_str());
		err = cu_set_propval(&tmp_msg.proplist, PR_RECEIVED_BY_SEARCH_KEY, &searchkey_bin);
		if (err != ecSuccess) {
			mlog(LV_DEBUG, "deliver_message %s: set_propval 5: %s", dir, mapi_strerror(err));
			return false;
		}
		if (!pmsg->proplist.has(PR_RCVD_REPRESENTING_ENTRYID)) {
			err = cu_set_propval(&tmp_msg.proplist, PR_RCVD_REPRESENTING_ENTRYID, pentryid);
			if (err != ecSuccess) {
				mlog(LV_DEBUG, "deliver_message %s: set_propval 6: %s", dir, mapi_strerror(err));
				return false;
			}
			err = cu_set_propval(&tmp_msg.proplist, PR_RCVD_REPRESENTING_ADDRTYPE, "EX");
			if (err != ecSuccess) {
				mlog(LV_DEBUG, "deliver_message %s: set_propval 7: %s", dir, mapi_strerror(err));
				return false;
			}
			err = cu_set_propval(&tmp_msg.proplist, PR_RCVD_REPRESENTING_EMAIL_ADDRESS, rcv_emaddr);
			if (err != ecSuccess) {
				mlog(LV_DEBUG, "deliver_message %s: set_propval 8: %s", dir, mapi_strerror(err));
				return false;
			}
			if (!display_name.empty()) {
				err = cu_set_propval(&tmp_msg.proplist, PR_RCVD_REPRESENTING_NAME, display_name.c_str());
				if (err != ecSuccess) {
					mlog(LV_DEBUG, "deliver_message %s: set_propval 9: %s", dir, mapi_strerror(err));
					return false;
				}
			}
			err = cu_set_propval(&tmp_msg.proplist, PR_RCVD_REPRESENTING_SEARCH_KEY, &searchkey_bin);
			if (err != ecSuccess) {
				mlog(LV_DEBUG, "deliver_message %s: set_propval 10: %s", dir, mapi_strerror(err));
				return false;
			}
		}
		auto rcpt_type = detect_rcpt_type(account.c_str(), pmsg->children.prcpts);
		if (rcpt_type == MAPI_TO || rcpt_type == MAPI_CC) {
			err = cu_set_propval(&tmp_msg.proplist, rcpt_type == MAPI_TO ?
				PR_MESSAGE_TO_ME : PR_MESSAGE_CC_ME, &byte_value_one);
			if (err != ecSuccess) {
				mlog(LV_DEBUG, "deliver_message %s: set_propval 11: %s", dir, mapi_strerror(err));
				return false;
			}
		}
		if (rcpt_type == MAPI_TO || rcpt_type == MAPI_CC || rcpt_type == MAPI_BCC) {
			err = cu_set_propval(&tmp_msg.proplist, PR_MESSAGE_RECIP_ME, &byte_value_one);
			if (err != ecSuccess) {
				mlog(LV_DEBUG, "deliver_message %s: set_propval 12: %s", dir, mapi_strerror(err));
				return false;
			}
		}
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
	if (!message_write_message(false, *pdb, cpid, false,
	    fid_val, &tmp_msg, &message_id, &new_cn, &partial)) {
		mlog(LV_DEBUG, "deliver_message %s: message_write_message failed", dir);
		return FALSE;
	}
	if (0 == message_id) {
		*presult = static_cast<uint32_t>(deliver_message_result::result_error);
		return TRUE;
	}
	std::optional<Json::Value> digest;
	if (pdigest != nullptr) {
		digest.emplace();
		if (!str_to_json(pdigest, *digest))
			digest.reset();
	}
	if (digest.has_value() &&
	    get_digest(*digest, "file", mid_string, std::size(mid_string))) {
		Json::Value newdigest = *digest;
		newdigest["file"] = "";
		auto ext_path = exmdb_server::get_dir() + "/ext/"s + mid_string;
		auto djson = json_to_str(std::move(newdigest));
		auto ret = gx_mkbasedir(ext_path.c_str(), FMODE_PRIVATE | S_IXUSR | S_IXGRP);
		if (ret < 0) {
			mlog(LV_ERR, "E-1942: mkbasedir for %s: %s", ext_path.c_str(), strerror(-ret));
			return false;
		}
		wrapfd fd = open(ext_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, FMODE_PRIVATE);
		if (fd.get() >= 0) {
			if (HXio_fullwrite(fd.get(), djson.c_str(), djson.size()) < 0) {
				mlog(LV_ERR, "E-1319: write %s: %s", ext_path.c_str(), strerror(errno));
				return false;
			}
			auto err = fd.close_wr();
			if (err != 0) {
				mlog(LV_ERR, "E-1320: close %s: %s", ext_path.c_str(), strerror(err));
				return false;
			}
			if (!common_util_set_mid_string(pdb->psqlite,
			    message_id, mid_string)) {
				mlog(LV_ERR, "deliver_message %s: set_mid_str %s failed", dir, mid_string);
				return FALSE;
			}
		}
	}
	mlog(LV_DEBUG, "to=%s from=%s fid=%llu delivery mid=%llu (%s)", account.c_str(),
		znul(from_address), LLU{fid_val}, LLU{message_id},
		partial ? " (partial only)" : "");

	seen.msg.emplace_back(fid_val, message_id);

	//---DO_RULES_SV

	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	for (const auto &mn : seen.msg) {
		pdb->proc_dynamic_event(cpid, dynamic_event::new_msg,
			mn.folder_id, mn.message_id, 0, *dbase, notifq);
		/*
		 * Hint from <https://groups.google.com/g/microsoft.public.win32.programmer.messaging/c/LPnk0QqNTog>:
		 * "fnevObjectCreated event arrives [...] when there is a new
		 * incoming message but also when a new message is created"
		 */
		pdb->notify_message_creation(mn.folder_id,
			mn.message_id, *dbase, notifq);
		if (message_id == mn.message_id && dlflags & DELIVERY_DO_NOTIF_SV)
			pdb->notify_new_mail(mn.folder_id,
				mn.message_id, *dbase, notifq);
	}
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	for (const auto &audit : seen.deletions)
		mlog(LV_INFO, "gromox-audit: rule hard-deleted message \"%s\" in %s from folder \"%s\"",
			txt2cstr(audit.subject).c_str(), audit.mailbox.c_str(),
			txt2cstr(audit.folder).c_str());
	auto subject = pmsg->proplist.get<const char>(PR_SUBJECT);
	if (subject == nullptr)
		subject = pmsg->proplist.get<const char>(PR_NORMALIZED_SUBJECT);
	mlog(LV_INFO, "gromox-audit: delivered message \"%s\" from %s to mailbox %s%s",
		txt2cstr(subject).c_str(),
		txt2cstr(from_address).c_str(), account.c_str(),
		partial ? " (partial completion)" : "");
	dg_notify(std::move(notifq));
	*new_folder_id = eid_t(1, fid_val);
	*new_msg_id = eid_t(1, message_id);
	*presult = static_cast<uint32_t>(partial ?
	           deliver_message_result::partial_completion :
	           deliver_message_result::result_ok);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
}

BOOL exmdb_server::transport_new_mail(const char *dir, uint64_t folder_id,
	uint64_t message_id, uint32_t message_flags, const char *pstr_class)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Single lookup at most, so no transaction. */
	folder_id = cu_resolve_folder(pdb->psqlite, folder_id);
	auto dbase = pdb->lock_base_rd();
	db_conn::NOTIFQ notifq;
	pdb->transport_new_mail(eid_t(folder_id).gcv(),
		eid_t(message_id).gcv(), message_flags, pstr_class,
		*dbase, notifq);
	dg_notify(std::move(notifq));
	return TRUE;
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
BOOL exmdb_server::write_message(const char *dir, cpid_t cpid,
    uint64_t folder_id, const MESSAGE_CONTENT *pmsgctnt,
    const std::string &digest_stream,
    uint64_t *outmid, uint64_t *outcn, ec_error_t *pe_result)
{
	BOOL b_exist = false;
	auto pmid = pmsgctnt->proplist.get<const eid_t>(PidTagMid);
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	if (cu_store_msgsize_limit_reached(*pdb, PR_STORAGE_QUOTA_LIMIT) ||
	    cu_store_msgcount_limit_reached(pdb->psqlite)) {
		*pe_result = MAPI_E_STORE_FULL;
		return TRUE;	
	}
	folder_id = cu_resolve_folder(pdb->psqlite, folder_id);
	auto fid_val = eid_t(folder_id).gcv();
	if (NULL != pmid) {
		uint64_t parent_fid = 0;
		if (!common_util_get_message_parent_folder(pdb->psqlite,
		    pmid->gcv(), &parent_fid))
			return FALSE;	
		if (parent_fid != 0) {
			b_exist = TRUE;
			if (fid_val != parent_fid) {
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
	if (!message_write_message(false, *pdb, cpid, false,
	    fid_val, pmsgctnt, outmid, outcn, &partial))
		return FALSE;
	if (*outmid == 0) {
		// auto rollback at end of scope
		*pe_result = ecRpcFailed;
		return false;
	}

	/* Audit metadata */
	void *pv_subject = nullptr, *pv_folder = nullptr;
	cu_get_property(MAPI_MESSAGE, *outmid, cpid, *pdb, PR_SUBJECT, &pv_subject);
	cu_get_property(MAPI_FOLDER, fid_val, CP_ACP, *pdb, PR_DISPLAY_NAME, &pv_folder);
	auto subject = static_cast<const char *>(pv_subject);
	auto folder = static_cast<const char *>(pv_folder);
	auto mailbox = audit_store_location();

	if (digest_stream.size() > 0) {
		Json::Value digest;
		std::string mid_string;
		if (str_to_json(digest_stream, digest) &&
		    digest["file"].asString().size() > 0) {
			std::string ext_file = exmdb_server::get_dir() + "/ext/"s + digest["file"].asString();
			auto ret = gx_mkbasedir(ext_file.c_str(), FMODE_PRIVATE);
			if (ret < 0) {
				mlog(LV_ERR, "E-1944: mkbasedir for %s: %s", ext_file.c_str(), strerror(-ret));
				return false;
			}
			wrapfd fd = open(ext_file.c_str(), O_CREAT | O_TRUNC | O_WRONLY, FMODE_PRIVATE);
			if (fd.get() >= 0) {
				if (HXio_fullwrite(fd.get(), digest_stream.c_str(), digest_stream.size()) < 0) {
					mlog(LV_ERR, "E-1321: write %s: %s", ext_file.c_str(), strerror(errno));
					return false;
				}
				auto err = fd.close_wr();
				if (err != 0) {
					mlog(LV_ERR, "E-1322: close %s: %s", ext_file.c_str(), strerror(err));
					return false;
				}
				if (!common_util_set_mid_string(pdb->psqlite,
				    *outmid, digest["file"].asCString()))
					return false;
			}
		}
	}

	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	if (b_exist) {
		pdb->proc_dynamic_event(cpid, dynamic_event::modify_msg,
			fid_val, *outmid, 0, *dbase, notifq);
		pdb->notify_message_modification(fid_val, *outmid, *dbase, notifq);
	} else {
		pdb->proc_dynamic_event(cpid, dynamic_event::new_msg, fid_val,
			*outmid, 0, *dbase, notifq);
		pdb->notify_message_creation(fid_val, *outmid, *dbase, notifq);
	}
	if (sql_transact.commit() != SQLITE_OK)
		return false;

	mlog(LV_INFO, "gromox-audit: %s message \"%s\" in %s in folder \"%s\"",
		b_exist ? "updated" : "created",
		txt2cstr(subject).c_str(), mailbox.c_str(),
		txt2cstr(folder).c_str());

	dg_notify(std::move(notifq));
	*outmid = eid_t(1, *outmid);
	*pe_result = ecSuccess;
	return TRUE;
}

/**
 * @username:   Used for adjusting public store readstates
 */
BOOL exmdb_server::read_message(const char *dir, const char *username,
    cpid_t cpid, uint64_t message_id, MESSAGE_CONTENT **ppmsgctnt) try
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	if (!exmdb_server::is_private())
		exmdb_server::set_public_username(username);
	auto cl_0 = HX::make_scope_exit([]() STATIC_IN_CXX23 { exmdb_server::set_public_username(nullptr); });
	auto mid_val = eid_t(message_id).gcv();
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!pdb->begin_optim())
		return FALSE;
	auto cl_1 = HX::make_scope_exit([&]() { pdb->end_optim(); });
	auto ret = message_read_message(*pdb, cpid, mid_val, ppmsgctnt);
	if (!ret)
		return FALSE;
	return sql_transact.commit() == SQLITE_OK ? TRUE : false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

BOOL exmdb_server::rule_new_message(const char *dir, const char *username,
    cpid_t cpid, uint64_t folder_id, uint64_t message_id)
{
	return false;
}
