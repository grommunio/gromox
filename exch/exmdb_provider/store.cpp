// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <gromox/database.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/list_file.hpp>
#include <gromox/mapidefs.h>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "db_engine.h"

using namespace std::string_literals;
using namespace gromox;

static constexpr uint64_t GLOBCNT_MAX = 0x7fffffffffff;

BOOL exmdb_server::ping_store(const char *dir)
{
	auto pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_server::get_all_named_propids(const char *dir,
    PROPID_ARRAY *ppropids)
{
	int total_count;
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT "
			"count(*) FROM named_properties");
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	total_count = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	if (0 == total_count) {
		ppropids->count = 0;
		ppropids->ppropid = NULL;
		return TRUE;
	}
	ppropids->ppropid = cu_alloc<uint16_t>(total_count);
	if (NULL == ppropids->ppropid) {
		return FALSE;
	}
	snprintf(sql_string, arsizeof(sql_string), "SELECT"
		" propid FROM named_properties");
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	ppropids->count = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		ppropids->ppropid[ppropids->count++] = sqlite3_column_int64(pstmt, 0);
	}
	return TRUE;
}

BOOL exmdb_server::get_named_propids(const char *dir,
	BOOL b_create, const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto transact = gx_sql_begin_trans(pdb->psqlite);
	if (!common_util_get_named_propids(pdb->psqlite,
	    b_create, ppropnames, ppropids))
		return FALSE;
	transact.commit();
	return TRUE;
}

BOOL exmdb_server::get_named_propnames(const char *dir,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	return common_util_get_named_propnames(pdb->psqlite, ppropids, ppropnames);
}

/* public only */
BOOL exmdb_server::get_mapping_guid(const char *dir,
	uint16_t replid, BOOL *pb_found, GUID *pguid)
{
	if (exmdb_server::is_private())
		return FALSE;
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (!common_util_get_mapping_guid(pdb->psqlite, replid, pb_found, pguid))
		return FALSE;
	*pb_found = TRUE;
	return TRUE;
}

/* public only */
BOOL exmdb_server::get_mapping_replid(const char *dir,
	GUID guid, BOOL *pb_found, uint16_t *preplid)
{
	if (exmdb_server::is_private())
		return FALSE;
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	char guid_string[GUIDSTR_SIZE], sql_string[128];
	guid.to_str(guid_string, arsizeof(guid_string));
	snprintf(sql_string, arsizeof(sql_string), "SELECT replid FROM "
		"replca_mapping WHERE replguid='%s'", guid_string);
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		*pb_found = FALSE;
		return TRUE;
	}
	*preplid = sqlite3_column_int64(pstmt, 0);
	*pb_found = TRUE;
	return TRUE;
}

BOOL exmdb_server::get_store_all_proptags(const char *dir,
    PROPTAG_ARRAY *pproptags)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (!cu_get_proptags(db_table::store_props, 0,
		pdb->psqlite, pproptags)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_server::get_store_properties(const char *dir,
	uint32_t cpid, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (!cu_get_properties(db_table::store_props, 0, cpid, pdb->psqlite,
		pproptags, ppropvals)) {
		return FALSE;
	}
	return TRUE;
}

BOOL exmdb_server::set_store_properties(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *ppropvals,
	PROBLEM_ARRAY *pproblems)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto transact = gx_sql_begin_trans(pdb->psqlite);
	if (!cu_set_properties(db_table::store_props, 0, cpid, pdb->psqlite,
		ppropvals, pproblems)) {
		return FALSE;
	}
	transact.commit();
	return TRUE;
}

BOOL exmdb_server::remove_store_properties(const char *dir,
    const PROPTAG_ARRAY *pproptags)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto transact = gx_sql_begin_trans(pdb->psqlite);
	if (!cu_remove_properties(db_table::store_props, 0, pdb->psqlite, pproptags)) {
		return FALSE;
	}
	transact.commit();
	return TRUE;
}

/* private only */
BOOL exmdb_server::get_mbox_perm(const char *dir,
    const char *username, uint32_t *ppermission) try
{
	char sql_string[128];
	
	if (!exmdb_server::is_private())
		return FALSE;
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	*ppermission = rightsNone;

	/* Store permission := union of folder permissions */
	auto pstmt = gx_sql_prep(pdb->psqlite, "SELECT permission, folder_id "
	             "FROM permissions WHERE username=?");
	if (pstmt == nullptr) {
		return FALSE;
	}
	sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		auto perm = pstmt.col_uint64(0);
		auto fid  = pstmt.col_uint64(1);
		*ppermission |= perm;
	/*
	 * Tryout for conveying the special store ownership.
	 * Take FOLDEROWNER bit _only_ from Top Of Information Store.
	 */
		if (fid == PRIVATE_FID_IPMSUBTREE && perm & frightsOwner)
			*ppermission |= frightsGromoxStoreOwner;
	}
	pstmt.finalize();

	/* add in mlist permissions(?) */
	snprintf(sql_string, arsizeof(sql_string), "SELECT "
		"username, permission FROM permissions");
	pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		if (common_util_check_mlist_include(reinterpret_cast<const char *>(sqlite3_column_text(pstmt, 0)), username))
			*ppermission |= sqlite3_column_int64(pstmt, 1);
	}
	pstmt.finalize();
	pdb.reset();

	/* Delegate bit */
	auto dlg_path = dir + "/config/delegates.txt"s;
	std::vector<std::string> delegate_list;
	auto ret = read_file_by_line(dlg_path.c_str(), delegate_list);
	if (ret != 0 && ret != ENOENT)
		mlog(LV_ERR, "E-2050: %s: %s", dlg_path.c_str(), strerror(ret));
	for (const auto &d : delegate_list) {
		if (strcasecmp(d.c_str(), username) == 0 ||
		    common_util_check_mlist_include(d.c_str(), username)) {
			*ppermission |= frightsGromoxSendAs;
			break;
		}
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2044: ENOMEM");
	return false;
}

BOOL exmdb_server::allocate_cn(const char *dir, uint64_t *pcn)
{
	uint64_t change_num;
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	if (!common_util_allocate_cn(pdb->psqlite, &change_num))
		return FALSE;
	*pcn = rop_util_make_eid_ex(1, change_num);
	return TRUE;
}

/* if *pbegin_eid is 0, means too many
	allocation requests within an interval */
BOOL exmdb_server::allocate_ids(const char *dir,
	uint32_t count, uint64_t *pbegin_eid)
{
	uint64_t tmp_eid;
	char sql_string[128];
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	snprintf(sql_string, arsizeof(sql_string), "SELECT "
		"max(range_end) FROM allocated_eids");
	auto pstmt = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW)
		return FALSE;
	tmp_eid = sqlite3_column_int64(pstmt, 0) + 1;
	/*
	 * Old versions of this function used to limit ID reservation per time.
	 * Nowadays it's unlimited and we just check for final exhaustion.
	 */
	if (tmp_eid + count > GLOBCNT_MAX) {
		mlog(LV_ERR, "E-1592: store \"%s\" has used up all local replica IDs. "
		        "(Did you create too many Offline profiles?)", dir);
		*pbegin_eid = 0;
		return TRUE;
	}
	pstmt.finalize();
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO allocated_eids "
	          "VALUES (%llu, %llu, %lld, 0)",
	          static_cast<unsigned long long>(tmp_eid),
	          static_cast<unsigned long long>(tmp_eid + count),
	          static_cast<long long>(time(nullptr)));
	if (gx_sql_exec(pdb->psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	*pbegin_eid = rop_util_make_eid_ex(1, tmp_eid);
	return TRUE;
}

BOOL exmdb_server::subscribe_notification(const char *dir,
   uint16_t notificaton_type, BOOL b_whole, uint64_t folder_id,
   uint64_t message_id, uint32_t *psub_id) try
{
	uint16_t replid;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	uint32_t last_id = pdb->nsub_list.size() == 0 ? 0 :
	                   pdb->nsub_list.back().sub_id;
	nsub_node sub, *pnsub = &sub;
	pnsub->sub_id = last_id + 1;
	auto remote_id = exmdb_server::get_remote_id();
	if (NULL == remote_id) {
		pnsub->remote_id = NULL;
	} else {
		pnsub->remote_id = strdup(remote_id);
		if (NULL == pnsub->remote_id) {
			return FALSE;
		}
	}
	pnsub->notificaton_type = notificaton_type;
	pnsub->b_whole = b_whole;
	if (0 == folder_id) {
		pnsub->folder_id = 0;
	} else if (exmdb_server::is_private()) {
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
	pnsub->message_id = message_id == 0 ? 0 :
	                    rop_util_get_gc_value(message_id);
	pdb->nsub_list.push_back(std::move(sub));
	*psub_id = last_id + 1;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2130: ENOMEM");
	return false;
}

BOOL exmdb_server::unsubscribe_notification(const char *dir, uint32_t sub_id)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto i = std::find_if(pdb->nsub_list.begin(), pdb->nsub_list.end(),
		[&](const nsub_node &n) { return n.sub_id == sub_id; });
	if (i != pdb->nsub_list.end())
		pdb->nsub_list.erase(i);
	return TRUE;
}

BOOL exmdb_server::transport_new_mail(const char *dir, uint64_t folder_id,
	uint64_t message_id, uint32_t message_flags, const char *pstr_class)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	db_engine_transport_new_mail(pdb, rop_util_get_gc_value(folder_id),
		rop_util_get_gc_value(message_id), message_flags, pstr_class);
	return TRUE;
}

static BOOL table_check_address_in_contact_folder(
	sqlite3_stmt *pstmt_subfolder, sqlite3_stmt *pstmt_search,
	uint64_t folder_id, const char *paddress, BOOL *pb_found)
{
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
		auto pnode = cu_alloc<DOUBLE_LIST_NODE>();
		if (NULL == pnode) {
			return FALSE;
		}
		auto uv = cu_alloc<uint64_t>();
		pnode->pdata = uv;
		if (NULL == pnode->pdata) {
			return FALSE;
		}
		*uv = sqlite3_column_int64(pstmt_subfolder, 0);
		double_list_append_as_tail(&folder_list, pnode);
	}
	DOUBLE_LIST_NODE *pnode;
	while ((pnode = double_list_pop_front(&folder_list)) != nullptr) {
		if (!table_check_address_in_contact_folder(pstmt_subfolder,
		    pstmt_search, *static_cast<uint64_t *>(pnode->pdata),
		    paddress, pb_found))
			return FALSE;	
		if (*pb_found)
			return TRUE;
	}
	*pb_found = FALSE;
	return TRUE;
}

BOOL exmdb_server::check_contact_address(const char *dir,
	const char *paddress, BOOL *pb_found)
{
	uint32_t proptags[3];
	char sql_string[512];
	PROPID_ARRAY propids;
	PROPNAME_ARRAY propnames;
	PROPERTY_NAME propname_buff[3];
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	propnames.count = 3;
	propnames.ppropname = propname_buff;
	for (size_t i = 0; i < arsizeof(propname_buff); ++i) {
		propname_buff[i].guid = PSETID_ADDRESS;
		propname_buff[i].kind = MNID_ID;
	}
	propname_buff[0].lid = PidLidEmail1EmailAddress;
	propname_buff[1].lid = PidLidEmail2EmailAddress;
	propname_buff[2].lid = PidLidEmail3EmailAddress;
	if (!common_util_get_named_propids(pdb->psqlite,
	    false, &propnames, &propids) || 3 != propids.count)
		return FALSE;	
	proptags[0] = PROP_TAG(PT_UNICODE, propids.ppropid[0]);
	proptags[1] = PROP_TAG(PT_UNICODE, propids.ppropid[1]);
	proptags[2] = PROP_TAG(PT_UNICODE, propids.ppropid[2]);
	auto pstmt1 = gx_sql_prep(pdb->psqlite, "SELECT folder_id"
	              " FROM folders WHERE parent_id=?");
	if (pstmt1 == nullptr) {
		return FALSE;
	}
	snprintf(sql_string, arsizeof(sql_string), "SELECT messages.message_id"
		" FROM messages JOIN message_properties ON "
		"messages.message_id=message_properties.message_id "
		"WHERE parent_fid=? AND (message_properties.proptag=%u"
		" OR message_properties.proptag=%u"
		" OR message_properties.proptag=%u)"
		" AND message_properties.propval=?"
		" LIMIT 1", proptags[0], proptags[1],
		proptags[2]);
	auto pstmt2 = gx_sql_prep(pdb->psqlite, sql_string);
	if (pstmt2 == nullptr) {
		return FALSE;
	}
	return table_check_address_in_contact_folder(pstmt1, pstmt2,
	       PRIVATE_FID_CONTACTS, paddress, pb_found);
}

BOOL exmdb_server::vacuum(const char *dir)
{
	return db_engine_vacuum(dir);
}

BOOL exmdb_server::unload_store(const char *dir)
{
	return db_engine_unload_db(dir);
}
