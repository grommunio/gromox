// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <libHX/string.h>
#include <gromox/database.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/list_file.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "db_engine.hpp"

using namespace std::string_literals;
using namespace gromox;

static constexpr uint64_t GLOBCNT_MAX = 0x7fffffffffff;

BOOL exmdb_server::ping_store(const char *dir)
{
	auto pdb = db_engine_get_db(dir);
	return !!pdb;
}

BOOL exmdb_server::get_all_named_propids(const char *dir,
    PROPID_ARRAY *ppropids) try
{
	int total_count;
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	snprintf(sql_string, std::size(sql_string), "SELECT "
			"count(*) FROM named_properties");
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	total_count = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	ppropids->clear();
	if (0 == total_count) {
		return TRUE;
	}
	snprintf(sql_string, std::size(sql_string), "SELECT"
		" propid FROM named_properties");
	pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW)
		ppropids->push_back(pstmt.col_int64(0));
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2209: ENOMEM");
	return false;
}

BOOL exmdb_server::get_named_propids(const char *dir,
	BOOL b_create, const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!transact)
		return false;
	if (!common_util_get_named_propids(pdb->psqlite,
	    b_create, ppropnames, ppropids))
		return FALSE;
	return transact.commit() == SQLITE_OK ? TRUE : false;
}

BOOL exmdb_server::get_named_propnames(const char *dir,
    const PROPID_ARRAY &ppropids, PROPNAME_ARRAY *ppropnames)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	return common_util_get_named_propnames(pdb->psqlite, ppropids, ppropnames);
}

BOOL exmdb_server::get_mapping_guid(const char *dir,
	uint16_t replid, BOOL *pb_found, GUID *pguid)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	if (!common_util_get_mapping_guid(pdb->psqlite, replid, pb_found, pguid))
		return FALSE;
	*pb_found = TRUE;
	return TRUE;
}

BOOL exmdb_server::get_mapping_replid(const char *dir, GUID guid,
    uint16_t *preplid, ec_error_t *e_result)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	char guid_string[GUIDSTR_SIZE], sql_string[128];
	guid.to_str(guid_string, std::size(guid_string));

	/* Implicit create (MS-OXCSTOR v25 §3.2.5.9) */
	gx_strlcpy(sql_string, "INSERT INTO replguidmap (`replguid`) VALUES (?)", std::size(sql_string));
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	pstmt.bind_text(1, guid_string);
	auto sr = pstmt.step(SQLEXEC_SILENT_CONSTRAINT);
	if (sr == SQLITE_CONSTRAINT)
		/* nothing */;
	else if (sr != SQLITE_DONE)
		return false;
	snprintf(sql_string, std::size(sql_string), "SELECT replid FROM "
	         "replguidmap WHERE replguid='%s'", guid_string);
	pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW) {
		*e_result = ecNotFound;
		return TRUE;
	}
	auto replid = sqlite3_column_int64(pstmt, 0);
	if (replid > 0xFFFF) {
		*e_result = ecParameterOverflow;
		return TRUE;
	}
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	*preplid  = replid;
	*e_result = ecSuccess;
	return TRUE;
}

BOOL exmdb_server::get_store_all_proptags(const char *dir,
    PROPTAG_ARRAY *pproptags)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	std::vector<uint32_t> tags;
	if (!cu_get_proptags(MAPI_STORE, 0, pdb->psqlite, tags))
		return FALSE;
	pproptags->pproptag = cu_alloc<uint32_t>(tags.size());
	if (pproptags->pproptag == nullptr)
		return false;
	pproptags->count = tags.size();
	memcpy(pproptags->pproptag, tags.data(), sizeof(tags[0]) * pproptags->count);
	return TRUE;
}

BOOL exmdb_server::get_store_properties(const char *dir, cpid_t cpid,
    const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	return cu_get_properties(MAPI_STORE, 0, cpid, pdb->psqlite,
	       pproptags, ppropvals);
}

BOOL exmdb_server::set_store_properties(const char *dir, cpid_t cpid,
    const TPROPVAL_ARRAY *ppropvals, PROBLEM_ARRAY *pproblems)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!cu_set_properties(MAPI_STORE, 0, cpid, pdb->psqlite,
	    ppropvals, pproblems))
		return FALSE;
	return transact.commit() == SQLITE_OK ? TRUE : false;
}

BOOL exmdb_server::remove_store_properties(const char *dir,
    const PROPTAG_ARRAY *pproptags)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!cu_remove_properties(MAPI_STORE, 0, pdb->psqlite, pproptags))
		return FALSE;
	return transact.commit() == SQLITE_OK ? TRUE : false;
}

/**
 * @username:   Identity for which to calculate permission bits
 *
 * This function is used to determine if the user has any rights to any object
 * in the mailbox, and this influences whether more front-facing services like
 * emsmdb or zcore permit MAPI clients to open a emsmdb/zcore store object.
 * (exmdb is almost stateless and has no store "objects" — you just run one-off
 * EXRPCs to read/write to the database.)
 *
 * Public stores get a different treatment (no call to get_mbox_perm), so
 * get_mbox_perm happens to reject invocation with a public store.
 */
BOOL exmdb_server::get_mbox_perm(const char *dir,
    const char *username, uint32_t *ppermission) try
{
	char sql_string[128];
	
	if (!exmdb_server::is_private())
		return FALSE;
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	*ppermission = rightsNone;

	/* Store permission := union of folder permissions */
	auto pstmt = gx_sql_prep(pdb->psqlite,
	             "SELECT p1.folder_id, p2.permission, p3.permission "
	             "FROM permissions AS p1 LEFT JOIN permissions AS p2 "
	             "ON p1.folder_id=p2.folder_id AND p2.username=? "
	             "LEFT JOIN permissions AS p3 "
	             "ON p1.folder_id=p3.folder_id AND p3.username='default'");
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_text(pstmt, 1, username, -1, SQLITE_STATIC);
	while (pstmt.step() == SQLITE_ROW) {
		auto fid  = pstmt.col_uint64(0);
		auto perm = pstmt.col_uint64(sqlite3_column_type(pstmt, 1) != SQLITE_NULL ? 1 : 2);
		*ppermission |= perm;
	/*
	 * Outlook and g-web only expose IPM_SUBTREE and below, so permissions
	 * can only be set on those folders with those UIs.
	 *
	 * In EXC, store ownership is a separate bit only settable via Admin
	 * Center. FOLDEROWNER on IPM_SUBTREE only gives permission on
	 * IPM_SUBTREE.
	 *
	 * In Gromox, the FOLDEROWNER bit on IPM_SUBTREE is interpreted as
	 * store ownership. This allows users to delegate full ownership by
	 * themselves, but the implication is that someone else can also
	 * modify folders outside of IPM_SUBTREE, e.g. search folders - which
	 * may not be strictly desired. But then, just don't give out
	 * such broad permission in the first place, I guess.
	 */
		if (fid == PRIVATE_FID_IPMSUBTREE && perm & frightsOwner)
			*ppermission |= frightsGromoxStoreOwner;
	}
	pstmt.finalize();

	/* add in mlist permissions(?) */
	snprintf(sql_string, std::size(sql_string), "SELECT "
		"username, permission FROM permissions");
	pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		auto ben = pstmt.col_text(0);
		if (!mysql_adaptor_check_mlist_include(ben, username))
			continue;
		auto perm = pstmt.col_uint64(1);
		auto fid  = pstmt.col_uint64(2);
		*ppermission |= perm;
		if (fid == PRIVATE_FID_IPMSUBTREE && perm & frightsOwner)
			*ppermission |= frightsGromoxStoreOwner;
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
		    mysql_adaptor_check_mlist_include(d.c_str(), username)) {
			*ppermission |= frightsGromoxSendAs;
			break;
		}
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2066: ENOMEM");
	return false;
}

BOOL exmdb_server::allocate_cn(const char *dir, uint64_t *pcn)
{
	uint64_t change_num;
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	if (cu_allocate_cn(pdb->psqlite, &change_num) != ecSuccess ||
	    sql_transact.commit() != SQLITE_OK)
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
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	snprintf(sql_string, std::size(sql_string), "SELECT "
		"max(range_end) FROM allocated_eids");
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	tmp_eid = sqlite3_column_int64(pstmt, 0) + 1;
	/*
	 * Old versions of this function used to limit ID reservation per time.
	 * Nowadays it's unlimited and we just check for final exhaustion.
	 */
	if (tmp_eid + count > GLOBCNT_MAX) {
		mlog(LV_ERR, "E-1592: store \"%s\" has used up all GCVs, cannot reserve any more. "
		        "(Did you create too many Offline profiles?)", dir);
		*pbegin_eid = 0;
		return TRUE;
	}
	pstmt.finalize();
	snprintf(sql_string, std::size(sql_string), "INSERT INTO allocated_eids "
	          "VALUES (%llu, %llu, %lld, 0)",
	          static_cast<unsigned long long>(tmp_eid),
	          static_cast<unsigned long long>(tmp_eid + count),
	          static_cast<long long>(time(nullptr)));
	if (pdb->exec(sql_string) != SQLITE_OK || sql_transact.commit() != SQLITE_OK)
		return FALSE;
	*pbegin_eid = rop_util_make_eid_ex(1, tmp_eid);
	return TRUE;
}

BOOL exmdb_server::subscribe_notification(const char *dir,
   uint16_t notification_type, BOOL b_whole, uint64_t folder_id,
   uint64_t message_id, uint32_t *psub_id) try
{
	uint16_t replid;
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* No database access, so no transaction. */
	auto dbase = pdb->lock_base_wr();
	uint32_t last_id = dbase->nsub_list.size() == 0 ? 0 :
	                   dbase->nsub_list.back().sub_id;
	nsub_node sub, *pnsub = &sub;
	pnsub->sub_id = last_id + 1;
	auto remote_id = exmdb_server::get_remote_id();
	if (NULL == remote_id) {
		pnsub->remote_id = NULL;
	} else {
		pnsub->remote_id = strdup(remote_id);
		if (pnsub->remote_id == nullptr)
			return FALSE;
	}
	pnsub->notification_type = notification_type;
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
	dbase->nsub_list.push_back(std::move(sub));
	*psub_id = last_id + 1;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2130: ENOMEM");
	return false;
}

BOOL exmdb_server::unsubscribe_notification(const char *dir, uint32_t sub_id)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* No database access, so no transaction. */
	auto dbase = pdb->lock_base_wr();
	auto i = std::find_if(dbase->nsub_list.begin(), dbase->nsub_list.end(),
		[&](const nsub_node &n) { return n.sub_id == sub_id; });
	if (i != dbase->nsub_list.end())
		dbase->nsub_list.erase(i);
	return TRUE;
}

BOOL exmdb_server::transport_new_mail(const char *dir, uint64_t folder_id,
	uint64_t message_id, uint32_t message_flags, const char *pstr_class)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* No database access, so no transaction. */
	auto dbase = pdb->lock_base_rd();
	db_conn::NOTIFQ notifq;
	pdb->transport_new_mail(rop_util_get_gc_value(folder_id),
		rop_util_get_gc_value(message_id), message_flags, pstr_class,
		*dbase, notifq);
	dg_notify(std::move(notifq));
	return TRUE;
}

static BOOL table_check_address_in_contact_folder(
	sqlite3_stmt *pstmt_subfolder, sqlite3_stmt *pstmt_search,
	uint64_t folder_id, const char *paddress, BOOL *pb_found) try
{
	sqlite3_reset(pstmt_search);
	sqlite3_bind_int64(pstmt_search, 1, folder_id);
	sqlite3_bind_text(pstmt_search, 2, paddress, -1, SQLITE_STATIC);
	if (gx_sql_step(pstmt_search) == SQLITE_ROW) {
		*pb_found = TRUE;
		return TRUE;
	}
	std::vector<uint64_t> folder_list;
	sqlite3_reset(pstmt_subfolder);
	sqlite3_bind_int64(pstmt_subfolder, 1, folder_id);
	while (gx_sql_step(pstmt_subfolder) == SQLITE_ROW)
		folder_list.push_back(sqlite3_column_int64(pstmt_subfolder, 0));
	for (auto fid : folder_list) {
		if (!table_check_address_in_contact_folder(pstmt_subfolder,
		    pstmt_search, fid, paddress, pb_found))
			return FALSE;	
		if (*pb_found)
			return TRUE;
	}
	*pb_found = FALSE;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2089: ENOMEM");
	return false;
}

BOOL exmdb_server::check_contact_address(const char *dir,
	const char *paddress, BOOL *pb_found)
{
	char sql_string[198];
	PROPID_ARRAY propids;
	PROPNAME_ARRAY propnames;
	PROPERTY_NAME propname_buff[3];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	propnames.count = 3;
	propnames.ppropname = propname_buff;
	for (size_t i = 0; i < std::size(propname_buff); ++i) {
		propname_buff[i].guid = PSETID_Address;
		propname_buff[i].kind = MNID_ID;
	}
	propname_buff[0].lid = PidLidEmail1EmailAddress;
	propname_buff[1].lid = PidLidEmail2EmailAddress;
	propname_buff[2].lid = PidLidEmail3EmailAddress;
	if (!common_util_get_named_propids(pdb->psqlite,
	    false, &propnames, &propids) || propids.size() != 3)
		return FALSE;	
	const proptag_t proptags[] = {
		PROP_TAG(PT_UNICODE, propids[0]),
		PROP_TAG(PT_UNICODE, propids[1]),
		PROP_TAG(PT_UNICODE, propids[2]),
	};
	auto pstmt1 = pdb->prep("SELECT folder_id"
	              " FROM folders WHERE parent_id=?");
	if (pstmt1 == nullptr)
		return FALSE;
	snprintf(sql_string, sizeof(sql_string), "SELECT m.message_id "
	         "FROM messages AS m JOIN message_properties AS mp ON "
	         "m.message_id=mp.message_id WHERE m.parent_fid=? AND "
	         "mp.proptag IN (%u,%u,%u) AND mp.propval=? LIMIT 1",
	         proptags[0], proptags[1], proptags[2]);
	auto pstmt2 = pdb->prep(sql_string);
	if (pstmt2 == nullptr)
		return FALSE;
	return table_check_address_in_contact_folder(pstmt1, pstmt2,
	       PRIVATE_FID_CONTACTS, paddress, pb_found);
}
