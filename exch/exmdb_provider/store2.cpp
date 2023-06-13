// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2023 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <gromox/database.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/rop_util.hpp>
#include "db_engine.h"

using LLU = unsigned long long;
using namespace gromox;

BOOL exmdb_server::vacuum(const char *dir)
{
	return db_engine_vacuum(dir);
}

BOOL exmdb_server::unload_store(const char *dir)
{
	return db_engine_unload_db(dir);
}

BOOL exmdb_server::notify_new_mail(const char *dir, uint64_t folder_id,
	uint64_t message_id)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return false;
	db_engine_notify_new_mail(pdb, rop_util_get_gc_value(folder_id),
		rop_util_get_gc_value(message_id));
	return TRUE;
}

BOOL exmdb_server::store_eid_to_user(const char *, const STORE_ENTRYID *store_eid,
    char **maildir, uint32_t *user_id, uint32_t *domain_id)
{
	unsigned int uid = 0, domid = 0;
	char md[256];
	if (store_eid == nullptr || store_eid->pserver_name == nullptr)
		return false;
	if (store_eid->wrapped_provider_uid == g_muidStorePrivate) {
		enum display_type dt;
		if (!common_util_get_user_ids(store_eid->pserver_name, &uid, &domid, &dt) ||
		    !common_util_get_maildir(store_eid->pserver_name, md, std::size(md)))
			return false;
	} else {
		unsigned int orgid;
		if (!common_util_get_domain_ids(store_eid->pserver_name, &domid, &orgid) ||
		    !common_util_get_homedir(store_eid->pserver_name, md, std::size(md)))
			return false;
	}
	*maildir = common_util_dup(md);
	*user_id = uid;
	*domain_id = domid;
	return TRUE;
}

int need_msg_perm_check(sqlite3 *db, const char *user, uint64_t fid)
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

int have_delete_perm(sqlite3 *db, const char *user, uint64_t fid, uint64_t mid)
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
