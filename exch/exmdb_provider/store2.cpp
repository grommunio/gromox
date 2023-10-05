// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2023 grommunio GmbH
// This file is part of Gromox.
#define _GNU_SOURCE 1 /* AT_* */
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <sqlite3.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <fmt/core.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <gromox/database.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/fileio.h>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/rop_util.hpp>
#include <gromox/tie.hpp>
#include "db_engine.h"

using LLU = unsigned long long;
using namespace std::string_literals;
using namespace gromox;

struct sql_del {
	void operator()(sqlite3 *x) const { sqlite3_close(x); }
};

BOOL exmdb_server::vacuum(const char *dir)
{
	sleep(305);
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
	if (user == STORE_OWNER_GRANTED)
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
	if (user == STORE_OWNER_GRANTED)
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
 * @username:    Used for permission checking
 * @normal_size: Size that the caller should subtract from store size
 * @fai_size:    Size that the caller should subtract from store size/FAI
 * @msg_count:   Indicator for the caller to update the folder commit time
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
 * @username:   Used for permission checking, can be %STORE_OWNER_GRANTED
 *              or a less-privileged user.
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

static bool purg_discover_ids(sqlite3 *db, const std::string &query,
    std::vector<std::string> &used)
{
	auto stm = gx_sql_prep(db, query.c_str());
	if (stm == nullptr)
		return false;
	while (stm.step() == SQLITE_ROW)
		used.push_back(stm.col_text(0));
	return true;
}

#if defined(FMT_VERSION) && FMT_VERSION >= 90000
namespace {
unsigned int format_as(proptag_t x) { return x; }
}
#endif

static bool purg_discover_cids(sqlite3 *db, const char *dir,
    std::vector<std::string> &used)
{
	used.clear();
	auto query = fmt::format("SELECT propval FROM message_properties "
	             "WHERE proptag IN ({},{},{},{},{},{})",
	             PR_TRANSPORT_MESSAGE_HEADERS,
	             PR_TRANSPORT_MESSAGE_HEADERS_A,
	             PR_BODY, PR_BODY_A, PR_HTML, PR_RTF_COMPRESSED);
	if (!purg_discover_ids(db, query, used))
		return false;
	query = fmt::format("SELECT propval FROM attachment_properties "
	        "WHERE proptag IN ({},{})",
	        PR_ATTACH_DATA_BIN, PR_ATTACH_DATA_OBJ);
	return purg_discover_ids(db, query, used);
}

static bool purg_discover_mids(const char *dir, std::vector<std::string> &used)
{
	used.clear();
	std::unique_ptr<sqlite3, sql_del> db;
	auto dbpath = dir + "/exmdb/midb.sqlite3"s;
	auto ret = access(dbpath.c_str(), R_OK);
	if (ret < 0 && errno == ENOENT)
		/* File is allowed to be absent and is equivalent to used={}. */
		return true;
	ret = sqlite3_open_v2(dbpath.c_str(), &unique_tie(db),
	      SQLITE_OPEN_READWRITE, nullptr);
	if (ret != SQLITE_OK) {
		mlog(LV_ERR, "E-2386: cannot open %s: %s", dbpath.c_str(), sqlite3_errstr(ret));
		return false;
	}
	return purg_discover_ids(db.get(), "SELECT mid_string FROM messages", used);
}

static std::pair<uint64_t, size_t>
purg_delete_unused_files4(const std::string &cid_dir, const std::string &subdir,
    const std::vector<std::string> &used_ids, time_t upper_bound_ts)
{
	std::unique_ptr<DIR, file_deleter> dh(opendir((cid_dir + "/" + subdir).c_str()));
	if (dh == nullptr) {
		if (errno == ENOENT)
			return {0, 0};
		mlog(LV_ERR, "E-2387: cannot open %s/%s: %s",
			cid_dir.c_str(), subdir.c_str(), strerror(errno));
		return {UINT64_MAX, 0};
	}

	struct dirent *de;
	auto dfd = dirfd(dh.get());
	uint64_t bytes = 0;
	size_t filecount = 0;
	while ((de = readdir(dh.get())) != nullptr) {
		if (*de->d_name == '.')
			continue;
		std::string defix;
		if (subdir.empty()) {
			defix = de->d_name;
			if (defix.size() > 4 &&
			    (defix.compare(defix.size() - 4, 4, ".zst") == 0 ||
			    defix.compare(defix.size() - 4, 4, ".v1z") == 0))
				defix.erase(defix.size() - 4);
		} else {
			defix = subdir + "/" + de->d_name;
		}
		if (std::binary_search(used_ids.begin(), used_ids.end(), defix))
			continue;
		struct stat sb;
		if (fstatat(dfd, de->d_name, &sb, 0) != 0)
			/* e.g. removal by another racing entity, just don't bother */
			continue;
		if (S_ISDIR(sb.st_mode)) {
			auto [a, b] = purg_delete_unused_files4(cid_dir, defix.c_str(),
			              used_ids, upper_bound_ts);
			if (a != UINT64_MAX) {
				bytes += a;
				filecount += b;
			}
			if (unlinkat(dfd, de->d_name, AT_REMOVEDIR) != 0 && errno != ENOTEMPTY)
				mlog(LV_ERR, "E-2399: unlink %s/%s: %s",
					subdir.c_str(), de->d_name, strerror(errno));
			continue;
		}
		if (sb.st_mtime >= upper_bound_ts)
			continue;
		if (unlinkat(dfd, de->d_name, 0) != 0) {
			mlog(LV_ERR, "E-2392: unlink %s/%s: %s", subdir.c_str(), de->d_name, strerror(errno));
		} else {
			bytes += sb.st_size;
			++filecount;
		}
	}
	return {bytes, filecount};
}

static uint64_t purg_delete_unused_files(const std::string &cid_dir,
    const std::vector<std::string> &used_ids, time_t upper_bound_ts)
{
	mlog(LV_INFO, "I-2388: purge_data: processing %s...", cid_dir.c_str());
	auto [bytes, filecount] = purg_delete_unused_files4(cid_dir, {}, used_ids, upper_bound_ts);
	if (bytes == UINT64_MAX)
		return bytes;
	char buf[32];
	HX_unit_size(buf, std::size(buf), bytes, 0, 0);
	mlog(LV_NOTICE, "I-2393: Purged %zu files (%sB) from %s",
	     filecount, buf, cid_dir.c_str());
	return bytes;
}

static void sort_unique(std::vector<std::string> &c)
{
	std::sort(c.begin(), c.end());
	c.erase(std::unique(c.begin(), c.end()), c.end());
}

static bool purg_clean_cid(sqlite3 *db, const char *maildir, time_t upper_bound_ts)
{
	std::vector<std::string> used;
	if (!purg_discover_cids(db, maildir, used))
		return false;
	sort_unique(used);
	return purg_delete_unused_files(maildir + "/cid"s,
	       std::move(used), upper_bound_ts) < UINT64_MAX;
}

static bool purg_clean_mid(const char *maildir, time_t upper_bound_ts)
{
	std::vector<std::string> used;
	if (!purg_discover_mids(maildir, used))
		return false;
	sort_unique(used);
	if (purg_delete_unused_files(maildir + "/eml"s, used, upper_bound_ts) == UINT64_MAX)
		return false;
	if (purg_delete_unused_files(maildir + "/ext"s, used, upper_bound_ts) == UINT64_MAX)
		return false;
	return true;
}

BOOL exmdb_server::purge_datafiles(const char *dir)
{
	auto db = db_engine_get_db(dir);
	if (db == nullptr || db->psqlite == nullptr)
		return false;
	auto upper_bound_ts = time(nullptr) - 60;
	return purg_clean_cid(db->psqlite, dir, upper_bound_ts) &&
	       purg_clean_mid(dir, upper_bound_ts) ? TRUE : false;
}

BOOL exmdb_server::autoreply_tsquery(const char *dir, const char *peer,
    uint64_t window, uint64_t *status) try
{
	if (window == 0)
		window = INT64_MAX;
	auto db = db_engine_get_db(dir);
	if (db == nullptr || db->psqlite == nullptr)
		return false;
	auto adb = db->psqlite;
	auto stm = gx_sql_prep(adb, "SELECT `ts` FROM `autoreply_ts` WHERE `peer`=?");
	if (stm == nullptr)
		return false;
	stm.bind_text(1, peer);
	auto now = time(nullptr);
	if (stm.step() == SQLITE_ROW) {
		auto last_sent = stm.col_int64(0);
		*status = now - last_sent;
		if (*status < window)
			return TRUE;
	} else {
		*status = now;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2225: ENOMEM");
	return false;
}

BOOL exmdb_server::autoreply_tsupdate(const char *dir, const char *peer) try
{
	auto db = db_engine_get_db(dir);
	if (db == nullptr || db->psqlite == nullptr)
		return false;
	auto adb = db->psqlite;
	auto stm = gx_sql_prep(adb, "REPLACE INTO `autoreply_ts` (`peer`,`ts`) VALUES (?,?)");
	if (stm == nullptr)
		return false;
	stm.bind_text(1, peer);
	stm.bind_int64(2, time(nullptr));
	return stm.step() == SQLITE_DONE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2226: ENOMEM");
	return false;
}

BOOL exmdb_server::recalc_store_size(const char *dir, uint32_t flags)
{
	auto db = db_engine_get_db(dir);
	if (db == nullptr || db->psqlite == nullptr)
		return false;
	auto idb = db->psqlite;
	auto comp = [&](proptag_t tag, const char *wh) {
		char query[240];
		gx_snprintf(query, std::size(query), "REPLACE INTO store_properties "
			"(proptag,propval) VALUES (%u, (SELECT SUM(message_size) "
			"FROM messages WHERE %s))",
			tag, wh);
		gx_sql_exec(idb, query);
	};
#ifdef EXC
	/*
	 * In EXC2019, softdeleting an item decreases PR_MESSAGE_SIZE_EXTENDED,
	 * restoring it (or other forms of creation) re-increases it.
	 *
	 * This means a user can fill up the disk with endless softdelete items.
	 */
	comp(PR_MESSAGE_SIZE_EXTENDED, "is_deleted=0");
	comp(PR_NORMAL_MESSAGE_SIZE_EXTENDED, "is_deleted=0 AND is_associated=0");
	comp(PR_ASSOC_MESSAGE_SIZE_EXTENDED, "is_deleted=0 AND is_associated=1");
	comp(PR_DELETED_MESSAGE_SIZE_EXTENDED, "is_deleted=1");
	comp(PR_DELETED_NORMAL_MESSAGE_SIZE_EXTENDED, "is_deleted=1 AND is_associated=0");
	comp(PR_DELETED_ASSOC_MESSAGE_SIZE_EXTENDED, "is_deleted=1 AND is_associated=1");
#else
	/* Gromox tracks/reports actual use that is controllable by the user (GXL-407). */
	comp(PR_MESSAGE_SIZE_EXTENDED, "1");
	comp(PR_NORMAL_MESSAGE_SIZE_EXTENDED, "is_associated=0");
	comp(PR_ASSOC_MESSAGE_SIZE_EXTENDED, "is_associated=1");
	char query[240];
	snprintf(query, std::size(query), "DELETE FROM store_properties WHERE proptag IN (%u,%u,%u)",
	         PR_DELETED_MESSAGE_SIZE_EXTENDED,
	         PR_DELETED_NORMAL_MESSAGE_SIZE_EXTENDED,
	         PR_DELETED_ASSOC_MESSAGE_SIZE_EXTENDED);
	gx_sql_exec(idb, query);
#endif
	/*
	 * Currently folder sizes are calculated on-the-fly, but perhaps we
	 * should keep a rolling number for folders too?
	 */
	return TRUE;
}
