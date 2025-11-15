// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iconv.h>
#include <list>
#include <unistd.h>
#include <utility>
#include <vector>
#include <fmt/core.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/database.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/flat_set.hpp>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/proptag_array.hpp>
#include <gromox/propval.hpp>
#include <gromox/restriction.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/sortorder_set.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "db_engine.hpp"
#include "parser.hpp"

using LLU = unsigned long long;
using namespace gromox;

namespace {

struct condition_node {
	proptag_t proptag;
	void *pvalue;
};

struct CONTENT_ROW_PARAM {
	const db_conn &db;
	cpid_t cpid;
	sqlite3 *psqlite;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	uint64_t folder_id;
	uint64_t inst_id;
	int row_type;
	const SORTORDER_SET *psorts;
	proptag_t instance_tag, extremum_tag;
};

struct HIERARCHY_ROW_PARAM {
	const db_conn &db;
	cpid_t cpid;
	sqlite3 *psqlite;
	sqlite3_stmt *pstmt;
	uint64_t folder_id;
};

}

using TABLE_GET_ROW_PROPERTY = bool (*)(const void *, uint32_t, void **);

static bool table_sum_table_count(db_conn &db, uint32_t table_id, uint32_t *prows)
{
	char sql_string[128];
	
	snprintf(sql_string, std::size(sql_string), "SELECT "
			"count(idx) FROM t%u", table_id);
	auto pstmt = db.eph_prep(sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	*prows = sqlite3_column_int64(pstmt, 0);
	return TRUE;
}

/**
 * @username:   Used for retrieving public store readstates
 */
static uint32_t table_sum_hierarchy(sqlite3 *psqlite,
	uint64_t folder_id, const char *username, BOOL b_depth)
{
	uint32_t count;
	uint32_t permission;
	char sql_string[128];
	
	if (!b_depth) {
		if (username == STORE_OWNER_GRANTED) {
			snprintf(sql_string, std::size(sql_string), "SELECT count(*) FROM"
			          " folders WHERE parent_id=%llu", LLU{folder_id});
			auto pstmt = gx_sql_prep(psqlite, sql_string);
			if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
				return 0;
			count = sqlite3_column_int64(pstmt, 0);
		} else {
			count = 0;
			snprintf(sql_string, std::size(sql_string), "SELECT folder_id FROM "
			          "folders WHERE parent_id=%llu", LLU{folder_id});
			auto pstmt = gx_sql_prep(psqlite, sql_string);
			if (pstmt == nullptr)
				return 0;
			while (pstmt.step() == SQLITE_ROW) {
				if (!cu_get_folder_permission(psqlite,
				    sqlite3_column_int64(pstmt, 0),
				    username, &permission))
					continue;
				if (!(permission & (frightsReadAny | frightsVisible | frightsOwner)))
					continue;
				count ++;
			}
		}
	} else {
		count = 0;
		snprintf(sql_string, std::size(sql_string), "SELECT folder_id FROM "
		          "folders WHERE parent_id=%llu", LLU{folder_id});
		auto pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return 0;
		while (pstmt.step() == SQLITE_ROW) {
			if (username != STORE_OWNER_GRANTED) {
				if (!cu_get_folder_permission(psqlite,
				    sqlite3_column_int64(pstmt, 0), username, &permission))
					continue;
				if (!(permission & (frightsReadAny | frightsVisible | frightsOwner)))
					continue;
			}
			count += table_sum_hierarchy(psqlite,
				sqlite3_column_int64(pstmt, 0), username, TRUE);
			count ++;
		}
	}
	return count;
}

/**
 * @username:   Used for retrieving public store readstates
 */
static bool table_load_hierarchy(const db_conn &db,
	uint64_t folder_id, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, sqlite3_stmt *pstmt, int depth,
	uint32_t *prow_count)
{
	uint64_t folder_id1;
	uint32_t permission;
	char sql_string[256];
	
	snprintf(sql_string, std::size(sql_string), "SELECT folder_id FROM"
	         " folders WHERE parent_id=%llu AND is_deleted=%u",
	         LLU{folder_id}, !!(table_flags & TABLE_FLAG_SOFTDELETES));
	auto &psqlite = db.psqlite;
	auto pstmt1 = gx_sql_prep(psqlite, sql_string);
	if (pstmt1 == nullptr)
		return FALSE;
	while (pstmt1.step() == SQLITE_ROW) {
		folder_id1 = sqlite3_column_int64(pstmt1, 0);
		if (username != STORE_OWNER_GRANTED) {
			if (!cu_get_folder_permission(psqlite,
			    folder_id1, username, &permission))
				continue;
			if (!(permission & (frightsReadAny | frightsVisible | frightsOwner)))
				continue;
		}
		if (prestriction != nullptr &&
		    !cu_eval_folder_restriction(db, folder_id1, prestriction))
			goto LOAD_SUBFOLDER;
		sqlite3_bind_int64(pstmt, 1, folder_id1);
		sqlite3_bind_int64(pstmt, 2, depth);
		if (gx_sql_step(pstmt) != SQLITE_DONE)
			return FALSE;
		(*prow_count) ++;
		sqlite3_reset(pstmt);
 LOAD_SUBFOLDER:
		if ((table_flags & TABLE_FLAG_DEPTH) &&
		    !table_load_hierarchy(db, folder_id1, username,
		    table_flags, prestriction, pstmt, depth + 1, prow_count))
			return FALSE;
	}
	return TRUE;
}

/**
 * @username:   Used for retrieving public store readstates
 */
BOOL exmdb_server::sum_hierarchy(const char *dir,
	uint64_t folder_id, const char *username,
	BOOL b_depth, uint32_t *pcount)
{
	uint64_t fid_val;
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	fid_val = rop_util_get_gc_value(folder_id);
	*pcount = table_sum_hierarchy(pdb->psqlite,
					fid_val, username, b_depth);
	return TRUE;
}
	
/**
 * @username:   Used for retrieving public store readstates
 */
BOOL exmdb_server::load_hierarchy_table(const char *dir, uint64_t folder_id,
    const char *username, uint8_t table_flags, const RESTRICTION *prestriction,
    uint32_t *ptable_id, uint32_t *prow_count) try
{
	uint64_t fid_val;
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	if (!exmdb_server::is_private())
		exmdb_server::set_public_username(username);
	auto cl_0 = HX::make_scope_exit([]() { exmdb_server::set_public_username(nullptr); });
	fid_val = rop_util_get_gc_value(folder_id);
	auto table_id = pdb->next_table_id();
	auto table_transact = gx_sql_begin(pdb->m_sqlite_eph, txn_mode::write);
	if (!table_transact)
		return false;
	snprintf(sql_string, std::size(sql_string), "CREATE TABLE t%u "
		"(idx INTEGER PRIMARY KEY AUTOINCREMENT, "
		"folder_id INTEGER UNIQUE NOT NULL, "
		"depth INTEGER NOT NULL)", table_id);
	if (pdb->eph_exec(sql_string) != SQLITE_OK)
		return FALSE;

	std::list<table_node> holder;
	auto ptnode = &holder.emplace_back();
	ptnode->table_id = table_id;
	auto remote_id = exmdb_server::get_remote_id();
	if (NULL != remote_id) {
		ptnode->remote_id = strdup(remote_id);
		if (ptnode->remote_id == nullptr)
			return FALSE;
	}
	ptnode->type = table_type::hierarchy;
	ptnode->folder_id = fid_val;
	ptnode->table_flags = table_flags;
	if (table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
		auto phandle_guid = exmdb_server::get_handle();
		if (phandle_guid == nullptr)
			memset(&ptnode->handle_guid, 0, sizeof(GUID));
		else
			ptnode->handle_guid = *phandle_guid;
	}
	if (NULL != prestriction) {
		ptnode->prestriction = prestriction->dup();
		if (ptnode->prestriction == nullptr)
			return FALSE;
	}
	snprintf(sql_string, std::size(sql_string), "INSERT INTO t%u (folder_id,"
					" depth) VALUES (?, ?)", ptnode->table_id);
	auto pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*prow_count = 0;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	if (!table_load_hierarchy(*pdb, fid_val, username, table_flags,
	    prestriction, pstmt, 1, prow_count))
		return FALSE;
	sql_transact = xtransaction();
	pstmt.finalize();
	if (table_transact.commit() != SQLITE_OK)
		return false;
	*ptable_id = ptnode->table_id;
	auto dbase = pdb->lock_base_wr();
	dbase->tables.table_list.splice(dbase->tables.table_list.end(), std::move(holder));
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}

BOOL exmdb_server::sum_content(const char *dir, uint64_t folder_id,
	BOOL b_fai, BOOL b_deleted, uint32_t *pcount)
{
	uint64_t fid_val;
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	fid_val = rop_util_get_gc_value(folder_id);
	snprintf(sql_string, std::size(sql_string), "SELECT count(*)"
	         " FROM messages WHERE parent_fid=%llu AND "
	         "(is_associated=%u AND is_deleted=%u)",
	         LLU{fid_val}, !!b_fai, !!b_deleted);
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return FALSE;
	*pcount = sqlite3_column_int64(pstmt, 0);
	return TRUE;
}

static std::string table_cond_to_where(const std::vector<condition_node> &list)
{
	std::string w;
	for (const auto &cnode : list) {
		if (w.empty())
			w = "WHERE ";
		else
			w += " AND ";
		if (cnode.pvalue == nullptr)
			w += fmt::format("v{:x} IS NULL", cnode.proptag);
		else
			w += fmt::format("v{:x}=?", cnode.proptag);
	}
	return w;
}

static bool table_load_content(db_conn &db, sqlite3 *psqlite,
	const SORTORDER_SET *psorts, int depth, uint64_t parent_id,
    std::vector<condition_node> &cond_list, sqlite3_stmt *pstmt_insert,
	uint32_t *pheader_id, sqlite3_stmt *pstmt_update,
    uint32_t *punread_count) try
{
	void *pvalue;
	uint16_t type;
	BOOL b_orderby;
	int bind_index;
	int multi_index;
	BOOL b_extremum;
	uint64_t header_id;
	uint32_t unread_count;
	
	int64_t prev_id = -parent_id;
	auto where = table_cond_to_where(cond_list);
	if (depth == psorts->ccategories) {
		proptag_t tmp_proptag;
		multi_index = -1;
		for (unsigned int i = 0; i < psorts->count; ++i) {
			if ((psorts->psort[i].type & MVI_FLAG) == MVI_FLAG) {
				tmp_proptag = PROP_TAG(psorts->psort[i].type, psorts->psort[i].propid);
				multi_index = i;
				break;
			}
		}
		std::string qstr;
		if (multi_index != -1)
			qstr = fmt::format("SELECT message_id, read_state, "
			       "inst_num, v{:x} FROM stbl {}", tmp_proptag, where);
		else
			qstr = fmt::format("SELECT message_id, read_state, "
			       "inst_num FROM stbl {}", where);
		b_orderby = FALSE;
		for (unsigned int i = psorts->ccategories; i < psorts->count; ++i) {
			tmp_proptag = PROP_TAG(psorts->psort[i].type, psorts->psort[i].propid);
			if (TABLE_SORT_MAXIMUM_CATEGORY ==
				psorts->psort[i].table_sort ||
				TABLE_SORT_MINIMUM_CATEGORY ==
				psorts->psort[i].table_sort) {
				continue;
			}
			auto ord = psorts->psort[i].table_sort == TABLE_SORT_ASCEND ?
			           " ASC" : " DESC";
			if (!b_orderby) {
				qstr += fmt::format(" ORDER BY v{:x} {}", tmp_proptag, ord);
				b_orderby = TRUE;
			} else {
				qstr += fmt::format(", v{:x} {}", tmp_proptag, ord);
			}
		}
		auto pstmt = gx_sql_prep(psqlite, qstr);
		if (pstmt == nullptr)
			return FALSE;
		bind_index = 1;
		size_t i = 0;
		for (const auto &cond : cond_list) {
			if (cond.pvalue == nullptr) {
				++i;
				continue;
			}
			type = psorts->psort[i].type & ~MVI_FLAG;
			if (!common_util_bind_sqlite_statement(pstmt,
			    bind_index, type, cond.pvalue))
				return FALSE;
			bind_index++;
			++i;
		}
		while (pstmt.step() == SQLITE_ROW) {
			if (psorts->ccategories <= 0) {
				sqlite3_bind_null(pstmt_insert, 9);
			} else if (0 == sqlite3_column_int64(pstmt, 1)) {
				(*punread_count)++;
				/* unread(0) in extremum for message row */
				sqlite3_bind_int64(pstmt_insert, 9, 0);
			} else {
				/* read(1) in extremum for message row */
				sqlite3_bind_int64(pstmt_insert, 9, 1);
			}
			sqlite3_bind_int64(pstmt_insert, 1,
				sqlite3_column_int64(pstmt, 0));
			sqlite3_bind_int64(pstmt_insert, 2, CONTENT_ROW_MESSAGE);
			sqlite3_bind_null(pstmt_insert, 3);
			sqlite3_bind_int64(pstmt_insert, 4, parent_id);
			sqlite3_bind_int64(pstmt_insert, 5, depth);
			sqlite3_bind_null(pstmt_insert, 6);
			if (-1 != multi_index) {
				sqlite3_bind_int64(pstmt_insert, 7,
					sqlite3_column_int64(pstmt, 2));
				type = psorts->psort[multi_index].type & ~MVI_FLAG;
				pvalue = common_util_column_sqlite_statement(pstmt, 3, type);
				if (pvalue == nullptr)
					sqlite3_bind_null(pstmt_insert, 8);
				else if (!common_util_bind_sqlite_statement(pstmt_insert,
				    8, type, pvalue))
					return FALSE;
			} else {
				sqlite3_bind_int64(pstmt_insert, 7, 0);
				sqlite3_bind_null(pstmt_insert, 8);
			}
			sqlite3_bind_int64(pstmt_insert, 10, prev_id);
			if (gx_sql_step(pstmt_insert) != SQLITE_DONE)
				return FALSE;
			prev_id = sqlite3_last_insert_rowid(db.m_sqlite_eph);
			sqlite3_reset(pstmt_insert);
		}
		return TRUE;
	}
	std::string qstr;
	auto tmp_proptag = PROP_TAG(psorts->psort[depth].type, psorts->psort[depth].propid);
	if (depth == psorts->ccategories - 1 &&
		psorts->count > psorts->ccategories
		&& (TABLE_SORT_MAXIMUM_CATEGORY ==
		psorts->psort[depth + 1].table_sort ||
		TABLE_SORT_MINIMUM_CATEGORY ==
		psorts->psort[depth + 1].table_sort)) {
		b_extremum = TRUE;
		auto tmp_proptag1 = PROP_TAG(psorts->psort[depth+1].type, psorts->psort[depth+1].propid);
		if (TABLE_SORT_MAXIMUM_CATEGORY ==
			psorts->psort[depth + 1].table_sort) {
			qstr = fmt::format("SELECT v{:x}, COUNT(*), MAX(v{:x}) AS max_field "
			       "FROM stbl {} GROUP BY v{:x} ORDER BY max_field",
			       tmp_proptag, tmp_proptag1, where, tmp_proptag);
		} else {
			qstr = fmt::format("SELECT v{:x}, COUNT(*), MIN(v{:x}) AS max_field "
			       "FROM stbl {} GROUP BY v{:x} ORDER BY max_field",
			       tmp_proptag, tmp_proptag1, where, tmp_proptag);
		}
	} else {
		b_extremum = FALSE;
		qstr = fmt::format("SELECT v{:x}, COUNT(*) FROM stbl {} "
		       "GROUP BY v{:x} ORDER BY v{:x}",
		       tmp_proptag, where, tmp_proptag, tmp_proptag);
	}
	qstr += psorts->psort[depth].table_sort == TABLE_SORT_ASCEND ?
	        " ASC" : " DESC";
	auto pstmt = gx_sql_prep(psqlite, qstr);
	if (pstmt == nullptr)
		return FALSE;
	bind_index = 1;
	size_t i = 0;
	for (const auto &cond : cond_list) {
		if (cond.pvalue == nullptr) {
			++i;
			continue;
		}
		type = psorts->psort[i].type & ~MVI_FLAG;
		if (!common_util_bind_sqlite_statement(pstmt, bind_index, type,
		    cond.pvalue))
			return FALSE;
		bind_index++;
		++i;
	}
	auto &tmp_cnode = cond_list.emplace_back();
	while (pstmt.step() == SQLITE_ROW) {
		(*pheader_id) ++;
		header_id = *pheader_id | 0x100000000000000ULL;
		sqlite3_bind_int64(pstmt_insert, 1, header_id);
		sqlite3_bind_int64(pstmt_insert, 2, CONTENT_ROW_HEADER);
		sqlite3_bind_int64(pstmt_insert, 3, depth < psorts->cexpanded);
		sqlite3_bind_int64(pstmt_insert, 4, parent_id);
		sqlite3_bind_int64(pstmt_insert, 5, depth);
		/* total messages */
		sqlite3_bind_int64(pstmt_insert, 6,
			sqlite3_column_int64(pstmt, 1));
		sqlite3_bind_int64(pstmt_insert, 7, 0);
		type = psorts->psort[depth].type & ~MVI_FLAG;
		if (!b_extremum || (pvalue = common_util_column_sqlite_statement(pstmt,
		    2, psorts->psort[depth + 1].type)) == nullptr)
			sqlite3_bind_null(pstmt_insert, 9);
		else if (!common_util_bind_sqlite_statement(pstmt_insert,
		    9, psorts->psort[depth + 1].type, pvalue))
			return FALSE;
		/* pvalue will be recorded in condition list */
		pvalue = common_util_column_sqlite_statement(pstmt, 0, type);
		if (pvalue == nullptr)
			sqlite3_bind_null(pstmt_insert, 8);
		else if (!common_util_bind_sqlite_statement(pstmt_insert, 8, type, pvalue))
			return FALSE;
		sqlite3_bind_int64(pstmt_insert, 10, prev_id);
		if (gx_sql_step(pstmt_insert) != SQLITE_DONE)
			return FALSE;
		prev_id = sqlite3_last_insert_rowid(db.m_sqlite_eph);
		sqlite3_reset(pstmt_insert);
		tmp_cnode.proptag = tmp_proptag;
		unread_count = 0;
		tmp_cnode.pvalue = pvalue;
		if (!table_load_content(db, psqlite, psorts,
		    depth + 1, prev_id, cond_list, pstmt_insert,
		    pheader_id, pstmt_update, &unread_count))
			return FALSE;
		sqlite3_bind_int64(pstmt_update, 1, unread_count);
		sqlite3_bind_int64(pstmt_update, 2, prev_id);
		if (gx_sql_step(pstmt_update) != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt_update);
		*punread_count += unread_count;
	}
	cond_list.pop_back();
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static inline const BINARY *get_conv_id(const RESTRICTION *x)
{
	if (x == nullptr || x->rt != RES_PROPERTY || x->prop == nullptr)
		return nullptr;
	auto y = x->prop;
	if (y->relop != RELOP_EQ || y->proptag != PR_CONVERSATION_ID ||
	    PROP_TYPE(y->propval.proptag) != PT_BINARY)
		return nullptr;
	auto b = static_cast<const BINARY *>(y->propval.pvalue);
	return b->cb == 16 ? b : nullptr;
}

namespace {
struct acsort {
	int dir = 0;
	proptag_t tag{};
};
}

static acsort accel_sorting(const SORTORDER_SET *set)
{
	if (set == nullptr)
		return {};
	if (set->count != 1)
		return {};
	auto &so = set->psort[0];
	int dir = so.table_sort == TABLE_SORT_ASCEND ? 1 : -1;
	auto tag = PROP_TAG(so.type, so.propid);
	switch (tag) {
	case PR_LAST_MODIFICATION_TIME:
	case PR_MESSAGE_DELIVERY_TIME:
	case PR_CLIENT_SUBMIT_TIME:
		return {dir, tag};
	default:
		return {};
	}
}

static std::string gct_makequery_fai(uint64_t fid_val, bool b_search, bool b_del)
{
	if (!b_search)
		return fmt::format("SELECT message_id FROM messages "
		       "WHERE parent_fid={} AND is_associated=1 AND is_deleted={}",
		       LLU{fid_val}, b_del);

	return fmt::format("SELECT m.message_id FROM messages AS m "
	       "JOIN search_result AS sr ON sr.folder_id={} AND "
	       "sr.message_id=m.message_id AND m.is_associated=1 "
	       "AND m.is_deleted={}", LLU{fid_val}, b_del);
}

static std::string gct_makequery_regular(uint64_t fid_val, bool b_search, bool b_del)
{
	if (!b_search)
		return fmt::format("SELECT message_id FROM messages "
		       "WHERE parent_fid={} AND is_deleted={} AND "
		       "is_associated=0", LLU{fid_val}, b_del);

	return fmt::format("SELECT m.message_id FROM messages AS m "
	       "JOIN search_result AS sr ON sr.folder_id={} AND "
	       "sr.message_id=m.message_id AND m.is_associated=0 "
	       "AND m.is_deleted={}", LLU{fid_val}, b_del);
}

static std::string gct_makequery_conv(uint64_t fid_val,
    const BINARY *conv_id, bool b_del)
{
	if (conv_id == nullptr)
		return fmt::format("SELECT message_id FROM messages "
		       "WHERE parent_fid IS NOT NULL AND is_associated=0 "
		       "AND is_deleted={}", b_del);

	return fmt::format("SELECT mp.message_id FROM message_properties AS mp "
	       "JOIN messages AS m ON mp.message_id=m.message_id "
	       "WHERE mp.proptag={} AND mp.propval=x'{}' "
	       "AND m.is_deleted={}", static_cast<uint32_t>(PR_CONVERSATION_ID),
	       bin2hex(conv_id->pv, conv_id->cb), b_del);
}

static std::string gct_makequery(uint64_t fid_val, unsigned int flags,
    const acsort &accel_pair, const BINARY *conv, bool b_private, bool b_search)
{
	if (!g_enable_dam && b_private && fid_val == PRIVATE_FID_DEFERRED_ACTION)
		return "SELECT message_id FROM messages WHERE 0";
	/*
	 * accel tag is only set under no-frills conditions anyway, so no harm
	 * in testing it before table_falgs.
	 */
	static constexpr char order_kw[2][5] = {"DESC", "ASC"};
	auto adir = order_kw[accel_pair.dir > 0];
	if (accel_pair.tag == PR_LAST_MODIFICATION_TIME)
		return fmt::format("SELECT message_id FROM msgtime_index "
		       "WHERE folder_id={} ORDER BY mtime {}", LLU{fid_val}, adir);
	else if (accel_pair.tag == PR_MESSAGE_DELIVERY_TIME)
		return fmt::format("SELECT message_id FROM msgtime_index "
		       "WHERE folder_id={} ORDER BY rcvtime {}", LLU{fid_val}, adir);
	else if (accel_pair.tag == PR_CLIENT_SUBMIT_TIME)
		return fmt::format("SELECT message_id FROM msgtime_index "
		       "WHERE folder_id={} ORDER BY sndtime {}", LLU{fid_val}, adir);

	auto b_del = flags & TABLE_FLAG_SOFTDELETES;
	if (flags & TABLE_FLAG_CONVERSATIONMEMBERS)
		return gct_makequery_conv(fid_val, conv, b_del);
	if (flags & TABLE_FLAG_ASSOCIATED)
		return gct_makequery_fai(fid_val, b_search, b_del);

	return gct_makequery_regular(fid_val, b_search, b_del);
}

/**
 * @username:   Used for retrieving public store readstates
 *
 * ptable_id can remain untouched when the folder does not exist.
 *
 * Under public mode username, always available for read state.
 */
static bool table_load_content_table(db_conn &db, db_base_wr_ptr &dbase,
    cpid_t cpid, uint64_t fid_val, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, const SORTORDER_SET *psorts,
   uint32_t *ptable_id, uint32_t *prow_count) try
{
	unsigned int multi_index = 0; /* stbl column number (1-based) for MV propval */
	unsigned int col_read = 0; /* stbl column number for read_state */
	unsigned int col_inum = 0; /* stbl column number for inst_num */
	size_t tag_count = 0;
	void *pvalue;
	proptag_t tmp_proptags[16];

	auto conv_id = (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS) ?
	               get_conv_id(prestriction) : nullptr;
	if (psorts != nullptr && psorts->count > std::size(tmp_proptags))
		return FALSE;	
	bool b_search = false;
	if (!exmdb_server::is_private()) {
		exmdb_server::set_public_username(username);
	} else {
		auto sql_string = fmt::format("SELECT is_search FROM "
		                  "folders WHERE folder_id={}", LLU{fid_val});
		auto pstmt = db.prep(sql_string);
		if (pstmt == nullptr)
			return FALSE;
		if (pstmt.step() != SQLITE_ROW) {
			*ptable_id = 0;
			*prow_count = 0;
			return TRUE;
		}
		b_search = pstmt.col_int64(0) != 0;
	}
	auto cl_1 = HX::make_scope_exit([]() { exmdb_server::set_public_username(nullptr); });
	uint32_t table_id = *ptable_id != 0 ? *ptable_id : db.next_table_id();
	auto table_transact = gx_sql_begin(db.m_sqlite_eph, txn_mode::write);
	if (!table_transact)
		return false;
	auto sql_string = fmt::format("CREATE TABLE t{} "
		"(row_id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"idx INTEGER UNIQUE DEFAULT NULL, "
		"prev_id INTEGER UNIQUE DEFAULT NULL, "
		"inst_id INTEGER NOT NULL, "
		"row_type INTEGER NOT NULL, "
		"row_stat INTEGER DEFAULT NULL, "	/* expanded(1) or collapsed(0) */
		"parent_id INTEGER DEFAULT NULL, "
		"depth INTEGER NOT NULL, "
		"count INTEGER DEFAULT NULL, "
		"unread INTEGER DEFAULT NULL, "
		"inst_num INTEGER NOT NULL, "
		"value NONE DEFAULT NULL, "
		"extremum NONE DEFAULT NULL)",		/* read(unread) for message row */
		table_id);
	if (db.eph_exec(sql_string) != SQLITE_OK)
		return FALSE;
	if (NULL != psorts && psorts->ccategories > 0) {
		sql_string = fmt::format("CREATE UNIQUE INDEX t{}_1 ON "
		             "t{} (inst_id, inst_num)", table_id, table_id);
		if (db.eph_exec(sql_string) != SQLITE_OK)
			return FALSE;
		sql_string = fmt::format("CREATE INDEX t{}_2 ON"
		             " t{} (parent_id)", table_id, table_id);
		if (db.eph_exec(sql_string) != SQLITE_OK)
			return FALSE;
		sql_string = fmt::format("CREATE INDEX t{}_3 ON t{}"
		             " (parent_id, value)", table_id, table_id);
		if (db.eph_exec(sql_string) != SQLITE_OK)
			return FALSE;
	}

	std::list<table_node> holder;
	auto ptnode = &holder.emplace_back();
	xstmt pstmt, pstmt1;
	sqlite3 *psqlite = nullptr;
	ptnode->table_id = table_id;
	auto remote_id = exmdb_server::get_remote_id();
	auto cl_0 = HX::make_scope_exit([&]() {
		pstmt.finalize();
		pstmt1.finalize();
		if (psqlite != nullptr)
			sqlite3_close(psqlite);
	});
	if (NULL != remote_id) {
		ptnode->remote_id = strdup(remote_id);
		if (ptnode->remote_id == nullptr)
			return false;
	}
	ptnode->type = table_type::content;
	ptnode->folder_id = fid_val;
	ptnode->table_flags = table_flags;
	ptnode->b_search = b_search ? TRUE : false;
	ptnode->cpid = cpid;
	if (!exmdb_server::is_private()) {
		ptnode->username = strdup(username);
		if (ptnode->username == nullptr)
			return false;
	}
	if (NULL != prestriction) {
		ptnode->prestriction = prestriction->dup();
		if (ptnode->prestriction == nullptr)
			return false;
	}

	/* [Block 1] */
	xtransaction psort_transact;
	acsort accel_pair;
	if ((table_flags & (TABLE_FLAG_CONVERSATIONMEMBERS | TABLE_FLAG_ASSOCIATED | TABLE_FLAG_SOFTDELETES)) == 0 &&
	    !b_search)
		accel_pair = accel_sorting(psorts);
	if (accel_pair.dir != 0)
		psorts = nullptr;
	if (NULL != psorts) {
		/*
		 * The propvals of the sort criterion proptags are copied from
		 * the individual messages to rows in stbl. By way of stbl's
		 * PRIMARY KEY, rows automatically get sorted as part of
		 * filling the table. Then we read out the msgids from the rows
		 * in primary key order.
		 */
		ptnode->psorts = sortorder_set_dup(psorts);
		if (ptnode->psorts == nullptr)
			return false;
		if (sqlite3_open_v2(":memory:", &psqlite,
		    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK)
			return false;
		psort_transact = gx_sql_begin(psqlite, txn_mode::write);
		if (!psort_transact)
			return false;
		sql_string = "CREATE TABLE stbl (message_id INTEGER NOT NULL";
		for (size_t i = 0; i < psorts->count; ++i) {
			auto tmp_proptag = PROP_TAG(psorts->psort[i].type, psorts->psort[i].propid);
			if (psorts->psort[i].table_sort == TABLE_SORT_MAXIMUM_CATEGORY ||
			    psorts->psort[i].table_sort == TABLE_SORT_MINIMUM_CATEGORY)
				ptnode->extremum_tag = tmp_proptag;
			tmp_proptags[tag_count] = tmp_proptag;
			/* check if proptag is already in the field list */
			if (i >= psorts->ccategories) {
				size_t j;
				for (j = 0; j < tag_count; ++j)
					if (tmp_proptags[j] == tmp_proptag)
						break;
				if (j < tag_count)
					continue;
			}
			tag_count ++;
			uint16_t type = psorts->psort[i].type;
			if ((type & MVI_FLAG) == MVI_FLAG) {
				type &= ~MVI_FLAG;
				ptnode->instance_tag = tmp_proptag;
				multi_index = i + 2;
			}
			switch (type) {
			case PT_STRING8:
			case PT_UNICODE:
				sql_string += fmt::format(", v{:x} TEXT COLLATE NOCASE", tmp_proptag);
				break;
			case PT_FLOAT:
			case PT_DOUBLE:
			case PT_APPTIME:
				sql_string += fmt::format(", v{:x} REAL", tmp_proptag);
				break;
			case PT_CURRENCY:
			case PT_I8:
			case PT_SYSTIME:
			case PT_SHORT:
			case PT_LONG:
			case PT_BOOLEAN:
				sql_string += fmt::format(", v{:x} INTEGER", tmp_proptag);
				break;
			case PT_CLSID:
			case PT_SVREID:
			case PT_OBJECT:
			case PT_BINARY:
				sql_string += fmt::format(", v{:x} BLOB", tmp_proptag);
				break;
			default:
				return false;
			}
		}
		col_read = tag_count + 2;
		col_inum = tag_count + 3;
		sql_string += ", read_state INTEGER DEFAULT 0, inst_num INTEGER DEFAULT 0)";
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return false;
		for (size_t i = 0; i < tag_count; ++i) {
			auto tmp_proptag = tmp_proptags[i];
			sql_string = fmt::format("CREATE INDEX stbl_{} ON stbl (v{:x})",
			             i, tmp_proptag);
			if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
				return false;
		}
		if (ptnode->instance_tag == 0)
			sql_string = fmt::format("CREATE UNIQUE INDEX t{}_4 ON t{} (inst_id)", table_id, table_id);
		else
			sql_string = fmt::format("CREATE INDEX t{}_4 ON t{} (inst_id)", table_id, table_id);
		if (db.eph_exec(sql_string) != SQLITE_OK)
			return false;
		sql_string = "INSERT INTO stbl VALUES (?";
		for (size_t i = 0; i < tag_count; ++i)
			sql_string += ", ?";
		sql_string += ", ?, ?)";
		pstmt1 = gx_sql_prep(psqlite, sql_string);
		if (pstmt1 == nullptr)
			return false;
	} else {
		auto sql_string = fmt::format("INSERT INTO t{} (inst_id,"
		                  " prev_id, row_type, depth, inst_num, idx) VALUES "
		                  "(?, ?, {}, 0, 0, ?)",
		                  table_id, CONTENT_ROW_MESSAGE);
		pstmt1 = db.eph_prep(sql_string);
		if (pstmt1 == nullptr)
			return false;
	}

	/* [Block 2] Construct the SQL query that will scan the folder */
	sql_string = gct_makequery(fid_val, table_flags, accel_pair, conv_id,
	             exmdb_server::is_private(), b_search);
	pstmt = db.prep(sql_string);
	if (pstmt == nullptr)
		return false;

	/*
	 * [Block 3] Loop for reading the folder content. The first pass either
	 * fills the MAPI content table, or, in case a sort criteria is
	 * defined, stbl.
	 */
	uint64_t last_row_id = 0;
	while (pstmt.step() == SQLITE_ROW) {
		uint64_t mid_val = pstmt.col_uint64(0);
		if (conv_id != nullptr) {
			uint64_t parent_fid = 0;
			if (common_util_check_message_associated(db.psqlite, mid_val))
				continue;
			if (!common_util_get_message_parent_folder(db.psqlite,
			    mid_val, &parent_fid))
				return false;
			if (parent_fid == 0)
				continue;
		} else if (prestriction != nullptr &&
		    !cu_eval_msg_restriction(db, cpid, mid_val, prestriction)) {
			continue;
		}
		sqlite3_bind_int64(pstmt1, 1, mid_val);
		if (NULL != psorts) {
			for (size_t i = 0; i < tag_count; ++i) {
				auto tmp_proptag = tmp_proptags[i];
				if (tmp_proptag == ptnode->instance_tag)
					continue;
				if (!cu_get_property(MAPI_MESSAGE, mid_val,
				    cpid, db, tmp_proptag, &pvalue))
					return false;
				if (pvalue == nullptr)
					sqlite3_bind_null(pstmt1, i + 2);
				else if (!common_util_bind_sqlite_statement(pstmt1,
				    i + 2, PROP_TYPE(tmp_proptag), pvalue))
					return false;
			}
			if (psorts->ccategories > 0) {
				if (!cu_get_property(MAPI_MESSAGE, mid_val,
				    CP_ACP, db, PR_READ, &pvalue))
					return false;
				sqlite3_bind_int64(pstmt1, col_read,
					pvb_disabled(pvalue) ? 0 : 1);
			}
			/* insert all instances into stbl */
			if (0 != ptnode->instance_tag) {
				if (!cu_get_property(MAPI_MESSAGE,
				    mid_val, cpid, db,
				    ptnode->instance_tag & ~MV_INSTANCE, &pvalue))
					return false;
				if (NULL == pvalue) {
 BIND_NULL_INSTANCE:
					sqlite3_bind_null(pstmt1, multi_index);
					sqlite3_bind_int64(pstmt1, col_inum, 0);
					if (pstmt1.step() != SQLITE_DONE)
						return false;
					sqlite3_reset(pstmt1);
					continue;
				}
				uint16_t type = PROP_TYPE(ptnode->instance_tag) & ~MV_INSTANCE;
				switch (type) {
#define H(ctyp, memb) { \
		auto sa = static_cast<ctyp *>(pvalue); \
		if (sa->count == 0) \
			goto BIND_NULL_INSTANCE; \
		for (size_t i = 0; i < sa->count; ++i) { \
			if (!common_util_bind_sqlite_statement(pstmt1, multi_index, type & ~MVI_FLAG, &sa->memb[i])) \
				return false; \
			pstmt1.bind_int64(col_inum, i + 1); \
			if (pstmt1.step() != SQLITE_DONE) \
				return false; \
			pstmt1.reset(); \
		} \
		break; \
	}

				case PT_MV_SHORT: H(SHORT_ARRAY, ps)
				case PT_MV_LONG: H(LONG_ARRAY, pl)
				case PT_MV_CURRENCY:
				case PT_MV_I8:
				case PT_MV_SYSTIME: H(LONGLONG_ARRAY, pll)
				case PT_MV_FLOAT: H(FLOAT_ARRAY, mval)
				case PT_MV_DOUBLE:
				case PT_MV_APPTIME: H(DOUBLE_ARRAY, mval)
				case PT_MV_STRING8:
				case PT_MV_UNICODE: H(STRING_ARRAY, ppstr)
				case PT_MV_CLSID: H(GUID_ARRAY, pguid)
				case PT_MV_BINARY: H(BINARY_ARRAY, pbin)
				default:
					return false;
#undef H
				}
				continue;
			}
		} else {
			sqlite3_bind_int64(pstmt1, 2, last_row_id);
			sqlite3_bind_int64(pstmt1, 3, last_row_id + 1);
		}
		if (pstmt1.step() != SQLITE_DONE)
			return false;
		if (psorts == nullptr)
			last_row_id = sqlite3_last_insert_rowid(db.m_sqlite_eph);
		sqlite3_reset(pstmt1);
	}
	pstmt.finalize();
	pstmt1.finalize();

	/* [Block 4] Second pass copying from stbl into the MAPI content table. */
	if (NULL != psorts) {
		sql_string = fmt::format("INSERT INTO t{} "
		             "(inst_id, row_type, row_stat, parent_id, depth, "
		             "count, inst_num, value, extremum, prev_id) VALUES"
		             " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", table_id);
		pstmt = db.eph_prep(sql_string);
		if (pstmt == nullptr)
			return false;
		sql_string = fmt::format("UPDATE t{} SET unread=? WHERE row_id=?", table_id);
		pstmt1 = db.eph_prep(sql_string);
		if (pstmt1 == nullptr)
			return false;

		std::vector<condition_node> cond_list;
		uint32_t unread_count = 0;
		if (!table_load_content(db, psqlite, psorts, 0, 0, cond_list,
		    pstmt, &ptnode->header_id, pstmt1, &unread_count))
			return false;
		pstmt.finalize();
		pstmt1.finalize();
		if (psort_transact.commit() != SQLITE_OK)
			return false;
		sqlite3_close(psqlite);
		psqlite = NULL;
		/* index the content table */
		if (psorts->ccategories > 0) {
			sql_string = fmt::format("SELECT row_id, "
			             "row_type, row_stat, depth, prev_id FROM "
			             "t{} ORDER BY row_id", table_id);
			pstmt = db.eph_prep(sql_string);
			if (pstmt == nullptr)
				return false;
			sql_string = fmt::format("UPDATE t{} SET idx=? WHERE row_id=?", table_id);
			pstmt1 = db.eph_prep(sql_string);
			if (pstmt1 == nullptr)
				return false;

			size_t i = 1;
			uint64_t prev_id = 0;
			int depth = 0;
			while (pstmt.step() == SQLITE_ROW) {
				if (0 != prev_id &&
					depth < sqlite3_column_int64(pstmt, 3) &&
				    gx_sql_col_uint64(pstmt, 4) != prev_id)
					continue;
				uint64_t row_id = pstmt.col_uint64(0);
				if (CONTENT_ROW_HEADER == sqlite3_column_int64(pstmt, 1)) {
					if (0 == sqlite3_column_int64(pstmt, 2)) {
						prev_id = row_id;
						depth = sqlite3_column_int64(pstmt, 3);
					} else {
						prev_id = 0;
					}
				}
				sqlite3_bind_int64(pstmt1, 1, i);
				sqlite3_bind_int64(pstmt1, 2, row_id);
				if (pstmt1.step() != SQLITE_DONE)
					return false;
				sqlite3_reset(pstmt1);
				i ++;
			}
			pstmt.finalize();
			pstmt1.finalize();
		} else {
			sql_string = fmt::format("UPDATE t{} SET idx=row_id", table_id);
			if (db.eph_exec(sql_string) != SQLITE_OK)
				return false;
		}
	}
	cl_0.release();
	if (table_transact.commit() != SQLITE_OK)
		return false;
	dbase->tables.table_list.splice(dbase->tables.table_list.end(), std::move(holder));
	if (*ptable_id == 0)
		*ptable_id = table_id;
	*prow_count = 0;
	table_sum_table_count(db, table_id, prow_count);
	return TRUE;
} catch (const std::bad_alloc &) {
	return FALSE;
}

/**
 * @ptable_id:  Output table id
 * @username:   Used for retrieving public store readstates
 *
 * *ptable_id can be 0 even with a success return code, indicating that no data
 * is available (e.g. folder was deleted while table object is still open).
 */
BOOL exmdb_server::load_content_table(const char *dir, cpid_t cpid,
	uint64_t folder_id, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, const SORTORDER_SET *psorts,
	uint32_t *ptable_id, uint32_t *prow_count)
{
	if (psorts != nullptr)
		/*
		 * Sorting is only implemented for scalars, so MV is rejected
		 * if it is not MVI.
		 */
		for (unsigned int i = 0; i < psorts->count; ++i)
			if ((psorts->psort[i].type & MVI_FLAG) == MV_FLAG)
				return false; // ecTooComplex
	uint64_t fid_val;
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto dbase = pdb->lock_base_wr();
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	*ptable_id = 0;
	fid_val = rop_util_get_gc_value(folder_id);
	return table_load_content_table(*pdb, dbase, cpid, fid_val, username,
	       table_flags, prestriction, psorts, ptable_id, prow_count);
}

BOOL exmdb_server::reload_content_table(const char *dir, uint32_t table_id)
{
	BOOL b_result;
	uint32_t row_count;
	char sql_string[128];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto dbase = pdb->lock_base_wr();
	db_conn::NOTIFQ notifq;
	auto &table_list = dbase->tables.table_list;
	auto iter = std::find_if(table_list.begin(), table_list.end(),
	            [&](const table_node &t) {
	            	return t.type == table_type::content && t.table_id == table_id;
	            });
	if (iter == table_list.end())
		return TRUE;

	std::list<table_node> holder;
	holder.splice(holder.end(), table_list, iter);
	auto ptnode = &holder.back();
	snprintf(sql_string, std::size(sql_string), "DROP TABLE t%u", table_id);
	if (pdb->eph_exec(sql_string) != SQLITE_OK)
		/* ignore; the id won't be reused anyway */;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	b_result = table_load_content_table(*pdb, dbase, ptnode->cpid,
			ptnode->folder_id, ptnode->username, ptnode->table_flags,
			ptnode->prestriction, ptnode->psorts, &table_id,
			&row_count);
	pdb->notify_cttbl_reload(table_id, *dbase, notifq);
	dg_notify(std::move(notifq));
	return b_result;
}

static BOOL table_load_permissions(sqlite3 *psqlite,
	uint64_t folder_id, sqlite3_stmt *pstmt, uint32_t *prow_count)
{
	BOOL b_default;
	BOOL b_anonymous;
	uint64_t member_id;
	char sql_string[256];
	const char *pusername;
	
	snprintf(sql_string, std::size(sql_string), "SELECT member_id, username"
	          " FROM permissions WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt1 = gx_sql_prep(psqlite, sql_string);
	if (pstmt1 == nullptr)
		return FALSE;
	b_default = FALSE;
	b_anonymous = FALSE;
	while (pstmt1.step() == SQLITE_ROW) {
		member_id = sqlite3_column_int64(pstmt1, 0);
		sqlite3_bind_int64(pstmt, 1, member_id);
		if (gx_sql_step(pstmt) != SQLITE_DONE)
			return FALSE;
		(*prow_count) ++;
		sqlite3_reset(pstmt);
		if (sqlite3_column_type(pstmt1, 1) == SQLITE_NULL)
			return FALSE;
		pusername = reinterpret_cast<const char *>(sqlite3_column_text(pstmt1, 1));
		if (*pusername == '\0')
			b_anonymous = TRUE;
		else if (strcasecmp("default", pusername) == 0)
			b_default = TRUE;
	}
	if (!b_default) {
		sqlite3_bind_int64(pstmt, 1, MEMBER_ID_DEFAULT);
		if (gx_sql_step(pstmt) != SQLITE_DONE)
			return FALSE;
		(*prow_count) ++;
		sqlite3_reset(pstmt);
	}
	if (!b_anonymous) {
		sqlite3_bind_int64(pstmt, 1, MEMBER_ID_ANONYMOUS);
		if (gx_sql_step(pstmt) != SQLITE_DONE)
			return FALSE;
		(*prow_count) ++;
		sqlite3_reset(pstmt);
	}
	return TRUE;
}

BOOL exmdb_server::load_permission_table(const char *dir, uint64_t folder_id,
    uint32_t table_flags, uint32_t *ptable_id, uint32_t *prow_count) try
{
	uint64_t fid_val;
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation on main, no transaction needed. */
	fid_val = rop_util_get_gc_value(folder_id);
	auto table_id = pdb->next_table_id();
	auto table_transact = gx_sql_begin(pdb->m_sqlite_eph, txn_mode::write);
	if (!table_transact)
		return false;
	snprintf(sql_string, std::size(sql_string), "CREATE TABLE t%u (idx INTEGER PRIMARY KEY "
		"AUTOINCREMENT, member_id INTEGER UNIQUE NOT NULL)", table_id);
	if (pdb->eph_exec(sql_string) != SQLITE_OK)
		return FALSE;

	std::list<table_node> holder;
	auto ptnode = &holder.emplace_back();
	ptnode->table_id = table_id;
	auto remote_id = exmdb_server::get_remote_id();
	if (NULL != remote_id) {
		ptnode->remote_id = strdup(remote_id);
		if (ptnode->remote_id == nullptr)
			return FALSE;
	}
	ptnode->type = table_type::permission;
	ptnode->folder_id = fid_val;
	ptnode->table_flags = table_flags;
	snprintf(sql_string, std::size(sql_string), "INSERT INTO t%u "
		"(member_id) VALUES (?)", ptnode->table_id);
	auto pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*prow_count = 0;
	if (!table_load_permissions(pdb->psqlite, fid_val, pstmt, prow_count))
		return FALSE;
	pstmt.finalize();
	if (table_transact.commit() != SQLITE_OK)
		return false;
	*ptable_id = ptnode->table_id;
	auto dbase = pdb->lock_base_wr();
	dbase->tables.table_list.splice(dbase->tables.table_list.end(), std::move(holder));
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}

static bool table_evaluate_rule_restriction(sqlite3 *psqlite, uint64_t rule_id,
    const RESTRICTION *pres)
{
	void *pvalue;
	void *pvalue1;
	
	switch (pres->rt) {
	case RES_AND:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (!table_evaluate_rule_restriction(psqlite,
			    rule_id, &pres->andor->pres[i]))
				return FALSE;
		return TRUE;
	case RES_OR:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (table_evaluate_rule_restriction(psqlite,
			    rule_id, &pres->andor->pres[i]))
				return TRUE;
		return false;
	case RES_NOT:
		if (table_evaluate_rule_restriction(psqlite,
		    rule_id, &pres->xnot->res))
			return FALSE;
		return TRUE;
	case RES_CONTENT: {
		auto rcon = pres->cont;
		if (!rcon->comparable())
			return FALSE;
		if (!common_util_get_rule_property(rule_id, psqlite,
		    rcon->proptag, &pvalue))
			return FALSE;
		return rcon->eval(pvalue);
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		if (!rprop->comparable())
			return false;
		if (!common_util_get_rule_property(rule_id, psqlite,
		    rprop->proptag, &pvalue))
			return FALSE;
		if (pvalue == nullptr || rprop->proptag != PR_ANR)
			return rprop->eval(pvalue);
		return strcasestr(static_cast<char *>(pvalue),
		       static_cast<char *>(rprop->propval.pvalue)) != nullptr;
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (!rprop->comparable())
			return FALSE;
		if (!common_util_get_rule_property(rule_id, psqlite,
		    rprop->proptag1, &pvalue) || pvalue == nullptr)
			return FALSE;
		if (!common_util_get_rule_property(rule_id, psqlite,
		    rprop->proptag2, &pvalue1) || pvalue1 == nullptr)
			return FALSE;
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag1), pvalue, pvalue1);
	}
	case RES_BITMASK: {
		auto rbm = pres->bm;
		if (!rbm->comparable())
			return FALSE;
		if (!common_util_get_rule_property(rule_id, psqlite,
		    rbm->proptag, &pvalue))
			return FALSE;
		return rbm->eval(pvalue);
	}
	case RES_SIZE: {
		auto rsize = pres->size;
		if (!common_util_get_rule_property(rule_id, psqlite,
		    rsize->proptag, &pvalue))
			return FALSE;
		return rsize->eval(pvalue);
	}
	case RES_EXIST:
		if (!common_util_get_rule_property(rule_id, psqlite,
		    pres->exist->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		return TRUE;
	case RES_COMMENT:
	case RES_ANNOTATION:
		if (pres->comment->pres == nullptr)
			return TRUE;
		return table_evaluate_rule_restriction(psqlite, rule_id,
		       pres->comment->pres);
	default:
		mlog(LV_WARN, "W-2240: restriction type %u unevaluated",
			static_cast<unsigned int>(pres->rt));
		return FALSE;
	}	
	return FALSE;
}

static BOOL table_load_rules(sqlite3 *psqlite, uint64_t folder_id,
	uint8_t table_flags, const RESTRICTION *prestriction,
	sqlite3_stmt *pstmt, uint32_t *prow_count)
{
	uint64_t rule_id;
	char sql_string[80];
	
	snprintf(sql_string, std::size(sql_string), "SELECT rule_id FROM "
	          "rules WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt1 = gx_sql_prep(psqlite, sql_string);
	if (pstmt1 == nullptr)
		return FALSE;
	while (pstmt1.step() == SQLITE_ROW) {
		rule_id = sqlite3_column_int64(pstmt1, 0);
		if (prestriction != nullptr &&
		    !table_evaluate_rule_restriction(psqlite, rule_id, prestriction))
			continue;
		sqlite3_bind_int64(pstmt, 1, rule_id);
		if (gx_sql_step(pstmt) != SQLITE_DONE)
			return FALSE;
		(*prow_count) ++;
		sqlite3_reset(pstmt);
	}
	return TRUE;
}

BOOL exmdb_server::load_rule_table(const char *dir, uint64_t folder_id,
    uint8_t table_flags, const RESTRICTION *prestriction, uint32_t *ptable_id,
    uint32_t *prow_count) try
{
	uint64_t fid_val;
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	fid_val = rop_util_get_gc_value(folder_id);
	auto table_id = pdb->next_table_id();
	auto table_transact = gx_sql_begin(pdb->m_sqlite_eph, txn_mode::write);
	if (!table_transact)
		return false;
	snprintf(sql_string, std::size(sql_string), "CREATE TABLE t%u (idx INTEGER PRIMARY KEY "
		"AUTOINCREMENT, rule_id INTEGER UNIQUE NOT NULL)", table_id);
	if (pdb->eph_exec(sql_string) != SQLITE_OK)
		return FALSE;

	std::list<table_node> holder;
	auto ptnode = &holder.emplace_back();
	ptnode->table_id = table_id;
	auto remote_id = exmdb_server::get_remote_id();
	if (NULL != remote_id) {
		ptnode->remote_id = strdup(remote_id);
		if (ptnode->remote_id == nullptr)
			return FALSE;
	}
	ptnode->type = table_type::rule;
	ptnode->folder_id = fid_val;
	if (NULL != prestriction) {
		ptnode->prestriction = prestriction->dup();
		if (ptnode->prestriction == nullptr)
			return FALSE;
	}
	snprintf(sql_string, std::size(sql_string), "INSERT INTO t%u "
		"(rule_id) VALUES (?)", ptnode->table_id);
	auto pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*prow_count = 0;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	if (!table_load_rules(pdb->psqlite, fid_val, table_flags, prestriction,
	    pstmt, prow_count))
		return FALSE;
	sql_transact = xtransaction();
	pstmt.finalize();
	if (table_transact.commit() != SQLITE_OK)
		return false;
	auto dbase = pdb->lock_base_wr();
	dbase->tables.table_list.splice(dbase->tables.table_list.end(), std::move(holder));
	*ptable_id = ptnode->table_id;
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}

BOOL exmdb_server::unload_table(const char *dir, uint32_t table_id)
{
	char sql_string[128];
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	auto dbase = pdb->lock_base_wr();
	auto &table_list = dbase->tables.table_list;
	auto iter = std::find_if(table_list.begin(), table_list.end(),
	            [&](const table_node &t) { return t.table_id == table_id; });
	if (iter == table_list.end())
		return TRUE;

	std::list<table_node> holder;
	holder.splice(holder.end(), table_list, iter);
	dbase.reset();
	snprintf(sql_string, std::size(sql_string), "DROP TABLE t%u", table_id);
	if (pdb->eph_exec(sql_string) != SQLITE_OK)
		/* ignore - table_id is not going to get reused anyway */;
	return TRUE;
}

BOOL exmdb_server::sum_table(const char *dir,
	uint32_t table_id, uint32_t *prows)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	return table_sum_table_count(*pdb, table_id, prows);
}

static BOOL table_column_content_tmptbl(
	sqlite3_stmt *pstmt, sqlite3_stmt *pstmt1, sqlite3_stmt *pstmt2,
	const SORTORDER_SET *psorts, uint64_t folder_id, int row_type,
    proptag_t proptag, proptag_t instance_tag, proptag_t extremum_tag,
	void **ppvalue)
{
	int i;
	int depth;
	uint64_t row_id;
	
	switch (proptag) {
	case PidTagFolderId: {
		if (row_type != CONTENT_ROW_HEADER)
			break;
		auto v = cu_alloc<uint64_t>();
		*ppvalue = v;
		if (*ppvalue != nullptr)
			*v = rop_util_make_eid_ex(1, folder_id);
		return TRUE;
	}
	case PidTagInstID:
		*ppvalue = common_util_column_sqlite_statement(pstmt, 3, PT_I8);
		if (*ppvalue == nullptr)
			return TRUE;
		*static_cast<uint64_t *>(*ppvalue) = row_type == CONTENT_ROW_MESSAGE ?
			rop_util_make_eid_ex(1, *static_cast<uint64_t *>(*ppvalue)) :
			rop_util_make_eid_ex(2, *static_cast<uint64_t *>(*ppvalue) & NFID_LOWER_PART);
		return TRUE;
	case PidTagInstanceNum:
		*ppvalue = common_util_column_sqlite_statement(pstmt, 10, PT_LONG);
		return TRUE;
	case PR_ROW_TYPE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (v == nullptr)
			return false;
		*v = psorts == nullptr || psorts->ccategories == 0 ||
		     row_type == CONTENT_ROW_MESSAGE ? TBL_LEAF_ROW :
			sqlite3_column_int64(pstmt, 8) == 0 ? TBL_EMPTY_CATEGORY :
			sqlite3_column_int64(pstmt, 5) == 0 ? TBL_COLLAPSED_CATEGORY :
			TBL_EXPANDED_CATEGORY;
		return TRUE;
	}
	case PR_DEPTH:
		*ppvalue = psorts != nullptr && psorts->ccategories != 0 ?
		           common_util_column_sqlite_statement(pstmt, 7, PT_LONG) :
		           nullptr;
		return TRUE;
	case PR_CONTENT_COUNT: {
		if (row_type != CONTENT_ROW_MESSAGE) {
			*ppvalue = common_util_column_sqlite_statement(pstmt, 8, PT_LONG);
			return TRUE;
		}
		*ppvalue = nullptr;
		return TRUE;
	}
	case PR_CONTENT_UNREAD: {
		if (row_type != CONTENT_ROW_MESSAGE) {
			*ppvalue = common_util_column_sqlite_statement(pstmt, 9, PT_LONG);
			return TRUE;
		}
		*ppvalue = nullptr;
		return TRUE;
	}
	}
	if (CONTENT_ROW_MESSAGE == row_type) {
		if (instance_tag == 0 || instance_tag != proptag)
			return false;
		*ppvalue = common_util_column_sqlite_statement(pstmt,
		           11, PROP_TYPE(instance_tag) & ~MVI_FLAG);
		return TRUE;
	}
	if (psorts == nullptr || psorts->ccategories == 0)
		return FALSE;
	if (extremum_tag == proptag) {
		*ppvalue = common_util_column_sqlite_statement(pstmt, 12, PROP_TYPE(proptag));
		return TRUE;
	}
	for (i=psorts->ccategories-1; i>=0; i--) {
		auto tmp_proptag = PROP_TAG(psorts->psort[i].type, psorts->psort[i].propid);
		if (proptag == tmp_proptag)
			break;
	}
	if (i < 0)
		return FALSE;
	depth = sqlite3_column_int64(pstmt, 7);
	if (i > depth)
		return FALSE;
	row_id = sqlite3_column_int64(pstmt, 0);
	for (; depth>i; depth--) {
		sqlite3_bind_int64(pstmt1, 1, row_id);
		if (gx_sql_step(pstmt1) != SQLITE_ROW)
			return FALSE;
		row_id = sqlite3_column_int64(pstmt1, 0);
		sqlite3_reset(pstmt1);
	}
	sqlite3_bind_int64(pstmt2, 1, row_id);
	if (gx_sql_step(pstmt2) != SQLITE_ROW)
		return FALSE;
	*ppvalue = common_util_column_sqlite_statement(pstmt2, 0,
	           PROP_TYPE(proptag) & ~MVI_FLAG);
	sqlite3_reset(pstmt2);
	return TRUE;
}

static void table_truncate_string(cpid_t cpid, char *pstring)
{
	iconv_t conv_id;
	char *pin, *pout;
	char tmp_buff[512];
	char tmp_charset[256];
	
	cpid_cstr_compatible(cpid);
	auto string_len = strlen(pstring);
	if (string_len <= 510)
		return;
	pstring[510] = '\0';
	/*
	 * We might have cut off the value in the middle of a multibyte
	 * sequence, which now needs fixup. To that end, iconv is employed,
	 * which will stop at the first illegal/incomplete sequence.
	 */
	auto charset = cpid_to_cset(cpid);
	if (charset == nullptr)
		return;
	size_t in_len = 510, out_len = std::min(string_len, std::size(tmp_buff));
	pin = pstring;
	pout = tmp_buff;
	memset(tmp_buff, 0, sizeof(tmp_buff));
	snprintf(tmp_charset, std::size(tmp_charset), "%s//IGNORE", charset);
	conv_id = iconv_open(tmp_charset, charset);
	if (conv_id == (iconv_t)-1)
		return;
	if (iconv(conv_id, &pin, &in_len, &pout, &out_len) == static_cast<size_t>(-1))
		/* ignore */;
	iconv_close(conv_id);
	if (out_len < sizeof(tmp_buff))
		gx_strlcpy(pstring, tmp_buff, string_len + 1);
}

const table_node *db_base::find_table(uint32_t table_id) const
{
	for (const auto &t : tables.table_list)
		if (t.table_id == table_id)
			return &t;
	return nullptr;
}

static bool query_hierarchy(db_conn &db, cpid_t cpid, uint32_t table_id,
    const PROPTAG_ARRAY *pproptags, uint32_t start_pos, int32_t row_needed,
    TARRAY_SET *pset)
{
	char sql_string[1024];
	int32_t end_pos;

	if (row_needed > 0) {
		end_pos = start_pos + row_needed;
		snprintf(sql_string, std::size(sql_string), "SELECT folder_id, depth FROM"
			" t%u WHERE idx>=%u AND idx<%u ORDER BY idx ASC",
			table_id, start_pos + 1, end_pos + 1);
		// XXX: ridiculously large upfront allocation,
		// we do not know yet how many rows will come back
		pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(row_needed);
	} else {
		end_pos = start_pos + row_needed;
		if (end_pos < 0)
			end_pos = 0;
		snprintf(sql_string, std::size(sql_string), "SELECT folder_id, depth FROM "
			"t%u WHERE idx>%u AND idx<=%u ORDER BY idx DESC",
			table_id, end_pos + 1, start_pos + 1);
		pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(start_pos - end_pos);
	}
	if (pset->pparray == nullptr)
		return FALSE;
	auto pstmt = db.eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	auto sql_transact = gx_sql_begin(db.psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	while (pstmt.step() == SQLITE_ROW) {
		auto folder_id = pstmt.col_uint64(0);
		auto mrow = pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
		if (mrow == nullptr)
			return FALSE;
		mrow->count = 0;
		mrow->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
		if (mrow->ppropval == nullptr)
			return FALSE;
		for (unsigned int i = 0; i < pproptags->count; ++i) {
			void *pvalue = nullptr;
			const auto tag = pproptags->pproptag[i];
			if (tag == PR_DEPTH) {
				auto v = cu_alloc<uint32_t>();
				pvalue = v;
				if (pvalue == nullptr)
					return FALSE;
				*v = sqlite3_column_int64(pstmt, 1);
			} else {
				if (!cu_get_property(MAPI_FOLDER, folder_id, cpid,
				    db, tag, &pvalue))
					return FALSE;
				if (pvalue == nullptr)
					continue;
				switch (PROP_TYPE(tag)) {
				case PT_UNICODE:
					utf8_truncate(static_cast<char *>(pvalue), 255);
					break;
				case PT_STRING8:
					table_truncate_string(cpid, static_cast<char *>(pvalue));
					break;
				case PT_BINARY:
					if (static_cast<BINARY *>(pvalue)->cb > 510)
						static_cast<BINARY *>(pvalue)->cb = 510;
					break;
				}
			}
			mrow->emplace_back(tag, pvalue);
		}
		++pset->count;
	}
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	return TRUE;
}

static bool query_content(db_conn &db, cpid_t cpid, uint32_t table_id,
    const PROPTAG_ARRAY *pproptags, uint32_t start_pos, int32_t row_needed,
    const table_node *ptnode, TARRAY_SET *pset)
{
	char sql_string[1024];
	int32_t end_pos;

	if (row_needed > 0) {
		end_pos = start_pos + row_needed;
		snprintf(sql_string, std::size(sql_string), "SELECT * FROM t%u"
			" WHERE idx>=%u AND idx<%u ORDER BY idx ASC",
			table_id, start_pos + 1, end_pos + 1);
		pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(row_needed);
	} else {
		end_pos = start_pos + row_needed;
		if (end_pos < 0)
			end_pos = 0;
		snprintf(sql_string, std::size(sql_string), "SELECT * FROM t%u"
			" WHERE idx>=%u AND idx<%u ORDER BY idx DESC",
			table_id, end_pos + 1, start_pos + 1);
		pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(start_pos - end_pos);
	}
	if (pset->pparray == nullptr)
		return FALSE;
	auto pstmt = db.eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	xstmt pstmt1, pstmt2;
	if (NULL != ptnode->psorts && ptnode->psorts->ccategories > 0) {
		snprintf(sql_string, std::size(sql_string), "SELECT parent_id FROM"
			" t%u WHERE row_id=?", ptnode->table_id);
		pstmt1 = db.eph_prep(sql_string);
		if (pstmt1 == nullptr)
			return FALSE;
	}
	if (ptnode->psorts != nullptr) {
		snprintf(sql_string, std::size(sql_string), "SELECT value FROM"
			" t%u WHERE row_id=?", ptnode->table_id);
		pstmt2 = db.eph_prep(sql_string);
		if (pstmt2 == nullptr)
			return FALSE;
	}
	auto sql_transact = gx_sql_begin(db.psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	auto sql_transact_eph = gx_sql_begin(db.m_sqlite_eph, txn_mode::read);
	if (!sql_transact_eph)
		return false;
	if (!db.begin_optim())
		return FALSE;
	auto cl_0 = HX::make_scope_exit([&]() { db.end_optim(); });
	while (pstmt.step() == SQLITE_ROW) {
		auto inst_id = pstmt.col_uint64(3);
		uint32_t row_type = pstmt.col_uint64(4);
		auto mrow = pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
		if (mrow == nullptr)
			return FALSE;
		mrow->count = 0;
		mrow->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
		if (mrow->ppropval == nullptr)
			return FALSE;
		for (unsigned int i = 0; i < pproptags->count; ++i) {
			void *pvalue = nullptr;
			const auto tag = pproptags->pproptag[i];
			if (!table_column_content_tmptbl(pstmt, pstmt1,
			    pstmt2, ptnode->psorts, ptnode->folder_id, row_type,
			    tag, ptnode->instance_tag,
			    ptnode->extremum_tag, &pvalue)) {
				if (row_type == CONTENT_ROW_HEADER)
					continue;
				if (!cu_get_property(MAPI_MESSAGE, inst_id, cpid,
				    db, tag, &pvalue))
					return FALSE;
			}
			if (pvalue == nullptr)
				continue;
			switch (PROP_TYPE(tag)) {
			case PT_UNICODE:
				utf8_truncate(static_cast<char *>(pvalue), 255);
				break;
			case PT_STRING8:
				table_truncate_string(cpid, static_cast<char *>(pvalue));
				break;
			case PT_BINARY:
				if (static_cast<BINARY *>(pvalue)->cb > 510)
					static_cast<BINARY *>(pvalue)->cb = 510;
				break;
			}
			mrow->emplace_back(tag, pvalue);
		}
		++pset->count;
	}
	sql_transact_eph = xtransaction();
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	return TRUE;
}

static bool query_perm(db_conn &db, cpid_t cpid, uint32_t table_id,
    const PROPTAG_ARRAY *pproptags, uint32_t start_pos, int32_t row_needed,
    const table_node *ptnode, TARRAY_SET *pset)
{
	char sql_string[1024];
	int32_t end_pos;

	if (row_needed > 0) {
		end_pos = start_pos + row_needed;
		snprintf(sql_string, std::size(sql_string), "SELECT member_id FROM t%u "
			"WHERE idx>=%u AND idx<%u ORDER BY idx ASC",
			table_id, start_pos + 1, end_pos + 1);
		pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(row_needed);
	} else {
		end_pos = start_pos + row_needed;
		if (end_pos < 0)
			end_pos = 0;
		snprintf(sql_string, std::size(sql_string), "SELECT member_id FROM t%u "
			"WHERE idx>%u AND idx<=%u ORDER BY idx DESC",
			table_id, end_pos + 1, start_pos + 1);
		pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(start_pos - end_pos);
	}
	if (pset->pparray == nullptr)
		return FALSE;
	auto pstmt = db.eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		auto member_id = pstmt.col_int64(0);
		auto mrow = pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
		if (mrow == nullptr)
			return FALSE;
		mrow->count = 0;
		mrow->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
		if (mrow->ppropval == nullptr)
			return FALSE;
		for (unsigned int i = 0; i < pproptags->count; ++i) {
			void *pvalue = nullptr;
			const auto tag = pproptags->pproptag[i];
			auto u_tag = tag;
			if (u_tag == PR_MEMBER_NAME_A)
				u_tag = PR_MEMBER_NAME;
			if (!cu_get_permission_property(member_id,
			    db.psqlite, u_tag, &pvalue))
				return FALSE;
			if (tag == PR_MEMBER_RIGHTS &&
			    !(ptnode->table_flags & PERMISSIONS_TABLE_FLAG_INCLUDEFREEBUSY))
				*static_cast<uint32_t *>(pvalue) &= ~(frightsFreeBusySimple | frightsFreeBusyDetailed);
			if (tag == PR_MEMBER_RIGHTS &&
			    (ptnode->table_flags & PERMISSIONS_TABLE_FLAG_ROPFILTER))
				*static_cast<uint32_t *>(pvalue) &= rightsMaxROP;
			if (pvalue == nullptr)
				continue;
			if (tag == PR_MEMBER_NAME_A)
				mrow->emplace_back(tag, cu_utf8_to_mb_dup(cpid, static_cast<char *>(pvalue)));
			else
				mrow->emplace_back(tag, pvalue);
		}
		++pset->count;
	}
	return TRUE;
}

static bool query_rule(db_conn &db, cpid_t cpid, uint32_t table_id,
    const PROPTAG_ARRAY *pproptags, uint32_t start_pos, int32_t row_needed,
    TARRAY_SET *pset)
{
	char sql_string[1024];
	int32_t end_pos;

	if (row_needed > 0) {
		end_pos = start_pos + row_needed;
		snprintf(sql_string, std::size(sql_string), "SELECT rule_id FROM t%u "
			"WHERE idx>=%u AND idx<%u ORDER BY idx ASC",
			table_id, start_pos + 1, end_pos + 1);
		pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(row_needed);
	} else {
		end_pos = start_pos + row_needed;
		if (end_pos < 0)
			end_pos = 0;
		snprintf(sql_string, std::size(sql_string), "SELECT rule_id FROM t%u "
			"WHERE idx>%u AND idx<=%u ORDER BY idx DESC",
			table_id, end_pos + 1, start_pos + 1);
		pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(start_pos - end_pos);
	}
	if (pset->pparray == nullptr)
		return FALSE;
	auto pstmt = db.eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		auto rule_id = pstmt.col_uint64(0);
		auto mrow = pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
		if (mrow == nullptr)
			return FALSE;
		mrow->count = 0;
		mrow->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
		if (mrow->ppropval == nullptr)
			return FALSE;
		for (unsigned int i = 0; i < pproptags->count; ++i) {
			void *pvalue = nullptr;
			const auto tag = pproptags->pproptag[i];
			auto u_tag = tag;
			if (u_tag == PR_RULE_NAME_A)
				u_tag = PR_RULE_NAME;
			else if (u_tag == PR_RULE_PROVIDER_A)
				u_tag = PR_RULE_PROVIDER;
			if (!common_util_get_rule_property(rule_id,
			    db.psqlite, u_tag, &pvalue))
				return FALSE;
			if (pvalue == nullptr)
				continue;
			if (tag == PR_RULE_NAME_A || tag == PR_RULE_PROVIDER_A)
				mrow->emplace_back(tag, cu_utf8_to_mb_dup(cpid, static_cast<char *>(pvalue)));
			else
				mrow->emplace_back(tag, pvalue);
		}
		++pset->count;
	}
	return TRUE;
}

/**
 * @username:   Used for retrieving public store readstates
 *
 * ...every property value returned in a row MUST
 * be less than or equal to 510 bytes in size.
 *
 * XXX: But that's stupid for rules, which are not objects and cannot be opened
 * any other way.
 */
BOOL exmdb_server::query_table(const char *dir, const char *username,
    cpid_t cpid, uint32_t table_id, const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Transaction is managed in query_* subfunctions. */
	pset->count = 0;
	pset->pparray = NULL;
	auto dbase = pdb->lock_base_rd();
	auto ptnode = dbase->find_table(table_id);
	if (ptnode == nullptr)
		return TRUE;
	if (!exmdb_server::is_private())
		exmdb_server::set_public_username(username);
	auto cl_0 = HX::make_scope_exit([]() { exmdb_server::set_public_username(nullptr); });
	switch (ptnode->type) {
	case table_type::hierarchy:
		return query_hierarchy(*pdb, cpid, table_id,
		       pproptags, start_pos, row_needed, pset);
	case table_type::content:
		return query_content(*pdb, cpid, table_id, pproptags,
		       start_pos, row_needed, ptnode, pset);
	case table_type::permission:
		return query_perm(*pdb, cpid, table_id, pproptags,
		       start_pos, row_needed, ptnode, pset);
	case table_type::rule:
		return query_rule(*pdb, cpid, table_id, pproptags,
		       start_pos, row_needed, pset);
	}
	return TRUE;
}

static bool table_get_content_row_property(const void *pparam, proptag_t proptag,
    void **ppvalue)
{
	uint32_t *pinst_num;
	uint64_t parent_fid;
	
	auto prow_param = static_cast<const CONTENT_ROW_PARAM *>(pparam);
	if (proptag == PR_INSTANCE_SVREID) {
		auto eid = cu_alloc<SVREID>();
		if (eid == nullptr)
			return FALSE;
		*ppvalue = eid;
		eid->pbin = nullptr;
		if (CONTENT_ROW_HEADER == prow_param->row_type) {
			eid->folder_id = rop_util_make_eid_ex(1, prow_param->folder_id);
			eid->message_id = rop_util_make_eid_ex(2, prow_param->inst_id & NFID_LOWER_PART);
			eid->instance = 0;
		} else {
			if (!common_util_get_message_parent_folder(prow_param->psqlite,
			    prow_param->inst_id, &parent_fid))
				return FALSE;	
			eid->folder_id = rop_util_make_eid_ex(1, parent_fid);
			eid->message_id = rop_util_make_eid_ex(1, prow_param->inst_id);
			pinst_num = static_cast<uint32_t *>(common_util_column_sqlite_statement(
			            prow_param->pstmt, 10, PT_LONG));
			if (pinst_num == nullptr)
				return FALSE;
			eid->instance = *pinst_num;
		}
		return TRUE;
	}
	if (!table_column_content_tmptbl(prow_param->pstmt, prow_param->pstmt1,
	    prow_param->pstmt2, prow_param->psorts, prow_param->folder_id,
	    prow_param->row_type, proptag, prow_param->instance_tag,
	    prow_param->extremum_tag, ppvalue)) {
		if (CONTENT_ROW_HEADER == prow_param->row_type) {
			*ppvalue = NULL;
			return TRUE;
		}
		if (!cu_get_property(MAPI_MESSAGE, prow_param->inst_id,
		    prow_param->cpid, prow_param->db, proptag,
		    ppvalue))
			return FALSE;	
	}
	return TRUE;
}

static bool table_get_hierarchy_row_property(const void *pparam, proptag_t proptag,
    void **ppvalue)
{
	auto prow_param = static_cast<const HIERARCHY_ROW_PARAM *>(pparam);
	if (proptag != PR_DEPTH)
		return cu_get_property(MAPI_FOLDER, prow_param->folder_id,
		       prow_param->cpid, prow_param->db, proptag, ppvalue);
	auto v = cu_alloc<uint32_t>();
	*ppvalue = v;
	if (*ppvalue == nullptr)
		return FALSE;
	*v = sqlite3_column_int64(prow_param->pstmt, 2);
	return TRUE;
}

static bool table_evaluate_row_restriction(const RESTRICTION *pres,
    void *pparam, TABLE_GET_ROW_PROPERTY get_property)
{
	void *pvalue;
	void *pvalue1;
	
	switch (pres->rt) {
	case RES_AND:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (!table_evaluate_row_restriction(&pres->andor->pres[i],
			    pparam, get_property))
				return FALSE;
		return TRUE;
	case RES_OR:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (table_evaluate_row_restriction(&pres->andor->pres[i],
			    pparam, get_property))
				return TRUE;
		return FALSE;
	case RES_NOT:
		if (table_evaluate_row_restriction(&pres->xnot->res,
		    pparam, get_property))
			return FALSE;
		return TRUE;
	case RES_CONTENT: {
		auto rcon = pres->cont;
		if (!rcon->comparable())
			return FALSE;
		if (!get_property(pparam, rcon->proptag, &pvalue))
			return FALSE;
		return rcon->eval(pvalue);
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		if (!rprop->comparable())
			return false;
		if (!get_property(pparam, rprop->proptag, &pvalue))
			return FALSE;
		if (pvalue == nullptr || rprop->proptag != PR_ANR)
			return rprop->eval(pvalue);
		return strcasestr(static_cast<char *>(pvalue),
		       static_cast<char *>(rprop->propval.pvalue)) != nullptr;
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (!rprop->comparable())
			return FALSE;
		if (!get_property(pparam, rprop->proptag1, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		if (!get_property(pparam, rprop->proptag2, &pvalue1) ||
		    pvalue1 == nullptr)
			return FALSE;
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag1), pvalue, pvalue1);
	}
	case RES_BITMASK: {
		auto rbm = pres->bm;
		if (!rbm->comparable())
			return FALSE;
		if (!get_property(pparam, rbm->proptag, &pvalue))
			return FALSE;
		return rbm->eval(pvalue);
	}
	case RES_SIZE: {
		auto rsize = pres->size;
		if (!get_property(pparam, rsize->proptag, &pvalue))
			return FALSE;
		return rsize->eval(pvalue);
	}
	case RES_EXIST:
		if (!get_property(pparam, pres->exist->proptag, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		return TRUE;
	case RES_COMMENT:
	case RES_ANNOTATION:
		if (pres->comment->pres == nullptr)
			return TRUE;
		return table_evaluate_row_restriction(pres->comment->pres,
		       pparam, get_property);
	default:
		mlog(LV_WARN, "W-2241: restriction type %u unevaluated",
			static_cast<unsigned int>(pres->rt));
		return FALSE;
	}	
	return FALSE;
}

static bool match_tbl_hier(cpid_t cpid, uint32_t table_id, BOOL b_forward,
    uint32_t start_pos, const RESTRICTION *pres, const PROPTAG_ARRAY *pproptags,
    int32_t *pposition, TPROPVAL_ARRAY *ppropvals, db_conn &db)
{
	char sql_string[1024];
	int idx = 0;

	if (b_forward)
		snprintf(sql_string, std::size(sql_string), "SELECT folder_id,"
		         " idx, depth FROM t%u WHERE idx>=%u ORDER BY"
		         " idx ASC", table_id, start_pos + 1);
	else
		snprintf(sql_string, std::size(sql_string), "SELECT folder_id,"
		         " idx, depth FROM t%u WHERE idx<=%u ORDER BY"
		         " idx DESC", table_id, start_pos + 1);
	auto pstmt = db.eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	auto sql_transact = gx_sql_begin(db.psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	while (pstmt.step() == SQLITE_ROW) {
		HIERARCHY_ROW_PARAM hierarchy_param{db};
		uint64_t folder_id;

		folder_id = sqlite3_column_int64(pstmt, 0);
		hierarchy_param.cpid = cpid;
		hierarchy_param.psqlite = db.psqlite;
		hierarchy_param.pstmt = pstmt;
		hierarchy_param.folder_id = folder_id;
		if (!table_evaluate_row_restriction(pres,
		    &hierarchy_param, table_get_hierarchy_row_property))
			continue;
		idx = sqlite3_column_int64(pstmt, 1);
		ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
		if (ppropvals->ppropval == nullptr)
			return FALSE;
		for (unsigned int i = 0; i < pproptags->count; ++i) {
			void *pvalue;
			const auto tag = pproptags->pproptag[i];
			if (tag == PR_DEPTH) {
				auto v = cu_alloc<uint32_t>();
				pvalue = v;
				if (pvalue == nullptr)
					return FALSE;
				*v = sqlite3_column_int64(pstmt, 2);
			} else {
				if (!cu_get_property(MAPI_FOLDER, folder_id, cpid,
				    db, tag, &pvalue))
					return FALSE;
				if (pvalue == nullptr)
					continue;
				switch (PROP_TYPE(tag)) {
				case PT_UNICODE:
					utf8_truncate(static_cast<char *>(pvalue), 255);
					break;
				case PT_STRING8:
					table_truncate_string(cpid, static_cast<char *>(pvalue));
					break;
				case PT_BINARY:
					if (static_cast<BINARY *>(pvalue)->cb > 510)
						static_cast<BINARY *>(pvalue)->cb = 510;
					break;
				}
			}
			ppropvals->emplace_back(tag, pvalue);
		}
		break;
	}
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	*pposition = idx - 1;
	return TRUE;
}

static bool match_tbl_ctnt(cpid_t cpid, uint32_t table_id, BOOL b_forward,
    uint32_t start_pos, const RESTRICTION *pres, const PROPTAG_ARRAY *pproptags,
    int32_t *pposition, TPROPVAL_ARRAY *ppropvals, db_conn &db,
    const table_node *ptnode)
{
	char sql_string[1024];
	int row_type, idx = 0;
	uint64_t inst_id;

	if (b_forward)
		snprintf(sql_string, std::size(sql_string), "SELECT * FROM t%u"
		         " WHERE idx>=%u ORDER BY idx ASC", table_id,
		         start_pos + 1);
	else
		snprintf(sql_string, std::size(sql_string), "SELECT * FROM t%u"
		         " WHERE idx<=%u ORDER BY idx DESC", table_id,
		         start_pos + 1);
	auto pstmt = db.eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	xstmt pstmt1, pstmt2;
	if (NULL != ptnode->psorts && ptnode->psorts->ccategories > 0) {
		snprintf(sql_string, std::size(sql_string), "SELECT parent_id FROM"
		         " t%u WHERE row_id=?", ptnode->table_id);
		pstmt1 = db.eph_prep(sql_string);
		if (pstmt1 == nullptr)
			return FALSE;
		snprintf(sql_string, std::size(sql_string), "SELECT value FROM"
		         " t%u WHERE row_id=?", ptnode->table_id);
		pstmt2 = db.eph_prep(sql_string);
		if (pstmt2 == nullptr)
			return FALSE;
	} else {
		pstmt1 = NULL;
		pstmt2 = NULL;
	}
	auto sql_transact = gx_sql_begin(db.psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	auto sql_transact_eph = gx_sql_begin(db.m_sqlite_eph, txn_mode::read);
	if (!sql_transact_eph)
		return false;
	if (!db.begin_optim())
		return FALSE;
	auto cl_0 = HX::make_scope_exit([&]() { db.end_optim(); });
	while (pstmt.step() == SQLITE_ROW) {
		CONTENT_ROW_PARAM content_param{db};

		inst_id = sqlite3_column_int64(pstmt, 3);
		row_type = sqlite3_column_int64(pstmt, 4);
		content_param.cpid = cpid;
		content_param.psqlite = db.psqlite;
		content_param.pstmt = pstmt;
		content_param.pstmt1 = pstmt1;
		content_param.pstmt2 = pstmt2;
		content_param.folder_id = ptnode->folder_id;
		content_param.inst_id = inst_id;
		content_param.row_type = row_type;
		content_param.psorts = ptnode->psorts;
		content_param.instance_tag = ptnode->instance_tag;
		content_param.extremum_tag = ptnode->extremum_tag;
		if (!table_evaluate_row_restriction(pres,
		    &content_param, table_get_content_row_property))
			continue;
		idx = sqlite3_column_int64(pstmt, 1);
		ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
		if (ppropvals->ppropval == nullptr)
			return FALSE;
		for (unsigned int i = 0; i < pproptags->count; ++i) {
			void *pvalue;
			const auto tag = pproptags->pproptag[i];
			if (!table_column_content_tmptbl(pstmt, pstmt1,
			    pstmt2, ptnode->psorts, ptnode->folder_id, row_type,
			    tag, ptnode->instance_tag,
			    ptnode->extremum_tag, &pvalue)) {
				if (row_type == CONTENT_ROW_HEADER)
					continue;
				if (!cu_get_property(MAPI_MESSAGE, inst_id, cpid,
				    db, tag, &pvalue))
					return FALSE;
			}
			if (pvalue == nullptr)
				continue;
			switch (PROP_TYPE(tag)) {
			case PT_UNICODE:
				utf8_truncate(static_cast<char *>(pvalue), 255);
				break;
			case PT_STRING8:
				table_truncate_string(cpid, static_cast<char *>(pvalue));
				break;
			case PT_BINARY:
				if (static_cast<BINARY *>(pvalue)->cb > 510)
					static_cast<BINARY *>(pvalue)->cb = 510;
				break;
			}
			ppropvals->emplace_back(tag, pvalue);
		}
		break;
	}
	sql_transact_eph = xtransaction();
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	*pposition = idx - 1;
	return TRUE;
}

static bool match_tbl_rule(cpid_t cpid, uint32_t table_id, BOOL b_forward,
    uint32_t start_pos, const RESTRICTION *pres, const PROPTAG_ARRAY *pproptags,
    int32_t *pposition, TPROPVAL_ARRAY *ppropvals, db_conn &db)
{
	char sql_string[1024];
	int idx = 0;
	uint64_t rule_id;

	if (b_forward)
		snprintf(sql_string, std::size(sql_string), "SELECT rule_id"
		         " idx FROM t%u WHERE idx>=%u ORDER BY"
		         " idx ASC", table_id, start_pos + 1);
	else
		snprintf(sql_string, std::size(sql_string), "SELECT rule_id,"
		         " idx FROM t%u WHERE idx<=%u ORDER BY"
		         " idx DESC", table_id, start_pos + 1);
	auto pstmt = db.eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		rule_id = sqlite3_column_int64(pstmt, 0);
		if (!table_evaluate_rule_restriction(
		    db.psqlite, rule_id, pres))
			continue;
		ppropvals->count = 0;
		ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
		if (ppropvals->ppropval == nullptr)
			return FALSE;
		for (unsigned int i = 0; i < pproptags->count; ++i) {
			void *pvalue;
			const auto tag = pproptags->pproptag[i];
			auto u_tag = tag;
			if (u_tag == PR_RULE_NAME_A)
				u_tag = PR_RULE_NAME;
			else if (u_tag == PR_RULE_PROVIDER_A)
				u_tag = PR_RULE_PROVIDER;
			if (!common_util_get_rule_property(rule_id,
			    db.psqlite, u_tag, &pvalue))
				return FALSE;
			if (pvalue == nullptr)
				continue;
			if (tag == PR_RULE_NAME_A ||
			    tag == PR_RULE_PROVIDER_A)
				ppropvals->emplace_back(tag, cu_utf8_to_mb_dup(cpid, static_cast<char *>(pvalue)));
			else
				ppropvals->emplace_back(tag, pvalue);
		}
		break;
	}
	*pposition = idx - 1;
	return TRUE;
}

/**
 * @username:   Used for retrieving public store readstates
 */
BOOL exmdb_server::match_table(const char *dir, const char *username,
    cpid_t cpid, uint32_t table_id, BOOL b_forward, uint32_t start_pos,
	const RESTRICTION *pres, const PROPTAG_ARRAY *pproptags,
	int32_t *pposition, TPROPVAL_ARRAY *ppropvals)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Transaction is managed within match_tbl_* subfunctions. */
	auto dbase = pdb->lock_base_rd();
	auto ptnode = dbase->find_table(table_id);
	if (ptnode == nullptr) {
		*pposition = -1;
		return TRUE;
	}
	if (!exmdb_server::is_private())
		exmdb_server::set_public_username(username);
	auto cl_0 = HX::make_scope_exit([]() { exmdb_server::set_public_username(nullptr); });
	ppropvals->count = 0;
	ppropvals->ppropval = NULL;
	BOOL ret = TRUE;
	if (ptnode->type == table_type::hierarchy)
		ret = match_tbl_hier(cpid, table_id, b_forward, start_pos, pres,
		      pproptags, pposition, ppropvals, *pdb);
	else if (ptnode->type == table_type::content)
		ret = match_tbl_ctnt(cpid, table_id, b_forward, start_pos, pres,
		      pproptags, pposition, ppropvals, *pdb, ptnode);
	else if (ptnode->type == table_type::rule)
		ret = match_tbl_rule(cpid, table_id, b_forward, start_pos, pres,
		      pproptags, pposition, ppropvals, *pdb);
	else
		*pposition = -1;
	return ret;
}

BOOL exmdb_server::locate_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, uint32_t inst_num,
	int32_t *pposition, uint32_t *prow_type)
{
	int idx;
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	auto dbase = pdb->lock_base_rd();
	auto ptnode = dbase->find_table(table_id);
	if (ptnode == nullptr) {
		*pposition = -1;
		return TRUE;
	}
	switch (ptnode->type) {
	case table_type::hierarchy:
		if (1 == rop_util_get_replid(inst_id)) {
			inst_id = rop_util_get_gc_value(inst_id);
		} else {
			inst_id = rop_util_get_replid(inst_id);
			inst_id <<= 48;
			inst_id |= rop_util_get_gc_value(inst_id);
		}
		snprintf(sql_string, std::size(sql_string), "SELECT idx FROM t%u "
		          "WHERE folder_id=%llu", ptnode->table_id, LLU{inst_id});
		break;
	case table_type::content:
		inst_id = rop_util_get_replid(inst_id) == 1 ?
		          rop_util_get_gc_value(inst_id) :
		          rop_util_get_gc_value(inst_id) | 0x100000000000000ULL;
		snprintf(sql_string, std::size(sql_string), "SELECT idx, row_type "
				"FROM t%u WHERE inst_id=%llu AND inst_num=%u",
				ptnode->table_id, LLU{inst_id}, inst_num);
		break;
	case table_type::permission:
		snprintf(sql_string, std::size(sql_string), "SELECT idx FROM t%u "
			"WHERE member_id=%llu", ptnode->table_id, LLU{inst_id});
		break;
	case table_type::rule:
		inst_id = rop_util_get_gc_value(inst_id);
		snprintf(sql_string, std::size(sql_string), "SELECT idx FROM t%u "
		          "WHERE rule_id=%llu", ptnode->table_id, LLU{inst_id});
		break;
	default:
		return FALSE;
	}
	auto pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	*prow_type = 0;
	if (pstmt.step() == SQLITE_ROW) {
		idx = sqlite3_column_int64(pstmt, 0);
		if (ptnode->type == table_type::content)
			*prow_type = sqlite3_column_int64(pstmt, 1);
	} else {
		idx = 0;
	}
	*pposition = idx - 1;
	return TRUE;
}

static bool read_tblrow_hier(cpid_t cpid, uint32_t table_id,
    const PROPTAG_ARRAY *pproptags, uint64_t inst_id, uint32_t inst_num,
    TPROPVAL_ARRAY *ppropvals, db_conn &db)
{
	uint32_t depth;
	uint64_t folder_id;
	char sql_string[1024];

	if (1 == rop_util_get_replid(inst_id)) {
		folder_id = rop_util_get_gc_value(inst_id);
	} else {
		folder_id = rop_util_get_replid(inst_id);
		folder_id <<= 48;
		folder_id |= rop_util_get_gc_value(inst_id);
	}
	snprintf(sql_string, std::size(sql_string), "SELECT depth FROM t%u"
	         " WHERE folder_id=%llu", table_id, LLU{folder_id});
	auto pstmt = db.eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW) {
		ppropvals->count = 0;
		return TRUE;
	}
	depth = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	auto sql_transact = gx_sql_begin(db.psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		void *pvalue = nullptr;
		const auto tag = pproptags->pproptag[i];
		if (tag == PR_DEPTH) {
			auto v = cu_alloc<uint32_t>();
			pvalue = v;
			if (pvalue == nullptr)
				return FALSE;
			*v = depth;
		} else {
			if (!cu_get_property(MAPI_FOLDER, folder_id, cpid,
			    db, tag, &pvalue))
				return FALSE;
			if (pvalue == nullptr)
				continue;
			switch (PROP_TYPE(tag)) {
			case PT_UNICODE:
				utf8_truncate(static_cast<char *>(pvalue), 255);
				break;
			case PT_STRING8:
				table_truncate_string(cpid, static_cast<char *>(pvalue));
				break;
			case PT_BINARY:
				if (static_cast<BINARY *>(pvalue)->cb > 510)
					static_cast<BINARY *>(pvalue)->cb = 510;
				break;
			}
		}
		ppropvals->emplace_back(tag, pvalue);
	}
	return sql_transact.commit() == SQLITE_OK;
}

static bool read_tblrow_ctnt(cpid_t cpid, uint32_t table_id,
    const PROPTAG_ARRAY *pproptags, uint64_t inst_id, uint32_t inst_num,
    TPROPVAL_ARRAY *ppropvals, db_conn &db, const table_node *ptnode)
{
	int row_type;
	char sql_string[1024];

	inst_id = rop_util_get_replid(inst_id) == 1 ?
		  rop_util_get_gc_value(inst_id) :
		  rop_util_get_gc_value(inst_id) | 0x100000000000000ULL;
	snprintf(sql_string, std::size(sql_string), "SELECT * FROM t%u"
	         " WHERE inst_id=%llu AND inst_num=%u",
	         table_id, LLU{inst_id}, inst_num);
	auto pstmt = db.eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW) {
		ppropvals->count = 0;
		return TRUE;
	}
	row_type = sqlite3_column_int64(pstmt, 4);
	xstmt pstmt1, pstmt2;
	if (NULL != ptnode->psorts && ptnode->psorts->ccategories > 0) {
		snprintf(sql_string, std::size(sql_string), "SELECT parent_id FROM"
		         " t%u WHERE row_id=?", ptnode->table_id);
		pstmt1 = db.eph_prep(sql_string);
		if (pstmt1 == nullptr)
			return FALSE;
		snprintf(sql_string, std::size(sql_string), "SELECT value FROM"
		         " t%u WHERE row_id=?", ptnode->table_id);
		pstmt2 = db.eph_prep(sql_string);
		if (pstmt2 == nullptr)
			return FALSE;
	} else {
		pstmt1 = NULL;
		pstmt2 = NULL;
	}
	auto sql_transact = gx_sql_begin(db.psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	auto sql_transact_eph = gx_sql_begin(db.m_sqlite_eph, txn_mode::read);
	if (!sql_transact_eph)
		return false;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		void *pvalue = nullptr;
		const auto tag = pproptags->pproptag[i];
		if (!table_column_content_tmptbl(pstmt, pstmt1,
		    pstmt2, ptnode->psorts, ptnode->folder_id, row_type,
		    tag, ptnode->instance_tag,
		    ptnode->extremum_tag, &pvalue)) {
			if (row_type == CONTENT_ROW_HEADER)
				continue;
			if (!cu_get_property(MAPI_MESSAGE, inst_id, cpid,
			    db, tag, &pvalue))
				return FALSE;
		}
		if (pvalue == nullptr)
			continue;
		switch (PROP_TYPE(tag)) {
		case PT_UNICODE:
			utf8_truncate(static_cast<char *>(pvalue), 255);
			break;
		case PT_STRING8:
			table_truncate_string(cpid, static_cast<char *>(pvalue));
			break;
		case PT_BINARY:
			if (static_cast<BINARY *>(pvalue)->cb > 510)
				static_cast<BINARY *>(pvalue)->cb = 510;
			break;
		}
		ppropvals->emplace_back(tag, pvalue);
	}
	sql_transact_eph = xtransaction();
	return sql_transact.commit() == SQLITE_OK;
}

/**
 * @username:   Used for retrieving public store readstates
 */
BOOL exmdb_server::read_table_row(const char *dir, const char *username,
    cpid_t cpid, uint32_t table_id, const PROPTAG_ARRAY *pproptags,
	uint64_t inst_id, uint32_t inst_num, TPROPVAL_ARRAY *ppropvals)
{
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Transaction is managed within read_tblrow_* subfunction. */
	auto dbase = pdb->lock_base_rd();
	auto ptnode = dbase->find_table(table_id);
	if (ptnode == nullptr) {
		ppropvals->count = 0;
		return TRUE;
	}
	if (!exmdb_server::is_private())
		exmdb_server::set_public_username(username);
	auto cl_1 = HX::make_scope_exit([]() { exmdb_server::set_public_username(nullptr); });
	ppropvals->count = 0;
	ppropvals->ppropval = nullptr;
	if (ptnode->type == table_type::hierarchy)
		return read_tblrow_hier(cpid, table_id, pproptags, inst_id,
		       inst_num, ppropvals, *pdb);
	else if (ptnode->type == table_type::content)
		return read_tblrow_ctnt(cpid, table_id, pproptags, inst_id,
		       inst_num, ppropvals, *pdb, ptnode);
	return TRUE;
}
	
BOOL exmdb_server::mark_table(const char *dir,
	uint32_t table_id, uint32_t position, uint64_t *pinst_id,
	uint32_t *pinst_num, uint32_t *prow_type)
{
	char sql_string[256];
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/* Only one SQL operation, no transaction needed. */
	*pinst_id = 0;
	*pinst_num = 0;
	*prow_type = 0;
	auto dbase = pdb->lock_base_rd();
	auto ptnode = dbase->find_table(table_id);
	if (ptnode == nullptr)
		return TRUE;
	switch (ptnode->type) {
	case table_type::hierarchy:
		snprintf(sql_string, std::size(sql_string), "SELECT folder_id FROM t%u"
				" WHERE idx=%u", ptnode->table_id, position + 1);
		break;
	case table_type::content:
		snprintf(sql_string, std::size(sql_string), "SELECT inst_id,"
			" inst_num, row_type FROM t%u WHERE idx=%u",
			ptnode->table_id, position + 1);
		break;
	case table_type::permission:
		snprintf(sql_string, std::size(sql_string), "SELECT member_id FROM t%u "
			"WHERE idx=%u", ptnode->table_id, position + 1);
		break;
	case table_type::rule:
		snprintf(sql_string, std::size(sql_string), "SELECT rule_id FROM t%u "
			"WHERE idx=%u", ptnode->table_id, position + 1);
		break;
	default:
		return FALSE;
	}
	auto pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() == SQLITE_ROW) {
		*pinst_id = sqlite3_column_int64(pstmt, 0);
		switch (ptnode->type) {
		case table_type::hierarchy:
			*pinst_id = rop_util_nfid_to_eid(*pinst_id);
			break;
		case table_type::content:
			*pinst_id = rop_util_nfid_to_eid2(*pinst_id);
			*pinst_num = sqlite3_column_int64(pstmt, 1);
			*prow_type = sqlite3_column_int64(pstmt, 2);
			break;
		case table_type::rule:
			*pinst_id = rop_util_make_eid_ex(1, *pinst_id);
			break;
		default:
			break;
		}
	}
	return TRUE;
}

BOOL exmdb_server::get_table_all_proptags(const char *dir,
    uint32_t table_id, PROPTAG_ARRAY *pproptags) try
{
	char sql_string[256];
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!sql_transact)
		return false;
	auto dbase = pdb->lock_base_rd();

	auto ptnode = dbase->find_table(table_id);
	if (ptnode == nullptr) {
		pproptags->count = 0;
		pproptags->pproptag = NULL;
		return TRUE;
	}
	switch (ptnode->type) {
	case table_type::hierarchy: {
		maybe_flat_set<proptag_t> tags;
		snprintf(sql_string, std::size(sql_string), "SELECT "
			"folder_id FROM t%u", ptnode->table_id);
		auto pstmt = pdb->eph_prep(sql_string);
		if (pstmt == nullptr)
			return FALSE;
		auto pstmt1 = pdb->prep("SELECT DISTINCT proptag "
		              "FROM folder_properties WHERE folder_id=?");
		if (pstmt1 == nullptr)
			return FALSE;
		while (pstmt.step() == SQLITE_ROW) {
			sqlite3_bind_int64(pstmt1, 1,
				sqlite3_column_int64(pstmt, 0));
			while (pstmt1.step() == SQLITE_ROW)
				tags.emplace(pstmt1.col_int64(0));
			sqlite3_reset(pstmt1);
		}
		pstmt.finalize();
		pstmt1.finalize();
		tags.emplace(PR_DEPTH);
		pproptags->count = 0;
		pproptags->pproptag = cu_alloc<proptag_t>(tags.size());
		if (pproptags->pproptag == nullptr)
			return FALSE;
		for (const auto tag : tags)
			pproptags->emplace_back(tag);
		return TRUE;
	}
	case table_type::content: {
		maybe_flat_set<proptag_t> tags;
		snprintf(sql_string, std::size(sql_string), "SELECT inst_id,"
				" row_type FROM t%u", ptnode->table_id);
		auto pstmt = pdb->eph_prep(sql_string);
		if (pstmt == nullptr)
			return FALSE;
		auto pstmt1 = pdb->prep("SELECT DISTINCT proptag "
		              "FROM message_properties WHERE message_id=?");
		if (pstmt1 == nullptr)
			return FALSE;
		while (pstmt.step() == SQLITE_ROW) {
			if (sqlite3_column_int64(pstmt, 1) != CONTENT_ROW_MESSAGE)
				continue;
			sqlite3_bind_int64(pstmt1, 1,
				sqlite3_column_int64(pstmt, 0));
			while (pstmt1.step() == SQLITE_ROW)
				tags.emplace(pstmt1.col_int64(0));
			sqlite3_reset(pstmt1);
		}
		pstmt.finalize();
		pstmt1.finalize();
		pproptags->count = 0;
		static constexpr proptag_t extras[] = {
			PidTagMid, PR_MESSAGE_SIZE,
			PR_ASSOCIATED, PidTagChangeNumber, PR_READ,
			PR_HASATTACH, PR_MESSAGE_FLAGS, PR_DISPLAY_TO,
			PR_DISPLAY_CC, PR_DISPLAY_BCC, PidTagInstID,
			PidTagInstanceNum, PR_ROW_TYPE, PR_DEPTH,
			PR_CONTENT_COUNT, PR_CONTENT_UNREAD,
		};
		tags.insert(std::cbegin(extras), std::cend(extras));
		pproptags->count = 0;
		pproptags->pproptag = cu_alloc<proptag_t>(tags.size());
		if (pproptags->pproptag == nullptr)
			return FALSE;
		for (const auto tag : tags)
			pproptags->emplace_back(tag);
		return TRUE;
	}
	case table_type::permission:
		pproptags->count = 4;
		pproptags->pproptag = cu_alloc<proptag_t>(4);
		if (pproptags->pproptag == nullptr)
			return FALSE;
		pproptags->pproptag[0] = PR_ENTRYID;
		pproptags->pproptag[1] = PR_MEMBER_ID;
		pproptags->pproptag[2] = PR_MEMBER_NAME;
		pproptags->pproptag[3] = PR_MEMBER_RIGHTS;
		return TRUE;
	case table_type::rule:
		pproptags->count = 10;
		pproptags->pproptag = cu_alloc<proptag_t>(10);
		if (pproptags->pproptag == nullptr)
			return FALSE;
		pproptags->pproptag[0] = PR_RULE_ID;
		pproptags->pproptag[1] = PR_RULE_SEQUENCE;
		pproptags->pproptag[2] = PR_RULE_STATE;
		pproptags->pproptag[3] = PR_RULE_NAME;
		pproptags->pproptag[4] = PR_RULE_PROVIDER;
		pproptags->pproptag[5] = PR_RULE_LEVEL;
		pproptags->pproptag[6] = PR_RULE_USER_FLAGS;
		pproptags->pproptag[7] = PR_RULE_PROVIDER_DATA;
		pproptags->pproptag[8] = PR_RULE_CONDITION;
		pproptags->pproptag[9] = PR_RULE_ACTIONS;
		return TRUE;
	}
	return FALSE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
}

static BOOL table_traverse_sub_contents(uint32_t step,
	uint64_t parent_id, sqlite3_stmt *pstmt,
	sqlite3_stmt *pstmt1, uint32_t *pcount)
{
	uint64_t row_id;
	DOUBLE_LIST tmp_list;
	
	double_list_init(&tmp_list);
	sqlite3_bind_int64(pstmt1, 1, parent_id);
	while (gx_sql_step(pstmt1) == SQLITE_ROW) {
		(*pcount) ++;
		if (sqlite3_column_int64(pstmt1, 1) == 0)
			continue;
		row_id = sqlite3_column_int64(pstmt1, 0);
		if (1 == step) {
			sqlite3_bind_int64(pstmt, 1, row_id);
			if (gx_sql_step(pstmt) != SQLITE_ROW)
				return FALSE;
			*pcount += sqlite3_column_int64(pstmt, 0);
			sqlite3_reset(pstmt);
			continue;
		}
		auto pnode = cu_alloc<DOUBLE_LIST_NODE>();
		if (pnode == nullptr)
			return FALSE;
		auto v = cu_alloc<uint64_t>();
		pnode->pdata = v;
		if (pnode->pdata == nullptr)
			return FALSE;
		*v = row_id;
		double_list_append_as_tail(&tmp_list, pnode);
	}
	sqlite3_reset(pstmt1);
	if (step == 1)
		return TRUE;
	DOUBLE_LIST_NODE *pnode;
	while ((pnode = double_list_pop_front(&tmp_list)) != nullptr)
		if (!table_traverse_sub_contents(step - 1,
		    *static_cast<uint64_t *>(pnode->pdata), pstmt, pstmt1, pcount))
			return FALSE;	
	return TRUE;
}

static BOOL table_expand_sub_contents(int depth,
	uint64_t parent_id, sqlite3_stmt *pstmt,
	sqlite3_stmt *pstmt1, uint32_t *pidx)
{
	uint64_t row_id;
	uint8_t row_stat;
	
	sqlite3_bind_int64(pstmt, 1, -parent_id);
	if (gx_sql_step(pstmt) != SQLITE_ROW) {
		sqlite3_reset(pstmt);
		return TRUE;
	}
	do {
		row_id = sqlite3_column_int64(pstmt, 0);
		row_stat = sqlite3_column_int64(pstmt, 1);
		sqlite3_reset(pstmt);
		(*pidx) ++;
		sqlite3_bind_int64(pstmt1, 1, *pidx);
		sqlite3_bind_int64(pstmt1, 2, row_id);
		if (gx_sql_step(pstmt1) != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt1);
		if (depth > 0 && row_stat != 0 &&
		    !table_expand_sub_contents(depth - 1, row_id,
		    pstmt, pstmt1, pidx))
			return FALSE;
		sqlite3_bind_int64(pstmt, 1, row_id);
	} while (gx_sql_step(pstmt) == SQLITE_ROW);
	sqlite3_reset(pstmt);
	return TRUE;
}

BOOL exmdb_server::expand_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, BOOL *pb_found,
	int32_t *pposition, uint32_t *prow_count)
{
	int depth;
	uint32_t idx;
	uint64_t row_id;
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact_eph = gx_sql_begin(pdb->m_sqlite_eph, txn_mode::write);
	if (!sql_transact_eph)
		return false;
	auto dbase = pdb->lock_base_rd();
	auto ptnode = dbase->find_table(table_id);
	if (ptnode == nullptr) {
		*pb_found = FALSE;
		return TRUE;
	}
	if (ptnode->type != table_type::content ||
		2 != rop_util_get_replid(inst_id)) {
		*pb_found = FALSE;
		return TRUE;
	}
	inst_id = rop_util_get_gc_value(inst_id) | 0x100000000000000ULL;
	snprintf(sql_string, std::size(sql_string), "SELECT row_id, row_type, "
			"row_stat, depth, idx FROM t%u WHERE inst_id=%llu"
			" AND inst_num=0", ptnode->table_id, LLU{inst_id});
	auto pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW ||
		CONTENT_ROW_HEADER != sqlite3_column_int64(pstmt, 1)) {
		*pb_found = FALSE;
		return TRUE;
	}
	*pb_found = TRUE;
	if (0 != sqlite3_column_int64(pstmt, 2)) {
		*pposition = -1;
		return TRUE;
	}
	row_id = sqlite3_column_int64(pstmt, 0);
	depth = sqlite3_column_int64(pstmt, 3);
	idx = sqlite3_column_int64(pstmt, 4);
	*pposition = idx - 1;
	pstmt.finalize();
	snprintf(sql_string, std::size(sql_string), "SELECT count(*) FROM"
			" t%u WHERE parent_id=?", ptnode->table_id);
	pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (ptnode->psorts->ccategories == depth + 1) {
		sqlite3_bind_int64(pstmt, 1, row_id);
		if (pstmt.step() != SQLITE_ROW)
			return FALSE;
		*prow_count = sqlite3_column_int64(pstmt, 0);
	} else {
		snprintf(sql_string, std::size(sql_string), "SELECT row_id, row_stat "
				"FROM t%u WHERE parent_id=?", ptnode->table_id);
		auto pstmt1 = pdb->eph_prep(sql_string);
		if (pstmt1 == nullptr)
			return FALSE;
		*prow_count = 0;
		if (!table_traverse_sub_contents(ptnode->psorts->ccategories - depth - 1,
		    row_id, pstmt, pstmt1, prow_count))
			return FALSE;
	}
	pstmt.finalize();
	snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET row_stat=1 "
	        "WHERE row_id=%llu", ptnode->table_id, LLU{row_id});
	if (pdb->eph_exec(sql_string) != SQLITE_OK)
		return FALSE;
	if (*prow_count == 0)
		return TRUE;
	snprintf(sql_string, std::size(sql_string), "SELECT row_id "
		"FROM t%u WHERE idx>%u ORDER BY idx DESC",
		ptnode->table_id, idx);
	pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET idx=idx+%u"
			" WHERE row_id=?", ptnode->table_id, *prow_count);
	auto pstmt1 = pdb->eph_prep(sql_string);
	if (pstmt1 == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		sqlite3_bind_int64(pstmt1, 1,
			sqlite3_column_int64(pstmt, 0));
		if (pstmt1.step() != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt1);
	}
	pstmt.finalize();
	pstmt1.finalize();
	snprintf(sql_string, std::size(sql_string), "SELECT row_id, row_stat"
			" FROM t%u WHERE prev_id=?", ptnode->table_id);
	pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET"
		" idx=? WHERE row_id=?", ptnode->table_id);
	pstmt1 = pdb->eph_prep(sql_string);
	if (pstmt1 == nullptr)
		return FALSE;
	if (!table_expand_sub_contents(ptnode->psorts->ccategories - depth - 1,
	    row_id, pstmt, pstmt1, &idx))
		return false;
	return sql_transact_eph.commit() == SQLITE_OK ? TRUE : false;
}

BOOL exmdb_server::collapse_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, BOOL *pb_found,
	int32_t *pposition, uint32_t *prow_count)
{
	int depth;
	uint32_t idx;
	uint64_t row_id;
	uint64_t prev_id;
	char sql_string[256];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto dbase = pdb->lock_base_rd();
	auto ptnode = dbase->find_table(table_id);
	if (ptnode == nullptr) {
		*pb_found = FALSE;
		return TRUE;
	}
	if (ptnode->type != table_type::content ||
		2 != rop_util_get_replid(inst_id)) {
		*pb_found = FALSE;
		return TRUE;
	}
	inst_id = rop_util_get_gc_value(inst_id) | 0x100000000000000ULL;
	auto sql_transact_eph = gx_sql_begin(pdb->m_sqlite_eph, txn_mode::write);
	if (!sql_transact_eph)
		return false;
	snprintf(sql_string, std::size(sql_string), "SELECT row_id, row_type, "
		"row_stat, depth, idx FROM t%u WHERE inst_id=%llu AND"
		" inst_num=0", ptnode->table_id, LLU{inst_id});
	auto pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW ||
		CONTENT_ROW_HEADER != sqlite3_column_int64(pstmt, 1)) {
		*pb_found = FALSE;
		return TRUE;
	}
	*pb_found = TRUE;
	if (0 == sqlite3_column_int64(pstmt, 2)) {
		*pposition = -1;
		return TRUE;
	}
	row_id = sqlite3_column_int64(pstmt, 0);
	depth = sqlite3_column_int64(pstmt, 3);
	idx = sqlite3_column_int64(pstmt, 4);
	*pposition = idx - 1;
	pstmt.finalize();
	snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET row_stat=0 "
	        "WHERE row_id=%llu", ptnode->table_id, LLU{row_id});
	if (pdb->eph_exec(sql_string) != SQLITE_OK)
		return FALSE;
	*prow_count = 0;
	prev_id = row_id;
	snprintf(sql_string, std::size(sql_string), "SELECT row_id, "
			"depth, prev_id FROM t%u WHERE idx>%u "
			"ORDER BY idx ASC", ptnode->table_id, idx);
	pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET"
		" idx=? WHERE row_id=?", ptnode->table_id);
	dbase.reset();
	auto pstmt1 = pdb->eph_prep(sql_string);
	if (pstmt1 == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		row_id = sqlite3_column_int64(pstmt, 0);
		if (0 != prev_id &&
			(depth > sqlite3_column_int64(pstmt, 1) ||
		    gx_sql_col_uint64(pstmt, 2) == prev_id)) {
			if (*prow_count == 0)
				break;
			prev_id = 0;
		}
		if (0 != prev_id) {
			(*prow_count) ++;
			sqlite3_bind_null(pstmt1, 1);
		} else {
			idx ++;
			sqlite3_bind_int64(pstmt1, 1, idx);
		}
		sqlite3_bind_int64(pstmt1, 2, row_id);
		if (pstmt1.step() != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt1);
	}
	return sql_transact_eph.commit() == SQLITE_OK ? TRUE : false;
}

BOOL exmdb_server::store_table_state(const char *dir, uint32_t table_id,
    uint64_t inst_id, uint32_t inst_num, uint32_t *pstate_id) try
{
	int depth;
	void *pvalue;
	uint16_t type;
	uint64_t row_id;
	uint64_t last_id;
	sqlite3 *psqlite;
	EXT_PUSH ext_push;
	char tmp_buff[1024];
	char sql_string[1024];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto dbase = pdb->lock_base_rd();
	auto ptnode = dbase->find_table(table_id);
	*pstate_id = 0;
	if (ptnode == nullptr)
		return TRUE;
	if (ptnode->type != table_type::content)
		return TRUE;
	const auto &state_path = exmdb_eph_prefix + "/" + exmdb_server::get_dir() + "/tablestate.sqlite3";
	auto ret = gx_mkbasedir(state_path.c_str(), FMODE_PRIVATE | S_IXUSR | S_IXGRP);
	if (ret < 0) {
		mlog(LV_ERR, "E-2711: mkbasedir %s: %s", state_path.c_str(), strerror(-ret));
		return false;
	}
	/*
	 * sqlite3_open does not expose O_EXCL, so let's create the file under
	 * EXCL semantics ahead of time.
	 */
	auto tfd = open(state_path.c_str(), O_RDWR | O_CREAT | O_EXCL, FMODE_PRIVATE);
	if (tfd >= 0) {
		close(tfd);
		ret = sqlite3_open_v2(state_path.c_str(), &psqlite, SQLITE_OPEN_READWRITE, nullptr);
		if (ret != SQLITE_OK) {
			mlog(LV_ERR, "E-1435: sqlite3_open %s: %s", state_path.c_str(), sqlite3_errstr(ret));
			return FALSE;
		}
		gx_sql_exec(psqlite, "PRAGMA journal_mode=OFF");
		gx_sql_exec(psqlite, "PRAGMA synchronous=OFF");
		sprintf(sql_string,
			"CREATE TABLE state_info "
			"(state_id INTEGER PRIMARY KEY AUTOINCREMENT, "
			"folder_id INTEGER NOT NULL, "
			"table_flags INTEGER NOT NULL, "
			"sorts BLOB, "
			"message_id INTEGER DEFAULT NULL, "
			"inst_num INTEGER DEFAULT NULL, "
			"header_id INTEGER DEFAULT NULL, "
			"header_stat INTEGER DEFAULT NULL)");
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK) {
			sqlite3_close(psqlite);
			if (remove(state_path.c_str()) < 0 && errno != ENOENT)
				mlog(LV_WARN, "W-1348: remove %s: %s", state_path.c_str(), strerror(errno));
			return FALSE;
		}
		snprintf(sql_string, std::size(sql_string), "CREATE UNIQUE INDEX state_index"
			" ON state_info (folder_id, table_flags, sorts)");
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK) {
			sqlite3_close(psqlite);
			remove(state_path.c_str());
			return FALSE;
		}
	} else if (errno == EEXIST) {
		ret = sqlite3_open_v2(state_path.c_str(), &psqlite, SQLITE_OPEN_READWRITE, nullptr);
		if (ret != SQLITE_OK) {
			mlog(LV_ERR, "E-1436: sqlite3_open %s: %s", state_path.c_str(), sqlite3_errstr(ret));
			return FALSE;
		}
		gx_sql_exec(psqlite, "PRAGMA journal_mode=OFF");
		gx_sql_exec(psqlite, "PRAGMA synchronous=OFF");
	} else {
		mlog(LV_ERR, "E-1943: open %s: %s", state_path.c_str(), strerror(errno));
		return false;
	}
	auto cl_0 = HX::make_scope_exit([&]() { sqlite3_close(psqlite); });
	if (ptnode->psorts != nullptr && ptnode->psorts->ccategories != 0)
		strcpy(sql_string, "SELECT state_id FROM "
			"state_info WHERE folder_id=? AND table_flags=? "
			"AND sorts=?");
	else
		strcpy(sql_string, "SELECT state_id FROM "
			"state_info WHERE folder_id=? AND table_flags=? "
			"AND sorts IS NULL");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, ptnode->folder_id);
	sqlite3_bind_int64(pstmt, 2, ptnode->table_flags);
	if (NULL != ptnode->psorts && 0 != ptnode->psorts->ccategories) {
		if (!ext_push.init(tmp_buff, sizeof(tmp_buff), 0) ||
		    ext_push.p_sortorder_set(*ptnode->psorts) != pack_result::ok)
			return FALSE;
		sqlite3_bind_blob(pstmt, 3, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
	}
	if (pstmt.step() == SQLITE_ROW)
		*pstate_id = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	auto sql_transact = gx_sql_begin(psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
	if (0 == *pstate_id) {
		strcpy(sql_string, "INSERT INTO state_info"
			"(folder_id, table_flags, sorts) VALUES (?, ?, ?)");
		pstmt = gx_sql_prep(psqlite, sql_string);
		if (pstmt == nullptr)
			return FALSE;
		sqlite3_bind_int64(pstmt, 1, ptnode->folder_id);
		sqlite3_bind_int64(pstmt, 2, ptnode->table_flags);
		if (ptnode->psorts == nullptr || ptnode->psorts->ccategories == 0)
			sqlite3_bind_null(pstmt, 3);
		else
			sqlite3_bind_blob(pstmt, 3, ext_push.m_udata, ext_push.m_offset, SQLITE_STATIC);
		if (pstmt.step() != SQLITE_DONE)
			return FALSE;
		*pstate_id = sqlite3_last_insert_rowid(psqlite);
		pstmt.finalize();
	} else {
		if (NULL != ptnode->psorts && 0 != ptnode->psorts->ccategories) {
			snprintf(sql_string, std::size(sql_string), "DROP TABLE s%u", *pstate_id);
			if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
				return FALSE;
		}
		if (1 != rop_util_get_replid(inst_id)) {
			snprintf(sql_string, std::size(sql_string), "UPDATE "
				"state_info SET message_id=NULL, "
				"inst_num=NULL WHERE state_id=%u",
				*pstate_id);
			if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
				return FALSE;
		}
	}
	if (1 == rop_util_get_replid(inst_id)) {
		snprintf(sql_string, std::size(sql_string), "UPDATE "
			"state_info SET message_id=%llu, "
			"inst_num=%u WHERE state_id=%u",
			LLU{rop_util_get_gc_value(inst_id)},
			inst_num, *pstate_id);
		if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	}
	if (ptnode->psorts == nullptr || ptnode->psorts->ccategories == 0)
		return TRUE;
	auto sql_len = snprintf(sql_string, std::size(sql_string), "CREATE TABLE s%u "
			"(depth INTEGER NOT NULL ", *pstate_id);
	for (unsigned int i = 0; i < ptnode->psorts->ccategories; ++i) {
		auto tmp_proptag = PROP_TAG(ptnode->psorts->psort[i].type, ptnode->psorts->psort[i].propid);
		type = ptnode->psorts->psort[i].type;
		if (ptnode->instance_tag == tmp_proptag)
			type &= ~MVI_FLAG;
		switch (type) {
		case PT_STRING8:
		case PT_UNICODE:
			sql_len += gx_snprintf(sql_string + sql_len,
			           std::size(sql_string) - sql_len,
						", v%x TEXT", tmp_proptag);
			break;
		case PT_FLOAT:
		case PT_DOUBLE:
		case PT_APPTIME:
			sql_len += gx_snprintf(sql_string + sql_len,
			           std::size(sql_string) - sql_len,
						", v%x REAL", tmp_proptag);
			break;
		case PT_CURRENCY:
		case PT_I8:
		case PT_SYSTIME:
		case PT_SHORT:
		case PT_LONG:
		case PT_BOOLEAN:
			sql_len += gx_snprintf(sql_string + sql_len,
			           std::size(sql_string) - sql_len,
						", v%x INTEGER", tmp_proptag);
			break;
		case PT_CLSID:
		case PT_SVREID:
		case PT_OBJECT:
		case PT_BINARY:
			sql_len += gx_snprintf(sql_string + sql_len,
			           std::size(sql_string) - sql_len,
						", v%x BLOB", tmp_proptag);
			break;
		default:
			return FALSE;
		}
	}
	sql_string[sql_len++] = ')';
	sql_string[sql_len] = '\0';
	if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
		return FALSE;

	auto sql_transact_eph = gx_sql_begin(pdb->m_sqlite_eph, txn_mode::read);
	if (!sql_transact_eph)
		return false;
	snprintf(sql_string, std::size(sql_string), "SELECT row_id, inst_id,"
			" row_stat, depth FROM t%u", ptnode->table_id);
	pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sql_len = snprintf(sql_string, std::size(sql_string), "INSERT"
		" INTO s%u VALUES (?", *pstate_id);
	for (unsigned int i = 0; i < ptnode->psorts->ccategories; ++i)
		sql_len += gx_snprintf(sql_string + sql_len,
		           std::size(sql_string) - sql_len, ", ?");
	sql_string[sql_len++] = ')';
	sql_string[sql_len] = '\0';
	auto pstmt1 = gx_sql_prep(psqlite, sql_string);
	if (pstmt1 == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT parent_id FROM"
			" t%u WHERE row_id=?", ptnode->table_id);
	auto pstmt2 = pdb->eph_prep(sql_string);
	if (pstmt2 == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT value FROM"
			" t%u WHERE row_id=?", ptnode->table_id);
	auto stm_sel_vtx = pdb->eph_prep(sql_string);
	if (stm_sel_vtx == nullptr)
		return FALSE;
	uint64_t inst_id1 = rop_util_get_replid(inst_id) == 2 ?
	                    rop_util_get_gc_value(inst_id) | 0x100000000000000ULL : 0;

	while (pstmt.step() == SQLITE_ROW) {
		depth = sqlite3_column_int64(pstmt, 3);
		if (ptnode->psorts->ccategories == depth)
			continue;	
		if (gx_sql_col_uint64(pstmt, 1) == inst_id1) {
			last_id = sqlite3_last_insert_rowid(psqlite);
			snprintf(sql_string, std::size(sql_string), "UPDATE state_info SET header_id=%llu,"
				" header_stat=%llu WHERE state_id=%u", LLU{last_id + 1},
				LLU{pstmt.col_uint64(2)}, *pstate_id);
			if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
				return FALSE;
		} else {
			if (0 == sqlite3_column_int64(pstmt, 2)) {
				if (depth >= ptnode->psorts->cexpanded)
					continue;
			} else {
				if (depth < ptnode->psorts->cexpanded)
					continue;
			}
		}
		sqlite3_bind_int64(pstmt1, 1, depth);
		row_id = sqlite3_column_int64(pstmt, 0);
		int i = depth;
		while (true) {
			stm_sel_vtx.bind_int64(1, row_id);
			type = ptnode->psorts->psort[i].type & ~MVI_FLAG;
			if (stm_sel_vtx.step() != SQLITE_ROW)
				return FALSE;
			pvalue = common_util_column_sqlite_statement(stm_sel_vtx, 0, type);
			stm_sel_vtx.reset();
			if (pvalue == nullptr)
				sqlite3_bind_null(pstmt1, i + 2);
			else if (!common_util_bind_sqlite_statement(pstmt1, i + 2, type, pvalue))
				return FALSE;
			if (i == 0)
				break;
			i --;
			sqlite3_bind_int64(pstmt2, 1, row_id);
			if (pstmt2.step() != SQLITE_ROW)
				return FALSE;
			row_id = sqlite3_column_int64(pstmt2, 0);
			sqlite3_reset(pstmt2);
		}
		for (i=depth+1; i<ptnode->psorts->ccategories; i++)
			sqlite3_bind_null(pstmt1, i + 2);
		if (pstmt1.step() != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt1);
	}
	return sql_transact.commit() == SQLITE_OK ? TRUE : false;
} catch (const std::bad_alloc &) {
	return false;
}

BOOL exmdb_server::restore_table_state(const char *dir, uint32_t table_id,
    uint32_t state_id, int32_t *pposition) try
{
	void *pvalue;
	uint32_t idx;
	uint16_t type;
	uint64_t row_id;
	uint64_t row_id1;
	uint8_t row_stat;
	uint64_t inst_num;
	EXT_PUSH ext_push;
	uint64_t header_id;
	uint64_t message_id;
	uint8_t header_stat;
	uint64_t current_id;
	xstmt pstmt1, pstmt2, stm_upd_tx;
	char tmp_buff[1024];
	char sql_string[1024];
	struct stat node_stat;
	
	row_id1 = 0;
	*pposition = -1;
	if (state_id == 0)
		return TRUE;
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto dbase = pdb->lock_base_rd();
	auto ptnode = dbase->find_table(table_id);
	if (ptnode == nullptr)
		return TRUE;
	if (ptnode->type != table_type::content)
		return TRUE;
	const auto &state_path = exmdb_eph_prefix + "/" + exmdb_server::get_dir() + "/tablestate.sqlite3";
	if (stat(state_path.c_str(), &node_stat) != 0)
		return TRUE;
	sqlite3 *psqlite = nullptr;
	auto ret = sqlite3_open_v2(state_path.c_str(), &psqlite, SQLITE_OPEN_READWRITE, nullptr);
	if (ret != SQLITE_OK) {
		mlog(LV_ERR, "E-1437: sqlite3_open %s: %s", state_path.c_str(), sqlite3_errstr(ret));
		return false;
	}
	auto cl_0 = HX::make_scope_exit([&]() { sqlite3_close(psqlite); });
	gx_sql_exec(psqlite, "PRAGMA journal_mode=OFF");
	gx_sql_exec(psqlite, "PRAGMA synchronous=OFF");
	snprintf(sql_string, std::size(sql_string), "SELECT folder_id, table_flags,"
			" sorts, message_id, inst_num, header_id, header_stat"
			" FROM state_info WHERE state_id=%u", state_id);
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;	
	if (pstmt.step() != SQLITE_ROW)
		return TRUE;
	message_id = sqlite3_column_int64(pstmt, 3);
	inst_num = sqlite3_column_int64(pstmt, 4);
	if (gx_sql_col_uint64(pstmt, 0) != ptnode->folder_id ||
		ptnode->table_flags != sqlite3_column_int64(pstmt, 1)) {
		pstmt.finalize();
		goto RESTORE_POSITION;
	}
	if (NULL == ptnode->psorts || 0 == ptnode->psorts->ccategories) {
		if (SQLITE_NULL != sqlite3_column_type(pstmt, 2)) {
			pstmt.finalize();
			goto RESTORE_POSITION;
		}
	} else {
		if (!ext_push.init(tmp_buff, sizeof(tmp_buff), 0) ||
		    ext_push.p_sortorder_set(*ptnode->psorts) != pack_result::ok) {
			pstmt.finalize();
			goto RESTORE_POSITION;
		}
		if (static_cast<unsigned int>(sqlite3_column_bytes(pstmt, 2)) != ext_push.m_offset ||
		    memcmp(sqlite3_column_blob(pstmt, 2), ext_push.m_udata, ext_push.m_offset) != 0) {
			pstmt.finalize();
			goto RESTORE_POSITION;
		}
	}
	header_id = sqlite3_column_int64(pstmt, 5);
	header_stat = sqlite3_column_int64(pstmt, 6);
	pstmt.finalize();
	if (ptnode->psorts == nullptr || ptnode->psorts->ccategories == 0)
		goto RESTORE_POSITION;
	{
	auto table_transact = gx_sql_begin(pdb->m_sqlite_eph, txn_mode::write);
	if (!table_transact)
		return false;
	/* reset table into initial state */
	snprintf(sql_string, std::size(sql_string), "SELECT row_id, "
		"row_stat, depth FROM t%u WHERE row_type=%u",
		ptnode->table_id, CONTENT_ROW_HEADER);
	pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET "
		"row_stat=? WHERE row_id=?", ptnode->table_id);
	pstmt1 = pdb->eph_prep(sql_string);
	if (pstmt1 == nullptr)
		return FALSE;

	unsigned int depth = 0;
	while (pstmt.step() == SQLITE_ROW) {
		row_id = sqlite3_column_int64(pstmt, 0);
		row_stat = sqlite3_column_int64(pstmt, 1);
		depth = pstmt.col_uint64(2);
		if (depth >= ptnode->psorts->cexpanded) {
			if (row_stat == 0)
				continue;
			row_stat = 0;
		} else {
			if (row_stat != 0)
				continue;
			row_stat = 1;
		}
		sqlite3_bind_int64(pstmt1, 1, row_stat);
		sqlite3_bind_int64(pstmt1, 2, row_id);
		if (pstmt.step() != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt1);
	}
	pstmt.finalize();
	pstmt1.finalize();
	/* end of resetting table */
	snprintf(sql_string, std::size(sql_string), "SELECT * FROM"
			" s%u ORDER BY ROWID ASC", state_id);
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT row_id FROM t%u WHERE"
			" parent_id=? AND value IS NULL", ptnode->table_id);
	pstmt1 = pdb->eph_prep(sql_string);
	if (pstmt1 == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT row_id FROM t%u WHERE"
				" parent_id=? AND value=?", ptnode->table_id);
	pstmt2 = pdb->eph_prep(sql_string);
	if (pstmt2 == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET "
		"row_stat=? WHERE row_id=?", ptnode->table_id);
	stm_upd_tx = pdb->eph_prep(sql_string);
	if (stm_upd_tx == nullptr)
		return FALSE;
	current_id = 0;
	while (pstmt.step() == SQLITE_ROW) {
		current_id ++;
		depth = pstmt.col_uint64(0);
		row_id = 0;
		unsigned int i;
		for (i=0; i<=depth; i++) {
			type = ptnode->psorts->psort[i].type & ~MVI_FLAG;
			pvalue = common_util_column_sqlite_statement(pstmt, i + 1, type);
			if (NULL == pvalue) {
				sqlite3_bind_int64(pstmt1, 1, row_id);
				if (pstmt1.step() != SQLITE_ROW) {
					sqlite3_reset(pstmt1);
					break;
				}
				row_id = sqlite3_column_int64(pstmt1, 0);
				sqlite3_reset(pstmt1);
			} else {
				sqlite3_bind_int64(pstmt2, 1, row_id);
				if (!common_util_bind_sqlite_statement(pstmt2, 2, type, pvalue))
					return FALSE;
				if (pstmt2.step() != SQLITE_ROW) {
					sqlite3_reset(pstmt2);
					break;
				}
				row_id = sqlite3_column_int64(pstmt2, 0);
				sqlite3_reset(pstmt2);
			}
		}
		if (i <= depth)
			continue;
		if (header_id == current_id) {
			row_stat = header_stat;
			row_id1 = row_id;
		} else {
			row_stat = depth >= ptnode->psorts->cexpanded;
		}
		stm_upd_tx.bind_int64(1, row_stat);
		stm_upd_tx.bind_int64(2, row_id);
		if (stm_upd_tx.step() != SQLITE_DONE)
			return FALSE;
		stm_upd_tx.reset();
	}
	pstmt.finalize();
	pstmt1.finalize();
	pstmt2.finalize();
	stm_upd_tx.finalize();
	sqlite3_close(psqlite);
	cl_0.release();
	snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET idx=NULL", ptnode->table_id);
	if (pdb->eph_exec(sql_string) != SQLITE_OK)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT row_id, row_stat"
			" FROM t%u WHERE prev_id=?", ptnode->table_id);
	pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return false;
	snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET"
		" idx=? WHERE row_id=?", ptnode->table_id);
	pstmt1 = pdb->eph_prep(sql_string);
	if (pstmt1 == nullptr)
		return false;
	idx = 0;
	sqlite3_bind_int64(pstmt, 1, 0);
	if (pstmt.step() == SQLITE_ROW &&
	    !common_util_indexing_sub_contents(ptnode->psorts->ccategories,
	    pstmt, pstmt1, &idx))
		return FALSE;
	pstmt.finalize();
	pstmt1.finalize();
	if (table_transact.commit() != SQLITE_OK)
		return false;
	}
 RESTORE_POSITION:
	if (message_id != 0)
		snprintf(sql_string, std::size(sql_string), "SELECT idx FROM t%u WHERE "
				"inst_id=%llu AND inst_num=%llu", ptnode->table_id,
				LLU{message_id}, LLU{inst_num});
	else
		snprintf(sql_string, std::size(sql_string), "SELECT idx FROM t%u WHERE"
		          " row_id=%llu", ptnode->table_id, LLU{row_id1});
	pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return false;
	*pposition = pstmt.step() == SQLITE_ROW ? sqlite3_column_int64(pstmt, 0) - 1 : -1;
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}
