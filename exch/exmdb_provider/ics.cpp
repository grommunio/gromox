// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <cstring>
#include <gromox/database.h>
#include "exmdb_server.h"
#include "common_util.h"
#include "db_engine.h"
#include <gromox/eid_array.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/idset.hpp>
#include <gromox/scope.hpp>
#include <cstdio>
#define IDSET_CACHE_MIN_RANGE				10

using namespace gromox;

namespace {

struct ENUM_PARAM {
	xstmt stm_exist, stm_msg;
	EID_ARRAY *pdeleted_eids;
	EID_ARRAY *pnolonger_mids;
	BOOL b_result;
};

struct REPLID_ARRAY {
	unsigned int count;
	uint16_t replids[1024];
};

struct RANGE_NODE {
	DOUBLE_LIST_NODE node;
	uint64_t low_value;
	uint64_t high_value;
};

struct REPLID_NODE {
	DOUBLE_LIST_NODE node;
	uint16_t replid;
	DOUBLE_LIST range_list;
};

struct IDSET_CACHE {
	IDSET_CACHE();
	~IDSET_CACHE();
	NOMOVE(IDSET_CACHE);

	sqlite3 *psqlite = nullptr;
	xstmt pstmt;
	DOUBLE_LIST range_list;
};

}

IDSET_CACHE::IDSET_CACHE()
{
	double_list_init(&range_list);
}

IDSET_CACHE::~IDSET_CACHE()
{
	pstmt.finalize();
	if (psqlite != nullptr)
		sqlite3_close(psqlite);
	double_list_free(&range_list);
}

static BOOL ics_init_idset_cache(const IDSET *pset, IDSET_CACHE *pcache)
{
	uint64_t ival;
	DOUBLE_LIST_NODE *pnode;
	REPLID_NODE *prepl_node;
	RANGE_NODE *prange_node;
	RANGE_NODE *prange_node1;
	DOUBLE_LIST *prange_list;
	
	if (SQLITE_OK != sqlite3_open_v2(":memory:", &pcache->psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		return FALSE;
	}
	if (sqlite3_exec(pcache->psqlite, "CREATE TABLE id_vals "
	    "(id_val INTEGER PRIMARY KEY)", nullptr, nullptr, nullptr) != SQLITE_OK)
		return FALSE;
	pcache->pstmt = NULL;
	prange_list = NULL;
	for (pnode=double_list_get_head(
		(DOUBLE_LIST*)&pset->repl_list);
		NULL!=pnode; pnode=double_list_get_after(
		(DOUBLE_LIST*)&pset->repl_list, pnode)) {
		prepl_node = (REPLID_NODE*)pnode->pdata;
		if (1 == prepl_node->replid) {
			prange_list = &prepl_node->range_list;
			break;
		}
	}
	if (NULL == prange_list) {
		return TRUE;
	}
	auto pstmt = gx_sql_prep(pcache->psqlite, "INSERT INTO id_vals VALUES (?)");
	if (pstmt == nullptr) {
		return FALSE;
	}
	for (pnode=double_list_get_head(prange_list); NULL!=pnode;
		pnode=double_list_get_after(prange_list, pnode)) {
		prange_node = (RANGE_NODE*)pnode->pdata;
		if (prange_node->high_value -
			prange_node->low_value >=
			IDSET_CACHE_MIN_RANGE) {
			prange_node1 = cu_alloc<RANGE_NODE>();
			if (NULL == prange_node1) {
				return FALSE;
			}
			prange_node1->node.pdata = prange_node1;
			prange_node1->low_value = prange_node->low_value;
			prange_node1->high_value = prange_node->high_value;
			double_list_append_as_tail(
				&pcache->range_list, &prange_node1->node);
		} else {
			for (ival=prange_node->low_value;
				ival<=prange_node->high_value; ival++) {
				sqlite3_reset(pstmt);
				sqlite3_bind_int64(pstmt, 1, ival);
				if (SQLITE_DONE != sqlite3_step(pstmt)) {
					return FALSE;
				}
			}
		}
	}
	return TRUE;
}

static BOOL ics_hint_idset_cache(IDSET_CACHE *pcache, uint64_t id_val)
{
	RANGE_NODE *prange_node;
	DOUBLE_LIST_NODE *pnode;
	
	if (NULL == pcache->pstmt) {
		pcache->pstmt = gx_sql_prep(pcache->psqlite, "SELECT id_val FROM id_vals WHERE id_val=?");
		if (pcache->pstmt == nullptr)
			return FALSE;
	}
	sqlite3_reset(pcache->pstmt);
	sqlite3_bind_int64(pcache->pstmt, 1, id_val);
	if (SQLITE_ROW == sqlite3_step(pcache->pstmt)) {
		return TRUE;
	}
	for (pnode=double_list_get_head(&pcache->range_list); NULL!=pnode;
		pnode=double_list_get_after(&pcache->range_list, pnode)) {
		prange_node = (RANGE_NODE*)pnode->pdata;
		if (id_val >= prange_node->low_value &&
			id_val <= prange_node->high_value) {
			return TRUE;	
		}
	}
	return FALSE;
}

static void ics_enum_content_idset(void *vparam, uint64_t message_id)
{
	auto pparam = static_cast<ENUM_PARAM *>(vparam);
	uint64_t mid_val;
	
	if (FALSE == pparam->b_result) {
		return;
	}
	mid_val = rop_util_get_gc_value(message_id);
	sqlite3_reset(pparam->stm_exist);
	sqlite3_bind_int64(pparam->stm_exist, 1, mid_val);
	if (sqlite3_step(pparam->stm_exist) == SQLITE_ROW)
		return;
	sqlite3_reset(pparam->stm_msg);
	sqlite3_bind_int64(pparam->stm_msg, 1, mid_val);
	if (SQLITE_ROW == sqlite3_step(pparam->stm_msg)) {
		if (!eid_array_append(pparam->pnolonger_mids, message_id))
			pparam->b_result = FALSE;
	} else {
		if (!eid_array_append(pparam->pdeleted_eids, message_id))
			pparam->b_result = FALSE;
	}
}

/*  username is used in public mode to get
	read information and read change number */
BOOL exmdb_server_get_content_sync(const char *dir,
	uint64_t folder_id, const char *username, const IDSET *pgiven,
	const IDSET *pseen, const IDSET *pseen_fai, const IDSET *pread,
	uint32_t cpid, const RESTRICTION *prestriction, BOOL b_ordered,
	uint32_t *pfai_count, uint64_t *pfai_total, uint32_t *pnormal_count,
	uint64_t *pnormal_total, EID_ARRAY *pupdated_mids, EID_ARRAY *pchg_mids,
	uint64_t *plast_cn, EID_ARRAY *pgiven_mids, EID_ARRAY *pdeleted_mids,
	EID_ARRAY *pnolonger_mids, EID_ARRAY *pread_mids,
	EID_ARRAY *punread_mids, uint64_t *plast_readcn)
{
	sqlite3 *psqlite;
	
	*pfai_count = 0;
	*pfai_total = 0;
	*pnormal_count = 0;
	*pnormal_total = 0;
	auto b_private = exmdb_server_check_private();

	/* Setup of scratch space db */
	if (SQLITE_OK != sqlite3_open_v2(":memory:", &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		return FALSE;
	}
	auto cl_0 = make_scope_exit([&]() { sqlite3_close(psqlite); });
	if (sqlite3_exec(psqlite, "CREATE TABLE existence "
	    "(message_id INTEGER PRIMARY KEY)", nullptr, nullptr, nullptr) != SQLITE_OK)
		return FALSE;
	if (NULL != pread) {
		if (sqlite3_exec(psqlite, "CREATE TABLE reads "
		    "(message_id INTEGER PRIMARY KEY, read_state INTEGER)",
		    nullptr, nullptr, nullptr) != SQLITE_OK)
			return FALSE;
	}
	if (TRUE == b_ordered) {
		if (sqlite3_exec(psqlite, "CREATE TABLE changes"
		    " (message_id INTEGER PRIMARY KEY, "
		    "delivery_time INTEGER, mod_time INTEGER)",
		    nullptr, nullptr, nullptr) != SQLITE_OK)
			return FALSE;
		if (sqlite3_exec(psqlite, "CREATE INDEX idx_dtime ON changes (delivery_time)",
		    nullptr, nullptr, nullptr) != SQLITE_OK)
			return FALSE;
		if (sqlite3_exec(psqlite, "CREATE INDEX idx_mtime ON changes (mod_time)",
		    nullptr, nullptr, nullptr) != SQLITE_OK)
			return FALSE;
	} else {
		if (sqlite3_exec(psqlite, "CREATE TABLE changes "
		    "(message_id INTEGER PRIMARY KEY)",
		    nullptr, nullptr, nullptr) != SQLITE_OK)
			return FALSE;
	}
	IDSET_CACHE cache;
	if (FALSE == ics_init_idset_cache(pgiven, &cache)) {
		return FALSE;
	}
	auto fid_val = rop_util_get_gc_value(folder_id);
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;

	/* Query section 1 */
	{
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", nullptr, nullptr, nullptr);
	if (NULL != prestriction) {
		sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", nullptr, nullptr, nullptr);
	}
	auto clean_transact = make_scope_exit([&]() {
		sqlite3_exec(psqlite, "ROLLBACK", nullptr, nullptr, nullptr);
		if (prestriction != nullptr)
			sqlite3_exec(pdb->psqlite, "ROLLBACK", nullptr, nullptr, nullptr);
	});
	char sql_string[256];
	if (TRUE == b_private) {
		snprintf(sql_string, arsizeof(sql_string), "SELECT message_id,"
			" change_number, is_associated, message_size,"
			" read_state, read_cn FROM messages WHERE "
			"parent_fid=%llu", static_cast<unsigned long long>(fid_val));
	} else {
		snprintf(sql_string, arsizeof(sql_string), "SELECT message_id,"
			" change_number, is_associated, message_size "
			"FROM messages WHERE parent_fid=%llu AND "
			"is_deleted=0", static_cast<unsigned long long>(fid_val));
	}
	auto stm_select_msg = gx_sql_prep(pdb->psqlite, sql_string);
	if (stm_select_msg == nullptr)
		return false;
	auto stm_insert_chg = gx_sql_prep(psqlite, b_ordered ?
	                      "INSERT INTO changes VALUES (?, ?, ?)" :
	                      "INSERT INTO changes VALUES (?)");
	if (stm_insert_chg == nullptr)
		return false;
	auto stm_insert_exist = gx_sql_prep(psqlite, "INSERT INTO existence VALUES (?)");
	if (stm_insert_exist == nullptr)
		return false;
	xstmt stm_insert_reads, stm_select_rcn, stm_select_rst;
	if (NULL != pread) {
		if (FALSE == b_private) {
			stm_select_rcn = gx_sql_prep(pdb->psqlite, "SELECT read_cn FROM "
			                 "read_cns WHERE message_id=? AND username=?");
			if (stm_select_rcn == nullptr)
				return false;
			stm_select_rst = gx_sql_prep(pdb->psqlite, "SELECT message_id FROM "
			                 "read_states WHERE message_id=? AND username=?");
			if (stm_select_rst == nullptr)
				return false;
		}
		stm_insert_reads = gx_sql_prep(psqlite, "INSERT INTO reads VALUES (?, ?)");
		if (stm_insert_reads == nullptr)
			return false;
	}
	xstmt stm_select_mp;
	if (TRUE == b_ordered) {
		stm_select_mp = gx_sql_prep(pdb->psqlite, "SELECT propval FROM "
		                "message_properties WHERE proptag=? AND message_id=?");
		if (stm_select_mp == nullptr)
			return false;
	}
	*plast_cn = 0;
	*plast_readcn = 0;
	while (sqlite3_step(stm_select_msg) == SQLITE_ROW) {
		uint64_t mid_val = sqlite3_column_int64(stm_select_msg, 0);
		uint64_t change_num = sqlite3_column_int64(stm_select_msg, 1);
		BOOL b_fai = sqlite3_column_int64(stm_select_msg, 2) == 0 ? false : TRUE;
		uint64_t message_size = sqlite3_column_int64(stm_select_msg, 3);
		if (NULL == pseen && NULL == pseen_fai) {
			continue;
		} else if (NULL != pseen && NULL == pseen_fai) {
			if (TRUE == b_fai) {
				continue;
			}
		} else if (NULL == pseen && NULL != pseen_fai) {
			if (FALSE == b_fai) {
				continue;
			}
		}
		if (NULL != prestriction && FALSE ==
			common_util_evaluate_message_restriction(
			pdb->psqlite, cpid, mid_val, prestriction)) {
			continue;	
		}
		sqlite3_reset(stm_insert_exist);
		sqlite3_bind_int64(stm_insert_exist, 1, mid_val);
		if (sqlite3_step(stm_insert_exist) != SQLITE_DONE)
			return false;
		if (change_num > *plast_cn) {
			*plast_cn = change_num;
		}
		uint64_t read_cn;
		if (TRUE == b_private) {
			read_cn = sqlite3_column_type(stm_select_msg, 5) == SQLITE_NULL ? 0 :
			          sqlite3_column_int64(stm_select_msg, 5);
		} else {
			sqlite3_reset(stm_select_rcn);
			sqlite3_bind_int64(stm_select_rcn, 1, mid_val);
			sqlite3_bind_text(stm_select_rcn, 2,
				username, -1, SQLITE_STATIC);
			read_cn = sqlite3_step(stm_select_rcn) != SQLITE_ROW ? 0 :
			          sqlite3_column_int64(stm_select_rcn, 0);
		}
		if (read_cn > *plast_readcn) {
			*plast_readcn = read_cn;
		}
		if (TRUE == b_fai) {
			if (ics_hint_idset_cache(&cache, mid_val) &&
			    const_cast<IDSET *>(pseen_fai)->hint(rop_util_make_eid_ex(1, change_num)))
				continue;
		} else {
			if (ics_hint_idset_cache(&cache, mid_val) &&
			    const_cast<IDSET *>(pseen)->hint(rop_util_make_eid_ex(1, change_num))) {
				if (NULL == pread) {
					continue;
				}
				if (read_cn == 0 ||
				    const_cast<IDSET *>(pread)->hint(rop_util_make_eid_ex(1, read_cn))) {
					continue;	
				}
				int read_state;
				if (TRUE == b_private) {
					read_state = sqlite3_column_int64(stm_select_msg, 4);
				} else {
					sqlite3_reset(stm_select_rst);
					sqlite3_bind_int64(stm_select_rst, 1, mid_val);
					sqlite3_bind_text(stm_select_rst, 2,
						username, -1 , SQLITE_STATIC);
					read_state = sqlite3_step(stm_select_rst) == SQLITE_ROW;
				}
				sqlite3_reset(stm_insert_reads);
				sqlite3_bind_int64(stm_insert_reads, 1, mid_val);
				sqlite3_bind_int64(stm_insert_reads, 2, read_state);
				if (sqlite3_step(stm_insert_reads) != SQLITE_DONE)
					return false;
				continue;
			}
		}
		uint64_t dtime = 0, mtime = 0;
		if (TRUE == b_ordered) {
			sqlite3_reset(stm_select_mp);
			sqlite3_bind_int64(stm_select_mp, 1, PROP_TAG_MESSAGEDELIVERYTIME);
			sqlite3_bind_int64(stm_select_mp, 2, mid_val);
			dtime = sqlite3_step(stm_select_mp) == SQLITE_ROW ?
			        sqlite3_column_int64(stm_select_mp, 0) : 0;
			sqlite3_reset(stm_select_mp);
			sqlite3_bind_int64(stm_select_mp, 1, PR_LAST_MODIFICATION_TIME);
			sqlite3_bind_int64(stm_select_mp, 2, mid_val);
			mtime = sqlite3_step(stm_select_mp) == SQLITE_ROW ?
			        sqlite3_column_int64(stm_select_mp, 0) : 0;
		}
		if (TRUE == b_fai) {
			(*pfai_count) ++;
			*pfai_total += message_size;
		} else {
			(*pnormal_count) ++;
			*pnormal_total += message_size;
		}
		sqlite3_reset(stm_insert_chg);
		sqlite3_bind_int64(stm_insert_chg, 1, mid_val);
		if (TRUE == b_ordered) {
			sqlite3_bind_int64(stm_insert_chg, 2, dtime);
			sqlite3_bind_int64(stm_insert_chg, 3, mtime);
		}
		if (sqlite3_step(stm_insert_chg) != SQLITE_DONE)
			return false;
	}
	stm_select_msg.finalize();
	stm_insert_chg.finalize();
	stm_insert_exist.finalize();
	stm_insert_reads.finalize();
	stm_select_rcn.finalize();
	stm_select_rst.finalize();
	stm_select_mp.finalize();
	if (0 != *plast_cn) {
		*plast_cn = rop_util_make_eid_ex(1, *plast_cn);
	}
	if (0 != *plast_readcn) {
		*plast_readcn = rop_util_make_eid_ex(1, *plast_readcn);
	}
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", nullptr, nullptr, nullptr);
	if (NULL != prestriction) {
		sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", nullptr, nullptr, nullptr);
	}
	clean_transact.release();
	} /* section 1 */

	/* Query section 2a */
	{
	ssize_t count;
	{
	auto stm_select_chg = gx_sql_prep(psqlite, "SELECT count(*) FROM changes");
	if (stm_select_chg == nullptr || sqlite3_step(stm_select_chg) != SQLITE_ROW)
		return FALSE;
	count = sqlite3_column_int64(stm_select_chg, 0);
	stm_select_chg.finalize();
	pchg_mids->count = 0;
	pupdated_mids->count = 0;
	if (count > 0) {
		pupdated_mids->pids = cu_alloc<uint64_t>(count);
		pchg_mids->pids = cu_alloc<uint64_t>(count);
		if (NULL == pupdated_mids->pids || NULL == pchg_mids->pids) {
			return FALSE;
		}
	} else {
		pupdated_mids->pids = NULL;
		pchg_mids->pids = NULL;
	}
	} /* section 2a */

	/* Query section 2b */
	{
	auto stm_select_chg = gx_sql_prep(psqlite, b_ordered ?
	                      "SELECT message_id FROM changes ORDER BY delivery_time DESC, mod_time DESC" :
	                      "SELECT message_id FROM changes");
	if (stm_select_chg == nullptr)
		return FALSE;
	for (ssize_t i = 0; i < count; ++i) {
		if (sqlite3_step(stm_select_chg) != SQLITE_ROW)
			return FALSE;
		uint64_t mid_val = sqlite3_column_int64(stm_select_chg, 0);
		pchg_mids->pids[pchg_mids->count++] = rop_util_make_eid_ex(1, mid_val);
		if (TRUE == ics_hint_idset_cache(&cache, mid_val)) {
			pupdated_mids->pids[pupdated_mids->count++] = rop_util_make_eid_ex(1, mid_val);
		}
	}
	} /* section 2b */
	}

	/* Query section 3 */
	{
	ENUM_PARAM enum_param;
	enum_param.stm_exist = gx_sql_prep(psqlite,
	                       "SELECT message_id FROM existence WHERE message_id=?");
	if (enum_param.stm_exist == nullptr)
		return FALSE;
	enum_param.stm_msg = gx_sql_prep(pdb->psqlite,
	                     "SELECT message_id FROM messages WHERE message_id=?");
	if (enum_param.stm_msg == nullptr)
		return FALSE;
	enum_param.b_result = TRUE;
	enum_param.pdeleted_eids = eid_array_init();
	if (NULL == enum_param.pdeleted_eids) {
		return FALSE;
	}
	enum_param.pnolonger_mids = eid_array_init();
	if (NULL == enum_param.pnolonger_mids) {
		eid_array_free(enum_param.pdeleted_eids);
		return FALSE;
	}
	if (!const_cast<IDSET *>(pgiven)->enum_repl(1, &enum_param,
	    ics_enum_content_idset)) {
		eid_array_free(enum_param.pdeleted_eids);
		eid_array_free(enum_param.pnolonger_mids);
		return FALSE;	
	}
	enum_param.stm_exist.finalize();
	enum_param.stm_msg.finalize();
	pdeleted_mids->count = enum_param.pdeleted_eids->count;
	if (0 != enum_param.pdeleted_eids->count) {
		pdeleted_mids->pids = cu_alloc<uint64_t>(pdeleted_mids->count);
		if (NULL == pdeleted_mids->pids) {
			pdeleted_mids->count = 0;
			eid_array_free(enum_param.pdeleted_eids);
			eid_array_free(enum_param.pnolonger_mids);
			return FALSE;
		}
		memcpy(pdeleted_mids->pids,
			enum_param.pdeleted_eids->pids,
			sizeof(uint64_t)*pdeleted_mids->count);
	} else {
		pdeleted_mids->pids = NULL;
	}
	eid_array_free(enum_param.pdeleted_eids);
	pnolonger_mids->count = enum_param.pnolonger_mids->count;
	if (0 != enum_param.pnolonger_mids->count) {
		pnolonger_mids->pids = cu_alloc<uint64_t>(pnolonger_mids->count);
		if (NULL == pnolonger_mids->pids) {
			pnolonger_mids->count = 0;
			eid_array_free(enum_param.pnolonger_mids);
			return FALSE;
		}
		memcpy(pnolonger_mids->pids,
			enum_param.pnolonger_mids->pids,
			sizeof(uint64_t)*pnolonger_mids->count);
	} else {
		pnolonger_mids->pids = NULL;
	}
	eid_array_free(enum_param.pnolonger_mids);
	} /* section 3 */

	pdb.reset();

	/* Query section 4 */
	{
	auto stm_select_exist = gx_sql_prep(psqlite, "SELECT count(*) FROM existence");
	if (stm_select_exist == nullptr ||
	    sqlite3_step(stm_select_exist) != SQLITE_ROW)
		return FALSE;
	int64_t count = sqlite3_column_int64(stm_select_exist, 0);
	stm_select_exist.finalize();
	pgiven_mids->count = 0;
	if (count <= 0) {
		pgiven_mids->pids = NULL;
	} else {
		pgiven_mids->pids = cu_alloc<uint64_t>(count);
		if (NULL == pgiven_mids->pids) {
			return FALSE;
		}
		auto stm_select_ex = gx_sql_prep(psqlite, "SELECT message_id"
		                     " FROM existence ORDER BY message_id DESC");
		if (stm_select_ex == nullptr)
			return FALSE;
		while (sqlite3_step(stm_select_ex) == SQLITE_ROW) {
			uint64_t mid_val = sqlite3_column_int64(stm_select_ex, 0);
			pgiven_mids->pids[pgiven_mids->count++] = rop_util_make_eid_ex(1, mid_val);
		}
	}
	} /* section 4 */

	/* Query section 5 */
	{
	if (NULL != pread) {
		auto stm_select_rd = gx_sql_prep(psqlite, "SELECT count(*) FROM reads");
		if (stm_select_rd == nullptr ||
		    sqlite3_step(stm_select_rd) != SQLITE_ROW)
			return FALSE;
		ssize_t count = sqlite3_column_int64(stm_select_rd, 0);
		stm_select_rd.finalize();
		pread_mids->count = 0;
		punread_mids->count = 0;
		if (count <= 0) {
			pread_mids->pids = NULL;
			punread_mids->pids = NULL;
		} else {
			pread_mids->pids = cu_alloc<uint64_t>(count);
			if (NULL == pread_mids->pids) {
				return FALSE;
			}
			punread_mids->pids = cu_alloc<uint64_t>(count);
			if (NULL == punread_mids->pids) {
				return FALSE;
			}
		}
		stm_select_rd = gx_sql_prep(psqlite,
		                "SELECT message_id, read_state FROM reads");
		if (stm_select_rd == nullptr)
			return FALSE;
		while (sqlite3_step(stm_select_rd) == SQLITE_ROW) {
			uint64_t mid_val = sqlite3_column_int64(stm_select_rd, 0);
			if (sqlite3_column_int64(stm_select_rd, 1) == 0)
				punread_mids->pids[punread_mids->count++] = rop_util_make_eid_ex(1, mid_val);
			else
				pread_mids->pids[pread_mids->count++] = rop_util_make_eid_ex(1, mid_val);
		}
	} else {
		pread_mids->count = 0;
		pread_mids->pids = NULL;
		punread_mids->count = 0;
		punread_mids->pids = NULL;
	}
	} /* section 5 */
	return TRUE;
}

static void ics_enum_hierarchy_idset(void *vparam, uint64_t folder_id)
{
	auto pparam = static_cast<ENUM_PARAM *>(vparam);
	uint16_t replid;
	uint64_t fid_val;
	
	if (FALSE == pparam->b_result) {
		return;
	}
	replid = rop_util_get_replid(folder_id);
	fid_val = rop_util_get_gc_value(folder_id);
	if (1 != replid) {
		fid_val |= ((uint64_t)replid) << 48;
	}
	sqlite3_reset(pparam->stm_exist);
	sqlite3_bind_int64(pparam->stm_exist, 1, fid_val);
	if (sqlite3_step(pparam->stm_exist) == SQLITE_ROW)
		return;
	if (!eid_array_append(pparam->pdeleted_eids, folder_id))
		pparam->b_result = FALSE;
}

static void ics_enum_hierarchy_replist(void *vpar, uint16_t replid)
{
	auto preplids = static_cast<REPLID_ARRAY *>(vpar);
	if (preplids->count < 1024) {
		preplids->replids[preplids->count++] = replid;
	}
}

static BOOL ics_load_folder_changes(sqlite3 *psqlite,
	uint64_t folder_id, const char *username,
	const IDSET *pgiven, const IDSET *pseen,
	sqlite3_stmt *pstmt, sqlite3_stmt *stm_insert_chg,
	sqlite3_stmt *stm_insert_exist, uint64_t *plast_cn)
{
	uint64_t fid_val;
	uint64_t change_num;
	uint32_t permission;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	
	double_list_init(&tmp_list);
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, folder_id);
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		fid_val = sqlite3_column_int64(pstmt, 0);
		change_num = sqlite3_column_int64(pstmt, 1);
		if (NULL != username) {
			if (FALSE == common_util_check_folder_permission(
				psqlite, fid_val, username, &permission)) {
				return FALSE;
			}
			if (!(permission & (frightsReadAny | frightsVisible | frightsOwner)))
				continue;
		}
		pnode = cu_alloc<DOUBLE_LIST_NODE>();
		if (NULL == pnode) {
			return FALSE;
		}
		pnode->pdata = cu_alloc<uint64_t>();
		if (NULL == pnode->pdata) {
			return FALSE;
		}
		*(uint64_t*)pnode->pdata = fid_val;
		double_list_append_as_tail(&tmp_list, pnode);
		sqlite3_reset(stm_insert_exist);
		sqlite3_bind_int64(stm_insert_exist, 1, fid_val);
		if (sqlite3_step(stm_insert_exist) != SQLITE_DONE)
			return FALSE;
		if (change_num > *plast_cn) {
			*plast_cn = change_num;
		}
		if (const_cast<IDSET *>(pgiven)->hint(rop_util_make_eid_ex(1, fid_val)) &&
		    const_cast<IDSET *>(pseen)->hint(rop_util_make_eid_ex(1, change_num)))
			continue;
		sqlite3_reset(stm_insert_chg);
		sqlite3_bind_int64(stm_insert_chg, 1, fid_val);
		if (sqlite3_step(stm_insert_chg) != SQLITE_DONE)
			return FALSE;
	}
	while ((pnode = double_list_pop_front(&tmp_list)) != nullptr) {
		if (!ics_load_folder_changes(psqlite,
		    *static_cast<uint64_t *>(pnode->pdata), username, pgiven,
		    pseen, pstmt, stm_insert_chg, stm_insert_exist, plast_cn))
			return FALSE;	
	}
	return TRUE;
}

BOOL exmdb_server_get_hierarchy_sync(const char *dir,
	uint64_t folder_id, const char *username, const IDSET *pgiven,
	const IDSET *pseen, FOLDER_CHANGES *pfldchgs, uint64_t *plast_cn,
	EID_ARRAY *pgiven_fids, EID_ARRAY *pdeleted_fids)
{
	sqlite3 *psqlite;
	
	/* Setup of scratch space db */
	if (SQLITE_OK != sqlite3_open_v2(":memory:", &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		return FALSE;
	}
	auto cl_0 = make_scope_exit([&]() { sqlite3_close(psqlite); });
	if (sqlite3_exec(psqlite, "CREATE TABLE existence "
	    "(folder_id INTEGER PRIMARY KEY)",
	    nullptr, nullptr, nullptr) != SQLITE_OK)
		return FALSE;
	if (sqlite3_exec(psqlite, "CREATE TABLE changes "
	    "(idx INTEGER PRIMARY KEY AUTOINCREMENT,"
	    " folder_id INTEGER UNIQUE NOT NULL)",
	    nullptr, nullptr, nullptr) != SQLITE_OK)
		return FALSE;
	auto fid_val = rop_util_get_gc_value(folder_id);
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;

	/* Query section 1 */
	{
	auto stm_select_fld = gx_sql_prep(pdb->psqlite, exmdb_server_check_private() ?
	                      "SELECT folder_id, change_number FROM folders WHERE parent_id=?" :
	                      "SELECT folder_id, change_number FROM folders WHERE parent_id=? AND is_deleted=0");
	if (stm_select_fld == nullptr)
		return FALSE;
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	auto clean_transact = make_scope_exit([&]() {
		sqlite3_exec(psqlite, "ROLLBACK", nullptr, nullptr, nullptr);
	});
	auto stm_insert_chg = gx_sql_prep(psqlite,
	                      "INSERT INTO changes (folder_id) VALUES (?)");
	if (stm_insert_chg == nullptr)
		return FALSE;
	auto stm_insert_exist = gx_sql_prep(psqlite, "INSERT INTO existence VALUES (?)");
	if (stm_insert_exist == nullptr)
		return FALSE;
	*plast_cn = 0;
	if (!ics_load_folder_changes(pdb->psqlite, fid_val, username, pgiven,
	    pseen, stm_select_fld, stm_insert_chg, stm_insert_exist, plast_cn))
		return FALSE;
	stm_select_fld.finalize();
	stm_insert_chg.finalize();
	stm_insert_exist.finalize();
	if (0 != *plast_cn) {
		*plast_cn = rop_util_make_eid_ex(1, *plast_cn);
	}
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	clean_transact.release();
	} /* section 1 */

	/* Query section 2 */
	{
	auto stm_select_chg = gx_sql_prep(psqlite, "SELECT count(*) FROM changes");
	if (stm_select_chg == nullptr || sqlite3_step(stm_select_chg) != SQLITE_ROW)
		return FALSE;
	pfldchgs->count = sqlite3_column_int64(stm_select_chg, 0);
	stm_select_chg.finalize();
	if (0 != pfldchgs->count) {
		pfldchgs->pfldchgs = cu_alloc<TPROPVAL_ARRAY>(pfldchgs->count);
		if (NULL == pfldchgs->pfldchgs) {
			pfldchgs->count = 0;
			return FALSE;
		}
	} else {
		pfldchgs->pfldchgs = NULL;
	}
	} /* section 2 */

	/* Query section 3 */
	{
	sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	auto clean_transact2 = make_scope_exit([&]() {
		sqlite3_exec(pdb->psqlite, "ROLLBACK", nullptr, nullptr, nullptr);
	});
	auto stm_select_chg = gx_sql_prep(psqlite,
	                      "SELECT folder_id FROM changes ORDER BY idx ASC");
	if (stm_select_chg == nullptr)
		return FALSE;
	for (size_t i = 0; i < pfldchgs->count; ++i) {
		if (sqlite3_step(stm_select_chg) != SQLITE_ROW)
			return FALSE;
		auto fid_val1 = sqlite3_column_int64(stm_select_chg, 0);
		PROPTAG_ARRAY proptags;
		if (!cu_get_proptags(db_table::folder_props, fid_val1,
			pdb->psqlite, &proptags)) {
			return FALSE;
		}

		uint32_t tmp_proptags[0x8000];
		size_t count = 0;
		for (size_t j = 0; j < proptags.count; ++j) {
			if (PROP_TAG_HASRULES == proptags.pproptag[j] ||
				PROP_TAG_CHANGENUMBER == proptags.pproptag[j] ||
				PROP_TAG_LOCALCOMMITTIME == proptags.pproptag[j] ||
			    proptags.pproptag[j] == PR_DELETED_COUNT_TOTAL ||
			    proptags.pproptag[j] == PR_NORMAL_MESSAGE_SIZE ||
			    proptags.pproptag[j] == PR_LOCAL_COMMIT_TIME_MAX ||
			    proptags.pproptag[j] == PR_HIERARCHY_CHANGE_NUM)
				continue;
			tmp_proptags[count++] = proptags.pproptag[j];
		}
		tmp_proptags[count++] = PROP_TAG_PARENTFOLDERID;
		proptags.count = count;
		proptags.pproptag = tmp_proptags;
		if (!cu_get_properties(db_table::folder_props, fid_val1, 0,
			pdb->psqlite, &proptags, pfldchgs->pfldchgs + i)) {
			return FALSE;
		}
	}
	stm_select_chg.finalize();
	sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	clean_transact2.release();
	} /* section 3 */

	pdb.reset();

	/* Query section 4 */
	{
	auto stm_select_exist = gx_sql_prep(psqlite, "SELECT count(*) FROM existence");
	if (stm_select_exist == nullptr ||
	    sqlite3_step(stm_select_exist) != SQLITE_ROW)
		return FALSE;
	ssize_t count = sqlite3_column_int64(stm_select_exist, 0);
	stm_select_exist.finalize();
	pgiven_fids->count = 0;
	if (count <= 0) {
		pgiven_fids->pids = NULL;
	} else {
		pgiven_fids->pids = cu_alloc<uint64_t>(count);
		if (NULL == pgiven_fids->pids) {
			return FALSE;
		}
		auto stm_select_ex = gx_sql_prep(psqlite, "SELECT folder_id"
		                     " FROM existence ORDER BY folder_id DESC");
		if (stm_select_ex == nullptr)
			return FALSE;
		while (sqlite3_step(stm_select_ex) == SQLITE_ROW) {
			uint64_t fid_val = sqlite3_column_int64(stm_select_ex, 0);
			if (0 == (fid_val & 0xFF00000000000000ULL)) {
				pgiven_fids->pids[pgiven_fids->count++] =
						rop_util_make_eid_ex(1, fid_val);
			} else {
				pgiven_fids->pids[pgiven_fids->count++] =
					rop_util_make_eid_ex(fid_val >> 48,
					fid_val & 0x00FFFFFFFFFFFFFFULL);
			}
		}
	}
	} /* section 4 */

	/* Query section 5 */
	{
	REPLID_ARRAY replids;
	replids.count = 0;
	const_cast<IDSET *>(pgiven)->enum_replist(&replids, ics_enum_hierarchy_replist);
	ENUM_PARAM enum_param;
	enum_param.stm_exist = gx_sql_prep(psqlite, "SELECT folder_id"
	                       " FROM existence WHERE folder_id=?");
	if (enum_param.stm_exist == nullptr)
		return FALSE;
	enum_param.b_result = TRUE;
	enum_param.pdeleted_eids = eid_array_init();
	if (NULL == enum_param.pdeleted_eids) {
		return FALSE;
	}
	for (size_t i = 0; i < replids.count; ++i) {
		if (!const_cast<IDSET *>(pgiven)->enum_repl(replids.replids[i],
		    &enum_param, ics_enum_hierarchy_idset)) {
			eid_array_free(enum_param.pdeleted_eids);
			return FALSE;	
		}
	}

	pdeleted_fids->count = enum_param.pdeleted_eids->count;
	pdeleted_fids->pids = cu_alloc<uint64_t>(pdeleted_fids->count);
	if (NULL == pdeleted_fids->pids) {
		pdeleted_fids->count = 0;
		eid_array_free(enum_param.pdeleted_eids);
		return FALSE;
	}
	memcpy(pdeleted_fids->pids,
		enum_param.pdeleted_eids->pids,
		sizeof(uint64_t)*pdeleted_fids->count);
	eid_array_free(enum_param.pdeleted_eids);
	} /* section 5 */
	return TRUE;
}
