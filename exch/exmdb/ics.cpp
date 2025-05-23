// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>
#include <libHX/scope.hpp>
#include <gromox/database.h>
#include <gromox/eid_array.hpp>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/fileio.h>
#include <gromox/mapi_types.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "db_engine.hpp"

using namespace gromox;

namespace {

struct ENUM_PARAM {
	~ENUM_PARAM() {
		if (pnolonger_mids != nullptr)
			eid_array_free(pnolonger_mids);
		if (pdeleted_eids != nullptr)
			eid_array_free(pdeleted_eids);
	}

	xstmt stm_exist, stm_msg;
	EID_ARRAY *pdeleted_eids = nullptr, *pnolonger_mids = nullptr;
	BOOL b_result;
};

struct REPLID_ARRAY {
	unsigned int count;
	uint16_t replids[1024];
};

}

static std::mutex ics_log_mtx;
std::string g_exmdb_ics_log_file;

static void ics_enum_content_idset(void *vparam, uint64_t message_id)
{
	auto pparam = static_cast<ENUM_PARAM *>(vparam);
	uint64_t mid_val;
	
	if (!pparam->b_result)
		return;
	mid_val = rop_util_get_gc_value(message_id);
	sqlite3_reset(pparam->stm_exist);
	sqlite3_bind_int64(pparam->stm_exist, 1, mid_val);
	if (pparam->stm_exist.step() == SQLITE_ROW)
		return;
	sqlite3_reset(pparam->stm_msg);
	sqlite3_bind_int64(pparam->stm_msg, 1, mid_val);
	if (pparam->stm_msg.step() == SQLITE_ROW) {
		if (!eid_array_append(pparam->pnolonger_mids, message_id))
			pparam->b_result = FALSE;
	} else {
		if (!eid_array_append(pparam->pdeleted_eids, message_id))
			pparam->b_result = FALSE;
	}
}

/* Counterpart for simc_otherstore. */
static ec_error_t delete_impossible_mids(const idset &given, EID_ARRAY &del)
{
	struct p1data {
		const idset *given;
		EID_ARRAY *del;
		ec_error_t error;
	} p1 = {&given, &del, ecSuccess};
	const_cast<idset &>(given).enum_replist(&p1, [](void *param1, uint16_t replid) {
		if (replid <= 1)
			return;
		auto p2 = static_cast<p1data *>(param1);
		if (p2->error != ecSuccess)
			return;
		const_cast<idset *>(p2->given)->enum_repl(replid, p2, [](void *param2, uint64_t msgid) {
			auto p3 = static_cast<p1data *>(param2);
			if (p3->error != ecSuccess)
				return;
			if (!eid_array_append(p3->del, msgid))
				p3->error = ecServerOOM;
		});
	});
	return p1.error;
}

/**
 * @username:     Used for retrieving public store readstates
 * @pgiven:       Set of MIDs the client has
 * @pseen:        Set of CNs the client has
 * @prestriction: Used by the client to limit the timeframe to synchronize ("most recent x days")
 * @b_ordered:    Request that messages be ordered by delivery_time (fallback: lastmod_time)
 *                (else: no specific order; MS-OXCFXICS §3.2.5.9.1.1)
 */
BOOL exmdb_server::get_content_sync(const char *dir,
    uint64_t folder_id, const char *username, const idset *pgiven,
    const idset *pseen, const idset *pseen_fai, const idset *pread,
    cpid_t cpid, const RESTRICTION *prestriction, BOOL b_ordered,
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
	auto b_private = exmdb_server::is_private();

	/*
	 * Setup of scratch space db.
	 *
	 * All three tables are implicitly ordered by MID (due to PK)
	 * SELECTs on those three should use ORDER BY if explicit order is desired.
	 */
	if (sqlite3_open_v2(":memory:", &psqlite,
	    SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK)
		return FALSE;
	auto cl_0 = HX::make_scope_exit([&]() { sqlite3_close(psqlite); });
	if (gx_sql_exec(psqlite, "CREATE TABLE existence "
	    "(message_id INTEGER PRIMARY KEY)") != SQLITE_OK)
		return FALSE;
	if (pread != nullptr &&
	    gx_sql_exec(psqlite, "CREATE TABLE reads "
	    "(message_id INTEGER PRIMARY KEY, read_state INTEGER)") != SQLITE_OK)
		return FALSE;
	if (b_ordered) {
		if (gx_sql_exec(psqlite, "CREATE TABLE changes"
		    " (message_id INTEGER PRIMARY KEY, "
		    "delivery_time INTEGER, mod_time INTEGER)") != SQLITE_OK)
			return FALSE;
		if (gx_sql_exec(psqlite, "CREATE INDEX idx_dtime ON changes (delivery_time)") != SQLITE_OK)
			return FALSE;
		if (gx_sql_exec(psqlite, "CREATE INDEX idx_mtime ON changes (mod_time)") != SQLITE_OK)
			return FALSE;
	} else {
		if (gx_sql_exec(psqlite, "CREATE TABLE changes "
		    "(message_id INTEGER PRIMARY KEY)") != SQLITE_OK)
			return FALSE;
	}
	auto fid_val = rop_util_get_gc_value(folder_id);
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	/*
	 * Read-only transaction ensuring consistency of data across several blocks.
	 * Nothing is ever written to pdb->psqlite, so no need to commit anything.
	 */
	xtransaction transact2 = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!transact2)
		return false;

	/*
	 * #1:
	 * Determine message counts, bytesize totals, and maximum CNs.
	 * (The result is dependent on prestriction.)
	 */
	{
	auto transact1 = gx_sql_begin(psqlite, txn_mode::write);
	if (!transact1)
		return false;
	char sql_string[256];
	if (b_private)
		snprintf(sql_string, std::size(sql_string), "SELECT message_id,"
			" change_number, is_associated, message_size,"
			" read_state, read_cn FROM messages WHERE "
		         "parent_fid=%llu AND is_deleted=0",
		         static_cast<unsigned long long>(fid_val));
	else
		snprintf(sql_string, std::size(sql_string), "SELECT message_id,"
			" change_number, is_associated, message_size "
			"FROM messages WHERE parent_fid=%llu AND "
			"is_deleted=0", static_cast<unsigned long long>(fid_val));
	auto stm_select_msg = pdb->prep(sql_string);
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
		if (!b_private) {
			stm_select_rcn = pdb->prep("SELECT read_cn FROM "
			                 "read_cns WHERE message_id=? AND username=?");
			if (stm_select_rcn == nullptr)
				return false;
			stm_select_rst = pdb->prep("SELECT message_id FROM "
			                 "read_states WHERE message_id=? AND username=?");
			if (stm_select_rst == nullptr)
				return false;
		}
		stm_insert_reads = gx_sql_prep(psqlite, "INSERT INTO reads VALUES (?, ?)");
		if (stm_insert_reads == nullptr)
			return false;
	}
	xstmt stm_select_mp;
	if (b_ordered) {
		stm_select_mp = pdb->prep("SELECT propval FROM "
		                "message_properties WHERE proptag=? AND message_id=?");
		if (stm_select_mp == nullptr)
			return false;
	}
	*plast_cn = 0;
	*plast_readcn = 0;
	while (stm_select_msg.step() == SQLITE_ROW) {
		uint64_t mid_val = sqlite3_column_int64(stm_select_msg, 0);
		uint64_t change_num = sqlite3_column_int64(stm_select_msg, 1);
		BOOL b_fai = sqlite3_column_int64(stm_select_msg, 2) == 0 ? false : TRUE;
		uint64_t message_size = sqlite3_column_int64(stm_select_msg, 3);
		if (NULL == pseen && NULL == pseen_fai) {
			continue;
		} else if (NULL != pseen && NULL == pseen_fai) {
			if (b_fai)
				continue;
		} else if (NULL == pseen && NULL != pseen_fai) {
			if (!b_fai)
				continue;
		}
		if (prestriction != nullptr &&
		    !cu_eval_msg_restriction(pdb->psqlite,
		    cpid, mid_val, prestriction))
			continue;	
		sqlite3_reset(stm_insert_exist);
		sqlite3_bind_int64(stm_insert_exist, 1, mid_val);
		if (stm_insert_exist.step() != SQLITE_DONE)
			return false;
		if (change_num > *plast_cn)
			*plast_cn = change_num;
		uint64_t read_cn;
		if (b_private) {
			read_cn = sqlite3_column_type(stm_select_msg, 5) == SQLITE_NULL ? 0 :
			          sqlite3_column_int64(stm_select_msg, 5);
		} else {
			sqlite3_reset(stm_select_rcn);
			sqlite3_bind_int64(stm_select_rcn, 1, mid_val);
			sqlite3_bind_text(stm_select_rcn, 2,
				username, -1, SQLITE_STATIC);
			read_cn = stm_select_rcn.step() != SQLITE_ROW ? 0 :
			          sqlite3_column_int64(stm_select_rcn, 0);
		}
		if (read_cn > *plast_readcn)
			*plast_readcn = read_cn;
		auto msg_eid = rop_util_make_eid_ex(1, mid_val);
		auto chg_eid = rop_util_make_eid_ex(1, change_num);
		if (b_fai) {
			if (pgiven->contains(msg_eid) &&
			    pseen_fai->contains(chg_eid))
				continue;
		} else if (pgiven->contains(msg_eid) &&
		    pseen->contains(chg_eid)) {
			if (pread == nullptr)
				continue;
			if (read_cn == 0 ||
			    pread->contains(rop_util_make_eid_ex(1, read_cn)))
				continue;
			int read_state;
			if (b_private) {
				read_state = sqlite3_column_int64(stm_select_msg, 4);
			} else {
				sqlite3_reset(stm_select_rst);
				sqlite3_bind_int64(stm_select_rst, 1, mid_val);
				sqlite3_bind_text(stm_select_rst, 2,
					username, -1 , SQLITE_STATIC);
				read_state = stm_select_rst.step() == SQLITE_ROW;
			}
			sqlite3_reset(stm_insert_reads);
			sqlite3_bind_int64(stm_insert_reads, 1, mid_val);
			sqlite3_bind_int64(stm_insert_reads, 2, read_state);
			if (stm_insert_reads.step() != SQLITE_DONE)
				return false;
			continue;
		}
		uint64_t dtime = 0, mtime = 0;
		if (b_ordered) {
			sqlite3_reset(stm_select_mp);
			sqlite3_bind_int64(stm_select_mp, 1, PR_MESSAGE_DELIVERY_TIME);
			sqlite3_bind_int64(stm_select_mp, 2, mid_val);
			dtime = stm_select_mp.step() == SQLITE_ROW ?
			        sqlite3_column_int64(stm_select_mp, 0) : 0;
			sqlite3_reset(stm_select_mp);
			sqlite3_bind_int64(stm_select_mp, 1, PR_LAST_MODIFICATION_TIME);
			sqlite3_bind_int64(stm_select_mp, 2, mid_val);
			mtime = stm_select_mp.step() == SQLITE_ROW ?
			        sqlite3_column_int64(stm_select_mp, 0) : 0;
		}
		if (b_fai) {
			(*pfai_count) ++;
			*pfai_total += message_size;
		} else {
			(*pnormal_count) ++;
			*pnormal_total += message_size;
		}
		sqlite3_reset(stm_insert_chg);
		sqlite3_bind_int64(stm_insert_chg, 1, mid_val);
		if (b_ordered) {
			sqlite3_bind_int64(stm_insert_chg, 2, dtime);
			sqlite3_bind_int64(stm_insert_chg, 3, mtime);
		}
		if (stm_insert_chg.step() != SQLITE_DONE)
			return false;
	}
	stm_select_msg.finalize();
	stm_insert_chg.finalize();
	stm_insert_exist.finalize();
	stm_insert_reads.finalize();
	stm_select_rcn.finalize();
	stm_select_rst.finalize();
	stm_select_mp.finalize();
	if (*plast_cn != 0)
		*plast_cn = rop_util_make_eid_ex(1, *plast_cn);
	if (*plast_readcn != 0)
		*plast_readcn = rop_util_make_eid_ex(1, *plast_readcn);
	if (transact1.commit() != SQLITE_OK)
		return false;
	} /* section 1 */

	/*
	 * section #2a: exact-allocate pupdated_mids, pchg_mids
	 */
	{
	ssize_t count;
	{
	auto stm_select_chg = gx_sql_prep(psqlite, "SELECT count(*) FROM changes");
	if (stm_select_chg == nullptr || stm_select_chg.step() != SQLITE_ROW)
		return FALSE;
	count = sqlite3_column_int64(stm_select_chg, 0);
	stm_select_chg.finalize();
	pchg_mids->count = 0;
	pupdated_mids->count = 0;
	if (count > 0) {
		pupdated_mids->pids = cu_alloc<uint64_t>(count);
		pchg_mids->pids = cu_alloc<uint64_t>(count);
		if (pupdated_mids->pids == nullptr || pchg_mids->pids == nullptr)
			return FALSE;
	} else {
		pupdated_mids->pids = NULL;
		pchg_mids->pids = NULL;
	}
	} /* section 2a */

	/*
	 * #2b: compute pchg_mids, pupdated_mids
	 */
	{
	auto stm_select_chg = gx_sql_prep(psqlite, b_ordered ?
	                      "SELECT message_id FROM changes ORDER BY delivery_time DESC, mod_time DESC" :
	                      "SELECT message_id FROM changes");
	if (stm_select_chg == nullptr)
		return FALSE;
	for (ssize_t i = 0; i < count; ++i) {
		if (stm_select_chg.step() != SQLITE_ROW)
			return FALSE;
		uint64_t mid_val = sqlite3_column_int64(stm_select_chg, 0);
		auto eid = rop_util_make_eid_ex(1, mid_val);
		pchg_mids->pids[pchg_mids->count++] = eid;
		if (pgiven->contains(eid))
			pupdated_mids->pids[pupdated_mids->count++] = eid;
	}
	} /* section 2b */
	}

	/*
	 * #3: Build nolonger_mids, which is the set of MIDs that the client
	 * has but the server has deleted (and server is more recent).
	 */
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
	if (enum_param.pdeleted_eids == nullptr)
		return FALSE;
	enum_param.pnolonger_mids = eid_array_init();
	if (enum_param.pnolonger_mids == nullptr)
		return FALSE;
	if (delete_impossible_mids(*pgiven, *enum_param.pdeleted_eids) != ecSuccess)
		return false;
	if (!const_cast<idset *>(pgiven)->enum_repl(1, &enum_param,
	    ics_enum_content_idset))
		return FALSE;	
	enum_param.stm_exist.finalize();
	enum_param.stm_msg.finalize();
	pdeleted_mids->count = enum_param.pdeleted_eids->count;
	if (0 != enum_param.pdeleted_eids->count) {
		pdeleted_mids->pids = cu_alloc<uint64_t>(pdeleted_mids->count);
		if (NULL == pdeleted_mids->pids) {
			pdeleted_mids->count = 0;
			return FALSE;
		}
		memcpy(pdeleted_mids->pids,
			enum_param.pdeleted_eids->pids,
			sizeof(uint64_t)*pdeleted_mids->count);
	} else {
		pdeleted_mids->pids = NULL;
	}
	pnolonger_mids->count = enum_param.pnolonger_mids->count;
	if (0 != enum_param.pnolonger_mids->count) {
		pnolonger_mids->pids = cu_alloc<uint64_t>(pnolonger_mids->count);
		if (NULL == pnolonger_mids->pids) {
			pnolonger_mids->count = 0;
			return FALSE;
		}
		memcpy(pnolonger_mids->pids,
			enum_param.pnolonger_mids->pids,
			sizeof(uint64_t)*pnolonger_mids->count);
	} else {
		pnolonger_mids->pids = NULL;
	}
	} /* section 3 */

	/* Rollback transaction (no changes were made anyway) */
	transact2 = xtransaction();
	pdb.reset();

	/* Query section 4 - pgiven_mids: what the server has */
	{
	auto stm_select_exist = gx_sql_prep(psqlite, "SELECT count(*) FROM existence");
	if (stm_select_exist == nullptr ||
	    stm_select_exist.step() != SQLITE_ROW)
		return FALSE;
	int64_t count = sqlite3_column_int64(stm_select_exist, 0);
	stm_select_exist.finalize();
	pgiven_mids->count = 0;
	if (count <= 0) {
		pgiven_mids->pids = NULL;
	} else {
		pgiven_mids->pids = cu_alloc<uint64_t>(count);
		if (pgiven_mids->pids == nullptr)
			return FALSE;
		auto stm_select_ex = gx_sql_prep(psqlite, "SELECT message_id"
		                     " FROM existence ORDER BY message_id DESC");
		if (stm_select_ex == nullptr)
			return FALSE;
		while (stm_select_ex.step() == SQLITE_ROW) {
			uint64_t mid_val = sqlite3_column_int64(stm_select_ex, 0);
			pgiven_mids->pids[pgiven_mids->count++] = rop_util_make_eid_ex(1, mid_val);
		}
	}
	} /* section 4 */

	/* Query section 5 - Determine MIDs for unread and read sets */
	if (NULL != pread) {
		auto stm_select_rd = gx_sql_prep(psqlite, "SELECT count(*) FROM reads");
		if (stm_select_rd == nullptr ||
		    stm_select_rd.step() != SQLITE_ROW)
			return FALSE;
		uint64_t count = sqlite3_column_int64(stm_select_rd, 0);
		stm_select_rd.finalize();
		pread_mids->count = 0;
		punread_mids->count = 0;
		if (count <= 0) {
			pread_mids->pids = NULL;
			punread_mids->pids = NULL;
		} else {
			pread_mids->pids = cu_alloc<uint64_t>(count);
			if (pread_mids->pids == nullptr)
				return FALSE;
			punread_mids->pids = cu_alloc<uint64_t>(count);
			if (punread_mids->pids == nullptr)
				return FALSE;
			stm_select_rd = gx_sql_prep(psqlite,
					"SELECT message_id, read_state FROM reads");
			if (stm_select_rd == nullptr)
				return FALSE;
			while (stm_select_rd.step() == SQLITE_ROW) {
				uint64_t mid_val = sqlite3_column_int64(stm_select_rd, 0);
				if (punread_mids->count == count ||
				    pread_mids->count == count)
					/*
					 * This thread is holding the DB. There can't really be a
					 * discrepance between SELECT COUNT(*) and the subsequent
					 * SELECT. But check for it anyway to appease static checkers.
					 */
					break;
				if (sqlite3_column_int64(stm_select_rd, 1) == 0)
					punread_mids->pids[punread_mids->count++] = rop_util_make_eid_ex(1, mid_val);
				else
					pread_mids->pids[pread_mids->count++] = rop_util_make_eid_ex(1, mid_val);
			}
		}
	} else {
		pread_mids->count = 0;
		pread_mids->pids = NULL;
		punread_mids->count = 0;
		punread_mids->pids = NULL;
	} /* section 5 */

	if (g_exmdb_ics_log_file.empty())
		return TRUE;
	std::lock_guard lk(ics_log_mtx);
	std::unique_ptr<FILE, file_deleter> fh;
	if (g_exmdb_ics_log_file != "-")
		fh.reset(fopen(g_exmdb_ics_log_file.c_str(), "a"));
	if (fh == nullptr)
		return TRUE;
	fprintf(fh.get(), "-------------\n");
	fprintf(fh.get(), "dir=%s actor=%s CONTENT_SYNC folder_id=%llxh given=",
		dir, znul(username), static_cast<unsigned long long>(folder_id));
	pgiven->dump(fh.get());
	fprintf(fh.get(), " read=");
	pread->dump(fh.get());
	fprintf(fh.get(), " rst=");
	if (prestriction != nullptr)
		fprintf(fh.get(), "%s", prestriction->repr().c_str());
	fprintf(fh.get(), " Out: Msg+FAI=%u+%u upd[%u]={",
		*pnormal_count, *pfai_count, pupdated_mids->count);
	for (unsigned long long mid : *pupdated_mids)
		fprintf(fh.get(), "%llxh,", mid);
	fprintf(fh.get(), "}\nchg[%u]={", pchg_mids->count);
	for (unsigned long long mid : *pchg_mids)
		fprintf(fh.get(), "%llxh,", mid);
	fprintf(fh.get(), "}\ngiven[%u]={", pgiven_mids->count);
	for (unsigned long long mid : *pgiven_mids)
		fprintf(fh.get(), "%llxh,", mid);
	fprintf(fh.get(), "}\ndel[%u]={", pdeleted_mids->count);
	for (unsigned long long mid : *pdeleted_mids)
		fprintf(fh.get(), "%llxh,", mid);
	fprintf(fh.get(), "}\nnolonger[%u]={", pnolonger_mids->count);
	for (unsigned long long mid : *pnolonger_mids)
		fprintf(fh.get(), "%llxh,", mid);
	fprintf(fh.get(), "}\nlastcn=%llxh\n", static_cast<unsigned long long>(*plast_cn));
	return TRUE;
}

static void ics_enum_hierarchy_idset(void *vparam, uint64_t folder_id)
{
	auto pparam = static_cast<ENUM_PARAM *>(vparam);
	uint16_t replid;
	uint64_t fid_val;
	
	if (!pparam->b_result)
		return;
	replid = rop_util_get_replid(folder_id);
	fid_val = rop_util_get_gc_value(folder_id);
	if (replid != 1)
		fid_val |= ((uint64_t)replid) << 48;
	sqlite3_reset(pparam->stm_exist);
	sqlite3_bind_int64(pparam->stm_exist, 1, fid_val);
	if (pparam->stm_exist.step() == SQLITE_ROW)
		return;
	if (!eid_array_append(pparam->pdeleted_eids, folder_id))
		pparam->b_result = FALSE;
}

static void ics_enum_hierarchy_replist(void *vpar, uint16_t replid)
{
	auto preplids = static_cast<REPLID_ARRAY *>(vpar);
	if (preplids->count < 1024)
		preplids->replids[preplids->count++] = replid;
}

/**
 * @username:   Used for permission checking and retrieving public store readstates
 */
static BOOL ics_load_folder_changes(sqlite3 *psqlite, uint64_t folder_id,
    const char *username, const idset *pgiven, const idset *pseen,
    sqlite3_stmt *pstmt, sqlite3_stmt *stm_insert_chg,
    sqlite3_stmt *stm_insert_exist, uint64_t *plast_cn) try
{
	uint64_t change_num;
	uint32_t permission;
	std::vector<eid_t> recurse_list;
	
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, folder_id);
	while (gx_sql_step(pstmt) == SQLITE_ROW) {
		uint64_t fid_val = sqlite3_column_int64(pstmt, 0);
		change_num = sqlite3_column_int64(pstmt, 1);
		if (username != STORE_OWNER_GRANTED) {
			if (!cu_get_folder_permission(psqlite,
			    fid_val, username, &permission))
				return FALSE;
			if (!(permission & (frightsReadAny | frightsVisible | frightsOwner)))
				continue;
		}
		recurse_list.push_back(fid_val);
		sqlite3_reset(stm_insert_exist);
		sqlite3_bind_int64(stm_insert_exist, 1, fid_val);
		if (gx_sql_step(stm_insert_exist) != SQLITE_DONE)
			return FALSE;
		if (change_num > *plast_cn)
			*plast_cn = change_num;
		if (pgiven->contains(rop_util_make_eid_ex(1, fid_val)) &&
		    pseen->contains(rop_util_make_eid_ex(1, change_num)))
			continue;
		sqlite3_reset(stm_insert_chg);
		sqlite3_bind_int64(stm_insert_chg, 1, fid_val);
		if (gx_sql_step(stm_insert_chg) != SQLITE_DONE)
			return FALSE;
	}
	for (auto fid_val : recurse_list)
		if (!ics_load_folder_changes(psqlite, fid_val, username, pgiven,
		    pseen, pstmt, stm_insert_chg, stm_insert_exist, plast_cn))
			return FALSE;	
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1141: ENOMEM");
	return false;
}

/**
 * @username:   Passed through to ics_load_folder_changes(), see there
 */
BOOL exmdb_server::get_hierarchy_sync(const char *dir,
    uint64_t folder_id, const char *username, const idset *pgiven,
    const idset *pseen, FOLDER_CHANGES *pfldchgs, uint64_t *plast_cn,
	EID_ARRAY *pgiven_fids, EID_ARRAY *pdeleted_fids)
{
	sqlite3 *psqlite;
	
	/* Setup of scratch space db */
	if (sqlite3_open_v2(":memory:", &psqlite,
	    SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK)
		return FALSE;
	auto cl_0 = HX::make_scope_exit([&]() { sqlite3_close(psqlite); });
	if (gx_sql_exec(psqlite, "CREATE TABLE existence "
	    "(folder_id INTEGER PRIMARY KEY)") != SQLITE_OK)
		return FALSE;
	if (gx_sql_exec(psqlite, "CREATE TABLE changes "
	    "(idx INTEGER PRIMARY KEY AUTOINCREMENT,"
	    " folder_id INTEGER UNIQUE NOT NULL)") != SQLITE_OK)
		return FALSE;
	auto fid_val = rop_util_get_gc_value(folder_id);
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	auto sql_transact2 = gx_sql_begin(pdb->psqlite, txn_mode::read);
	if (!sql_transact2)
		return false;

	/* Query section 1 */
	{
	auto stm_select_fld = gx_sql_prep(pdb->psqlite,
	                      "SELECT folder_id, change_number FROM folders WHERE parent_id=? AND is_deleted=0");
	if (stm_select_fld == nullptr)
		return FALSE;
	auto sql_transact = gx_sql_begin(psqlite, txn_mode::write);
	if (!sql_transact)
		return false;
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
	if (*plast_cn != 0)
		*plast_cn = rop_util_make_eid_ex(1, *plast_cn);
	if (sql_transact.commit() != SQLITE_OK)
		return false;
	} /* section 1 */

	/* Query section 2 */
	{
	auto stm_select_chg = gx_sql_prep(psqlite, "SELECT count(*) FROM changes");
	if (stm_select_chg == nullptr || stm_select_chg.step() != SQLITE_ROW)
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
	auto stm_select_chg = gx_sql_prep(psqlite,
	                      "SELECT folder_id FROM changes ORDER BY idx ASC");
	if (stm_select_chg == nullptr)
		return FALSE;
	for (size_t i = 0; i < pfldchgs->count; ++i) {
		if (stm_select_chg.step() != SQLITE_ROW)
			return FALSE;
		auto fid_val1 = sqlite3_column_int64(stm_select_chg, 0);
		PROPTAG_ARRAY proptags;
		std::vector<uint32_t> tags;
		if (!cu_get_proptags(MAPI_FOLDER, fid_val1,
		    pdb->psqlite, tags))
			return FALSE;
		tags.erase(std::remove_if(tags.begin(), tags.end(), [](uint32_t t) {
			return t == PR_HAS_RULES || t == PidTagChangeNumber ||
			       t == PR_LOCAL_COMMIT_TIME || t == PR_DELETED_COUNT_TOTAL ||
			       t == PR_NORMAL_MESSAGE_SIZE || t == PR_LOCAL_COMMIT_TIME_MAX ||
			       t == PR_HIERARCHY_CHANGE_NUM;
		}), tags.end());
		tags.push_back(PidTagParentFolderId);
		proptags.count = tags.size();
		proptags.pproptag = tags.data();
		if (!cu_get_properties(MAPI_FOLDER, fid_val1, CP_ACP,
		    pdb->psqlite, &proptags, &pfldchgs->pfldchgs[i]))
			return FALSE;
	}
	stm_select_chg.finalize();
	} /* section 3 */

	sql_transact2 = xtransaction();
	pdb.reset();

	/* Query section 4 */
	{
	auto stm_select_exist = gx_sql_prep(psqlite, "SELECT count(*) FROM existence");
	if (stm_select_exist == nullptr ||
	    stm_select_exist.step() != SQLITE_ROW)
		return FALSE;
	ssize_t count = sqlite3_column_int64(stm_select_exist, 0);
	stm_select_exist.finalize();
	pgiven_fids->count = 0;
	if (count <= 0) {
		pgiven_fids->pids = NULL;
	} else {
		pgiven_fids->pids = cu_alloc<uint64_t>(count);
		if (pgiven_fids->pids == nullptr)
			return FALSE;
		auto stm_select_ex = gx_sql_prep(psqlite, "SELECT folder_id"
		                     " FROM existence ORDER BY folder_id DESC");
		if (stm_select_ex == nullptr)
			return FALSE;
		while (stm_select_ex.step() == SQLITE_ROW) {
			uint64_t fv = sqlite3_column_int64(stm_select_ex, 0);
			pgiven_fids->pids[pgiven_fids->count++] =
				(fv & NFID_UPPER_PART) == 0 ?
				rop_util_make_eid_ex(1, fv) :
				rop_util_make_eid_ex(fv >> 48, fv & NFID_LOWER_PART);
		}
	}
	} /* section 4 */

	/* Query section 5 */
	{
	REPLID_ARRAY replids;
	replids.count = 0;
	const_cast<idset *>(pgiven)->enum_replist(&replids, ics_enum_hierarchy_replist);
	ENUM_PARAM enum_param;
	enum_param.stm_exist = gx_sql_prep(psqlite, "SELECT folder_id"
	                       " FROM existence WHERE folder_id=?");
	if (enum_param.stm_exist == nullptr)
		return FALSE;
	enum_param.b_result = TRUE;
	enum_param.pdeleted_eids = eid_array_init();
	if (enum_param.pdeleted_eids == nullptr)
		return FALSE;
	for (size_t i = 0; i < replids.count; ++i)
		if (!const_cast<idset *>(pgiven)->enum_repl(replids.replids[i],
		    &enum_param, ics_enum_hierarchy_idset))
			return FALSE;	

	pdeleted_fids->count = enum_param.pdeleted_eids->count;
	pdeleted_fids->pids = cu_alloc<uint64_t>(pdeleted_fids->count);
	if (NULL == pdeleted_fids->pids) {
		pdeleted_fids->count = 0;
		return FALSE;
	}
	memcpy(pdeleted_fids->pids,
		enum_param.pdeleted_eids->pids,
		sizeof(uint64_t)*pdeleted_fids->count);
	} /* section 5 */

	if (g_exmdb_ics_log_file.empty())
		return TRUE;
	std::lock_guard lk(ics_log_mtx);
	std::unique_ptr<FILE, file_deleter> fh;
	if (g_exmdb_ics_log_file != "-")
		fh.reset(fopen(g_exmdb_ics_log_file.c_str(), "a"));
	if (fh == nullptr)
		return TRUE;
	fprintf(fh.get(), "-------------\n");
	fprintf(fh.get(), "* dir=%s actor=%s HIER_SYNC folder_id=%llxh given=",
		dir, znul(username), static_cast<unsigned long long>(folder_id));
	pgiven->dump(fh.get());
	fprintf(fh.get(), " Out: given={");
	for (unsigned long long fid : *pgiven_fids)
		fprintf(fh.get(), "%llxh,", fid);
	fprintf(fh.get(), "}\ndel={");
	for (unsigned long long fid : *pdeleted_fids)
		fprintf(fh.get(), "%llxh,", fid);
	fprintf(fh.get(), "}\nlastcn=%llxh\n", static_cast<unsigned long long>(*plast_cn));
	return TRUE;
}
