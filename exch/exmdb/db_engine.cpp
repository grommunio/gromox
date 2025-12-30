// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cassert>
#include <chrono>
#include <climits>
#include <compare>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <future>
#include <list>
#include <mutex>
#include <optional>
#include <pthread.h>
#include <semaphore>
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <fmt/core.h>
#include <sys/stat.h>
#include <libHX/scope.hpp>
#include <gromox/atomic.hpp>
#include <gromox/clock.hpp>
#include <gromox/database.h>
#include <gromox/dbop.h>
#include <gromox/double_list.hpp>
#include <gromox/eid_array.hpp>
#include <gromox/fileio.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/process.hpp>
#include <gromox/proptag_array.hpp>
#include <gromox/propval.hpp>
#include <gromox/restriction.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/sortorder_set.hpp>
#include <gromox/util.hpp>
#include <gromox/fileio.h>
#include "db_engine.hpp"
#include "notification_agent.hpp"
#define MAX_DYNAMIC_NODES				100

using LLD = long long;
using LLU = unsigned long long;
using GCV_ARRAY = LONGLONG_ARRAY;
using namespace gromox;

struct db_close {
	void operator()(sqlite3 *x) const;
};

namespace {

struct POPULATING_NODE {
	POPULATING_NODE() = default;
	~POPULATING_NODE();
	NOMOVE(POPULATING_NODE);

	std::string dir;
	uint64_t folder_id = 0;
	cpid_t cpid = CP_ACP;
	BOOL b_recursive = false;
	RESTRICTION *prestriction = nullptr;
	std::vector<uint64_t> scope_list;
};

struct rowinfo_node {
	bool b_added = false;
	uint64_t row_id = 0;
};

struct rowdel_node {
	uint64_t row_id = 0;
	int64_t prev_id = 0;
	uint64_t inst_id = 0, parent_id = 0;
	uint32_t depth, inst_num = 0, idx = 0;
	bool b_read = false;
};

}

static size_t g_table_size; /* hash table size */
static unsigned int g_threads_num;
static gromox::atomic_bool g_dbeng_stop; /* stop signal for scanning thread */
static pthread_t g_scan_tid;
static gromox::time_duration g_cache_interval; /* maximum living interval in table */
static std::vector<pthread_t> g_thread_ids;
static std::mutex g_list_lock, g_hash_lock, g_maint_lock;
static std::condition_variable g_waken_cond, g_maint_cv, g_maint_ref_cv;
static std::unordered_map<std::string, db_base> g_hash_table; /* protected by g_hash_lock */
static std::unordered_map<std::string, db_maint_mode> g_maint_table; /* protected by g_maint_lock */
/* List of queued searchcriteria, and list of searchcriteria evaluated right now */
static std::list<POPULATING_NODE> g_populating_list, g_populating_list_active;
static std::optional<std::counting_semaphore<>> g_autoupg_limiter;
unsigned int g_exmdb_schema_upgrades, g_exmdb_search_pacing;
unsigned long long g_exmdb_search_pacing_time = 2000000000;
unsigned int g_exmdb_search_yield, g_exmdb_search_nice;
unsigned int g_exmdb_pvt_folder_softdel, g_exmdb_max_sqlite_spares;
unsigned long long g_sqlite_busy_timeout_ns;
std::string exmdb_eph_prefix;

static bool remove_from_hash(const db_base &, time_point);
static void dbeng_notify_cttbl_modify_row(db_conn &, uint64_t folder_id, uint64_t message_id, db_base &, db_conn::NOTIFQ &);

static void db_engine_load_dynamic_list(db_base *dbase, sqlite3* psqlite) try
{
	EXT_PULL ext_pull;
	char sql_string[256];
	uint32_t search_flags;
	RESTRICTION tmp_restriction;
	
	snprintf(sql_string, std::size(sql_string), "SELECT folder_id,"
		" search_flags, search_criteria FROM folders"
		" WHERE is_search=1");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return;
	while (pstmt.step() == SQLITE_ROW) {
		if (dbase->dynamic_list.size() >= MAX_DYNAMIC_NODES)
			break;
		search_flags = sqlite3_column_int64(pstmt, 1);
		if (search_flags == 0 || (search_flags & (STATIC_SEARCH | STOP_SEARCH)))
			continue;
		dynamic_node dn, *pdynamic = &dn;
		pdynamic->folder_id = sqlite3_column_int64(pstmt, 0);
		pdynamic->search_flags = search_flags;
		ext_pull.init(sqlite3_column_blob(pstmt, 2),
			sqlite3_column_bytes(pstmt, 2), common_util_alloc, 0);
		if (ext_pull.g_restriction(&tmp_restriction) != pack_result::ok)
			continue;
		pdynamic->prestriction = tmp_restriction.dup();
		if (pdynamic->prestriction == nullptr)
			break;
		if (!cu_load_search_scopes(psqlite,
		    pdynamic->folder_id, dn.scope_list))
			continue;
		dbase->dynamic_list.push_back(std::move(dn));
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

static int db_engine_autoupgrade(sqlite3 *db, const char *filedesc)
{
	if (g_exmdb_schema_upgrades == EXMDB_UPGRADE_NO)
		return 0;
	auto is_pvt = exmdb_server::is_private();
	auto kind = is_pvt ? sqlite_kind::pvt : sqlite_kind::pub;
	auto recent = dbop_sqlite_recentversion(kind);
	auto current = dbop_sqlite_schemaversion(db, kind);
	if (current < 0) {
		mlog(LV_ERR, "dbop_sqlite upgrade %s: impossible to determine schemaversion", filedesc);
		return -1;
	}
	if (current >= recent)
		return 0;

	/*
	 * db_engine is prone to starting way too many threads. Until that is
	 * fixed, here is a limiter over a cpu-intensive operation as a
	 * workaround.
	 */
	g_autoupg_limiter->acquire();
	auto cl_0 = HX::make_scope_exit([]() { g_autoupg_limiter->release(); });

	auto c = is_pvt ? 'V' : 'B';
	mlog(LV_NOTICE, "dbop_sqlite: %s: current schema E%c-%d; upgrading to E%c-%d.",
		filedesc, c, current, c, recent);
	auto start = tp_now();
	auto ret = dbop_sqlite_upgrade(db, filedesc, kind, DBOP_VERBOSE);
	if (ret != 0) {
		mlog(LV_ERR, "dbop_sqlite upgrade %s: %s",
		        filedesc, strerror(-ret));
		return -1;
	}
	auto d1 = tp_now() - start;
	auto d2 = std::chrono::duration<double>(d1).count();
	mlog(LV_NOTICE, "dbop_sqlite: Completed upgrade of %s in %.2fs.",
	        filedesc, d2);
	return 0;
}

bool db_engine_set_maint(const char *path, enum db_maint_mode mode) try
{
	if (mode == db_maint_mode::usable) {
		std::lock_guard mhold(g_maint_lock);
		g_maint_table.erase(path);
		g_maint_cv.notify_all();
		mlog(LV_INFO, "I-2510: Mailbox %s set to maintenance mode %u",
			path, static_cast<unsigned int>(mode));
		return true;
	}
	bool wait = false;
	if (mode == db_maint_mode::hold_waitforexcl) {
		wait = true;
		mode = db_maint_mode::hold;
	} else if (mode == db_maint_mode::reject_waitforexcl) {
		wait = true;
		mode = db_maint_mode::reject;
	}

	{
		std::lock_guard mhold(g_maint_lock);
		g_maint_table.try_emplace(path).first->second = mode;
	}
	g_maint_cv.notify_all();
	mlog(LV_INFO, "I-2510: Mailbox %s set to maintenance mode %u",
		path, static_cast<unsigned int>(mode));
	if (!wait)
		return true;
	std::unique_lock hhold(g_hash_lock);
	g_maint_ref_cv.wait(hhold, [&]() {
		auto it = g_hash_table.find(path);
		return it == g_hash_table.end() || it->second.reference == 0;
	});
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

/**
 * Query or create db_conn in hash table.
 *
 * Iff this function returns a non-null pointer, then pdb->psqlite and
 * pdb->m_sqlite_eph are also guaranteed to be viable.
 */
db_conn_ptr db_engine_get_db(const char *path)
{
	if (*path == '\0')
		return std::nullopt;

	{
		std::unique_lock mhold(g_maint_lock);
		g_maint_cv.wait(mhold, [&]() {
			auto i = g_maint_table.find(path);
			return i == g_maint_table.cend() || i->second != db_maint_mode::hold;
		});
		auto m_iter = g_maint_table.find(path);
		if (m_iter != g_maint_table.cend() && m_iter->second == db_maint_mode::reject)
			return std::nullopt;
	}

	db_base *pdb;
	std::unique_lock hhold(g_hash_lock);
	auto it = g_hash_table.find(path);
	if (it != g_hash_table.end()) {
		pdb = &it->second;
		db_conn_ptr conn(*pdb);
		hhold.unlock();
		if (!conn->open(path))
			return std::nullopt;
		return conn;
	}
	if (g_hash_table.size() >= g_table_size) {
		hhold.unlock();
		mlog(LV_ERR, "E-1297: Reached the maximum number of concurrently active users/mailboxes (exmdb_provider.cfg:table_size=%zu)", g_table_size);
		return std::nullopt;
	}
	try {
		auto xp = g_hash_table.try_emplace(path);
		pdb = &xp.first->second;
	} catch (const std::bad_alloc &) {
		hhold.unlock();
		mlog(LV_ERR, "E-1296: ENOMEM");
		return std::nullopt;
	}

	/*
	 * Release central map lock (g_hash_lock) early to unblock map read
	 * access looking for DBs of other dirs. Other threads can now see this
	 * db_base instance. If ctor2_and_open has not completed yet, those
	 * other threads will be waiting on sqlite_lock and thus be safely
	 * serialized.
	 */
	hhold.unlock();
	try {
		pdb->ctor2_and_open(path);
	} catch (const std::runtime_error& err) {
		mlog(LV_ERR, "%s", err.what());
		return std::nullopt;
	}

	db_conn_ptr conn(*pdb);
	if (!conn->open(path))
		return std::nullopt;
	return conn;
}

BOOL db_engine_vacuum(const char *path)
{
	auto db = db_engine_get_db(path);
	if (!db)
		return false;
	mlog(LV_INFO, "I-2067: Vacuuming %s (exchange.sqlite3)", path);
	if (gx_sql_exec(db->psqlite, "VACUUM") != SQLITE_OK)
		return false;
	mlog(LV_INFO, "I-2102: Vacuuming %s ended", path);
	return TRUE;
}

BOOL db_engine_unload_db(const char *path)
{
	for (unsigned int i = 0; i < 20; ++i) {
		std::unique_lock hhold(g_hash_lock);
		auto it = g_hash_table.find(path);
		if (it == g_hash_table.end())
			return TRUE;
		auto now = tp_now();
		auto &dbase = it->second;
		std::unique_lock dhold(dbase.giant_lock);
		if (remove_from_hash(dbase, now + g_cache_interval)) {
			g_hash_table.erase(it);
			return TRUE;
		}
		dhold.unlock();
		hhold.unlock();
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	return FALSE;
}

/**
 * @db:      sqlite handle
 * @last_cn: counter for most recently assigned CN (GCV)
 * @q_list:  query for obtaining some objects
 *           (shall return 2 columns; id and eligibility)
 * @q_cn:    query for updating per-object CN
 * @q_prop:  query for updating per-object CK & PCL
 *
 * Iterate over an object set and assign new Change Numbers, Change Keys and
 * Predecessor Change Lists.
 */
static bool cgkreset_3(sqlite3 *db, uint64_t &last_cn, const GUID &store_guid,
    const char *q_list, const char *q_cn, const char *q_prop)
{
	std::vector<std::pair<uint64_t, uint64_t>> gcv_list;
	auto stm = gx_sql_prep(db, q_list);
	if (stm == nullptr)
		return false;
	while (stm.step() == SQLITE_ROW)
		gcv_list.emplace_back(stm.col_uint64(0), stm.col_uint64(1));
	stm = gx_sql_prep(db, q_cn);
	if (stm == nullptr)
		return false;
	auto stm_prop = gx_sql_prep(db, q_prop);
	if (stm_prop == nullptr)
		return false;

	for (auto [objid, parent_attid] : gcv_list) {
		auto next_cn = last_cn + 1;
		stm.reset();
		stm.bind_int64(1, next_cn);
		stm.bind_int64(2, objid);
		if (stm.step() != SQLITE_DONE)
			return false;
		++last_cn;
		if (parent_attid != 0)
			/* CK/PCL on attachments makes no sense */
			continue;

		char buf[23];
		XID xid{store_guid, rop_util_make_eid_ex(1, last_cn)};
		EXT_PUSH ep;
		if (!ep.init(&buf[1], sizeof(buf) - 1, 0))
			return false;
		ep.p_xid(xid);
		stm_prop.reset();
		stm_prop.bind_blob(1, &buf[1], ep.m_offset);
		stm_prop.bind_int64(2, objid);
		stm_prop.bind_int64(3, PR_CHANGE_KEY);
		if (stm_prop.step() != SQLITE_DONE)
			return false;

		stm_prop.reset();
		buf[0] = 22;
		stm_prop.bind_blob(1, buf, 23);
		stm_prop.bind_int64(2, objid);
		stm_prop.bind_int64(3, PR_PREDECESSOR_CHANGE_LIST);
		if (stm_prop.step() != SQLITE_DONE)
			return false;
	}
	return true;
}

static bool cgkreset_2(sqlite3 *db, uint64_t &last_cn, const GUID &store_guid,
    unsigned int flags)
{
	if (flags & CGKRESET_FOLDERS) {
		auto succ = cgkreset_3(db, last_cn, store_guid,
		            "SELECT folder_id, NULL FROM folders",
		            "UPDATE folders SET change_number=? WHERE folder_id=?",
		            "UPDATE folder_properties SET propval=? WHERE folder_id=? AND proptag=?");
		if (!succ)
			return false;
	}
	if (flags & CGKRESET_MESSAGES) {
		auto succ = cgkreset_3(db, last_cn, store_guid,
		            "SELECT message_id, parent_attid FROM messages",
		            "UPDATE messages SET change_number=? WHERE message_id=?",
		            "UPDATE message_properties SET propval=? WHERE message_id=? AND proptag=?");
		if (!succ)
			return false;
	}
	return true;
}

/**
 * Obtain essential parameters for a global CN/CK reassignment. In doing so, it
 * performs the first sanity check and returns a bumped last_cn if necessary.
 */
static bool cgkreset_load_param(sqlite3 *db, uint64_t &last_cn, GUID &store_guid)
{
	auto stm = gx_sql_prep(db, "SELECT config_value FROM configurations WHERE config_id=?");
	if (stm == nullptr)
		return false;
	stm.bind_int64(1, CONFIG_ID_MAILBOX_GUID);
	if (stm.step() != SQLITE_ROW)
		return false;
	if (!store_guid.from_str(stm.col_text(0)))
		return false;
	stm.reset();
	stm.bind_int64(1, CONFIG_ID_LAST_CHANGE_NUMBER);
	if (stm.step() != SQLITE_ROW)
		return false;
	last_cn = stm.col_uint64(0);

	stm = gx_sql_prep(db, "SELECT MAX(change_number) FROM folders");
	if (stm == nullptr)
		return false;
	if (stm.step() == SQLITE_ROW)
		last_cn = std::max(last_cn, stm.col_uint64(0));
	stm = gx_sql_prep(db, "SELECT MAX(change_number) FROM messages");
	if (stm == nullptr)
		return false;
	if (stm.step() == SQLITE_ROW)
		last_cn = std::max(last_cn, stm.col_uint64(0));
	return true;
}

static bool cgkreset_save_param(sqlite3 *db, uint64_t last_cn)
{
	auto stm = gx_sql_prep(db, "UPDATE configurations SET config_value=? WHERE config_id=?");
	if (stm == nullptr)
		return false;
	stm.bind_int64(1, last_cn);
	stm.bind_int64(2, CONFIG_ID_LAST_CHANGE_NUMBER);
	return stm.step() == SQLITE_DONE;
}

BOOL db_engine_cgkreset(const char *dir, uint32_t flags)
{
	auto db = db_engine_get_db(dir);
	if (!db)
		return false;
	auto xact = gx_sql_begin(db->psqlite, txn_mode::write);
	if (!xact)
		return false;
	uint64_t last_cn = 0;
	GUID store_guid;
	if (!cgkreset_load_param(db->psqlite, last_cn, store_guid))
		return false;
	if (flags & CGKRESET_ZERO_LASTCN)
		last_cn = 0;
	if (flags & (CGKRESET_ZERO_LASTCN | CGKRESET_FOLDERS | CGKRESET_MESSAGES)) {
		auto succ = cgkreset_2(db->psqlite, last_cn, store_guid, flags);
		if (!succ)
			return false;
	}
	auto succ = cgkreset_save_param(db->psqlite, last_cn);
	if (!succ)
		return false;
	return xact.commit() == SQLITE_OK;
}

dynamic_node::dynamic_node(dynamic_node &&o) noexcept :
	folder_id(o.folder_id), search_flags(o.search_flags),
	prestriction(o.prestriction), scope_list(std::move(o.scope_list))
{
	o.prestriction = nullptr;
}

dynamic_node::~dynamic_node()
{
	if (prestriction != nullptr)
		restriction_free(prestriction);
}

dynamic_node &dynamic_node::operator=(dynamic_node &&o) noexcept
{
	folder_id = o.folder_id;
	search_flags = o.search_flags;
	std::swap(prestriction, o.prestriction);
	scope_list = std::move(o.scope_list);
	return *this;
}

table_node::table_node(const table_node &o, clone_t) :
	table_id(o.table_id), table_flags(o.table_flags), cpid(o.cpid),
	type(o.type), cloned(true), remote_id(o.remote_id), username(o.username),
	folder_id(o.folder_id), handle_guid(o.handle_guid),
	prestriction(o.prestriction), psorts(o.psorts),
	instance_tag(o.instance_tag), extremum_tag(o.extremum_tag),
	header_id(o.header_id), b_search(o.b_search), b_hint(o.b_hint)
{}

table_node::~table_node()
{
	if (cloned)
		return;
	if (username != nullptr)
		free(username);
	if (remote_id != nullptr)
		free(remote_id);
	if (prestriction != nullptr)
		restriction_free(prestriction);
	if (psorts != nullptr)
		sortorder_set_free(psorts);
}

db_base::db_base() :
	reference(1), // is decremented when open() is run.
	last_time(tp_now())
{
	/* Prevent instantiation by db_conn until open() has completed. */
	sqlite_lock.lock();
}

/**
 * @brief      Get database handle
 *
 * @param      dir     User or domain base directory
 * @param      type    Requested database type
 *
 * @return     SQLite database handle or nullptr on error
 */
db_handle db_base::get_db(const char* dir, DB_TYPE type)
{
	auto& spares = type == DB_MAIN? mx_sqlite : mx_sqlite_eph;
	if (!spares.empty()) {
		db_handle handle = std::move(spares.back());
		spares.pop_back();
		return handle;
	}
	const auto &path = type == DB_MAIN ? fmt::format("{}/exmdb/exchange.sqlite3", dir) :
			   fmt::format("{}/{}/tables.sqlite3", exmdb_eph_prefix, dir);
	int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX;
	flags |= type == DB_MAIN? 0 : SQLITE_OPEN_CREATE;
	sqlite3 *db = nullptr;
	int ret = gx_mkbasedir(path.c_str(), FMODE_PRIVATE | S_IXUSR | S_IXGRP);
	if (ret < 0) {
		mlog(LV_ERR, "E-2710: mkbasedir %s: %s", path.c_str(), strerror(-ret));
		return nullptr;
	}
	if (access(path.c_str(), W_OK) != 0 && errno != ENOENT)
		mlog(LV_ERR, "E-1734: %s is not writable (%s), there may be more errors later",
			path.c_str(), strerror(errno));
	ret = sqlite3_open_v2(path.c_str(), &db, flags, nullptr);
	db_handle hdb(db); /* automatically close connection if something goes wrong */
	if (ret != SQLITE_OK) {
		mlog(LV_ERR, "E-1350: sqlite_open_v2(%s): %s (%d)",
			path.c_str(), sqlite3_errstr(ret), ret);
		return nullptr;
	}
	ret = gx_sql_exec(db, "PRAGMA foreign_keys=ON");
	if (ret != SQLITE_OK) {
		mlog(LV_ERR, "E-2101: enable foreign keys %s: %s (%d)", dir, sqlite3_errstr(ret), ret);
		return nullptr;
	}
	gx_sql_exec(db, "PRAGMA journal_mode=WAL");
	sqlite3_busy_timeout(db, int(g_sqlite_busy_timeout_ns / 1000000)); // ns -> ms
	if (type == DB_EPH)
		gx_sql_exec(db, "PRAGMA	synchronous=OFF"); /* completely disable disk synchronization for eph db */
	return hdb;
}

/**
 * Get cached database handles or open new ones.
 */
void db_base::get_dbs(const char* dir, sqlite3 *&main, sqlite3 *&eph)
{
	std::unique_lock lock(sqlite_lock);
	main = get_db(dir, db_base::DB_MAIN).release();
	eph  = get_db(dir, db_base::DB_EPH).release();
}

/**
 * @brief      Initialize and unlock database
 *
 * Perform one-time database operations; operations that should not be run for
 * each connection:
 *
 * - Remove residual ephemeral tables db from last process
 * - Perform schema upgrade
 *
 * @param      dir     User or domain base directory
 *
 * @throws     std::runtime_error  if any initialization step fails
 */
void db_base::ctor2_and_open(const char *dir)
{
	auto unlock = HX::make_scope_exit([this] { sqlite_lock.unlock(); --reference; }); /* unlock whenever we're done */
	auto db_path = fmt::format("{}/{}/tables.sqlite3", exmdb_eph_prefix, dir);
	auto ret = ::unlink(db_path.c_str());
	if (ret != 0 && errno != ENOENT)
		throw std::runtime_error(fmt::format("E-1351: unlink {}: {}", db_path.c_str(), strerror(errno)));

	/* We need a handle for the upgrade check... */
	db_handle hdb(get_db(dir, DB_MAIN));
	if (!hdb)
		throw std::runtime_error(fmt::format("E-1434: get_db({}) failed", dir));
	ret = db_engine_autoupgrade(hdb.get(), dir);
	if (ret != 0)
		throw std::runtime_error(fmt::format("E-2105: autoupgrade {}: {}", dir, ret));
	if (exmdb_server::is_private())
		db_engine_load_dynamic_list(this, hdb.get());

	/* ...don't let it go to waste */
	mx_sqlite.emplace_back(std::move(hdb));
}

void db_base::handle_spares(sqlite3 *main, sqlite3 *eph)
{
	static constexpr size_t unlimited = 0;
	std::unique_lock lock(sqlite_lock);
	try {
		if (eph != nullptr && g_exmdb_max_sqlite_spares != unlimited &&
		    mx_sqlite_eph.size() < g_exmdb_max_sqlite_spares) {
			mx_sqlite_eph.emplace_back(std::move(eph));
			eph = nullptr;
		}
		if (main != nullptr && g_exmdb_max_sqlite_spares != unlimited &&
		    mx_sqlite.size() < g_exmdb_max_sqlite_spares) {
			mx_sqlite.emplace_back(std::move(main));
			main = nullptr;
		}
	} catch (const std::bad_alloc &) {
	}
	lock.unlock();
	if (eph != nullptr)
		sqlite3_close(eph);
	if (main != nullptr)
		sqlite3_close(main);
}

db_conn::db_conn(db_base &base) :
	m_base(&base)
{
	++base.reference;
}

db_conn::db_conn(db_conn &&o) :
	psqlite(std::move(o.psqlite)),
	m_sqlite_eph(std::move(o.m_sqlite_eph)),
	m_base(std::move(o.m_base))
{
	o.psqlite = o.m_sqlite_eph = nullptr;
	o.m_base = nullptr;
}

db_conn::~db_conn()
{
	if (m_base == nullptr)
		return;
	m_base->handle_spares(std::move(psqlite), std::move(m_sqlite_eph));
	--m_base->reference;
	g_maint_ref_cv.notify_all();
}

db_conn &db_conn::operator=(db_conn &&o)
{
	psqlite = std::move(o.psqlite);
	m_sqlite_eph = std::move(o.m_sqlite_eph);
	o.psqlite = o.m_sqlite_eph = nullptr;
	m_base = std::move(o.m_base);
	o.m_base = nullptr;
	return *this;
}

/**
 * Create a new database connection (handle)
 *
 * Should be called exactly once after creation and before first usage.
 *
 * @dir:  Store directory
 */
bool db_conn::open(const char *dir) try
{
	m_base->get_dbs(dir, psqlite, m_sqlite_eph);
	return psqlite && m_sqlite_eph;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
}

/**
 * Get smart pointer to the shared control block,
 * ensuring that the control block is read-locked.
 */
db_base_rd_ptr db_conn::lock_base_rd() const
{
	assert(m_base != nullptr);
	m_base->giant_lock.lock_shared();
	return db_base_rd_ptr(m_base);
}

/**
 * Get smart pointer to the shared control block,
 * ensuring that the control block is write-locked.
 */
db_base_wr_ptr db_conn::lock_base_wr()
{
	assert(m_base != nullptr);
	m_base->giant_lock.lock();
	return db_base_wr_ptr(m_base);
}

db_base::~db_base()
{
	auto pdb = this;
	
	pdb->instance_list.clear();
	dynamic_list.clear();
	tables.table_list.clear();
}

void db_base::drop_all()
{
	instance_list.clear();
	dynamic_list.clear();
	tables.table_list.clear();
	mx_sqlite_eph.clear();
	mx_sqlite.clear();
}

/**
 * Check if this db_base object is ripe for deletion.
 */
static bool remove_from_hash(const db_base &pdb, time_point now)
{
	if (pdb.tables.table_list.size() > 0)
		/* emsmdb still references in-memory tables */
		return false;
	if (pdb.nsub_list.size() > 0)
		/* there is still a client wanting notifications */
		return false;
	if (pdb.reference != 0 || now - pdb.last_time <= g_cache_interval)
		return false;
	return true;
}

static void *db_expiry_thread(void *param)
{
	int count;

	count = 0;
	while (!g_dbeng_stop) {
		sleep(1);
		if (count < 10) {
			count ++;
			continue;
		}
		count = 0;
		/* Exclusive ownership over the list is needed, obviously, since we modify it */
		std::lock_guard hhold(g_hash_lock);
		auto now_time = tp_now();
		for (auto it = g_hash_table.begin(); it != g_hash_table.end(); ) {
			auto &dbase = it->second;
			/*
			 * There must be no readers nor writers if we destroy it.
			 * Hence another lock.
			 */
			std::unique_lock dhold(dbase.giant_lock);
			if (remove_from_hash(dbase, now_time))
				it = g_hash_table.erase(it);
			else
				++it;
		}
	}
	return nullptr;
}

void dg_notify(db_conn::NOTIFQ &&notifq)
{
	for (auto &&[dg, idarr] : notifq) {
		for (auto &&[remote_id, sub_ids] : idarr) {
			dg.id_array = std::move(sub_ids);
			notification_agent_backward_notify(remote_id, &dg);
		}
	}
	notifq.clear();
}

static bool db_engine_search_folder(const char *dir, cpid_t cpid,
    uint64_t search_fid, uint64_t scope_fid, const RESTRICTION *prestriction,
    db_conn &db)
{
	char sql_string[128];
	auto sql_transact = gx_sql_begin(db.psqlite, txn_mode::read); // ends before writes take place
	if (!sql_transact)
		return false;
	snprintf(sql_string, std::size(sql_string), "SELECT is_search "
	          "FROM folders WHERE folder_id=%llu", LLU{scope_fid});
	auto pstmt = db.prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW)
		return TRUE;
	if (sqlite3_column_int64(pstmt, 0) == 0)
		snprintf(sql_string, std::size(sql_string), "SELECT message_id FROM"
		          " messages WHERE parent_fid=%llu",
		          static_cast<unsigned long long>(scope_fid));
	else
		snprintf(sql_string, std::size(sql_string), "SELECT message_id FROM"
		          " search_result WHERE folder_id=%llu",
		          static_cast<unsigned long long>(scope_fid));
	pstmt.finalize();
	pstmt = db.prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	auto pmessage_ids = eid_array_init();
	if (pmessage_ids == nullptr)
		return FALSE;
	auto cl_0 = HX::make_scope_exit([&]() { eid_array_free(pmessage_ids); });
	while (pstmt.step() == SQLITE_ROW)
		if (!eid_array_append(pmessage_ids,
		    sqlite3_column_int64(pstmt, 0)))
			return FALSE;
	pstmt.finalize();
	auto t_start = tp_now();
	auto cl_1 = HX::make_scope_exit([&]() {
		auto t_end = tp_now();
		auto t_diff = std::chrono::duration<double>(t_end - t_start).count();
		if (pmessage_ids->count > 0 && t_diff >= 1)
			mlog(LV_DEBUG, "db_eng_sf: %u messages in %.2f seconds",
				pmessage_ids->count, t_diff);
	});
	sql_transact = xtransaction();
	for (size_t i = 0, count = 0; i < pmessage_ids->count; ++i, ++count) {
		if (g_dbeng_stop)
			break;
		auto sql_transact1 = gx_sql_begin(db.psqlite, txn_mode::write);
		if (!sql_transact1)
			return false;
		if (!cu_eval_msg_restriction(db,
		    cpid, pmessage_ids->pids[i], prestriction))
			continue;
		snprintf(sql_string, std::size(sql_string), "REPLACE INTO search_result "
		         "(folder_id, message_id) VALUES (%llu, %llu)",
		         LLU{search_fid}, LLU{pmessage_ids->pids[i]});
		auto ret = db.exec(sql_string, SQLEXEC_SILENT_CONSTRAINT);
		if (ret == SQLITE_CONSTRAINT)
			/*
			 * Search folder is closed (deleted) already, INSERT
			 * does not succeed, and neither will subsequent queries.
			 */
			break;
		else if (ret != SQLITE_OK)
			continue;
		if (sql_transact1.commit() != SQLITE_OK)
			return false;
		/*
		 * Update other search folders (seems like it is allowed to
		 * have a search folder have a scope containing another search
		 * folder; exmdb_provider only does a descendant check).
		 */
		db_conn::NOTIFQ notifq;
		auto dbase = db.lock_base_wr();
		db.proc_dynamic_event(cpid, dynamic_event::new_msg,
			search_fid, pmessage_ids->pids[i], 0, *dbase, notifq);
		/*
		 * Regular notifications
		 */
		db.notify_link_creation(search_fid, pmessage_ids->pids[i], *dbase, notifq);
		dg_notify(std::move(notifq));
		dbase.reset();
	}
	return TRUE;
}

static bool db_engine_load_folder_descendant(const char *dir,
    bool b_recursive, uint64_t folder_id, EID_ARRAY *pfolder_ids)
{
	char sql_string[128];
	
	auto pdb = db_engine_get_db(dir);
	if (!pdb)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "SELECT folder_id FROM "
	          "folders WHERE parent_id=%llu", LLU{folder_id});
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW)
		if (!eid_array_append(pfolder_ids,
		    sqlite3_column_int64(pstmt, 0)))
			return FALSE;
	return TRUE;
}

POPULATING_NODE::~POPULATING_NODE()
{
	restriction_free(prestriction);
}

/**
 * Construct pseudo-packets for different clients based on who is watching
 * @folder_id/@message_id. The output ID_ARRAYS is referencing db data, so
 * watch your lifetimes. (The ID_ARRAYS object must not outlive @db).
 */
static db_conn::ID_ARRAYS db_engine_classify_id_array(const db_base &db,
    unsigned int bits, uint64_t folder_id, uint64_t message_id) try
{
	db_conn::ID_ARRAYS out;
	for (const auto &sub : db.nsub_list) {
		if (!(sub.notification_type & bits))
			continue;
		if (sub.b_whole || (sub.folder_id == folder_id &&
		    sub.message_id == message_id)) {
			auto rid = sub.remote_id.has_value() ? sub.remote_id->c_str() : nullptr;
			out[rid].push_back(sub.sub_id);
		}
	}
	return out;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	throw;
}

static void dbeng_notify_search_completion(const db_base &dbase,
    uint64_t folder_id, db_conn::NOTIFQ &notifq) try
{
	DB_NOTIFY_DATAGRAM datagram;
	auto dir = exmdb_server::get_dir();
	auto parrays = db_engine_classify_id_array(dbase,
	               fnevSearchComplete, folder_id, 0);
	if (parrays.size() == 0)
		return;
	datagram.dir = deconst(dir);
	datagram.db_notify.type = db_notify_type::search_completed;
	auto psearch_completed = &datagram.db_notify.pdata.emplace<DB_NOTIFY_SEARCH_COMPLETED>();
	psearch_completed->folder_id = folder_id;
	notifq.emplace_back(std::move(datagram), std::move(parrays));
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

/**
 * Background task which is responsible for the initial filling of search
 * folders (e.g. when they are created, or the search criteria has been reset).
 */
static void *sf_popul_thread(void *param)
{
	if (nice(g_exmdb_search_nice) < 0)
		/* ignore */;
	
	while (!g_dbeng_stop) {
 NEXT_SEARCH:
		std::unique_lock lhold(g_list_lock);
		g_waken_cond.wait(lhold, []() { return g_dbeng_stop || g_populating_list.size() > 0; });
		if (g_dbeng_stop)
			break;
		if (g_populating_list.size() == 0)
			continue;
		g_populating_list_active.splice(g_populating_list_active.end(), g_populating_list, g_populating_list.begin());
		auto psearch = std::prev(g_populating_list_active.end());
		lhold.unlock();
		auto cl_0 = HX::make_scope_exit([&]() {
			lhold.lock();
			g_populating_list_active.erase(psearch);
			lhold.unlock();
		});
		auto pfolder_ids = eid_array_init(); /* Actually it's just GCVs */
		if (pfolder_ids == nullptr)
			goto NEXT_SEARCH;	
		auto cl_1 = HX::make_scope_exit([&]() { eid_array_free(pfolder_ids); });
		exmdb_server::build_env(EM_PRIVATE, psearch->dir.c_str());
		auto cl_2 = HX::make_scope_exit(exmdb_server::free_env);
		for (auto le_folder : psearch->scope_list) {
			if (!eid_array_append(pfolder_ids, le_folder))
				goto NEXT_SEARCH;	
			if (!psearch->b_recursive)
				continue;
			if (!db_engine_load_folder_descendant(psearch->dir.c_str(),
			    psearch->b_recursive, le_folder, pfolder_ids))
				goto NEXT_SEARCH;
		}
		auto pdb = db_engine_get_db(psearch->dir.c_str());
		if (!pdb)
			goto NEXT_SEARCH;
		for (size_t i = 0; i < pfolder_ids->count; ++i) {
			if (g_dbeng_stop)
				break;
			if (!db_engine_search_folder(psearch->dir.c_str(),
			    psearch->cpid, psearch->folder_id,
			    pfolder_ids->pids[i], psearch->prestriction, *pdb))
				break;
		}
		if (g_dbeng_stop)
			break;
		db_conn::NOTIFQ notifq;
		auto dbase = pdb->lock_base_wr();
		/* Stop animation (does nothing else in OL really) */
		dbeng_notify_search_completion(*dbase, psearch->folder_id, notifq);
		pdb->notify_folder_modification(common_util_get_folder_parent_fid(
			pdb->psqlite, psearch->folder_id),
			psearch->folder_id, *dbase, notifq);
		dg_notify(std::move(notifq));
		std::vector<uint32_t> table_ids;
		try {
			table_ids.reserve(dbase->tables.table_list.size());
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1649: ENOMEM");
			sleep(60);
			goto NEXT_SEARCH;
		}
		for (const auto &t : dbase->tables.table_list)
			if (t.type == table_type::content &&
			    psearch->folder_id == t.folder_id)
				table_ids.push_back(t.table_id);
		dbase.reset();
		pdb.reset();
		/*
		 * reload_ct triggers a table_change notification, and the
		 * client eventually learns of the new message count.
		 */
		while (table_ids.size() > 0) {
			exmdb_server::reload_content_table(psearch->dir.c_str(), table_ids.back());
			table_ids.pop_back();
		}
		goto NEXT_SEARCH;
	}
	return nullptr;
}

void db_engine_init(size_t table_size, int cache_interval, unsigned int threads_num)
{
	g_dbeng_stop = true;
	g_table_size = table_size;
	g_cache_interval = std::chrono::seconds{cache_interval};
	g_threads_num = threads_num;
	g_thread_ids.reserve(g_threads_num);
	g_autoupg_limiter.emplace(threads_num);
}

int db_engine_run()
{
	if (sqlite3_config(SQLITE_CONFIG_MULTITHREAD) != SQLITE_OK)
		mlog(LV_WARN, "exmdb_provider: failed to change"
			" to multiple thread mode for sqlite engine");
	if (sqlite3_config(SQLITE_CONFIG_MEMSTATUS, 0) != SQLITE_OK)
		mlog(LV_WARN, "exmdb_provider: failed to close"
			" memory statistic for sqlite engine");
	if (SQLITE_OK != sqlite3_initialize()) {
		mlog(LV_ERR, "exmdb_provider: Failed to initialize sqlite engine");
		return -2;
	}
	g_dbeng_stop = false;
	auto ret = pthread_create4(&g_scan_tid, nullptr,
	           db_expiry_thread, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "exmdb_provider: failed to create db scan thread: %s", strerror(ret));
		return -4;
	}
	pthread_setname_np(g_scan_tid, "db_expiry");
	for (unsigned int i = 0; i < g_threads_num; ++i) {
		pthread_t tid;
		ret = pthread_create4(&tid, nullptr, sf_popul_thread, nullptr);
		if (ret != 0) {
			mlog(LV_ERR, "E-1448: pthread_create: %s", strerror(ret));
			db_engine_stop();
			return -5;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "sfpop/%u", i);
		pthread_setname_np(tid, buf);
		g_thread_ids.push_back(tid);
	}
	return 0;
}

void db_engine_stop()
{
	if (!g_dbeng_stop) {
		g_dbeng_stop = true;
		g_waken_cond.notify_all();
		for (auto tid : g_thread_ids) {
			pthread_kill(tid, SIGALRM);
			pthread_join(tid, nullptr);
		}
		if (!pthread_equal(g_scan_tid, {})) {
			pthread_kill(g_scan_tid, SIGALRM);
			pthread_join(g_scan_tid, NULL);
		}
	}
	g_thread_ids.clear();
	/*
	 * This is db_engine_stop. We know we are single threaded and do not
	 * really need to hold any locks.
	 *
	 * And though we are temporarily multithreading again with std::async,
	 * it is a readonly operation as far as g_hash_table is concerned.
	 */
	{
		auto t_start = tp_now();
		size_t conc = std::min(gx_concurrency(), g_threads_num);
		std::vector<std::future<void>> futs;
		/*
		 * cov-scan may complain here about missing locks, but this is
		 * a paralellized section that only reads data structures.
		 */
		auto iter = g_hash_table.begin();
		for (size_t tid = 0; tid < conc; ++tid) {
			if (iter == g_hash_table.end())
				break;
			futs.emplace_back(std::async([](size_t tid, decltype(g_hash_table)::iterator iter, size_t skip) -> void {
				while (iter != g_hash_table.end()) {
					iter->second.drop_all();
					for (size_t i = 0; i < skip && iter != g_hash_table.end(); ++i)
						++iter;
				}
			}, tid, iter, conc));
			++iter;
		}
		futs.clear();
		/* Single-threaded write section */
		g_hash_table.clear();
		mlog(LV_INFO, "Database shutdown took %llu ms",
			LLU(std::chrono::duration_cast<std::chrono::milliseconds>(tp_now() - t_start).count()));
	}
	{
		std::lock_guard lk(g_list_lock);
		g_populating_list.clear();
	}
	sqlite3_shutdown();
}

bool db_engine_enqueue_populating_criteria(const char *dir, cpid_t cpid,
    uint64_t folder_id, bool b_recursive, const RESTRICTION *prestriction,
    std::vector<uint64_t> &&scope_list) try
{
	std::list<POPULATING_NODE> holder;
	holder.emplace_back();
	auto psearch = &holder.back();
	psearch->dir = dir;
	psearch->prestriction = prestriction->dup();
	if (psearch->prestriction == nullptr)
		return FALSE;
	psearch->scope_list = std::move(scope_list);
	psearch->cpid = cpid;
	psearch->folder_id = folder_id;
	psearch->b_recursive = b_recursive;
	std::unique_lock lhold(g_list_lock);
	g_populating_list.splice(g_populating_list.end(), std::move(holder));
	lhold.unlock();
	g_waken_cond.notify_one();
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

bool db_engine_check_populating(const char *dir, uint64_t folder_id)
{
	std::lock_guard lhold(g_list_lock);
	for (const auto &e : g_populating_list)
		if (e.dir == dir && e.folder_id == folder_id)
			return true;
	for (const auto &e : g_populating_list_active)
		if (e.dir == dir && e.folder_id == folder_id)
			return true;
	return false;
}

void db_conn::update_dynamic(uint64_t folder_id, uint32_t search_flags,
    const RESTRICTION *prestriction, const std::vector<uint64_t> &scope_list,
    db_base &dbase) try
{
	dynamic_node dn;
	
	dn.folder_id    = folder_id;
	dn.search_flags = search_flags;
	dn.prestriction = prestriction->dup();
	if (dn.prestriction == nullptr)
		return;
	dn.scope_list = scope_list;
	auto i = std::find_if(dbase.dynamic_list.begin(), dbase.dynamic_list.end(),
	         [=](const dynamic_node &n) { return n.folder_id == folder_id; });
	if (i == dbase.dynamic_list.end())
		dbase.dynamic_list.push_back(std::move(dn));
	else
		*i = std::move(dn);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

void db_conn::delete_dynamic(uint64_t folder_id, db_base *dbase)
{
	gromox::erase_first_if(dbase->dynamic_list,
		[=](const dynamic_node &n) { return n.folder_id == folder_id; });
}

static void dbeng_dynevt_1(db_conn &db, cpid_t cpid, uint64_t id1,
    uint64_t id2, uint64_t id3, uint32_t folder_type,
    const dynamic_node *pdynamic, size_t i, db_base &dbase, db_conn::NOTIFQ &notifq)
{
	auto pdb = &db;
	BOOL b_exist, b_included, b_included1;
	uint64_t message_id;
	char sql_string[128];

	if (!(pdynamic->search_flags & RECURSIVE_SEARCH))
		return;

	if (!cu_is_descendant_folder(pdb->psqlite,
	    id1, pdynamic->scope_list[i], &b_included) ||
	    !cu_is_descendant_folder(pdb->psqlite,
	    id2, pdynamic->scope_list[i], &b_included1)) {
		mlog(LV_DEBUG, "db_engine: fatal error in %s", __PRETTY_FUNCTION__);
		return;
	}
	if (b_included == b_included1)
		return;
	snprintf(sql_string, std::size(sql_string), folder_type == FOLDER_SEARCH ?
		 "SELECT message_id FROM search_result WHERE folder_id=%llu" :
		 "SELECT message_id FROM messages WHERE parent_fid=%llu", LLU{id3});
	auto pstmt = pdb->prep(sql_string);
	if (pstmt == nullptr)
		return;
	while (pstmt.step() == SQLITE_ROW) {
		message_id = sqlite3_column_int64(pstmt, 0);
		if (!common_util_check_search_result(pdb->psqlite,
		    pdynamic->folder_id, message_id, &b_exist)) {
			mlog(LV_DEBUG, "db_engine: failed to check item in search_result");
			return;
		}
		if (b_included != b_exist)
			return;
		if (b_included) {
			pdb->notify_link_deletion(pdynamic->folder_id, message_id, dbase, notifq);
			pdb->proc_dynamic_event(cpid, dynamic_event::del_msg,
				pdynamic->folder_id, message_id, 0, dbase, notifq);
			snprintf(sql_string, std::size(sql_string), "DELETE FROM search_result "
				"WHERE folder_id=%llu AND message_id=%llu",
				LLU{pdynamic->folder_id}, LLU{message_id});
			if (pdb->exec(sql_string) != SQLITE_OK)
				mlog(LV_DEBUG, "db_engine: failed to delete from search_result");
			continue;
		}
		if (!cu_eval_msg_restriction(db,
		    cpid, message_id, pdynamic->prestriction))
			return;
		snprintf(sql_string, std::size(sql_string), "INSERT INTO search_result "
			"(folder_id, message_id) VALUES (%llu, %llu)",
			LLU{pdynamic->folder_id}, LLU{message_id});
		if (pdb->exec(sql_string) == SQLITE_OK) {
			pdb->notify_link_creation(pdynamic->folder_id, message_id, dbase, notifq);
			pdb->proc_dynamic_event(cpid, dynamic_event::new_msg,
				pdynamic->folder_id, message_id, 0, dbase, notifq);
		}
	}
}

static void dbeng_dynevt_2(db_conn &db, cpid_t cpid, dynamic_event event_type,
    uint64_t id1, uint64_t id2, const dynamic_node *pdynamic, size_t i,
    db_base &dbase, db_conn::NOTIFQ &notifq)
{
	auto pdb = &db;
	BOOL b_exist;
	BOOL b_included;
	char sql_string[128];

	if (pdynamic->search_flags & RECURSIVE_SEARCH) {
		if (!cu_is_descendant_folder(pdb->psqlite,
		    id1, pdynamic->scope_list[i], &b_included)) {
			mlog(LV_DEBUG, "db_engine: fatal error in %s", __PRETTY_FUNCTION__);
			return;
		}
		if (!b_included)
			return;
	} else {
		if (id1 != pdynamic->scope_list[i])
			return;
	}
	switch (event_type) {
	case dynamic_event::new_msg:
		if (!common_util_check_search_result(pdb->psqlite,
		    pdynamic->folder_id, id2, &b_exist)) {
			mlog(LV_DEBUG, "db_engine: failed to check item in search_result");
			return;
		}
		if (b_exist)
			return;
		if (!cu_eval_msg_restriction(db,
		    cpid, id2, pdynamic->prestriction))
			return;
		snprintf(sql_string, std::size(sql_string), "INSERT INTO search_result "
			"(folder_id, message_id) VALUES (%llu, %llu)",
			LLU{pdynamic->folder_id}, LLU{id2});
		if (pdb->exec(sql_string) == SQLITE_OK) {
			pdb->notify_link_creation(pdynamic->folder_id, id2, dbase, notifq);
			pdb->proc_dynamic_event(cpid, dynamic_event::new_msg,
				pdynamic->folder_id, id2, 0, dbase, notifq);
		} else {
			mlog(LV_DEBUG, "db_engine: failed to insert into search_result");
		}
		break;
	case dynamic_event::del_msg:
		if (!common_util_check_search_result(pdb->psqlite,
		    pdynamic->folder_id, id2, &b_exist)) {
			mlog(LV_DEBUG, "db_engine: failed to check item in search_result");
			return;
		}
		if (!b_exist)
			return;
		pdb->notify_link_deletion(pdynamic->folder_id, id2, dbase, notifq);
		pdb->proc_dynamic_event(cpid, dynamic_event::del_msg,
			pdynamic->folder_id, id2, 0, dbase, notifq);
		snprintf(sql_string, std::size(sql_string), "DELETE FROM search_result "
			"WHERE folder_id=%llu AND message_id=%llu",
			LLU{pdynamic->folder_id}, LLU{id2});
		if (pdb->exec(sql_string) != SQLITE_OK)
			mlog(LV_DEBUG, "db_engine: failed to delete from search_result");
		break;
	case dynamic_event::modify_msg:
		if (!common_util_check_search_result(pdb->psqlite,
		    pdynamic->folder_id, id2, &b_exist)) {
			mlog(LV_DEBUG, "db_engine: failed to check item in search_result");
			return;
		}
		if (cu_eval_msg_restriction(
		    db, cpid, id2, pdynamic->prestriction)) {
			if (b_exist) {
				dbeng_notify_cttbl_modify_row(db, pdynamic->folder_id, id2, dbase, notifq);
				pdb->notify_folder_modification(
					common_util_get_folder_parent_fid(
					pdb->psqlite, pdynamic->folder_id),
					pdynamic->folder_id, dbase, notifq);
				return;
			}
			snprintf(sql_string, std::size(sql_string), "INSERT INTO search_result "
				"(folder_id, message_id) VALUES (%llu, %llu)",
				LLU{pdynamic->folder_id}, LLU{id2});
			if (pdb->exec(sql_string) == SQLITE_OK) {
				pdb->notify_link_creation(pdynamic->folder_id, id2, dbase, notifq);
				pdb->proc_dynamic_event(cpid, dynamic_event::new_msg,
					pdynamic->folder_id, id2, 0, dbase, notifq);
			} else {
				mlog(LV_DEBUG, "db_engine: failed to insert into search_result");
			}
		} else {
			if (!b_exist)
				return;
			pdb->notify_link_deletion(pdynamic->folder_id, id2, dbase, notifq);
			pdb->proc_dynamic_event(cpid, dynamic_event::del_msg,
				pdynamic->folder_id, id2, 0, dbase, notifq);
			snprintf(sql_string, std::size(sql_string), "DELETE FROM search_result "
				"WHERE folder_id=%llu AND message_id=%llu",
				LLU{pdynamic->folder_id}, LLU{id2});
			if (pdb->exec(sql_string) != SQLITE_OK)
				mlog(LV_DEBUG, "db_engine: failed to delete from search_result");
		}
		break;
	default:
		break;
	}
}

/**
 * This is the entry function called by most everything else to notify *search
 * folders* of events that happened elsewhere.
 *
 * @id1:        event source folder
 * @id2:        message involved in the event
 *
 * Caveat: id1 may be a regular folder like Inbox, but it also be a search
 * folder itself (population/depopulation as a result of search criteria
 * change).
 */
void db_conn::proc_dynamic_event(cpid_t cpid, dynamic_event event_type,
    uint64_t id1, uint64_t id2, uint64_t id3, db_base &dbase, NOTIFQ &notifq)
{
	auto pdb = this;
	uint32_t folder_type;
	
	if (event_type == dynamic_event::move_folder &&
	    !common_util_get_folder_type(pdb->psqlite, id3, &folder_type)) {
		mlog(LV_DEBUG, "db_engine: fatal error in %s", __PRETTY_FUNCTION__);
		return;
	}
	/* Iterate over all search folders (event sinks)... */
	for (auto &dn : dbase.dynamic_list) {
		auto pdynamic = &dn;
		/*
		 * Iterate over source folders (a.k.a. search scope; MS-OXCFOLD
		 * v23.2 §1.1).
		 *
		 * [In conjunction with dynevt_1/2] if id1 is within the scope,
		 * pdynamic gets the event.
		 */
		for (size_t i = 0; i < pdynamic->scope_list.size(); ++i) {
			if (dynamic_event::move_folder == event_type) {
				dbeng_dynevt_1(*pdb, cpid, id1, id2, id3,
					folder_type, pdynamic, i, dbase, notifq);
				continue;
			}
			dbeng_dynevt_2(*pdb, cpid, event_type, id1, id2,
				pdynamic, i, dbase, notifq);
		}
	}
}

static std::strong_ordering db_engine_compare_propval(proptype_t proptype,
    void *pvalue1, void *pvalue2)
{
	/*
	 * EXC2019-compatible behavior: absent values sort before anything
	 * else, and compare equal to another absent property.
	 * (See also: propval_compare_relop_nullok)
	 */
	if (pvalue1 == nullptr && pvalue2 == nullptr)
		return std::strong_ordering::equal;
	if (pvalue1 == nullptr && pvalue2 != nullptr)
		return std::strong_ordering::less;
	if (pvalue1 != nullptr && pvalue2 == nullptr)
		return std::strong_ordering::greater;
	return propval_compare(pvalue1, pvalue2, proptype);
}

static bool db_engine_insert_categories(sqlite3 *psqlite, int depth,
    uint64_t parent_id, uint64_t after_row_id, uint64_t before_row_id,
    const SORTORDER_SET *psorts, const TAGGED_PROPVAL *ppropvals,
    sqlite3_stmt *pstmt_insert, sqlite3_stmt *pstmt_update,
    uint32_t *pheader_id, std::vector<rowinfo_node> &notify_list,
    uint64_t *plast_row_id) try
{
	int i;
	uint16_t type;
	uint64_t row_id = 0, prev_id = 0, inst_id;
	
	if (0 != before_row_id) {
		sqlite3_bind_null(pstmt_update, 1);
		sqlite3_bind_int64(pstmt_update, 2, before_row_id);
		if (gx_sql_step(pstmt_update) != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt_update);
	}
	for (i=depth; i<psorts->ccategories; i++) {
		(*pheader_id) ++;
		inst_id = *pheader_id | 0x100000000000000ULL;
		sqlite3_bind_int64(pstmt_insert, 1, inst_id);
		sqlite3_bind_int64(pstmt_insert, 2, CONTENT_ROW_HEADER);
		sqlite3_bind_int64(pstmt_insert, 3, i < psorts->cexpanded);
		sqlite3_bind_int64(pstmt_insert, 4, parent_id);
		sqlite3_bind_int64(pstmt_insert, 5, i);
		sqlite3_bind_int64(pstmt_insert, 6, 0);
		sqlite3_bind_int64(pstmt_insert, 7, 0);
		sqlite3_bind_int64(pstmt_insert, 8, 0);
		type = psorts->psort[i].type;
		if ((type & MVI_FLAG) == MVI_FLAG)
			type &= ~MVI_FLAG;
		if (ppropvals[i].pvalue == nullptr)
			sqlite3_bind_null(pstmt_insert, 9);
		else if (!common_util_bind_sqlite_statement(pstmt_insert,
		    9, type, ppropvals[i].pvalue))
			return FALSE;
		sqlite3_bind_null(pstmt_insert, 10);
		sqlite3_bind_int64(pstmt_insert, 11, i == depth && after_row_id != 0 ?
			after_row_id : -parent_id);
		if (gx_sql_step(pstmt_insert) != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt_insert);
		row_id = sqlite3_last_insert_rowid(psqlite);
		notify_list.emplace_back(true, row_id);
		if (i == depth)
			prev_id = row_id;
		parent_id = row_id;
	}
	if (0 != before_row_id) {
		sqlite3_bind_int64(pstmt_update, 1, prev_id);
		sqlite3_bind_int64(pstmt_update, 2, before_row_id);
		if (gx_sql_step(pstmt_update) != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt_update);
	}
	*plast_row_id = row_id;
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}

static bool db_engine_insert_message(sqlite3 *psqlite, uint64_t message_id,
    bool b_read, int depth, uint32_t inst_num, uint16_t type, void *pvalue,
    uint64_t parent_id, uint64_t after_row_id, uint64_t before_row_id,
    sqlite3_stmt *pstmt_insert, sqlite3_stmt *pstmt_update,
    std::vector<rowinfo_node> &notify_list, uint64_t *plast_row_id) try
{
	uint64_t row_id;
	
	if (0 != before_row_id) {
		sqlite3_bind_null(pstmt_update, 1);
		sqlite3_bind_int64(pstmt_update, 2, before_row_id);
		if (gx_sql_step(pstmt_update) != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt_update);
	}
	sqlite3_bind_int64(pstmt_insert, 1, message_id);
	sqlite3_bind_int64(pstmt_insert, 2, CONTENT_ROW_MESSAGE);
	sqlite3_bind_null(pstmt_insert, 3);
	sqlite3_bind_int64(pstmt_insert, 4, parent_id);
	sqlite3_bind_int64(pstmt_insert, 5, depth);
	sqlite3_bind_null(pstmt_insert, 6);
	sqlite3_bind_null(pstmt_insert, 7);
	sqlite3_bind_int64(pstmt_insert, 8, inst_num);
	if (pvalue == nullptr)
		sqlite3_bind_null(pstmt_insert, 9);
	else if (!common_util_bind_sqlite_statement(pstmt_insert, 9, type, pvalue))
		return FALSE;
	sqlite3_bind_int64(pstmt_insert, 10, !!b_read);
	sqlite3_bind_int64(pstmt_insert, 11, after_row_id == 0 ? -parent_id : after_row_id);
	if (gx_sql_step(pstmt_insert) != SQLITE_DONE)
		return FALSE;
	row_id = sqlite3_last_insert_rowid(psqlite);
	if (0 != before_row_id) {
		sqlite3_bind_int64(pstmt_update, 1, row_id);
		sqlite3_bind_int64(pstmt_update, 2, before_row_id);
		if (gx_sql_step(pstmt_update) != SQLITE_DONE)
			return FALSE;
		sqlite3_reset(pstmt_update);
	}
	sqlite3_reset(pstmt_insert);
	notify_list.emplace_back(true, row_id);
	*plast_row_id = row_id;
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}

static void db_engine_append_rowinfo_node(std::vector<rowinfo_node> &notify_list,
    uint64_t row_id) try
{
	auto it = std::find_if(notify_list.begin(), notify_list.end(), [&](const rowinfo_node &e) {
	          	return e.row_id == row_id;
	          });
	if (it == notify_list.end())
		notify_list.emplace_back(false, row_id);
} catch (const std::bad_alloc &) {
}

static bool db_engine_check_new_header(const std::vector<rowinfo_node> &notify_list,
    uint64_t row_id)
{
	return std::find_if(notify_list.cbegin(), notify_list.cend(), [&](const rowinfo_node &e) {
	       	return e.b_added && e.row_id == row_id;
	       }) != notify_list.cend();
}

static inline size_t det_multi_num(uint16_t type, const void *mv)
{
	switch (type) {
	case PT_MV_SHORT:
		return static_cast<const SHORT_ARRAY *>(mv)->count;
	case PT_MV_LONG:
		return static_cast<const LONG_ARRAY *>(mv)->count;
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME:
		return static_cast<const LONGLONG_ARRAY *>(mv)->count;
	case PT_MV_FLOAT:
		return static_cast<const FLOAT_ARRAY *>(mv)->count;
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME:
		return static_cast<const DOUBLE_ARRAY *>(mv)->count;
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		return static_cast<const STRING_ARRAY *>(mv)->count;
	case PT_MV_CLSID:
		return static_cast<const GUID_ARRAY *>(mv)->count;
	case PT_MV_BINARY:
		return static_cast<const BINARY_ARRAY *>(mv)->count;
	}
	return UINT32_MAX;
}

static inline void *pick_single_val(uint16_t type, void *mv, size_t j)
{
	switch (type) {
	case PT_MV_SHORT:
		return &static_cast<const SHORT_ARRAY *>(mv)->ps[j];
	case PT_MV_LONG:
		return &static_cast<const LONG_ARRAY *>(mv)->pl[j];
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME:
		return &static_cast<const LONGLONG_ARRAY *>(mv)->pll[j];
	case PT_MV_FLOAT:
		return &static_cast<const FLOAT_ARRAY *>(mv)->mval[j];
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME:
		return &static_cast<const DOUBLE_ARRAY *>(mv)->mval[j];
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		return static_cast<const STRING_ARRAY *>(mv)->ppstr[j];
	case PT_MV_CLSID:
		return &static_cast<const GUID_ARRAY *>(mv)->pguid[j];
	case PT_MV_BINARY:
		return &static_cast<const BINARY_ARRAY *>(mv)->pbin[j];
	}
	return mv;
}

static db_conn::ID_ARRAYS table_to_idarray(const table_node &o)
{
	return db_conn::ID_ARRAYS{{o.remote_id, {o.table_id}}};
}

static void dbeng_notify_cttbl_add_row(db_conn &db, uint64_t folder_id,
    uint64_t message_id, db_base &dbase, db_conn::NOTIFQ &notifq) try
{
	auto pdb = &db;
	DB_NOTIFY_DATAGRAM datagram  = {deconst(exmdb_server::get_dir()), TRUE, {0}};
	DB_NOTIFY_DATAGRAM datagram1 = datagram;
	BOOL b_read = false;
	TAGGED_PROPVAL propvals[MAXIMUM_SORT_COUNT];
	DB_NOTIFY_CONTENT_TABLE_ROW_ADDED *padded_row = nullptr, *padded_row1 = nullptr;
	
	uint8_t *pread_byte = nullptr;
	void *pvalue0;
	if (!cu_get_property(MAPI_MESSAGE, message_id, CP_ACP,
	    db, PR_ASSOCIATED, &pvalue0))
		return;	
	char qstr[256];
	snprintf(qstr, std::size(qstr), "SELECT is_deleted FROM messages WHERE message_id=%llu", LLU{message_id});
	auto stm = pdb->prep(qstr);
	if (stm == nullptr)
		return;
	auto b_del = stm.step() != SQLITE_ROW || stm.col_uint64(0) != 0;
	stm.finalize();

	bool did_optim = false;
	auto cl_0 = HX::make_scope_exit([&]() { if (did_optim) db.end_optim(); });
	BOOL b_fai = pvb_enabled(pvalue0) ? TRUE : false;
	auto sql_transact_eph = gx_sql_begin(pdb->m_sqlite_eph, txn_mode::write);
	if (!sql_transact_eph) {
		mlog(LV_ERR, "E-2063: failed to start transaction in cttbl_add_row");
		return;
	}
	for (auto &tnode : dbase.tables.table_list) {
		auto ptable = &tnode;
		if (ptable->type != table_type::content ||
		    folder_id != ptable->folder_id)
			continue;
		if (!!(ptable->table_flags & TABLE_FLAG_ASSOCIATED) == !b_fai)
			continue;
		if (!!(ptable->table_flags & TABLE_FLAG_SOFTDELETES) == !b_del)
			continue;
		if (dbase.tables.b_batch && ptable->b_hint)
			continue;
		if (ptable->prestriction != nullptr &&
		    !cu_eval_msg_restriction(db,
		    ptable->cpid, message_id, ptable->prestriction))
			continue;
		if (dbase.tables.b_batch) {
			ptable->b_hint = TRUE;
			continue;
		}
		if (NULL == padded_row) {
			padded_row = &datagram.db_notify.pdata.emplace<DB_NOTIFY_CONTENT_TABLE_ROW_ADDED>();
			padded_row->row_folder_id = folder_id;
			padded_row->row_message_id = message_id;
			padded_row1 = &datagram1.db_notify.pdata.emplace<DB_NOTIFY_CONTENT_TABLE_ROW_ADDED>();
			padded_row1->row_folder_id = folder_id;
			padded_row1->row_instance = 0;
			if (!pdb->begin_optim())
				return;
			did_optim = true;
		}
		datagram.id_array[0] = datagram1.id_array[0] =
			ptable->table_id; // reserved earlier
		if (NULL == ptable->psorts) {
			char sql_string[148];
			snprintf(sql_string, std::size(sql_string), "SELECT "
				"count(*) FROM t%u", ptable->table_id);
			auto pstmt = pdb->eph_prep(sql_string);
			if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
				continue;
			uint32_t idx = sqlite3_column_int64(pstmt, 0);
			pstmt.finalize();
			uint64_t inst_id = 0, row_id = 0;
			if (0 == idx) {
				row_id = 0;
				inst_id = 0;
				snprintf(sql_string, std::size(sql_string), "INSERT INTO t%u (inst_id, prev_id,"
					" row_type, depth, inst_num, idx) VALUES (%llu, 0, "
					"%u, 0, 0, 1)", ptable->table_id, LLU{message_id},
					CONTENT_ROW_MESSAGE);
			} else {
				snprintf(sql_string, std::size(sql_string), "SELECT row_id, inst_id "
						"FROM t%u WHERE idx=%u", ptable->table_id, idx);
				pstmt = pdb->eph_prep(sql_string);
				if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
					continue;
				row_id = sqlite3_column_int64(pstmt, 0);
				inst_id = sqlite3_column_int64(pstmt, 1);
				pstmt.finalize();
				snprintf(sql_string, std::size(sql_string), "INSERT INTO t%u (inst_id, prev_id, "
					"row_type, depth, inst_num, idx) VALUES (%llu, %llu,"
					" %u, 0, 0, %u)", ptable->table_id, LLU{message_id}, LLU{row_id},
					CONTENT_ROW_MESSAGE, idx + 1);
			}
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				continue;
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS)
				continue;
			padded_row->row_instance = 0;
			padded_row->after_row_id = inst_id;
			padded_row->after_instance = 0;
			if (padded_row->after_row_id == 0)
				padded_row->after_folder_id = 0;
			else if (!common_util_get_message_parent_folder(pdb->psqlite,
			    padded_row->after_row_id, &padded_row->after_folder_id))
				continue;
			datagram.db_notify.type = ptable->b_search ?
			                          db_notify_type::srchtbl_row_added :
			                          db_notify_type::cttbl_row_added;
			notifq.emplace_back(datagram, table_to_idarray(*ptable));
			continue;
		} else if (0 == ptable->psorts->ccategories) {
			for (size_t i = 0; i < ptable->psorts->count; ++i) {
				propvals[i].proptag = PROP_TAG(ptable->psorts->psort[i].type, ptable->psorts->psort[i].propid);
				if (!cu_get_property(MAPI_MESSAGE, message_id,
				    ptable->cpid, db, propvals[i].proptag,
				    &propvals[i].pvalue))
					return;
			}
			char sql_string[148];
			snprintf(sql_string, std::size(sql_string), "SELECT row_id, inst_id,"
				" idx FROM t%u ORDER BY idx ASC", ptable->table_id);
			auto pstmt = pdb->eph_prep(sql_string);
			if (pstmt == nullptr)
				continue;
			uint32_t idx = 0;
			uint64_t row_id = 0, row_id1 = 0, inst_id = 0, inst_id1 = 0;
			BOOL b_break = FALSE;
			while (pstmt.step() == SQLITE_ROW) {
				row_id = row_id1;
				inst_id = inst_id1;
				row_id1 = sqlite3_column_int64(pstmt, 0);
				inst_id1 = sqlite3_column_int64(pstmt, 1);
				idx = sqlite3_column_int64(pstmt, 2);
				for (size_t i = 0; i < ptable->psorts->count; ++i) {
					void *pvalue = nullptr;
					if (!cu_get_property(MAPI_MESSAGE, inst_id1,
					    ptable->cpid, db,
					    propvals[i].proptag, &pvalue))
						return;
					auto result = db_engine_compare_propval(ptable->psorts->psort[i].type, propvals[i].pvalue, pvalue);
					auto asc = ptable->psorts->psort[i].table_sort == TABLE_SORT_ASCEND;
					if ((asc && result < 0) || (!asc && result > 0))
						b_break = TRUE;
					if (result != 0)
						break;
				}
				if (b_break)
					break;
			}
			pstmt.finalize();
			if (0 == idx) {
				snprintf(sql_string, std::size(sql_string), "INSERT INTO t%u (inst_id, prev_id,"
					" row_type, depth, inst_num, idx) VALUES (%llu, 0, "
					"%u, 0, 0, 1)", ptable->table_id, LLU{message_id},
					CONTENT_ROW_MESSAGE);
				if (pdb->eph_exec(sql_string) != SQLITE_OK)
					continue;
				padded_row->after_row_id = 0;
			} else if (!b_break) {
				snprintf(sql_string, std::size(sql_string), "INSERT INTO t%u (inst_id, prev_id, "
					"row_type, depth, inst_num, idx) VALUES (%llu, %llu,"
					" %u, 0, 0, %u)", ptable->table_id, LLU{message_id},
					LLU{row_id1}, CONTENT_ROW_MESSAGE, idx + 1);
				if (pdb->eph_exec(sql_string) != SQLITE_OK)
					continue;
				padded_row->after_row_id = inst_id1;
			} else {
				xsavepoint sql_savepoint(pdb->m_sqlite_eph, "sp1");
				if (!sql_savepoint)
					continue;
				snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET idx=-(idx+1)"
					" WHERE idx>=%u;UPDATE t%u SET idx=-idx WHERE"
					" idx<0", ptable->table_id, idx, ptable->table_id);
				if (pdb->eph_exec(sql_string) != SQLITE_OK)
					continue;
				snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET prev_id=NULL "
					"WHERE row_id=%llu", ptable->table_id, LLU{row_id1});
				if (pdb->eph_exec(sql_string) != SQLITE_OK)
					continue;
				if (row_id == 0)
					snprintf(sql_string, std::size(sql_string), "INSERT INTO t%u (inst_id, prev_id,"
						" row_type, depth, inst_num, idx) VALUES (%llu, 0, "
						"%u, 0, 0, 1)", ptable->table_id, LLU{message_id},
						CONTENT_ROW_MESSAGE);
				else
					snprintf(sql_string, std::size(sql_string), "INSERT INTO t%u (inst_id, prev_id, "
						"row_type, depth, inst_num, idx) VALUES (%llu, %llu,"
						" %u, 0, 0, %u)", ptable->table_id, LLU{message_id},
						LLU{row_id}, CONTENT_ROW_MESSAGE, idx);
				if (pdb->eph_exec(sql_string) != SQLITE_OK)
					continue;
				row_id = sqlite3_last_insert_rowid(pdb->m_sqlite_eph);
				snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET prev_id=%llu WHERE"
				        " row_id=%llu", ptable->table_id, LLU{row_id}, LLU{row_id1});
				if (pdb->eph_exec(sql_string) != SQLITE_OK)
					continue;
				if (sql_savepoint.commit() != SQLITE_OK)
					continue;
				padded_row->after_row_id = inst_id;
			}
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS)
				continue;
			if (padded_row->after_row_id == 0)
				padded_row->after_folder_id = 0;
			else if (!common_util_get_message_parent_folder(pdb->psqlite,
			    padded_row->after_row_id, &padded_row->after_folder_id))
				continue;
			padded_row->row_instance = 0;
			padded_row->after_instance = 0;
			datagram.db_notify.type = ptable->b_search ?
			                          db_notify_type::srchtbl_row_added :
			                          db_notify_type::cttbl_row_added;
			notifq.emplace_back(datagram, table_to_idarray(*ptable));
			continue;
		}
		if (NULL == pread_byte) {
			if (!cu_get_property(MAPI_MESSAGE,
			    message_id, ptable->cpid, db, PR_READ,
			    reinterpret_cast<void **>(&pread_byte)) ||
			    pread_byte == nullptr)
				return;
			b_read = *pread_byte == 0 ? false : TRUE;
		}
		int multi_index = -1;
		static_assert(sizeof(multi_index) > sizeof(ptable->psorts->count));
		for (unsigned int i = 0; i < ptable->psorts->count; ++i) {
			propvals[i].proptag = PROP_TAG(ptable->psorts->psort[i].type, ptable->psorts->psort[i].propid);
			if (propvals[i].proptag == ptable->instance_tag) {
				multi_index = i;
				if (!cu_get_property(
				    MAPI_MESSAGE, message_id, ptable->cpid,
				    db, propvals[i].proptag & ~MV_INSTANCE,
				    &propvals[i].pvalue))
					return;
			} else if (!cu_get_property(MAPI_MESSAGE, message_id,
			    ptable->cpid, db, propvals[i].proptag,
			    &propvals[i].pvalue)) {
				return;
			}
		}
		void *pmultival = nullptr;
		uint32_t multi_num = 1;
		if (multi_index >= 0) {
			pmultival = propvals[multi_index].pvalue;
			if (pmultival != nullptr) {
				multi_num = det_multi_num(ptable->psorts->psort[multi_index].type & ~MV_INSTANCE, pmultival);
				if (multi_num == UINT32_MAX)
					return;
				if (0 == multi_num) {
					pmultival = NULL;
					multi_num = 1;
					propvals[multi_index].pvalue = NULL;
				}
			}
		}
		xsavepoint sql_savepoint(pdb->m_sqlite_eph, "sp2");
		if (!sql_savepoint)
			continue;
		char sql_string[164];
		snprintf(sql_string, std::size(sql_string), "SELECT row_id, inst_id, "
		         "value FROM t%u WHERE prev_id=?", ptable->table_id);
		auto pstmt = pdb->eph_prep(sql_string);
		if (pstmt == nullptr)
			continue;
		snprintf(sql_string, std::size(sql_string), "INSERT INTO t%u (inst_id, "
		         "row_type, row_stat, parent_id, depth, count, unread,"
		         " inst_num, value, extremum, prev_id) VALUES (?, ?, "
		         "?, ?, ?, ?, ?, ?, ?, ?, ?)", ptable->table_id);
		auto pstmt1 = pdb->eph_prep(sql_string);
		if (pstmt1 == nullptr)
			continue;
		snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET "
		         "prev_id=? WHERE row_id=?", ptable->table_id);
		auto pstmt2 = pdb->eph_prep(sql_string);
		if (pstmt2 == nullptr)
			continue;
		snprintf(sql_string, std::size(sql_string), "SELECT * FROM"
		         " t%u WHERE row_id=?", ptable->table_id);
		auto stm_sel_tx = pdb->eph_prep(sql_string);
		if (stm_sel_tx == nullptr)
			continue;
		xstmt stm_set_ex;
		if (0 != ptable->extremum_tag) {
			snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET "
			         "extremum=? WHERE row_id=?", ptable->table_id);
			stm_set_ex = pdb->eph_prep(sql_string);
			if (stm_set_ex == nullptr)
				continue;
		}
		BOOL b_resorted = FALSE;
		std::vector<rowinfo_node> notify_list;
		for (size_t j = 0; j < multi_num; ++j) {
			uint64_t parent_id = 0, inst_num = 0, row_id = 0, row_id1 = 0;
			if (NULL != pmultival) {
				inst_num = j + 1;
				propvals[multi_index].pvalue = pick_single_val(ptable->psorts->psort[multi_index].type & ~MV_INSTANCE, pmultival, j);
			}
			BOOL b_break = FALSE;
			size_t i;
			for (i = 0; i < ptable->psorts->ccategories; i++) {
				uint16_t type = ptable->psorts->psort[i].type;
				if ((type & MVI_FLAG) == MVI_FLAG)
					type &= ~MVI_FLAG;
				sqlite3_reset(pstmt);
				sqlite3_bind_int64(pstmt, 1, -row_id1);
				while (pstmt.step() == SQLITE_ROW) {
					row_id = row_id1;
					row_id1 = sqlite3_column_int64(pstmt, 0);
					auto pvalue = common_util_column_sqlite_statement(pstmt, 2, type);
					auto result = db_engine_compare_propval(type, propvals[i].pvalue, pvalue);
					if (result == 0)
						goto MATCH_SUB_HEADER;
					if (0 == ptable->extremum_tag ||
					    i != static_cast<size_t>(ptable->psorts->ccategories) - 1) {
						auto asc = ptable->psorts->psort[i].table_sort == TABLE_SORT_ASCEND;
						if ((asc && result < 0) || (!asc && result > 0)) {
							b_break = TRUE;
							break;
						}
					}
					sqlite3_reset(pstmt);
					sqlite3_bind_int64(pstmt, 1, row_id1);
				}
				if (!b_break) {
					row_id = row_id1;
					row_id1 = 0;
					b_break = TRUE;
				}
				break;
 MATCH_SUB_HEADER:
				parent_id = row_id1;
			}
			if (b_break && !db_engine_insert_categories(pdb->m_sqlite_eph,
			    i, parent_id, row_id, row_id1, ptable->psorts,
			    propvals, pstmt1, pstmt2, &ptable->header_id,
			    notify_list, &parent_id))
				return;
			row_id = 0;
			row_id1 = 0;
			b_break = ptable->psorts->count > ptable->psorts->ccategories ? false : TRUE;
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, -parent_id);
			while (pstmt.step() == SQLITE_ROW) {
				row_id = row_id1;
				row_id1 = sqlite3_column_int64(pstmt, 0);
				uint64_t inst_id = sqlite3_column_int64(pstmt, 1);
				for (i = ptable->psorts->ccategories;
				     i < ptable->psorts->count; i++) {
					void *pvalue = nullptr;
					if (!cu_get_property(MAPI_MESSAGE, inst_id,
					    ptable->cpid, db,
					    propvals[i].proptag, &pvalue))
						return;
					auto result = db_engine_compare_propval(ptable->psorts->psort[i].type, propvals[i].pvalue, pvalue);
					auto asc = ptable->psorts->psort[i].table_sort == TABLE_SORT_ASCEND;
					if ((asc && result < 0) || (!asc && result > 0))
						b_break = TRUE;
					if (result != 0)
						break;
				}
				if (b_break)
					break;
				sqlite3_reset(pstmt);
				sqlite3_bind_int64(pstmt, 1, row_id1);
			}
			if (!b_break) {
				row_id = row_id1;
				row_id1 = 0;
			}
			uint16_t type = 0;
			void *pvalue = nullptr;
			if (multi_index >= 0) {
				type = ptable->psorts->psort[multi_index].type & ~MVI_FLAG;
				pvalue = propvals[multi_index].pvalue;
			}
			if (!db_engine_insert_message(
			    pdb->m_sqlite_eph, message_id, b_read,
			    ptable->psorts->ccategories, inst_num,
			    type, pvalue, parent_id, row_id, row_id1,
			    pstmt1, pstmt2, notify_list, &row_id))
				return;
			parent_id = 0;
			while (true) {
				stm_sel_tx.bind_int64(1, row_id);
				if (stm_sel_tx.step() != SQLITE_ROW)
					return;
				row_id = stm_sel_tx.col_int64(6);
				stm_sel_tx.reset();
				if (row_id == 0)
					break;
				if (parent_id == 0)
					parent_id = row_id;
				snprintf(sql_string, std::size(sql_string), b_read ?
				         "UPDATE t%u SET count=count+1 WHERE row_id=%llu" :
				         "UPDATE t%u SET count=count+1, unread=unread+1 WHERE row_id=%llu",
				         ptable->table_id, LLU{row_id});
				if (pdb->eph_exec(sql_string) != SQLITE_OK)
					return;
				db_engine_append_rowinfo_node(notify_list, row_id);
			}
			if (ptable->extremum_tag == 0)
				continue;
			row_id = parent_id;
			type = ptable->psorts->psort[
				ptable->psorts->ccategories].type;
			stm_sel_tx.bind_int64(1, row_id);
			if (stm_sel_tx.step() != SQLITE_ROW)
				return;
			parent_id = stm_sel_tx.col_int64(6);
			pvalue = common_util_column_sqlite_statement(
			         stm_sel_tx, 12, type);
			stm_sel_tx.reset();
			auto result = db_engine_compare_propval(type, pvalue,
			              propvals[ptable->psorts->ccategories].pvalue);
			uint8_t table_sort = ptable->psorts->psort[
			                     ptable->psorts->ccategories].table_sort;
			if (TABLE_SORT_MAXIMUM_CATEGORY == table_sort) {
				if (result >= 0)
					continue;
			} else if (pvalue == nullptr &&
			    propvals[ptable->psorts->ccategories].pvalue != nullptr &&
			    db_engine_check_new_header(notify_list, row_id)) {
				/* extremum should be written */
			} else if (result <= 0) {
				continue;
			}
			pvalue = propvals[ptable->psorts->ccategories].pvalue;
			if (pvalue == nullptr)
				stm_set_ex.bind_null(1);
			else if (!common_util_bind_sqlite_statement(stm_set_ex, 1, type, pvalue))
				return;
			stm_set_ex.bind_int64(2, row_id);
			if (stm_set_ex.step() != SQLITE_DONE)
				return;
			stm_set_ex.reset();
			table_sort = ptable->psorts->psort[
			             ptable->psorts->ccategories - 1].table_sort;
			auto prev_id = -static_cast<int64_t>(parent_id);
			row_id1 = 0;
			b_break = FALSE;
			sqlite3_reset(pstmt);
			sqlite3_bind_int64(pstmt, 1, prev_id);
			while (pstmt.step() == SQLITE_ROW) {
				if (gx_sql_col_uint64(pstmt, 0) != row_id &&
				    row_id1 != 0 && row_id != row_id1)
					prev_id = row_id1;
				row_id1 = sqlite3_column_int64(pstmt, 0);
				if (row_id1 != row_id) {
					pvalue = common_util_column_sqlite_statement(
					         pstmt, 2, type);
					result = db_engine_compare_propval(
					         type, pvalue, propvals[
					         ptable->psorts->ccategories].pvalue);
					auto asc = table_sort == TABLE_SORT_ASCEND;
					if ((asc && result > 0) || (!asc && result < 0)) {
						b_break = TRUE;
						break;
					}
				}
				sqlite3_reset(pstmt);
				sqlite3_bind_int64(pstmt, 1, row_id1);
			}
			if (row_id == row_id1)
				continue;
			if (!b_break) {
				prev_id = row_id1;
				row_id1 = 0;
			}
			stm_sel_tx.bind_int64(1, row_id);
			if (stm_sel_tx.step() != SQLITE_ROW)
				return;
			int64_t prev_id1 = stm_sel_tx.col_int64(2);
			stm_sel_tx.reset();
			if (prev_id == prev_id1)
				continue;
			/* position within the list has been changed */
			if (!db_engine_check_new_header(notify_list, row_id))
				b_resorted = TRUE;
			if (0 != row_id1) {
				sqlite3_bind_null(pstmt2, 1);
				sqlite3_bind_int64(pstmt2, 2, row_id1);
				if (pstmt2.step() != SQLITE_DONE)
					return;
				sqlite3_reset(pstmt2);
			}
			sqlite3_bind_int64(pstmt2, 1, prev_id);
			sqlite3_bind_int64(pstmt2, 2, row_id);
			if (pstmt2.step() != SQLITE_DONE)
				return;
			sqlite3_reset(pstmt2);
			snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET prev_id=%lld"
			         " WHERE prev_id=%llu", ptable->table_id,
			         LLD{prev_id1}, LLU{row_id});
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				return;
			if (0 != row_id1) {
				sqlite3_bind_int64(pstmt2, 1, row_id);
				sqlite3_bind_int64(pstmt2, 2, row_id1);
				if (pstmt2.step() != SQLITE_DONE)
					return;
				sqlite3_reset(pstmt2);
			}
		}
		pstmt.finalize();
		pstmt1.finalize();
		pstmt2.finalize();
		stm_set_ex.finalize();
		snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET idx=NULL", ptable->table_id);
		if (pdb->eph_exec(sql_string) != SQLITE_OK)
			return;
		snprintf(sql_string, std::size(sql_string), "SELECT row_id, row_stat"
		         " FROM t%u WHERE prev_id=?", ptable->table_id);
		pstmt = pdb->eph_prep(sql_string);
		if (pstmt == nullptr)
			return;
		snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET"
		         " idx=? WHERE row_id=?", ptable->table_id);
		pstmt1 = pdb->eph_prep(sql_string);
		if (pstmt1 == nullptr)
			return;
		uint32_t idx = 0;
		sqlite3_bind_int64(pstmt, 1, 0);
		if (pstmt.step() == SQLITE_ROW &&
		    !common_util_indexing_sub_contents(ptable->psorts->ccategories,
		    pstmt, pstmt1, &idx))
			return;
		pstmt.finalize();
		pstmt1.finalize();
		if (sql_savepoint.commit() != SQLITE_OK)
			continue;
		if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS)
			continue;
		if (b_resorted) {
			datagram1.db_notify.type = ptable->b_search ?
						   db_notify_type::srchtbl_changed :
						   db_notify_type::cttbl_changed;
			notifq.emplace_back(datagram1, table_to_idarray(*ptable));
			continue;
		}

		snprintf(sql_string, std::size(sql_string), "SELECT * FROM"
			 " t%u WHERE idx=?", ptable->table_id);
		pstmt = pdb->eph_prep(sql_string);
		if (pstmt == nullptr)
			continue;
		for (const auto &[b_added, row_id] : notify_list) {
			stm_sel_tx.bind_int64(1, row_id);
			if (stm_sel_tx.step() != SQLITE_ROW ||
			    sqlite3_column_type(stm_sel_tx, 1) == SQLITE_NULL) {
				stm_sel_tx.reset();
				continue;
			}
			idx = stm_sel_tx.col_int64(1);
			uint64_t inst_folder_id = 0, inst_id = 0;
			uint32_t inst_num = 0;
			if (idx != 1) {
				sqlite3_bind_int64(pstmt, 1, idx - 1);
				if (pstmt.step() != SQLITE_ROW) {
					sqlite3_reset(pstmt);
					stm_sel_tx.reset();
					continue;
				}
				inst_id = sqlite3_column_int64(pstmt, 3);
				inst_num = sqlite3_column_int64(pstmt, 10);
				if (CONTENT_ROW_HEADER ==
					sqlite3_column_int64(pstmt, 4)) {
					inst_folder_id = folder_id;
				} else if (!common_util_get_message_parent_folder(pdb->psqlite,
				    inst_id, &inst_folder_id)) {
					sqlite3_reset(pstmt);
					stm_sel_tx.reset();
					continue;
				}
				sqlite3_reset(pstmt);
			}
			if (!b_added) {
				padded_row1->row_message_id = stm_sel_tx.col_int64(3);
				padded_row1->after_row_id = inst_id;
				padded_row1->after_folder_id = inst_folder_id;
				padded_row1->after_instance = inst_num;
				datagram1.db_notify.type = ptable->b_search ?
							   db_notify_type::srchtbl_row_modified :
							   db_notify_type::cttbl_row_modified;
				notifq.emplace_back(datagram1, table_to_idarray(*ptable));
			} else if (stm_sel_tx.col_int64(4) == CONTENT_ROW_HEADER) {
				padded_row1->row_message_id = stm_sel_tx.col_int64(3);
				padded_row1->after_row_id = inst_id;
				padded_row1->after_folder_id = inst_folder_id;
				padded_row1->after_instance = inst_num;
				datagram1.db_notify.type = ptable->b_search ?
				                           db_notify_type::srchtbl_row_added :
				                           db_notify_type::cttbl_row_added;
				notifq.emplace_back(datagram1, table_to_idarray(*ptable));
			} else {
				padded_row->row_instance = stm_sel_tx.col_int64(10);
				padded_row->after_row_id = inst_id;
				padded_row->after_folder_id = inst_folder_id;
				padded_row->after_instance = inst_num;
				datagram.db_notify.type = ptable->b_search ?
				                          db_notify_type::srchtbl_row_added :
				                          db_notify_type::cttbl_row_added;
				notifq.emplace_back(datagram, table_to_idarray(*ptable));
			}
			stm_sel_tx.reset();
		}
	}
	if (sql_transact_eph.commit() != SQLITE_OK)
		mlog(LV_ERR, "E-2161: failed to commit cttbl_add_row");
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

/*
 * All ::notify_*() functions must be called with at least lock_base_rd held,
 * because we access nsub_list.
 */
void db_conn::transport_new_mail(uint64_t folder_id, uint64_t message_id,
    uint32_t message_flags, const char *pstr_class, const db_base &dbase,
    NOTIFQ &notifq) try
{
	DB_NOTIFY_DATAGRAM datagram;
	auto dir = exmdb_server::get_dir();
	auto parrays = db_engine_classify_id_array(dbase,
	               fnevNewMail, folder_id, 0);
	if (parrays.size() == 0)
		return;
	datagram.dir = deconst(dir);
	datagram.db_notify.type = db_notify_type::new_mail;
	auto pnew_mail = &datagram.db_notify.pdata.emplace<DB_NOTIFY_NEW_MAIL>();
	pnew_mail->folder_id = folder_id;
	pnew_mail->message_id = message_id;
	pnew_mail->message_flags = message_flags;
	pnew_mail->pmessage_class = pstr_class;
	notifq.emplace_back(std::move(datagram), std::move(parrays));
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}
	
void db_conn::notify_new_mail(uint64_t folder_id, uint64_t message_id,
    db_base &dbase, NOTIFQ &notifq) try
{
	auto pdb = this;
	void *pvalue;
	auto dir = exmdb_server::get_dir();
	auto parrays = db_engine_classify_id_array(dbase,
	               fnevNewMail, folder_id, 0);
	if (parrays.size() > 0) {
		DB_NOTIFY_DATAGRAM datagram;
		datagram.dir = deconst(dir);
		datagram.db_notify.type = db_notify_type::new_mail;
		auto pnew_mail = &datagram.db_notify.pdata.emplace<DB_NOTIFY_NEW_MAIL>();
		pnew_mail->folder_id = folder_id;
		pnew_mail->message_id = message_id;
		if (!cu_get_property(MAPI_MESSAGE, message_id, CP_ACP,
		    *pdb, PR_MESSAGE_FLAGS, &pvalue) || pvalue == nullptr)
			return;
		pnew_mail->message_flags = *static_cast<uint32_t *>(pvalue);
		if (!cu_get_property(MAPI_MESSAGE, message_id, CP_ACP,
		    *pdb, PR_MESSAGE_CLASS, &pvalue) || pvalue == nullptr)
			return;
		pnew_mail->pmessage_class = static_cast<char *>(pvalue);
		notifq.emplace_back(std::move(datagram), std::move(parrays));
	}
	dbeng_notify_cttbl_add_row(*pdb, folder_id, message_id, dbase, notifq);
	pdb->notify_folder_modification(common_util_get_folder_parent_fid(
		pdb->psqlite, folder_id), folder_id, dbase, notifq);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

void db_conn::notify_message_creation(uint64_t folder_id,
    uint64_t message_id, db_base &dbase, NOTIFQ &notifq) try
{
	auto pdb = this;
	auto dir = exmdb_server::get_dir();
	auto parrays = db_engine_classify_id_array(dbase,
	               fnevObjectCreated, folder_id, 0);
	if (parrays.size() > 0) {
		DB_NOTIFY_DATAGRAM datagram;
		datagram.dir = deconst(dir);
		datagram.db_notify.type = db_notify_type::message_created;
		auto pcreated_mail = &datagram.db_notify.pdata.emplace<DB_NOTIFY_MESSAGE_CREATED>();
		pcreated_mail->folder_id = folder_id;
		pcreated_mail->message_id = message_id;
		pcreated_mail->proptags.count = 0;
		notifq.emplace_back(std::move(datagram), std::move(parrays));
	}
	dbeng_notify_cttbl_add_row(*pdb, folder_id, message_id, dbase, notifq);
	pdb->notify_folder_modification(common_util_get_folder_parent_fid(
		pdb->psqlite, folder_id), folder_id, dbase, notifq);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

void db_conn::notify_link_creation(uint64_t srch_fld, uint64_t message_id,
    db_base &dbase, NOTIFQ &notifq) try
{
	auto pdb = this;
	uint64_t anchor_fld;
	
	if (!common_util_get_message_parent_folder(pdb->psqlite, message_id, &anchor_fld))
		return;

	auto dir = exmdb_server::get_dir();
	auto parrays = db_engine_classify_id_array(dbase,
	               fnevObjectCreated, anchor_fld, 0);
	if (parrays.size() > 0) {
		DB_NOTIFY_DATAGRAM datagram;
		datagram.dir = deconst(dir);
		datagram.db_notify.type = db_notify_type::link_created;
		auto plinked_mail = &datagram.db_notify.pdata.emplace<DB_NOTIFY_LINK_CREATED>();
		plinked_mail->folder_id = anchor_fld;
		plinked_mail->message_id = message_id;
		plinked_mail->parent_id = srch_fld;
		plinked_mail->proptags.count = 0;
		notifq.emplace_back(std::move(datagram), std::move(parrays));
	}
	dbeng_notify_cttbl_add_row(*pdb, srch_fld, message_id, dbase, notifq);
	pdb->notify_folder_modification(common_util_get_folder_parent_fid(
		pdb->psqlite, srch_fld), srch_fld, dbase, notifq);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

static void dbeng_notify_hiertbl_add_row(db_conn &db, uint64_t parent_id,
    uint64_t folder_id, const db_base &dbase, db_conn::NOTIFQ &notifq) try
{
	auto pdb = &db;
	uint32_t idx;
	uint32_t depth;
	BOOL b_included;
	uint64_t folder_id1;
	xstmt pstmt;
	char sql_string[256];
	DB_NOTIFY_DATAGRAM datagram = {deconst(exmdb_server::get_dir()), TRUE, {0}};
	DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED *padded_row;
	
	padded_row = NULL;
	auto sql_transact_eph = gx_sql_begin(pdb->m_sqlite_eph, txn_mode::write);
	if (!sql_transact_eph) {
		mlog(LV_ERR, "E-2166: failed to start transaction in hiertbl_add_row");
		return;
	}
	for (const auto &tnode : dbase.tables.table_list) {
		auto ptable = &tnode;
		if (ptable->type != table_type::hierarchy)
			continue;
		if (TABLE_FLAG_DEPTH & ptable->table_flags) {
			if (folder_id == ptable->folder_id ||
			    !cu_is_descendant_folder(pdb->psqlite,
			    folder_id, ptable->folder_id, &b_included) ||
			    !b_included)
				continue;
		} else {
			if (parent_id != ptable->folder_id)
				continue;
		}
		if (ptable->prestriction != nullptr &&
		    !cu_eval_folder_restriction(db,
		    folder_id, ptable->prestriction))
			continue;
		if (NULL == padded_row) {
			datagram.db_notify.type = db_notify_type::hiertbl_row_added;
			padded_row = &datagram.db_notify.pdata.emplace<DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED>();
		}
		datagram.id_array[0] = ptable->table_id; // reserved earlier
		if ((ptable->table_flags & TABLE_FLAG_DEPTH) &&
			ptable->folder_id != parent_id) {
			if (NULL == pstmt) {
				pstmt = pdb->prep("SELECT parent_id "
				        "FROM folders WHERE folder_id=?");
				if (pstmt == nullptr) {
					pstmt = NULL;
					continue;
				}
			}
			depth = 1;
			folder_id1 = parent_id;
			while (true) {
				sqlite3_bind_int64(pstmt, 1, folder_id1);
				if (pstmt.step() != SQLITE_ROW) {
					depth = 0;
					break;
				}
				depth ++;
				folder_id1 = sqlite3_column_int64(pstmt, 0);
				sqlite3_reset(pstmt);
				if (folder_id1 == ptable->folder_id)
					break;
			}
			if (depth == 0)
				continue;
			snprintf(sql_string, std::size(sql_string), "SELECT idx FROM t%u"
						" WHERE folder_id=?", ptable->table_id);
			auto pstmt1 = pdb->eph_prep(sql_string);
			if (pstmt1 == nullptr)
				continue;
			idx = 0;
			folder_id1 = parent_id;
			while (true) {
				sqlite3_bind_int64(pstmt1, 1, folder_id1);
				if (pstmt1.step() == SQLITE_ROW) {
					idx = sqlite3_column_int64(pstmt1, 0);
					break;
				}
				sqlite3_reset(pstmt1);
				sqlite3_bind_int64(pstmt, 1, folder_id1);
				if (pstmt.step() != SQLITE_ROW)
					break;
				folder_id1 = sqlite3_column_int64(pstmt, 0);
				sqlite3_reset(pstmt);
				if (folder_id1 == ptable->folder_id)
					break;
			}
			pstmt1.finalize();
			if (idx == 0)
				goto APPEND_END_OF_TABLE;
			xsavepoint sql_savepoint(pdb->m_sqlite_eph, "sp1");
			if (!sql_savepoint)
				continue;
			snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET idx=-(idx+1)"
				" WHERE idx>%u;UPDATE t%u SET idx=-idx WHERE"
				" idx<0", ptable->table_id, idx, ptable->table_id);
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				continue;
			snprintf(sql_string, std::size(sql_string), "INSERT INTO t%u (idx, "
				"folder_id, depth) VALUES (%u, %llu, %u)",
				ptable->table_id, idx + 1, LLU{folder_id}, depth);
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				continue;
			if (sql_savepoint.commit() != SQLITE_OK)
				continue;
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS)
				continue;
			if (ptable->table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
				auto h = exmdb_server::get_handle();
				if (h != nullptr && *h == ptable->handle_guid)
					continue;
			}
			padded_row->after_folder_id = folder_id1;
		} else {
			depth = 1;
 APPEND_END_OF_TABLE:
			snprintf(sql_string, std::size(sql_string), "INSERT INTO t%u (folder_id,"
				" depth) VALUES (%llu, %u)", ptable->table_id,
				LLU{folder_id}, depth);
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				continue;
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS)
				continue;
			if (ptable->table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
				auto h = exmdb_server::get_handle();
				if (h != nullptr && *h == ptable->handle_guid)
					continue;
			}
			idx = sqlite3_last_insert_rowid(pdb->m_sqlite_eph);
			if (1 == idx) {
				padded_row->after_folder_id = 0;
			} else {
				snprintf(sql_string, std::size(sql_string), "SELECT folder_id FROM "
					"t%u WHERE idx=%u", ptable->table_id, idx - 1);
				auto pstmt1 = pdb->eph_prep(sql_string);
				if (pstmt1 == nullptr || pstmt1.step() != SQLITE_ROW)
					continue;
				padded_row->after_folder_id = sqlite3_column_int64(pstmt1, 0);
			}
		}
		padded_row->row_folder_id = folder_id;
		notifq.emplace_back(datagram, table_to_idarray(*ptable));
	}
	if (sql_transact_eph.commit() != SQLITE_OK)
		mlog(LV_ERR, "E-2167: failed to commit hiertbl_add_row");
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

void db_conn::notify_folder_creation(uint64_t parent_id, uint64_t folder_id,
    const db_base &dbase, NOTIFQ &notifq) try
{
	auto pdb = this;
	auto dir = exmdb_server::get_dir();
	auto parrays = db_engine_classify_id_array(dbase,
	               fnevObjectCreated, parent_id, 0);
	if (parrays.size() > 0) {
		DB_NOTIFY_DATAGRAM datagram;
		datagram.dir = deconst(dir);
		datagram.db_notify.type = db_notify_type::folder_created;
		auto pcreated_folder = &datagram.db_notify.pdata.emplace<DB_NOTIFY_FOLDER_CREATED>();
		pcreated_folder->folder_id = folder_id;
		pcreated_folder->parent_id = parent_id;
		pcreated_folder->proptags.count = 0;
		notifq.emplace_back(std::move(datagram), std::move(parrays));
	}
	dbeng_notify_hiertbl_add_row(*pdb, parent_id, folder_id, dbase, notifq);
	pdb->notify_folder_modification(common_util_get_folder_parent_fid(
		pdb->psqlite, parent_id), parent_id, dbase, notifq);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

static void db_engine_update_prev_id(std::vector<rowdel_node> &list,
    int64_t prev_id, uint64_t original_prev_id)
{
	auto it = std::find_if(list.begin(), list.end(), [&](const rowdel_node &e) {
	          	return static_cast<uint64_t>(e.prev_id) == original_prev_id;
	          });
	if (it != list.end())
		it->prev_id = prev_id;
}

static void *db_engine_get_extremum_value(db_conn &db, cpid_t cpid,
    uint32_t table_id, uint32_t extremum_tag, uint64_t parent_id,
    uint8_t table_sort)
{
	auto pdb = &db;
	BOOL b_first;
	void *pvalue;
	void *pvalue1;
	uint64_t message_id;
	char sql_string[256];
	
	snprintf(sql_string, std::size(sql_string), "SELECT inst_id FROM t%u "
				"WHERE parent_id=%llu", table_id, LLU{parent_id});
	auto pstmt = pdb->eph_prep(sql_string);
	if (pstmt == nullptr)
		return NULL;
	pvalue = NULL;
	b_first = FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		message_id = sqlite3_column_int64(pstmt, 0);
		if (!cu_get_property(MAPI_MESSAGE, message_id,
		    cpid, db, extremum_tag, &pvalue1))
			continue;	
		if (!b_first) {
			pvalue = pvalue1;
			b_first = TRUE;
			continue;
		}
		auto result = db_engine_compare_propval(PROP_TYPE(extremum_tag), pvalue, pvalue1);
		if (TABLE_SORT_MAXIMUM_CATEGORY == table_sort) {
			if (result < 0)
				pvalue = pvalue1;
		} else {
			if (result > 0)
				pvalue = pvalue1;
		}
	}
	return pvalue;
}

static void dbeng_notify_cttbl_delete_row(db_conn &db, uint64_t folder_id,
    uint64_t message_id, db_base &dbase, db_conn::NOTIFQ &notifq) try
{
	auto pdb = &db;
	uint8_t type;
	void *pvalue;
	void *pvalue1;
	int64_t prev_id;
	int64_t prev_id1;
	uint8_t table_sort;
	uint64_t parent_id;
	DB_NOTIFY_DATAGRAM dg_del = {deconst(exmdb_server::get_dir()), TRUE, {0}};
	DB_NOTIFY_DATAGRAM dg_mod = dg_del;
	DB_NOTIFY_CONTENT_TABLE_ROW_DELETED *pdeleted_row;
	DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED *pmodified_row = nullptr;

	pdeleted_row = NULL;
	auto sql_transact_eph = gx_sql_begin(pdb->m_sqlite_eph, txn_mode::write);
	if (!sql_transact_eph) {
		mlog(LV_ERR, "E-2162: failed to start transaction in cttbl_delete_row");
		return;
	}
	for (auto &tnode : dbase.tables.table_list) {
		auto ptable = &tnode;
		if (ptable->type != table_type::content ||
		    folder_id != ptable->folder_id)
			continue;
		if (dbase.tables.b_batch && ptable->b_hint)
			continue;

		/* Part 1 */
		{
		char sql_string[1024];
		if (ptable->instance_tag == 0)
			snprintf(sql_string, std::size(sql_string), "SELECT row_id "
				"FROM t%u WHERE inst_id=%llu AND inst_num=0",
				ptable->table_id, LLU{message_id});
		else
			snprintf(sql_string, std::size(sql_string), "SELECT row_id"
							" FROM t%u WHERE inst_id=%llu",
							ptable->table_id, LLU{message_id});
		auto pstmt = pdb->eph_prep(sql_string);
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
			continue;
		pstmt.finalize();
		if (dbase.tables.b_batch) {
			ptable->b_hint = TRUE;
			continue;
		}
		if (NULL == pdeleted_row) {
			pdeleted_row  = &dg_del.db_notify.pdata.emplace<DB_NOTIFY_CONTENT_TABLE_ROW_DELETED>();
			pmodified_row = &dg_mod.db_notify.pdata.emplace<DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED>();
			pmodified_row->row_folder_id = folder_id;
			pmodified_row->row_instance = 0;
			pmodified_row->after_folder_id = folder_id;
		}
		dg_del.id_array[0] = dg_mod.id_array[0] =
			ptable->table_id; // reserved earlier
		if (NULL == ptable->psorts || 0 == ptable->psorts->ccategories) {
			char sql_string[1024];
			snprintf(sql_string, std::size(sql_string), "SELECT row_id, idx,"
					" prev_id FROM t%u WHERE inst_id=%llu AND "
					"inst_num=0", ptable->table_id, LLU{message_id});
			pstmt = pdb->eph_prep(sql_string);
			if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
				continue;
			uint64_t row_id = sqlite3_column_int64(pstmt, 0);
			uint32_t idx = sqlite3_column_int64(pstmt, 1);
			prev_id = sqlite3_column_int64(pstmt, 2);
			pstmt.finalize();
			xsavepoint sql_savepoint(pdb->m_sqlite_eph, "sp1");
			if (!sql_savepoint)
				continue;
			snprintf(sql_string, std::size(sql_string), "DELETE FROM t%u WHERE "
				"row_id=%llu", ptable->table_id, LLU{row_id});
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				continue;
			snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET prev_id=%lld WHERE"
					" idx=%u", ptable->table_id, LLD{prev_id}, idx + 1);
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				continue;
			snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET idx=-(idx-1)"
				" WHERE idx>%u;UPDATE t%u SET idx=-idx WHERE"
				" idx<0", ptable->table_id, idx, ptable->table_id);
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				continue;
			snprintf(sql_string, std::size(sql_string), "UPDATE sqlite_sequence SET seq="
				"(SELECT count(*) FROM t%u) WHERE name='t%u'",
				ptable->table_id, ptable->table_id);
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				continue;
			if (sql_savepoint.commit() != SQLITE_OK)
				continue;
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS)
				continue;
			if (!common_util_get_message_parent_folder(pdb->psqlite,
			    message_id, &pdeleted_row->row_folder_id))
				continue;
			pdeleted_row->row_message_id = message_id;
			pdeleted_row->row_instance = 0;
			dg_del.db_notify.type = ptable->b_search ?
			                          db_notify_type::srchtbl_row_deleted :
			                          db_notify_type::cttbl_row_deleted;
			notifq.emplace_back(dg_del, table_to_idarray(*ptable));
			continue;
		}
		}

		bool b_index = false;
		std::vector<rowdel_node> del_list;
		/* Part 2 */
		{
		char sql_string[1024];
		if (ptable->instance_tag == 0)
			snprintf(sql_string, std::size(sql_string), "SELECT * FROM t%u"
						" WHERE inst_id=%llu AND inst_num=0",
						ptable->table_id, LLU{message_id});
		else
			snprintf(sql_string, std::size(sql_string), "SELECT * FROM t%u "
						"WHERE inst_id=%llu", ptable->table_id,
						LLU{message_id});
		auto stm_sel = pdb->eph_prep(sql_string);
		if (stm_sel == nullptr)
			continue;

		while (stm_sel.step() == SQLITE_ROW) {
			rowdel_node dn;
			dn.row_id    = stm_sel.col_int64(0);
			/* will get 0 if SQLITE_NULL in 'idx' field */ 
			dn.idx       = stm_sel.col_int64(1);
			if (dn.idx != 0)
				b_index = TRUE;
			dn.prev_id   = stm_sel.col_int64(2);
			dn.inst_id   = stm_sel.col_int64(3);
			dn.parent_id = stm_sel.col_int64(6);
			dn.depth     = stm_sel.col_int64(7);
			dn.inst_num  = stm_sel.col_int64(10);
			dn.b_read    = stm_sel.col_int64(12) != 0;
			del_list.push_back(std::move(dn));
		}
		}

		std::vector<rowinfo_node> notify_list;
		xsavepoint sql_savepoint(pdb->m_sqlite_eph, "sp2");
			if (!sql_savepoint)
				continue;

		bool b_resorted = false;
		/* Part 3 */
		{
		char sql_string[1024];
		snprintf(sql_string, std::size(sql_string), "SELECT * FROM"
			" t%u WHERE row_id=?", ptable->table_id);
		auto pstmt = pdb->eph_prep(sql_string);
		if (pstmt == nullptr)
			continue;
		snprintf(sql_string, std::size(sql_string), "DELETE FROM t%u "
					"WHERE row_id=?", ptable->table_id);
		auto stm_del_tblrow = pdb->eph_prep(sql_string);
		if (stm_del_tblrow == nullptr)
			continue;

		xstmt stm_set_extremum, stm_upd_previd, stm_sel_ex;
		if (0 != ptable->extremum_tag) {
			snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET "
				"extremum=? WHERE row_id=?", ptable->table_id);
			stm_set_extremum = pdb->eph_prep(sql_string);
			if (stm_set_extremum == nullptr)
				continue;
			snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET "
				"prev_id=? WHERE row_id=?", ptable->table_id);
			stm_upd_previd = pdb->eph_prep(sql_string);
			if (stm_upd_previd == nullptr)
				continue;
			snprintf(sql_string, std::size(sql_string), "SELECT row_id, inst_id, "
				"extremum FROM t%u WHERE prev_id=?", ptable->table_id);
			stm_sel_ex = pdb->eph_prep(sql_string);
			if (stm_sel_ex == nullptr)
				continue;
		}

		size_t del_iter = 0;
		for (; del_iter != del_list.size(); ++del_iter) {
			auto &delnode = del_list[del_iter];
			auto pdelnode = &delnode;
			if (ptable->extremum_tag != 0 &&
			    pdelnode->depth == ptable->psorts->ccategories)
				/* historically no-op for some reason */;
			/* delete the row first */
			sqlite3_bind_int64(stm_del_tblrow, 1, pdelnode->row_id);
			if (stm_del_tblrow.step() != SQLITE_DONE)
				break;
			sqlite3_reset(stm_del_tblrow);
			snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET prev_id=%lld"
				" WHERE prev_id=%llu", ptable->table_id,
				LLD{pdelnode->prev_id}, LLU{pdelnode->row_id});
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				break;
			if (pdelnode->depth == ptable->psorts->ccategories &&
			    ptable->instance_tag != 0)
				db_engine_update_prev_id(del_list,
					pdelnode->prev_id, pdelnode->row_id);
			if (pdelnode->parent_id == 0)
				continue;
			sqlite3_bind_int64(pstmt, 1, pdelnode->parent_id);
			if (pstmt.step() != SQLITE_ROW)
				break;
			if (1 == sqlite3_column_int64(pstmt, 8)) {
				rowdel_node nn, *pdelnode = &nn;
				pdelnode->row_id = sqlite3_column_int64(pstmt, 0);
				pdelnode->idx = sqlite3_column_int64(pstmt, 1);
				if (pdelnode->idx != 0)
					b_index = TRUE;
				pdelnode->prev_id = sqlite3_column_int64(pstmt, 2);
				pdelnode->inst_id = sqlite3_column_int64(pstmt, 3);
				pdelnode->parent_id = sqlite3_column_int64(pstmt, 6);
				pdelnode->depth = sqlite3_column_int64(pstmt, 7);
				pdelnode->inst_num = 0;
				pdelnode->b_read = delnode.b_read;
				del_list.push_back(std::move(nn));
				sqlite3_reset(pstmt);
				continue;
			}
			snprintf(sql_string, std::size(sql_string), pdelnode->b_read ?
			         "UPDATE t%u SET count=count-1 WHERE row_id=%llu" :
			         "UPDATE t%u SET count=count-1, unread=unread-1 WHERE row_id=%llu",
			         ptable->table_id, LLU{pdelnode->parent_id});
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				break;
			try {
				notify_list.emplace_back(false, delnode.parent_id);
			} catch (const std::bad_alloc &) {
				break;
			}
			if (0 == ptable->extremum_tag ||
				pdelnode->depth != ptable->psorts->ccategories) {
				sqlite3_reset(pstmt);
				continue;
			}
			/* compare the extremum value of header
				row and message property value */
			auto row_id = pdelnode->parent_id;
			type = ptable->psorts->psort[
				ptable->psorts->ccategories].type;
			parent_id = sqlite3_column_int64(pstmt, 6);
			pvalue = common_util_column_sqlite_statement(pstmt, 12, type);
			sqlite3_reset(pstmt);
			table_sort = ptable->psorts->psort[
				ptable->psorts->ccategories].table_sort;
			pvalue1 = db_engine_get_extremum_value(db, ptable->cpid,
							ptable->table_id, ptable->extremum_tag,
							pdelnode->parent_id, table_sort);
			if (db_engine_compare_propval(type, pvalue, pvalue1) == 0)
				continue;
			if (pvalue1 == nullptr)
				sqlite3_bind_null(stm_set_extremum, 1);
			else if (!common_util_bind_sqlite_statement(stm_set_extremum, 1, type, pvalue1))
				break;
			sqlite3_bind_int64(stm_set_extremum, 2, row_id);
			if (stm_set_extremum.step() != SQLITE_DONE)
				break;
			sqlite3_reset(stm_set_extremum);
			table_sort = ptable->psorts->psort[
				ptable->psorts->ccategories - 1].table_sort;
			prev_id = -parent_id;

			uint64_t row_id1 = 0;
			bool b_break = false;
			stm_sel_ex.bind_int64(1, prev_id);

			while (stm_sel_ex.step() == SQLITE_ROW) {
				if (stm_sel_ex.col_uint64(0) != row_id &&
				    row_id1 != 0 && row_id != row_id1)
					prev_id = row_id1;
				row_id1 = stm_sel_ex.col_int64(0);
				if (row_id1 != row_id) {
					pvalue = common_util_column_sqlite_statement(stm_sel_ex, 2, type);
					auto result = db_engine_compare_propval(type, pvalue, pvalue1);
					auto asc = table_sort == TABLE_SORT_ASCEND;
					if ((asc && result > 0) || (!asc && result < 0)) {
						b_break = TRUE;
						break;
					}
				}
				stm_sel_ex.reset();
				stm_sel_ex.bind_int64(1, row_id1);
			}
			stm_sel_ex.reset();
			if (row_id == row_id1)
				continue;
			if (!b_break) {
				prev_id = row_id1;
				row_id1 = 0;
			}
			sqlite3_bind_int64(pstmt, 1, row_id);
			if (pstmt.step() != SQLITE_ROW)
				break;
			prev_id1 = sqlite3_column_int64(pstmt, 2);
			sqlite3_reset(pstmt);
			if (prev_id == prev_id1)
				continue;
			b_resorted = TRUE;
			/* position within the list has been changed */
			if (0 != row_id1) {
				stm_upd_previd.bind_null(1);
				stm_upd_previd.bind_int64(2, row_id1);
				if (stm_upd_previd.step() != SQLITE_DONE)
					break;
				sqlite3_reset(stm_upd_previd);
			}
			stm_upd_previd.bind_int64(1, prev_id);
			stm_upd_previd.bind_int64(2, row_id);
			if (stm_upd_previd.step() != SQLITE_DONE)
				break;
			stm_upd_previd.reset();
			snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET prev_id=%lld"
					" WHERE prev_id=%llu", ptable->table_id,
					LLD{prev_id1}, LLU{row_id});
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				break;
			if (0 != row_id1) {
				stm_upd_previd.bind_int64(1, row_id);
				stm_upd_previd.bind_int64(2, row_id1);
				if (stm_upd_previd.step() != SQLITE_DONE)
					break;
				stm_upd_previd.reset();
			}
		}
		pstmt.finalize();
		stm_del_tblrow.finalize();
		if (0 != ptable->extremum_tag) {
			stm_set_extremum.finalize();
			stm_upd_previd.finalize();
			stm_sel_ex.finalize();
		}
		if (del_iter != del_list.size())
			/* Iteration through del_list stopped half-way */
			continue;
		}

		/* Part 4 */
		{
		if (b_index) {
			char sql_string[1024];
			snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET idx=NULL", ptable->table_id);
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				continue;
			snprintf(sql_string, std::size(sql_string), "SELECT row_id, row_stat"
					" FROM t%u WHERE prev_id=?", ptable->table_id);
			auto stm_sel = pdb->eph_prep(sql_string);
			if (stm_sel == nullptr)
				continue;
			snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET"
				" idx=? WHERE row_id=?", ptable->table_id);
			auto stm_upd = pdb->eph_prep(sql_string);
			if (stm_upd == nullptr)
				continue;
			uint32_t idx = 0;
			sqlite3_bind_int64(stm_sel, 1, 0);
			if (stm_sel.step() == SQLITE_ROW &&
			    !common_util_indexing_sub_contents(ptable->psorts->ccategories,
			    stm_sel, stm_upd, &idx))
				continue;
		}
		if (sql_savepoint.commit() != SQLITE_OK)
			continue;
		if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS)
			continue;
		if (b_resorted) {
			dg_mod.db_notify.type = ptable->b_search ?
			                           db_notify_type::srchtbl_changed :
			                           db_notify_type::cttbl_changed;
			notifq.emplace_back(dg_mod, table_to_idarray(*ptable));
			continue;
		}
		}

		/* Part 5 */
		{
		for (const auto &delnode : del_list) {
			auto pdelnode = &delnode;
			if (pdelnode->idx == 0)
				continue;
			if (!ptable->b_search) {
				pdeleted_row->row_folder_id = folder_id;
			} else if ((pdelnode->inst_id & NFID_UPPER_PART) == 0) {
				if (!common_util_get_message_parent_folder(
				    pdb->psqlite, pdelnode->inst_id,
				    &pdeleted_row->row_folder_id))
					continue;
			} else {
				pdeleted_row->row_folder_id = folder_id;
			}
			pdeleted_row->row_message_id = pdelnode->inst_id;
			pdeleted_row->row_instance = pdelnode->inst_num;
			dg_del.db_notify.type = ptable->b_search ?
			                          db_notify_type::srchtbl_row_deleted :
			                          db_notify_type::cttbl_row_deleted;
			notifq.emplace_back(dg_del, table_to_idarray(*ptable));
		}
		if (notify_list.empty())
			continue;
		}

		/* Part 6 */
		{
		char sql_string[1024];
		snprintf(sql_string, std::size(sql_string), "SELECT * FROM"
		         " t%u WHERE idx=?", ptable->table_id);
		auto sel_by_idx = pdb->eph_prep(sql_string);
		if (sel_by_idx == nullptr)
			continue;
		snprintf(sql_string, std::size(sql_string), "SELECT * FROM "
		         "t%u WHERE row_id=?", ptable->table_id);
		auto sel_by_row = pdb->eph_prep(sql_string);
		if (sel_by_row == nullptr)
			continue;
		for (const auto &[_, row_id] : notify_list) {
			sel_by_row.bind_int64(1, row_id);
			if (sel_by_row.step() != SQLITE_ROW) {
				sel_by_row.reset();
				continue;
			} else if (sqlite3_column_type(sel_by_row, 1) == SQLITE_NULL) {
				sel_by_row.reset();
				continue;
			}
			uint32_t idx = sel_by_row.col_int64(1);
			uint64_t inst_id = 0;
			uint32_t inst_num = 0;
			if (idx != 1) {
				sel_by_idx.bind_int64(1, idx - 1);
				if (sel_by_idx.step() != SQLITE_ROW) {
					sel_by_idx.reset();
					sel_by_row.reset();
					continue;
				}
				inst_id  = sel_by_idx.col_int64(3);
				inst_num = sel_by_idx.col_int64(10);
				sel_by_idx.reset();
			}
			pmodified_row->row_message_id = sel_by_row.col_int64(3);
			pmodified_row->after_row_id = inst_id;
			pmodified_row->after_instance = inst_num;
			dg_mod.db_notify.type = ptable->b_search ?
			                           db_notify_type::srchtbl_row_modified :
			                           db_notify_type::cttbl_row_modified;
			notifq.emplace_back(dg_mod, table_to_idarray(*ptable));
			sel_by_row.reset();
		}
		}
	}
	if (sql_transact_eph.commit() != SQLITE_OK)
		mlog(LV_ERR, "E-2163: failed to commit cttbl_delete_row");
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

void db_conn::notify_message_deletion(uint64_t folder_id, uint64_t message_id,
    db_base &dbase, db_conn::NOTIFQ &notifq) try
{
	auto pdb = this;
	auto dir = exmdb_server::get_dir();
	auto parrays = db_engine_classify_id_array(dbase,
	               fnevObjectDeleted, folder_id, message_id);
	if (parrays.size() > 0) {
		DB_NOTIFY_DATAGRAM datagram;
		datagram.dir = deconst(dir);
		datagram.db_notify.type = db_notify_type::message_deleted;
		auto pdeleted_mail = &datagram.db_notify.pdata.emplace<DB_NOTIFY_MESSAGE_DELETED>();
		pdeleted_mail->folder_id = folder_id;
		pdeleted_mail->message_id = message_id;
		notifq.emplace_back(std::move(datagram), std::move(parrays));
	}
	dbeng_notify_cttbl_delete_row(*pdb, folder_id, message_id, dbase, notifq);
	pdb->notify_folder_modification(common_util_get_folder_parent_fid(
		pdb->psqlite, folder_id), folder_id, dbase, notifq);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

void db_conn::notify_link_deletion(uint64_t parent_id, uint64_t message_id,
    db_base &dbase, db_conn::NOTIFQ &notifq) try
{
	auto pdb = this;
	uint64_t folder_id;
	
	if (!common_util_get_message_parent_folder(pdb->psqlite,
	    message_id, &folder_id))
		return;

	auto dir = exmdb_server::get_dir();
	auto parrays = db_engine_classify_id_array(dbase,
	               fnevObjectDeleted, folder_id, message_id);
	if (parrays.size() > 0) {
		DB_NOTIFY_DATAGRAM datagram;
		datagram.dir = deconst(dir);
		datagram.db_notify.type = db_notify_type::link_deleted;
		auto punlinked_mail = &datagram.db_notify.pdata.emplace<DB_NOTIFY_LINK_DELETED>();
		punlinked_mail->folder_id = folder_id;
		punlinked_mail->message_id = message_id;
		punlinked_mail->parent_id = parent_id;
		notifq.emplace_back(std::move(datagram), std::move(parrays));
	}
	dbeng_notify_cttbl_delete_row(*pdb, parent_id, message_id, dbase, notifq);
	pdb->notify_folder_modification(common_util_get_folder_parent_fid(
		pdb->psqlite, parent_id), parent_id, dbase, notifq);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

static void dbeng_notify_hiertbl_delete_row(db_conn &db, uint64_t parent_id,
    uint64_t folder_id, const db_base &dbase, db_conn::NOTIFQ &notifq) try
{
	auto pdb = &db;
	int idx;
	BOOL b_included;
	char sql_string[256];
	DB_NOTIFY_DATAGRAM datagram = {deconst(exmdb_server::get_dir()), TRUE, {0}};
	DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED *pdeleted_row;
	
	pdeleted_row = NULL;
	auto sql_transact_eph = gx_sql_begin(pdb->m_sqlite_eph, txn_mode::write);
	if (!sql_transact_eph) {
		mlog(LV_ERR, "E-2168: failed to start transaction in hiertbl_delete_row");
		return;
	}
	for (const auto &tnode : dbase.tables.table_list) {
		auto ptable = &tnode;
		if (ptable->type != table_type::hierarchy)
			continue;
		if (TABLE_FLAG_DEPTH & ptable->table_flags) {
			if (!cu_is_descendant_folder(pdb->psqlite,
			    parent_id, ptable->folder_id, &b_included) ||
			    !b_included)
				continue;
		} else {
			if (parent_id != ptable->folder_id)
				continue;
		}
		snprintf(sql_string, std::size(sql_string), "SELECT idx FROM t%u "
			"WHERE folder_id=%llu", ptable->table_id, LLU{folder_id});
		auto pstmt = pdb->eph_prep(sql_string);
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
			continue;	
		idx = sqlite3_column_int64(pstmt, 0);
		pstmt.finalize();
		snprintf(sql_string, std::size(sql_string), "DELETE FROM t%u WHERE "
			"folder_id=%llu", ptable->table_id, LLU{folder_id});
		if (pdb->eph_exec(sql_string) != SQLITE_OK)
			continue;
		snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET idx=-(idx-1)"
			" WHERE idx>%u;UPDATE t%u SET idx=-idx WHERE"
			" idx<0", ptable->table_id, idx, ptable->table_id);
		if (pdb->eph_exec(sql_string) != SQLITE_OK)
			continue;
		snprintf(sql_string, std::size(sql_string), "UPDATE sqlite_sequence SET seq="
			"(SELECT count(*) FROM t%u) WHERE name='t%u'",
			ptable->table_id, ptable->table_id);
		if (pdb->eph_exec(sql_string) != SQLITE_OK)
			/* I guess ignore it? Autoincrement is just higher than expected. */;
		if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS)
			continue;
		if (ptable->table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
			auto h = exmdb_server::get_handle();
			if (h != nullptr && *h == ptable->handle_guid)
				continue;
		}
		if (NULL == pdeleted_row) {
			datagram.db_notify.type = db_notify_type::hiertbl_row_deleted;
			pdeleted_row = &datagram.db_notify.pdata.emplace<DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED>();
			pdeleted_row->row_folder_id = folder_id;
		}
		datagram.id_array[0] = ptable->table_id; // reserved earlier
		notifq.emplace_back(datagram, table_to_idarray(*ptable));
	}
	if (sql_transact_eph.commit() != SQLITE_OK)
		mlog(LV_ERR, "E-2169: failed to commit hiertbl_delete_row");
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

void db_conn::notify_folder_deletion(uint64_t parent_id, uint64_t folder_id,
    const db_base &dbase, NOTIFQ &notifq) try
{
	auto pdb = this;
	auto dir = exmdb_server::get_dir();
	auto parrays = db_engine_classify_id_array(dbase,
	               fnevObjectDeleted, parent_id, 0);
	if (parrays.size() > 0) {
		DB_NOTIFY_DATAGRAM datagram;
		datagram.dir = deconst(dir);
		datagram.db_notify.type = db_notify_type::folder_deleted;
		auto pdeleted_folder = &datagram.db_notify.pdata.emplace<DB_NOTIFY_FOLDER_DELETED>();
		pdeleted_folder->parent_id = parent_id;
		pdeleted_folder->folder_id = folder_id;
		notifq.emplace_back(std::move(datagram), std::move(parrays));
	}
	dbeng_notify_hiertbl_delete_row(*pdb, parent_id, folder_id, dbase, notifq);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

static void dbeng_notify_cttbl_modify_row(db_conn &db, uint64_t folder_id,
    uint64_t message_id, db_base &dbase, db_conn::NOTIFQ &notifq) try
{
	auto pdb = &db;
	int row_type;
	BOOL b_error;
	uint32_t idx;
	void *pvalue, *pvalue1 = nullptr;
	uint16_t type;
	void *pmultival;
	int64_t prev_id;
	uint64_t row_id1, inst_id = 0, inst_id1 = 0;
	uint8_t read_byte;
	uint32_t inst_num, multi_num = 0;
	uint64_t parent_id;
	int8_t unread_delta;
	std::list<table_node> tmp_list;
	char sql_string[1024];
	uint64_t row_folder_id;
	DB_NOTIFY_DATAGRAM datagram = {deconst(exmdb_server::get_dir()), TRUE, {0}};
	TAGGED_PROPVAL propvals[MAXIMUM_SORT_COUNT];
	DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED *pmodified_row;
	
	pmodified_row = NULL;
	auto sql_transact_eph = gx_sql_begin(pdb->m_sqlite_eph, txn_mode::write);
	if (!sql_transact_eph) {
		mlog(LV_ERR, "E-2164: failed to start transaction in cttbl_modify_row");
		return;
	}
	for (const auto &tnode : dbase.tables.table_list) {
		auto ptable = &tnode;
		if (ptable->type != table_type::content ||
		    folder_id != ptable->folder_id)
			continue;
		if (ptable->instance_tag == 0)
			snprintf(sql_string, std::size(sql_string), "SELECT count(*) "
				"FROM t%u WHERE inst_id=%llu AND inst_num=0",
				ptable->table_id, LLU{message_id});
		else
			snprintf(sql_string, std::size(sql_string), "SELECT count(*)"
							" FROM t%u WHERE inst_id=%llu",
							ptable->table_id, LLU{message_id});
		auto pstmt = pdb->eph_prep(sql_string);
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW ||
		    sqlite3_column_int64(pstmt, 0) == 0)
			continue;
		pstmt.finalize();
		if (NULL == pmodified_row) {
			pmodified_row = &datagram.db_notify.pdata.emplace<DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED>();
			if (!common_util_get_message_parent_folder(pdb->psqlite,
			    message_id, &row_folder_id))
				return;
		}
		datagram.id_array[0] = ptable->table_id; // reserved earlier
		if (NULL == ptable->psorts) {
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS)
				continue;
			pmodified_row->row_folder_id = row_folder_id;
			pmodified_row->row_message_id = message_id;
			pmodified_row->row_instance = 0;
			snprintf(sql_string, std::size(sql_string), "SELECT idx FROM "
					"t%u WHERE inst_id=%llu AND inst_num=0",
					ptable->table_id, LLU{message_id});
			pstmt = pdb->eph_prep(sql_string);
			if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
				continue;
			idx = sqlite3_column_int64(pstmt, 0);
			pstmt.finalize();
			if (1 == idx) {
				pmodified_row->after_row_id = 0;
				pmodified_row->after_folder_id = 0;
			} else {
				snprintf(sql_string, std::size(sql_string), "SELECT inst_id FROM "
					"t%u WHERE idx=%u", ptable->table_id, idx - 1);
				pstmt = pdb->eph_prep(sql_string);
				if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
					continue;
				pmodified_row->after_row_id =
					sqlite3_column_int64(pstmt, 0);
				if (!common_util_get_message_parent_folder(pdb->psqlite,
				    pmodified_row->after_row_id, &pmodified_row->after_folder_id))
					continue;
				pstmt.finalize();
			}
			pmodified_row->after_instance = 0;
			datagram.db_notify.type = ptable->b_search ?
			                          db_notify_type::srchtbl_row_modified :
			                          db_notify_type::cttbl_row_modified;
			notifq.emplace_back(datagram, table_to_idarray(*ptable));
			continue;
		} else if (0 == ptable->psorts->ccategories) {
			size_t i;
			for (i=0; i<ptable->psorts->count; i++) {
				propvals[i].proptag = PROP_TAG(ptable->psorts->psort[i].type, ptable->psorts->psort[i].propid);
				if (!cu_get_property(MAPI_MESSAGE, message_id,
				    ptable->cpid, db, propvals[i].proptag,
				    &propvals[i].pvalue))
					break;
			}
			if (i < ptable->psorts->count)
				continue;
			snprintf(sql_string, std::size(sql_string), "SELECT idx FROM "
					"t%u WHERE inst_id=%llu AND inst_num=0",
					ptable->table_id, LLU{message_id});
			pstmt = pdb->eph_prep(sql_string);
			if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
				continue;
			idx = sqlite3_column_int64(pstmt, 0);
			pstmt.finalize();
			snprintf(sql_string, std::size(sql_string), "SELECT inst_id"
				" FROM t%u WHERE idx=?", ptable->table_id);
			pstmt = pdb->eph_prep(sql_string);
			if (pstmt == nullptr)
				continue;
			if (1 == idx) {
				inst_id = 0;
			} else {
				sqlite3_bind_int64(pstmt, 1, idx - 1);
				if (pstmt.step() != SQLITE_ROW)
					continue;
				inst_id = sqlite3_column_int64(pstmt, 0);
				sqlite3_reset(pstmt);
			}
			sqlite3_bind_int64(pstmt, 1, idx + 1);
			inst_id1 = pstmt.step() != SQLITE_ROW ? 0 :
			           sqlite3_column_int64(pstmt, 0);
			pstmt.finalize();
			b_error = FALSE;
			for (i=0; i<ptable->psorts->count; i++) {
				if (inst_id == 0)
					continue;
				if (!cu_get_property(MAPI_MESSAGE, inst_id,
					ptable->cpid, db,
					propvals[i].proptag, &pvalue)) {
					b_error = TRUE;
					break;
				}
				auto result = db_engine_compare_propval(
					ptable->psorts->psort[i].type,
					propvals[i].pvalue, pvalue);
				auto asc = ptable->psorts->psort[i].table_sort == TABLE_SORT_ASCEND;
				if ((asc && result < 0) || (!asc && result > 0))
					goto REFRESH_TABLE;
				if (result != 0)
					break;
			}
			if (b_error)
				continue;
			for (i=0; i<ptable->psorts->count; i++) {
				if (inst_id1 == 0)
					continue;
				if (!cu_get_property(MAPI_MESSAGE, inst_id1,
					ptable->cpid, db,
					propvals[i].proptag, &pvalue)) {
					b_error = TRUE;
					break;
				}
				auto result = db_engine_compare_propval(
					ptable->psorts->psort[i].type,
					propvals[i].pvalue, pvalue);
				auto asc = ptable->psorts->psort[i].table_sort == TABLE_SORT_ASCEND;
				if ((asc && result > 0) || (!asc && result < 0))
					goto REFRESH_TABLE;
				if (result != 0)
					break;
			}
			if (b_error)
				continue;
			pmodified_row->row_folder_id = row_folder_id;
			pmodified_row->row_message_id = message_id;
			pmodified_row->row_instance = 0;
			pmodified_row->after_row_id = inst_id;
			if (pmodified_row->after_row_id == 0)
				pmodified_row->after_folder_id = 0;
			else if (!common_util_get_message_parent_folder(pdb->psqlite,
			     pmodified_row->after_row_id, &pmodified_row->after_folder_id))
				continue;
			pmodified_row->after_instance = 0;
			datagram.db_notify.type = ptable->b_search ?
			                          db_notify_type::srchtbl_row_modified :
			                          db_notify_type::cttbl_row_modified;
			notifq.emplace_back(datagram, table_to_idarray(*ptable));
			continue;
		}
		{
		/* check if the multiple instance value is changed */
		if (0 != ptable->instance_tag) {
			type = PROP_TYPE(ptable->instance_tag) & ~MVI_FLAG;
			if (!cu_get_property(MAPI_MESSAGE,
			    message_id, ptable->cpid, db,
			    ptable->instance_tag & ~MV_INSTANCE, &pmultival))
				continue;
			if (NULL != pmultival) {
				/*
				 * Original code in this section tested for PT_SHORT and
				 * did nothing with PT_MV_SHORT, hence we're using ^MV_FLAG
				 * to reuse det_multi_num to the same effect.
				 */
				multi_num = det_multi_num(type ^ MV_FLAG, pmultival);
				if (multi_num == 0 || multi_num == UINT32_MAX) {
					pmultival = NULL;
					multi_num = 1;
				}
			} else {
				multi_num = 1;
			}
			snprintf(sql_string, std::size(sql_string), "SELECT value, "
			         "inst_num FROM t%u WHERE inst_id=%llu",
			         ptable->table_id, LLU{message_id});
			pstmt = pdb->eph_prep(sql_string);
			if (pstmt == nullptr)
				continue;
			while (pstmt.step() == SQLITE_ROW) {
				pvalue = common_util_column_sqlite_statement(
				         pstmt, 0, type);
				inst_num = sqlite3_column_int64(pstmt, 1);
				if (NULL == pmultival) {
					if (0 != inst_num) {
						pstmt.finalize();
						goto REFRESH_TABLE;
					}
					continue;
				}
				if (0 == inst_num || inst_num > multi_num) {
					pstmt.finalize();
					goto REFRESH_TABLE;
				}
				pvalue1 = pick_single_val(type ^ MV_FLAG, pmultival, inst_num - 1);
				if (0 != db_engine_compare_propval(
				    type, pvalue, pvalue1)) {
					pstmt.finalize();
					goto REFRESH_TABLE;
				}
			}
			pstmt.finalize();
		} else {
			multi_num = 1;
		}
		size_t i;
		for (i = 0; i < ptable->psorts->count; i++) {
			propvals[i].proptag = PROP_TAG(ptable->psorts->psort[i].type, ptable->psorts->psort[i].propid);
			if (propvals[i].proptag == ptable->instance_tag)
				propvals[i].pvalue = NULL;
			else if (!cu_get_property(MAPI_MESSAGE, message_id,
			    ptable->cpid, db, propvals[i].proptag,
			    &propvals[i].pvalue))
				break;
		}
		if (i < ptable->psorts->count)
			continue;
		snprintf(sql_string, std::size(sql_string), "SELECT parent_id, value "
		         "FROM t%u WHERE row_id=?", ptable->table_id);
		pstmt = pdb->eph_prep(sql_string);
		if (pstmt == nullptr)
			continue;
		snprintf(sql_string, std::size(sql_string), "SELECT row_id, prev_id,"
		         " extremum FROM t%u WHERE inst_id=%llu AND"
		         " inst_num=?", ptable->table_id, LLU{message_id});
		auto pstmt1 = pdb->eph_prep(sql_string);
		if (pstmt1 == nullptr)
			continue;
		b_error = FALSE;

		std::vector<rowinfo_node> notify_list;
		for (i = 0; i < multi_num; i++) {
			inst_num = ptable->instance_tag == 0 || pmultival == nullptr ? 0 : i + 1;
			sqlite3_bind_int64(pstmt1, 1, inst_num);
			if (pstmt1.step() != SQLITE_ROW) {
				b_error = TRUE;
				break;
			}
			uint64_t row_id = sqlite3_column_int64(pstmt1, 0);
			prev_id = sqlite3_column_int64(pstmt1, 1);
			read_byte = sqlite3_column_int64(pstmt1, 2);
			sqlite3_reset(pstmt1);
			row_id1 = row_id;
			sqlite3_bind_int64(pstmt, 1, row_id);
			if (pstmt.step() != SQLITE_ROW) {
				b_error = TRUE;
				break;
			}
			row_id = sqlite3_column_int64(pstmt, 0);
			parent_id = row_id;
			sqlite3_reset(pstmt);
			for (ssize_t j = ptable->psorts->ccategories - 1; j >= 0; --j) {
				sqlite3_bind_int64(pstmt, 1, row_id);
				if (pstmt.step() != SQLITE_ROW) {
					b_error = TRUE;
					break;
				}
				row_id = sqlite3_column_int64(pstmt, 0);
				if (propvals[j].proptag == ptable->instance_tag) {
					sqlite3_reset(pstmt);
					continue;
				}
				pvalue = common_util_column_sqlite_statement(
				         pstmt, 1, ptable->psorts->psort[j].type);
				sqlite3_reset(pstmt);
				if (0 != db_engine_compare_propval(
				    ptable->psorts->psort[j].type,
				    pvalue, propvals[j].pvalue)) {
					pstmt.finalize();
					pstmt1.finalize();
					goto REFRESH_TABLE;
				}
			}
			if (b_error)
				break;
			if (0 != ptable->extremum_tag) {
				snprintf(sql_string, std::size(sql_string), "SELECT extremum FROM t%u"
				         " WHERE row_id=%llu", ptable->table_id, LLU{parent_id});
				auto pstmt2 = pdb->eph_prep(sql_string);
				if (pstmt2 == nullptr || pstmt2.step() != SQLITE_ROW) {
					b_error = TRUE;
					break;
				}
				pvalue = common_util_column_sqlite_statement(
				         pstmt2, 0, PROP_TYPE(ptable->extremum_tag));
				pstmt2.finalize();
				auto result = db_engine_compare_propval(
				         PROP_TYPE(ptable->extremum_tag), pvalue,
				         propvals[ptable->psorts->ccategories].pvalue);
				if (TABLE_SORT_MAXIMUM_CATEGORY == ptable->psorts->psort[
					ptable->psorts->ccategories].table_sort) {
					if (result < 0) {
						pstmt.finalize();
						pstmt1.finalize();
						goto REFRESH_TABLE;
					}
				} else if (result > 0) {
					pstmt.finalize();
					pstmt1.finalize();
					goto REFRESH_TABLE;
				}
			}
			i = ptable->psorts->ccategories;
			if (ptable->extremum_tag != 0)
				++i;
			if (ptable->psorts->count > i) {
				if (prev_id <= 0) {
					inst_id = 0;
				} else {
					snprintf(sql_string, std::size(sql_string), "SELECT inst_id FROM"
					         " t%u WHERE row_id=%lld", ptable->table_id, LLD{prev_id});
					auto pstmt2 = pdb->eph_prep(sql_string);
					if (pstmt2 == nullptr  || pstmt2.step() != SQLITE_ROW) {
						b_error = TRUE;
						break;
					}
					inst_id = sqlite3_column_int64(pstmt2, 0);
				}
				snprintf(sql_string, std::size(sql_string), "SELECT inst_id FROM t%u"
				         " WHERE prev_id=%llu", ptable->table_id, LLU{row_id1});
				auto pstmt2 = pdb->eph_prep(sql_string);
				if (pstmt2 == nullptr) {
					b_error = TRUE;
					break;
				}
				inst_id1 = pstmt2.step() != SQLITE_ROW ? 0 :
				           sqlite3_column_int64(pstmt2, 0);
			}
			for (; i < ptable->psorts->count; i++) {
				if (inst_id == 0)
					continue;
				if (!cu_get_property(MAPI_MESSAGE, inst_id,
				    ptable->cpid, db,
				    propvals[i].proptag, &pvalue)) {
					b_error = TRUE;
					break;
				}
				auto result = db_engine_compare_propval(
				         ptable->psorts->psort[i].type,
				         propvals[i].pvalue, pvalue);
				auto asc = ptable->psorts->psort[i].table_sort == TABLE_SORT_ASCEND;
				if ((asc && result < 0) || (!asc && result > 0)) {
					pstmt.finalize();
					pstmt1.finalize();
					goto REFRESH_TABLE;
				}
				if (result != 0)
					break;
			}
			if (b_error)
				break;
			i = ptable->psorts->ccategories;
			if (ptable->extremum_tag != 0)
				++i;
			for (; i < ptable->psorts->count; i++) {
				if (inst_id1 == 0)
					continue;
				if (!cu_get_property(MAPI_MESSAGE, inst_id1,
				    ptable->cpid, db,
				    propvals[i].proptag, &pvalue)) {
					b_error = TRUE;
					break;
				}
				auto result = db_engine_compare_propval(
				         ptable->psorts->psort[i].type,
				         propvals[i].pvalue, pvalue);
				auto asc = ptable->psorts->psort[i].table_sort == TABLE_SORT_ASCEND;
				if ((asc && result > 0) || (!asc && result < 0)) {
					pstmt.finalize();
					pstmt1.finalize();
					goto REFRESH_TABLE;
				}
				if (result != 0)
					break;
			}
			if (b_error)
				break;
			if (!cu_get_property(MAPI_MESSAGE, message_id,
			    CP_ACP, db, PR_READ, &pvalue) ||
			    pvalue == nullptr) {
				b_error = TRUE;
				break;
			}
			if (*static_cast<uint8_t *>(pvalue) == 0 && read_byte != 0) {
				unread_delta = 1;
				snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET extremum=0 "
				         "WHERE row_id=%llu", ptable->table_id, LLU{row_id1});
			} else if (*static_cast<uint8_t *>(pvalue) != 0 && read_byte == 0) {
				unread_delta = -1;
				snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET extremum=1 "
				         "WHERE row_id=%llu", ptable->table_id, LLU{row_id1});
			} else {
				unread_delta = 0;
			}
			if (unread_delta != 0 &&
			    pdb->eph_exec(sql_string) != SQLITE_OK) {
				b_error = TRUE;
				break;
			}
			row_id = row_id1;
			while (0 != unread_delta) {
				sqlite3_bind_int64(pstmt, 1, row_id);
				if (pstmt.step() != SQLITE_ROW) {
					b_error = TRUE;
					break;
				}
				row_id = sqlite3_column_int64(pstmt, 0);
				sqlite3_reset(pstmt);
				if (row_id == 0)
					break;
				if (unread_delta > 0)
					snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET unread=unread+1"
					         " WHERE row_id=%llu", ptable->table_id, LLU{row_id});
				else
					snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET unread=unread-1"
					         " WHERE row_id=%llu", ptable->table_id, LLU{row_id});
				if (pdb->eph_exec(sql_string) != SQLITE_OK) {
					b_error = TRUE;
					break;
				}
				notify_list.emplace_back(false, row_id);
			}
			if (b_error)
				break;
			notify_list.emplace_back(false, row_id1);
		}
		pstmt.finalize();
		pstmt1.finalize();
		if (b_error)
			continue;
		snprintf(sql_string, std::size(sql_string), "SELECT * FROM"
		         " t%u WHERE idx=?", ptable->table_id);
		pstmt = pdb->eph_prep(sql_string);
		if (pstmt == nullptr)
			continue;
		snprintf(sql_string, std::size(sql_string), "SELECT * FROM "
		         "t%u WHERE row_id=?", ptable->table_id);
		pstmt1 = pdb->eph_prep(sql_string);
		if (pstmt1 == nullptr)
			continue;

		for (const auto &[_, row_id] : notify_list) {
			sqlite3_bind_int64(pstmt1, 1, row_id);
			if (pstmt1.step() != SQLITE_ROW) {
				sqlite3_reset(pstmt1);
				continue;
			}
			/* row does not have an idx, it's invisible */
			if (SQLITE_NULL == sqlite3_column_type(pstmt1, 1)) {
				sqlite3_reset(pstmt1);
				continue;
			}
			idx = sqlite3_column_int64(pstmt1, 1);
			if (1 == idx) {
				inst_id = 0;
				inst_num = 0;
			} else {
				sqlite3_bind_int64(pstmt, 1, idx - 1);
				if (pstmt.step() != SQLITE_ROW) {
					sqlite3_reset(pstmt);
					sqlite3_reset(pstmt1);
					continue;
				}
				inst_id = sqlite3_column_int64(pstmt, 3);
				row_type = sqlite3_column_int64(pstmt, 4);
				inst_num = sqlite3_column_int64(pstmt, 10);
				sqlite3_reset(pstmt);
			}
			pmodified_row->row_message_id =
				sqlite3_column_int64(pstmt1, 3);
			pmodified_row->row_instance =
				sqlite3_column_int64(pstmt1, 10);
			pmodified_row->row_folder_id = sqlite3_column_int64(pstmt1, 4) == CONTENT_ROW_MESSAGE ?
			                               row_folder_id : folder_id;
			pmodified_row->after_row_id = inst_id;
			if (0 == inst_id) {
				pmodified_row->after_folder_id = 0;
			} else if (row_type == CONTENT_ROW_MESSAGE) {
				if (!common_util_get_message_parent_folder(
				    pdb->psqlite, pmodified_row->after_row_id,
				    &pmodified_row->after_folder_id)) {
					sqlite3_reset(pstmt1);
					continue;
				}
			} else {
				pmodified_row->after_folder_id = folder_id;
			}
			pmodified_row->after_instance = inst_num;
			datagram.db_notify.type = ptable->b_search ?
			                          db_notify_type::srchtbl_row_modified :
			                          db_notify_type::cttbl_row_modified;
			notifq.emplace_back(datagram, table_to_idarray(*ptable));
			sqlite3_reset(pstmt1);
		}
		continue;
		}
 REFRESH_TABLE:
		auto &stor = tmp_list.emplace_back(*ptable, table_node::clone_t{});
		if (ptable->psorts->ccategories != 0)
			stor.table_flags |= TABLE_FLAG_NONOTIFICATIONS;

		/* Else, some methods will need to be written */
		static_assert(!std::is_copy_constructible_v<table_node>);
		static_assert(!std::is_copy_assignable_v<table_node>);
		static_assert(!std::is_move_constructible_v<table_node>);
		static_assert(!std::is_move_assignable_v<table_node>);
	}
	if (sql_transact_eph.commit() != SQLITE_OK)
		mlog(LV_ERR, "E-2165: failed to commit cttbl_modify_row");
	if (tmp_list.empty())
		return;
	std::swap(dbase.tables.table_list, tmp_list);
	dbeng_notify_cttbl_delete_row(db, folder_id, message_id, dbase, notifq);
	dbeng_notify_cttbl_add_row(db, folder_id, message_id, dbase, notifq);
	std::swap(dbase.tables.table_list, tmp_list);
	for (const auto &tnode : tmp_list) {
		auto ptable = &tnode;
		datagram.id_array[0] = ptable->table_id; // reserved earlier
		for (auto &tnode1 : dbase.tables.table_list) {
			auto ptnode = &tnode1;
			if (ptable->table_id != ptnode->table_id)
				continue;
			ptnode->header_id = ptable->header_id;
			if (ptable->psorts->ccategories == 0 ||
			    (ptnode->table_flags & TABLE_FLAG_NONOTIFICATIONS))
				break;
			datagram.db_notify.type = ptnode->b_search ?
			                          db_notify_type::srchtbl_changed :
			                          db_notify_type::cttbl_changed;
			notifq.emplace_back(datagram, table_to_idarray(*ptable));
			break;
		}
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

void db_conn::notify_message_modification(uint64_t folder_id, uint64_t message_id,
    db_base &dbase, NOTIFQ &notifq) try
{
	auto pdb = this;
	auto dir = exmdb_server::get_dir();
	auto parrays = db_engine_classify_id_array(dbase,
	               fnevObjectModified, folder_id, message_id);
	if (parrays.size() > 0) {
		DB_NOTIFY_DATAGRAM datagram;
		datagram.dir = deconst(dir);
		datagram.db_notify.type = db_notify_type::message_modified;
		auto pmodified_mail = &datagram.db_notify.pdata.emplace<DB_NOTIFY_MESSAGE_MODIFIED>();
		pmodified_mail->folder_id = folder_id;
		pmodified_mail->message_id = message_id;
		pmodified_mail->proptags.count = 0;
		notifq.emplace_back(std::move(datagram), std::move(parrays));
	}
	dbeng_notify_cttbl_modify_row(*pdb, folder_id, message_id, dbase, notifq);
	pdb->notify_folder_modification(common_util_get_folder_parent_fid(
		pdb->psqlite, folder_id), folder_id, dbase, notifq);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

static void dbeng_notify_hiertbl_modify_row(const db_conn &db,
    uint64_t parent_id, uint64_t folder_id, const db_base &dbase,
    db_conn::NOTIFQ &notifq) try
{
	auto pdb = &db;
	int idx;
	BOOL b_included;
	char sql_string[256];
	DB_NOTIFY_DATAGRAM datagram  = {deconst(exmdb_server::get_dir()), TRUE, {0}};
	DB_NOTIFY_DATAGRAM datagram1 = datagram;
	DB_NOTIFY_DATAGRAM datagram2 = datagram;
	DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED *padded_row;
	DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED *pdeleted_row;
	DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED *pmodified_row;
	
	padded_row = NULL;
	pdeleted_row = NULL;
	pmodified_row = NULL;
	auto sql_transact_eph = gx_sql_begin(pdb->m_sqlite_eph, txn_mode::write);
	if (!sql_transact_eph) {
		mlog(LV_ERR, "E-2170: failed to start transaction in hiertbl_modify_row");
		return;
	}
	for (const auto &tnode : dbase.tables.table_list) {
		auto ptable = &tnode;
		if (ptable->type != table_type::hierarchy)
			continue;
		if (TABLE_FLAG_DEPTH & ptable->table_flags) {
			if (folder_id == ptable->folder_id ||
			    !cu_is_descendant_folder(pdb->psqlite,
			    folder_id, ptable->folder_id, &b_included) ||
			    !b_included)
				continue;
		} else {
			if (parent_id != ptable->folder_id)
				continue;
		}
		snprintf(sql_string, std::size(sql_string), "SELECT idx FROM t%u "
		          "WHERE folder_id=%llu", ptable->table_id, LLU{folder_id});
		auto pstmt = pdb->eph_prep(sql_string);
		if (pstmt == nullptr)
			continue;
		datagram.id_array[0] = datagram1.id_array[0] =
			datagram2.id_array[0] = ptable->table_id; // reserved earlier
		if (pstmt.step() != SQLITE_ROW) {
			pstmt.finalize();
			if (NULL != ptable->prestriction &&
			    cu_eval_folder_restriction(
			    db, folder_id, ptable->prestriction)) {
				if (NULL == padded_row) {
					datagram2.db_notify.type = db_notify_type::hiertbl_row_added;
					padded_row = &datagram2.db_notify.pdata.emplace<DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED>();
				}
				snprintf(sql_string, std::size(sql_string), "INSERT INTO t%u (folder_id)"
				        " VALUES (%llu)", ptable->table_id, LLU{folder_id});
				if (pdb->eph_exec(sql_string) != SQLITE_OK)
					continue;
				if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS)
					continue;
				if (ptable->table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
					auto h = exmdb_server::get_handle();
					if (h != nullptr && *h == ptable->handle_guid)
						continue;
				}
				idx = sqlite3_last_insert_rowid(pdb->m_sqlite_eph);
				if (1 == idx) {
					padded_row->after_folder_id = 0;
				} else {
					snprintf(sql_string, std::size(sql_string), "SELECT "
						"folder_id FROM t%u WHERE idx=%u",
						ptable->table_id, idx - 1);
					pstmt = pdb->eph_prep(sql_string);
					if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
						continue;
					padded_row->after_folder_id =
						sqlite3_column_int64(pstmt, 0);
					pstmt.finalize();
				}
				padded_row->row_folder_id = folder_id;
				notifq.emplace_back(datagram2, table_to_idarray(*ptable));
			}
			continue;
		}
		idx = sqlite3_column_int64(pstmt, 0);
		pstmt.finalize();
		if (NULL != ptable->prestriction &&
		    !cu_eval_folder_restriction(db,
		    folder_id, ptable->prestriction)) {
			xsavepoint sql_savepoint(pdb->m_sqlite_eph, "sp1");
			if (!sql_savepoint)
				continue;
			snprintf(sql_string, std::size(sql_string), "DELETE FROM t%u WHERE "
			        "folder_id=%llu", ptable->table_id, LLU{folder_id});
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				continue;
			snprintf(sql_string, std::size(sql_string), "UPDATE t%u SET idx=-(idx-1)"
				" WHERE idx>%u;UPDATE t%u SET idx=-idx WHERE"
				" idx<0", ptable->table_id, idx, ptable->table_id);
			if (pdb->eph_exec(sql_string) != SQLITE_OK)
				continue;
			snprintf(sql_string, std::size(sql_string), "UPDATE sqlite_sequence SET seq="
				"(SELECT count(*) FROM t%u) WHERE name='t%u'",
				ptable->table_id, ptable->table_id);
			pdb->eph_exec(sql_string);
			if (sql_savepoint.commit() != SQLITE_OK)
				continue;
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS)
				continue;
			if (ptable->table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
				auto h = exmdb_server::get_handle();
				if (h != nullptr && *h == ptable->handle_guid)
					continue;
			}
			if (NULL == pdeleted_row) {
				datagram1.db_notify.type = db_notify_type::hiertbl_row_deleted;
				pdeleted_row = &datagram1.db_notify.pdata.emplace<DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED>();
				pdeleted_row->row_folder_id = folder_id;
			}
			notifq.emplace_back(datagram1, table_to_idarray(*ptable));
			continue;
		}
		if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS)
			continue;
		if (ptable->table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
			auto h = exmdb_server::get_handle();
			if (h != nullptr && *h == ptable->handle_guid)
				continue;
		}
		if (NULL == pmodified_row) {
			datagram.db_notify.type = db_notify_type::hiertbl_row_modified;
			pmodified_row = &datagram.db_notify.pdata.emplace<DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED>();
			pmodified_row->row_folder_id = folder_id;
		}
		if (1 == idx) {
			pmodified_row->after_folder_id = 0;
		} else {
			snprintf(sql_string, std::size(sql_string), "SELECT folder_id FROM "
				"t%u WHERE idx=%u", ptable->table_id, idx - 1);
			pstmt = pdb->eph_prep(sql_string);
			if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
				continue;
			pmodified_row->after_folder_id =
				sqlite3_column_int64(pstmt, 0);
			pstmt.finalize();
		}
		notifq.emplace_back(datagram, table_to_idarray(*ptable));
	}
	if (sql_transact_eph.commit() != SQLITE_OK)
		mlog(LV_ERR, "E-2171: failed to commit hiertbl_modify_row");
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

void db_conn::notify_folder_modification(uint64_t parent_id, uint64_t folder_id,
    const db_base &dbase, NOTIFQ &notifq) try
{
	auto pdb = this;
	auto dir = exmdb_server::get_dir();
	auto parrays = db_engine_classify_id_array(dbase,
	               fnevObjectModified, folder_id, 0);
	if (parrays.size() > 0) {
		DB_NOTIFY_DATAGRAM datagram;
		datagram.dir = deconst(dir);
		datagram.db_notify.type = db_notify_type::folder_modified;
		auto pmodified_folder = &datagram.db_notify.pdata.emplace<DB_NOTIFY_FOLDER_MODIFIED>();
		pmodified_folder->folder_id = folder_id;
		pmodified_folder->parent_id = parent_id;
		pmodified_folder->ptotal = NULL;
		pmodified_folder->punread = NULL;
		pmodified_folder->proptags.count = 0;
		notifq.emplace_back(std::move(datagram), std::move(parrays));
	}
	dbeng_notify_hiertbl_modify_row(*pdb, parent_id, folder_id, dbase, notifq);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

void db_conn::notify_message_movecopy(BOOL b_copy, uint64_t folder_id,
    uint64_t message_id, uint64_t old_fid, uint64_t old_mid,
    db_base &dbase, NOTIFQ &notifq) try
{
	auto pdb = this;
	auto dir = exmdb_server::get_dir();

	/* open-coded db_engine_classify_id_array(4-arg) */
	ID_ARRAYS recv_list;
	for (const auto &sub : dbase.nsub_list) {
		auto pnsub = &sub;
		if (b_copy) {
			if (!(pnsub->notification_type & fnevObjectCopied))
				continue;
		} else {
			if (!(pnsub->notification_type & fnevObjectMoved))
				continue;
		}
		if (pnsub->b_whole || (pnsub->folder_id == old_fid &&
		    pnsub->message_id == old_mid)) {
			auto rid = sub.remote_id.has_value() ? sub.remote_id->c_str() : nullptr;
			recv_list[rid].push_back(pnsub->sub_id);
		}
	}
	if (recv_list.size() > 0) {
		DB_NOTIFY_DATAGRAM datagram;
		datagram.dir = deconst(dir);
		datagram.db_notify.type = b_copy ? db_notify_type::message_copied :
		                          db_notify_type::message_moved;
		auto pmvcp_mail = &datagram.db_notify.pdata.emplace<DB_NOTIFY_MESSAGE_MVCP>();
		pmvcp_mail->folder_id = folder_id;
		pmvcp_mail->message_id = message_id;
		pmvcp_mail->old_folder_id = old_fid;
		pmvcp_mail->old_message_id = old_mid;
		notifq.emplace_back(std::move(datagram), std::move(recv_list));
	}
	if (!b_copy) {
		dbeng_notify_cttbl_delete_row(*pdb, old_fid, old_mid, dbase, notifq);
		pdb->notify_folder_modification(common_util_get_folder_parent_fid(
			pdb->psqlite, old_fid), old_fid, dbase, notifq);
	}
	dbeng_notify_cttbl_add_row(*pdb, folder_id, message_id, dbase, notifq);
	pdb->notify_folder_modification(common_util_get_folder_parent_fid(
		pdb->psqlite, folder_id), folder_id, dbase, notifq);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

void db_conn::notify_folder_movecopy(BOOL b_copy, uint64_t parent_id,
    uint64_t folder_id, uint64_t old_pid, uint64_t old_fid,
    const db_base &dbase, NOTIFQ &notifq) try
{
	auto pdb = this;
	auto dir = exmdb_server::get_dir();

	/* open-coded db_engine_classify_id_array(4-arg) */
	ID_ARRAYS recv_list;
	for (const auto &sub : dbase.nsub_list) {
		auto pnsub = &sub;
		if (b_copy) {
			if (!(pnsub->notification_type & fnevObjectCopied))
				continue;
		} else {
			if (!(pnsub->notification_type & fnevObjectMoved))
				continue;
		}
		if (pnsub->b_whole ||
		    (pnsub->folder_id == folder_id && pnsub->message_id == 0) ||
		    (pnsub->folder_id == old_fid && pnsub->message_id == 0)) {
			auto rid = sub.remote_id.has_value() ? sub.remote_id->c_str() : nullptr;
			recv_list[rid].push_back(pnsub->sub_id);
		}
	}
	if (recv_list.size() > 0) {
		DB_NOTIFY_DATAGRAM datagram;
		datagram.dir = deconst(dir);
		datagram.db_notify.type = b_copy ? db_notify_type::folder_copied :
		                          db_notify_type::folder_moved;
		auto pmvcp_folder = &datagram.db_notify.pdata.emplace<DB_NOTIFY_FOLDER_MVCP>();
		pmvcp_folder->folder_id = folder_id;
		pmvcp_folder->parent_id = parent_id;
		pmvcp_folder->old_folder_id = old_fid;
		pmvcp_folder->old_parent_id = old_pid;
		notifq.emplace_back(std::move(datagram), std::move(recv_list));
	}
	if (!b_copy) {
		dbeng_notify_hiertbl_delete_row(*pdb, old_pid, old_fid, dbase, notifq);
		pdb->notify_folder_modification(common_util_get_folder_parent_fid(
			pdb->psqlite, old_pid), old_pid, dbase, notifq);
	}
	dbeng_notify_hiertbl_add_row(*pdb, parent_id, folder_id, dbase, notifq);
	pdb->notify_folder_modification(common_util_get_folder_parent_fid(
		pdb->psqlite, parent_id), parent_id, dbase, notifq);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

void db_conn::notify_cttbl_reload(uint32_t table_id, const db_base &dbase,
    NOTIFQ &notifq) try
{
	DB_NOTIFY_DATAGRAM datagram;
	const auto &list = dbase.tables.table_list;
	auto ptable = std::find_if(list.cbegin(), list.cend(),
	              [=](const table_node &n) { return n.table_id == table_id; });
	if (ptable == list.cend())
		return;
	datagram.dir = deconst(exmdb_server::get_dir());
	datagram.db_notify.type = !ptable->b_search ?
		db_notify_type::cttbl_changed :
		db_notify_type::srchtbl_changed;
	datagram.db_notify.pdata = NULL;
	datagram.b_table = TRUE;
	datagram.id_array.push_back(table_id);
	notifq.emplace_back(datagram, table_to_idarray(*ptable));
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

void db_conn::begin_batch_mode(db_base &dbase)
{
	dbase.tables.b_batch = true;
}

void db_conn::commit_batch_mode_release(db_conn_ptr &&pdb, db_base_wr_ptr &&dbase)
{
	auto table_num = dbase->tables.table_list.size();
	auto ptable_ids = table_num > 0 ? cu_alloc<uint32_t>(table_num) : nullptr;
	table_num = 0;
	if (ptable_ids != nullptr) {
		for (auto &tnode : dbase->tables.table_list) {
			auto ptable = &tnode;
			if (ptable->b_hint) {
				ptable_ids[table_num++] = ptable->table_id;
				ptable->b_hint = FALSE;
			}
		}
	}
	dbase->tables.b_batch = false;
	dbase.reset();
	pdb.reset();
	auto dir = exmdb_server::get_dir();
	while (table_num > 0)
		exmdb_server::reload_content_table(dir, ptable_ids[--table_num]);
}

void db_conn::cancel_batch_mode(db_base &dbase)
{
	for (auto &t : dbase.tables.table_list)
		t.b_hint = false;
	dbase.tables.b_batch = false;
}

void db_close::operator()(sqlite3 *x) const
{
	auto z = sqlite3_db_filename(x, nullptr);
	if (z != nullptr)
		mlog(LV_INFO, "I-1762: exmdb: closing %s", z);
	sqlite3_close_v2(x);
}
