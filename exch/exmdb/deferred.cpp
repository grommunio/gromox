// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
/*
 * Scheduler for deferred ("send later") submission. Due times live in each
 * store's deferred_sends table. The send itself runs in exmdb
 * (exmdb_execute_deferred_send, message.cpp).
 */
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>
#include <mutex>
#include <pthread.h>
#include <sqlite3.h>
#include <string>
#include <utility>
#include <vector>
#include <libHX/scope.hpp>
#include <gromox/atomic.hpp>
#include <gromox/authmgr.hpp>
#include <gromox/clock.hpp>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_ext.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/fileio.h>
#include <gromox/mapi_types.hpp>
#include <gromox/mapierr.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/paths.h>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "db_engine.hpp"
#include "parser.hpp"

using namespace gromox;

namespace {
struct defer_key {
	std::string dir;
	uint64_t mid = 0;
};
}

static std::multimap<time_t, defer_key> g_queue; /* ordered by due time */
static std::mutex g_lock;
static std::condition_variable g_cv;
static pthread_t g_thr{};
static gromox::atomic_bool g_stop{true};
static defer_role g_role = defer_role::executor;

static void defer_erase(uint64_t mid, const char *dir)
{
	for (auto it = g_queue.begin(); it != g_queue.end(); ++it)
		if (it->second.mid == mid && it->second.dir == dir) {
			g_queue.erase(it);
			return;
		}
}

void deferred_sched_arm(const char *dir, uint64_t mid_val, time_t due) try
{
	{
		std::lock_guard lk(g_lock);
		defer_erase(mid_val, dir);
		g_queue.emplace(due, defer_key{dir, mid_val});
	}
	g_cv.notify_one();
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM arming deferred send for %s:m%llu",
		__func__, dir, static_cast<unsigned long long>(mid_val));
}

void deferred_sched_cancel(const char *dir, uint64_t mid_val)
{
	{
		std::lock_guard lk(g_lock);
		defer_erase(mid_val, dir);
	}
	g_cv.notify_one();
}

/* Read one store's deferred_sends table and arm each row. */
static size_t defer_arm_store_i(const char *dir)
{
	auto path = std::string(dir) + "/exmdb/exchange.sqlite3";
	sqlite3 *db = nullptr;
	if (sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
		if (db != nullptr)
			sqlite3_close(db);
		return 0;
	}
	auto cl_db = HX::make_scope_exit([&]() { sqlite3_close(db); });
	sqlite3_stmt *st = nullptr;
	if (sqlite3_prepare_v2(db, "SELECT message_id, due_time FROM deferred_sends",
	    -1, &st, nullptr) != SQLITE_OK)
		return 0; /* store likely predates schema v30 */
	auto cl_st = HX::make_scope_exit([&]() { sqlite3_finalize(st); });
	size_t n = 0;
	while (sqlite3_step(st) == SQLITE_ROW) {
		uint64_t mid = sqlite3_column_int64(st, 0);
		time_t due = sqlite3_column_int64(st, 1);
		deferred_sched_arm(dir, mid, due);
		++n;
	}
	return n;
}

void deferred_arm_store(const char *dir)
{
	defer_arm_store_i(dir);
}

bool deferred_pending()
{
	std::lock_guard lk(g_lock);
	return !g_queue.empty();
}

/*
 * One-time sweep over all local mailboxes at startup, so a pending send is
 * honored even for a mailbox whose owner never reconnects after a restart.
 */
static void defer_scan_all()
{
	std::vector<sql_user> users;
	if (mysql_adaptor_mbop_userlist(users) != 0) {
		mlog(LV_WARN, "deferred: cannot enumerate mailboxes for startup scan");
		return;
	}
	size_t armed = 0, scanned = 0;
	for (const auto &u : users) {
		if (g_stop)
			return;
		if (u.maildir.empty())
			continue;
		armed += defer_arm_store_i(u.maildir.c_str());
		++scanned;
	}
	if (armed != 0)
		mlog(LV_NOTICE, "deferred: armed %zu pending send(s) across %zu mailbox(es)",
			armed, scanned);
}

/**
 * One-shot import of any jobs left by the removed timer(8gx) daemon. Each
 * timer.txt line is `tid<TAB>exectime<TAB>command`, command being
 * `<submit_command> <user> <gcv>` with spaces/backslashes escaped.
 */
static void defer_migrate_timertxt()
{
	auto path = std::string(PKGSTATEDIR) + "/timer.txt";
	std::unique_ptr<FILE, file_deleter> fp(fopen(path.c_str(), "r"));
	if (fp == nullptr)
		return;
	auto now = time(nullptr);
	size_t migrated = 0;
	char line[1024];
	while (fgets(line, std::size(line), fp.get()) != nullptr) {
		char *p = line, *f1 = strchr(p, '\t');
		if (f1 == nullptr)
			continue;
		*f1++ = '\0';
		char *f2 = strchr(f1, '\t');
		if (f2 == nullptr)
			continue;
		*f2++ = '\0';
		time_t due = strtoll(f1, nullptr, 0);
		if (due == 0)
			continue; /* completion marker */
		std::string cmd; /* unescape */
		for (char *q = f2; *q != '\0' && *q != '\n'; ++q)
			cmd += (*q == '\\' && q[1] != '\0') ? *++q : *q;
		auto sp2 = cmd.rfind(' ');
		if (sp2 == std::string::npos)
			continue;
		auto sp1 = cmd.rfind(' ', sp2 - 1);
		if (sp1 == std::string::npos)
			continue;
		auto user = cmd.substr(sp1 + 1, sp2 - sp1 - 1);
		uint64_t gcv = strtoull(cmd.c_str() + sp2 + 1, nullptr, 0);
		if (gcv == 0)
			continue;
		sql_meta_result mres;
		if (mysql_adaptor_meta(user.c_str(), WANTPRIV_METAONLY, mres) != 0)
			continue;
		due = due < now ? now : due;
		exmdb_server::build_env(EM_PRIVATE, mres.maildir.c_str());
		auto pdb = db_engine_get_db(mres.maildir.c_str()); /* also upgrades schema */
		if (pdb) {
			char q[160];
			snprintf(q, std::size(q), "INSERT OR REPLACE INTO deferred_sends "
				"(message_id, due_time) VALUES (%llu, %lld)",
				static_cast<unsigned long long>(gcv),
				static_cast<long long>(due));
			if (pdb->exec(q) == SQLITE_OK) {
				deferred_sched_arm(mres.maildir.c_str(), gcv, due);
				++migrated;
			}
		}
		exmdb_server::free_env();
	}
	fp.reset();
	::rename(path.c_str(), (path + ".migrated").c_str());
	if (migrated != 0)
		mlog(LV_NOTICE, "deferred: migrated %zu job(s) from timer.txt", migrated);
}

static void defer_fire(const std::string &dir, uint64_t mid)
{
	if (g_role == defer_role::director) {
		/* Director holds no stores: wake the worker, which sends on startup. */
		if (exmdb_wake_worker(dir.c_str()) != 0)
			mlog(LV_WARN, "deferred: could not wake worker for %s", dir.c_str());
		return;
	}
	auto err = exmdb_execute_deferred_send(dir.c_str(), mid);
	if (err != ecSuccess && err != ecNotFound)
		mlog(LV_WARN, "deferred send %s:m%llu failed: %s",
			dir.c_str(), static_cast<unsigned long long>(mid), mapi_strerror(err));
}

static void *defer_thread(void *)
{
	pthread_setname_np(pthread_self(), "deferred");
	if (g_role == defer_role::executor)
		defer_migrate_timertxt();
	if (g_role != defer_role::worker)
		defer_scan_all();
	std::unique_lock lk(g_lock);
	while (!g_stop) {
		if (g_queue.empty()) {
			g_cv.wait(lk);
			continue;
		}
		auto it = g_queue.begin();
		auto now = time(nullptr);
		if (it->first > now) {
			/* Cap the wait so a wall-clock jump cannot oversleep. */
			auto secs = std::min<time_t>(it->first - now, 60);
			g_cv.wait_for(lk, std::chrono::seconds(secs));
			continue;
		}
		auto dir = it->second.dir;
		auto mid = it->second.mid;
		g_queue.erase(it);
		lk.unlock();
		defer_fire(dir, mid);
		lk.lock();
	}
	return nullptr;
}

int deferred_run(defer_role role)
{
	g_role = role;
	g_stop = false;
	auto ret = pthread_create(&g_thr, nullptr, defer_thread, nullptr);
	if (ret != 0) {
		g_stop = true;
		g_thr = {};
		mlog(LV_ERR, "deferred_run: pthread_create: %s", strerror(ret));
		return -1;
	}
	return 0;
}

void deferred_stop()
{
	if (g_stop && pthread_equal(g_thr, {}))
		return;
	g_stop = true;
	g_cv.notify_all();
	if (!pthread_equal(g_thr, {})) {
		pthread_join(g_thr, nullptr);
		g_thr = {};
	}
	std::lock_guard lk(g_lock);
	g_queue.clear();
}
