// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021-2023 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <mutex>
#include <unordered_map>
#include <sqlite3.h>
#include <unistd.h>
#include <gromox/database.h>
#include <gromox/util.hpp>

namespace gromox {

unsigned int gx_sqlite_debug;

xstmt gx_sql_prep(sqlite3 *db, const char *query)
{
	xstmt out;
	if (gx_sqlite_debug >= 1)
		mlog(LV_DEBUG, "> sqlite3_prep(%s)", query);
	int ret = sqlite3_prepare_v2(db, query, -1, &out.m_ptr, nullptr);
	if (ret != SQLITE_OK)
		mlog(LV_ERR, "sqlite3_prepare_v2(%s) \"%s\": %s",
			znul(sqlite3_db_filename(db, nullptr)),
		        query, sqlite3_errstr(ret));
	return out;
}

xtransaction &xtransaction::operator=(xtransaction &&o) noexcept
{
	if (m_db != nullptr)
		sqlite3_exec(m_db, "ROLLBACK", nullptr, nullptr, nullptr);
	m_db = o.m_db;
	o.m_db = nullptr;
	return *this;
}

static std::unordered_map<void *, std::string> active_xa;
static std::mutex active_xa_lock;

xtransaction::~xtransaction()
{
	if (m_db != nullptr) {
		gx_sql_exec(m_db, "ROLLBACK");
		std::unique_lock lk(active_xa_lock);
		active_xa.erase(m_db);
	}
}

int xtransaction::commit()
{
	if (m_db == nullptr)
		return SQLITE_OK;
	auto ret = gx_sql_exec(m_db, "COMMIT TRANSACTION");
	if (ret == SQLITE_BUSY)
		mlog(LV_NOTICE, "Something external has a query running "
			"(stop doing that!) on this sqlite db that blocks us "
			"from writing the changes amassed in a transaction.");
	size_t count = 10;
	while (ret == SQLITE_BUSY && count-- > 0) {
		sleep(1);
		ret = gx_sql_exec(m_db, "COMMIT TRANSACTION");
	}
	if (ret == SQLITE_BUSY)
		/*
		 * As most callers have nothing else to do, they themselves
		 * return from their frame, triggering ~xtransaction and a
		 * rollback.
		 */
		return ret;

	{
		std::unique_lock lk(active_xa_lock);
		active_xa.erase(m_db);
	}
	m_db = nullptr;
	return ret;
}

xtransaction gx_sql_begin(sqlite3 *db, const std::string &pos)
{
	{
		std::unique_lock lk(active_xa_lock);
		auto pair = active_xa.emplace(db, pos);
		if (!pair.second)
			mlog(LV_ERR, "Nested transaction attempted. DB %p, origin %s, now %s",
				db, pair.first->second.c_str(), pos.c_str());
	}
	auto ret = gx_sql_exec(db, "BEGIN TRANSACTION");
	return xtransaction(ret == SQLITE_OK ? db : nullptr);
}

int gx_sql_exec(sqlite3 *db, const char *query, unsigned int flags)
{
	char *estr = nullptr;
	if (gx_sqlite_debug >= 1)
		mlog(LV_DEBUG, "> sqlite3_exec(%s)", query);
	auto ret = sqlite3_exec(db, query, nullptr, nullptr, &estr);
	if (ret == SQLITE_OK)
		return ret;
	else if (ret == SQLITE_CONSTRAINT && (flags & SQLEXEC_SILENT_CONSTRAINT))
		;
	else
		mlog(LV_ERR, "sqlite3_exec(%s) \"%s\": %s (%d)",
			znul(sqlite3_db_filename(db, nullptr)), query,
		        estr != nullptr ? estr : sqlite3_errstr(ret), ret);
	sqlite3_free(estr);
	return ret;
}

int gx_sql_step(sqlite3_stmt *stm, unsigned int flags)
{
	auto ret = sqlite3_step(stm);
	if (ret == SQLITE_OK || ret == SQLITE_ROW || ret == SQLITE_DONE)
		return ret;
	else if (ret == SQLITE_CONSTRAINT && (flags & SQLEXEC_SILENT_CONSTRAINT))
		return ret;
	auto exp = sqlite3_expanded_sql(stm);
	auto db  = sqlite3_db_handle(stm);
	auto fn  = db != nullptr ? sqlite3_db_filename(db, nullptr) : nullptr;
	mlog(LV_ERR, "sqlite3_step(%s) \"%s\": %s (%d)", znul(fn), exp != nullptr ?
		exp : sqlite3_sql(stm), sqlite3_errstr(ret), ret);
	sqlite3_free(exp);
	return ret;
}

}
