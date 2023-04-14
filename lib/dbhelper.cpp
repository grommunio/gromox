// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <sqlite3.h>
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
		mlog(LV_ERR, "sqlite3_prepare_v2 \"%s\": %s",
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

xtransaction::~xtransaction()
{
	if (m_db != nullptr)
		sqlite3_exec(m_db, "ROLLBACK", nullptr, nullptr, nullptr);
}

void xtransaction::commit()
{
	if (m_db == nullptr)
		return;
	sqlite3_exec(m_db, "COMMIT TRANSACTION", nullptr, nullptr, nullptr);
	m_db = nullptr;
}

xtransaction gx_sql_begin_trans(sqlite3 *db)
{
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
		mlog(LV_ERR, "sqlite3_exec \"%s\": %s", query,
		        estr != nullptr ? estr : sqlite3_errstr(ret));
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
	mlog(LV_ERR, "sqlite3_step \"%s\": %s", exp != nullptr ?
		exp : sqlite3_sql(stm), sqlite3_errstr(ret));
	sqlite3_free(exp);
	return ret;
}

}
