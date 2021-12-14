#pragma once
#include <cstdint>
#include <sqlite3.h>
#include <gromox/defs.h>
#include <gromox/scope.hpp>

struct xstmt {
	xstmt() = default;
	xstmt(xstmt &&o) : m_ptr(o.m_ptr) { o.m_ptr = nullptr; }
	~xstmt() {
		if (m_ptr != nullptr)
			sqlite3_finalize(m_ptr);
	}
	void finalize() { *this = nullptr; }
	void operator=(std::nullptr_t) {
		if (m_ptr != nullptr)
			sqlite3_finalize(m_ptr);
		m_ptr = nullptr;
	}
	void operator=(xstmt &&o) {
		if (m_ptr != nullptr)
			sqlite3_finalize(m_ptr);
		m_ptr = o.m_ptr;
		o.m_ptr = nullptr;
	}
	operator sqlite3_stmt *() { return m_ptr; }
	sqlite3_stmt *m_ptr = nullptr;
};

extern GX_EXPORT struct xstmt gx_sql_prep(sqlite3 *, const char *);

static inline uint64_t gx_sql_col_uint64(sqlite3_stmt *s, int c)
{
	auto x = sqlite3_column_int64(s, c);
	return x >= 0 ? x : 0;
}

static inline auto gx_sql_begin_trans(sqlite3 *db)
{
	sqlite3_exec(db, "BEGIN TRANSACTION", nullptr, nullptr, nullptr);
	return gromox::make_scope_exit([&]() { sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr); });
}
