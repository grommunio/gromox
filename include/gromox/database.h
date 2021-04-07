#pragma once
#include <cstdint>
#include <cstdio>
#include <sqlite3.h>

struct xstmt {
	void finalize() { sqlite3_finalize(m_ptr); m_ptr = nullptr; }
	void operator=(sqlite3_stmt *s) { m_ptr = s; }
	operator sqlite3_stmt *() { return m_ptr; }
	sqlite3_stmt *m_ptr = nullptr;
};

static inline xstmt gx_sql_prep(sqlite3 *db, const char *query)
{
	xstmt out;
	int ret = sqlite3_prepare_v2(db, query, -1, &out.m_ptr, nullptr);
	if (ret != SQLITE_OK)
		printf("sqlite3_prepare_v2 \"%s\": %s\n", query, sqlite3_errstr(ret));
	return out;
}

static inline uint64_t gx_sql_col_uint64(sqlite3_stmt *s, int c)
{
	auto x = sqlite3_column_int64(s, c);
	return x >= 0 ? x : 0;
}
