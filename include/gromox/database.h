#pragma once
#include <cstdint>
#include <cstdio>
#include <sqlite3.h>

static inline bool gx_sql_prep(sqlite3 *db, const char *query, sqlite3_stmt **out)
{
	int ret = sqlite3_prepare_v2(db, query, -1, out, nullptr);
	if (ret == SQLITE_OK)
		return true;
	printf("sqlite3_prepare_v2 \"%s\": %s\n", query, sqlite3_errstr(ret));
	return false;
}

static inline uint64_t gx_sql_col_uint64(sqlite3_stmt *s, int c)
{
	auto x = sqlite3_column_int64(s, c);
	return x >= 0 ? x : 0;
}
