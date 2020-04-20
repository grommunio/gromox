#pragma once
#ifndef __cplusplus
#	include <stdbool.h>
#	include <stdio.h>
#	include <string.h>
#else
#	include <cstdio>
#	include <cstring>
#endif
#include <sqlite3.h>
#include <gromox/defs.h>

static inline bool gx_sql_prep(sqlite3 *db, const char *query, sqlite3_stmt **out)
{
	int ret = sqlite3_prepare_v2(db, query, -1, out, nullptr);
	if (ret == SQLITE_OK)
		return true;
	printf("sqlite3_prepare_v2: %s\n", sqlite3_errstr(ret));
	return false;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
