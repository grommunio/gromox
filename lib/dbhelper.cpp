// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <sqlite3.h>
#include <gromox/database.h>

xstmt gx_sql_prep(sqlite3 *db, const char *query)
{
	xstmt out;
	int ret = sqlite3_prepare_v2(db, query, -1, &out.m_ptr, nullptr);
	if (ret != SQLITE_OK)
		fprintf(stderr, "sqlite3_prepare_v2 \"%s\": %s\n",
		        query, sqlite3_errstr(ret));
	return out;
}
