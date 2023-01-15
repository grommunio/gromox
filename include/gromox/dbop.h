#pragma once
#include <mysql.h>
#include <sqlite3.h>
#include <gromox/defs.h>

namespace gromox {

enum class sqlite_kind {
	pvt,
	pub,
	midb,
};

enum {
	DBOP_VERBOSE = 0x1,
	DBOP_SCHEMA_0 = 0x2,
};

/* Database schema mainteanance for user database */
extern GX_EXPORT int dbop_mysql_create_0(MYSQL *);
extern GX_EXPORT int dbop_mysql_create_top(MYSQL *);
extern GX_EXPORT int dbop_mysql_recentversion();
extern GX_EXPORT int dbop_mysql_schemaversion(MYSQL *);
extern GX_EXPORT int dbop_mysql_upgrade(MYSQL *);

/* Database schema maintenance for mailbox */
extern GX_EXPORT int dbop_sqlite_create(sqlite3 *, sqlite_kind, unsigned int flags);
extern GX_EXPORT int dbop_sqlite_recentversion(sqlite_kind);
extern GX_EXPORT int dbop_sqlite_schemaversion(sqlite3 *, sqlite_kind);
extern GX_EXPORT ssize_t dbop_sqlite_integcheck(sqlite3 *, int loglevel = -1);
extern GX_EXPORT int dbop_sqlite_upgrade(sqlite3 *, const char *, sqlite_kind, unsigned int flags);

}
