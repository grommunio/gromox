#pragma once
#include <mysql.h>
#include <gromox/defs.h>

namespace gromox {

extern GX_EXPORT int dbop_mysql_create_0(MYSQL *);
extern GX_EXPORT int dbop_mysql_create_top(MYSQL *);
extern GX_EXPORT int dbop_mysql_recentversion();
extern GX_EXPORT int dbop_mysql_schemaversion(MYSQL *);
extern GX_EXPORT int dbop_mysql_upgrade(MYSQL *);

}
