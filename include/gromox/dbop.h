#pragma once
#include <mysql.h>
#include <gromox/defs.h>

#ifdef __cplusplus
extern "C" {
#endif

extern GX_EXPORT int dbop_mysql_create_0(MYSQL *);
extern GX_EXPORT int dbop_mysql_create_top(MYSQL *);
extern GX_EXPORT unsigned int dbop_mysql_schemaversion(MYSQL *);
extern GX_EXPORT int dbop_mysql_upgrade(MYSQL *);

#ifdef __cplusplus
} /* extern "C" */
#endif
