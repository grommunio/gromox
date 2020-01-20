#pragma once
#include "common_types.h"
#include <sqlite3.h>

void midb_client_init(const char *list_path);
extern int midb_client_run(void);
extern int midb_client_stop(void);
extern void midb_client_free(void);
BOOL midb_client_rewrite_eml(const char *maildir, const char *mid_string);

BOOL midb_client_all_mid_strings(const char *maildir, sqlite3_stmt *pstmt);

BOOL midb_client_unload_db(const char *maildir);
