#pragma once
#include "common_types.h"

void midb_client_init(const char *list_path);
extern int midb_client_run(void);
extern int midb_client_stop(void);
extern void midb_client_free(void);
BOOL midb_client_delete(const char *maildir, const char *folder,
	const char *file);
