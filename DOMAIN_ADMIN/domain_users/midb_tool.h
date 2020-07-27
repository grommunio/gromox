#pragma once
#include "common_types.h"

void midb_tool_init(const char *data_path);
extern int midb_tool_run(void);
extern int midb_tool_stop(void);
extern void midb_tool_free(void);
BOOL midb_tool_create(const char *dir, const char *username);
