#ifndef _H_MIDB_TOOL_
#define _H_MIDB_TOOL_
#include "common_types.h"

void midb_tool_init(const char *data_path);

int midb_tool_run();

int midb_tool_stop();

void midb_tool_free();

BOOL midb_tool_create(const char *dir, const char *username);

#endif /* _H_MIDB_TOOL_ */
