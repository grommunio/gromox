#pragma once

extern void exmdb_tool_init(void);
extern int exmdb_tool_run(void);
extern int exmdb_tool_stop(void);
extern void exmdb_tool_free(void);
BOOL exmdb_tool_create(const char *dir, int domain_id, uint64_t max_size);
