#ifndef _H_EXMDB_TOOL_
#define _H_EXMDB_TOOL_

void exmdb_tool_init();

int exmdb_tool_run();

int exmdb_tool_stop();

void exmdb_tool_free();

BOOL exmdb_tool_create(const char *dir, int domain_id, uint64_t max_size);

#endif /* _H_EXMDB_TOOL_ */
