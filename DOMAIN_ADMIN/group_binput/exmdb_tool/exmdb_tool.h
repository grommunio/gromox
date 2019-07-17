#ifndef _H_EXMDB_TOOL_
#define _H_EXMDB_TOOL_

void exmdb_tool_init(const char *data_path);

int exmdb_tool_run();

int exmdb_tool_stop();

void exmdb_tool_free();

BOOL exmdb_tool_create(const char *dir, uint64_t max_size,
	const char *lang, int user_id);

#endif /* _H_EXMDB_TOOL_ */
