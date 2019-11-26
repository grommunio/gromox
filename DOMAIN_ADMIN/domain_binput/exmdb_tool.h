#ifndef _H_EXMDB_TOOL_
#define _H_EXMDB_TOOL_

void exmdb_tool_init(const char *data_path);
extern int exmdb_tool_run(void);
extern int exmdb_tool_stop(void);
extern void exmdb_tool_free(void);
BOOL exmdb_tool_create(const char *dir, uint64_t max_size,
	const char *lang, int user_id);

#endif /* _H_EXMDB_TOOL_ */
