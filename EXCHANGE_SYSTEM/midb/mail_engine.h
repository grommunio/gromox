#ifndef _H_MAIL_ENGINE_
#define _H_MAIL_ENGINE_

enum {
	MIDB_TABLE_SIZE,
	MIDB_TABLE_USED
};

void mail_engine_init(const char *default_charset,
	const char *default_timezone, const char *org_name,
	int table_size, BOOL b_async, BOOL b_wal,
	uint64_t mmap_size, int cache_interval, int mime_num);
extern int mail_engine_run(void);
extern int mail_engine_stop(void);
extern void mail_engine_free(void);
int mail_engine_get_param(int param);

#endif
