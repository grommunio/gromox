#pragma once

enum {
	MIDB_TABLE_SIZE,
	MIDB_TABLE_USED
};

extern void mail_engine_init(const char *dfl_cset, const char *dfl_tz, const char *org_name, size_t table_size, BOOL async, BOOL wal, uint64_t mmap_size, int cache_interval, int mime_num);
extern int mail_engine_run();
extern int mail_engine_stop();
int mail_engine_get_param(int param);
