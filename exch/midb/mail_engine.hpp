#pragma once

enum {
	MIDB_UPGRADE_NO = 0,
	MIDB_UPGRADE_YES,
	MIDB_UPGRADE_AUTO,
};

extern void mail_engine_init(const char *dfl_cset, const char *org_name, size_t table_size, BOOL async, BOOL wal, uint64_t mmap_size, int mime_num);
extern int mail_engine_run();
extern void mail_engine_stop();

extern unsigned int g_midb_schema_upgrades;
extern unsigned int g_midb_cache_interval, g_midb_reload_interval;
