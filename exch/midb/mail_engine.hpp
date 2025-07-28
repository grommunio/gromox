#pragma once

enum {
	MIDB_UPGRADE_NO = 0,
	MIDB_UPGRADE_YES,
	MIDB_UPGRADE_AUTO,
};

extern void me_init(const char *dfl_cset, const char *org_name, size_t table_size);
extern int me_run();
extern void me_stop();

extern unsigned int g_midb_schema_upgrades;
extern unsigned int g_midb_cache_interval, g_midb_reload_interval;
extern std::string g_host_id;
