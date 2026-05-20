#pragma once

enum {
	MIDB_UPGRADE_NO = 0,
	MIDB_UPGRADE_YES,
	MIDB_UPGRADE_AUTO,
};

struct DB_NOTIFY;

extern void me_init(const char *org_name, size_t table_size);
extern int me_run();
extern void me_stop();
extern void midb_notif_handler(const char *dir, BOOL table, uint32_t nid, const DB_NOTIFY *);

extern unsigned int g_midb_schema_upgrades;
extern unsigned int g_midb_cache_interval, g_midb_reload_interval;
extern unsigned long long g_midb_busy_timeout_ns;
extern std::string g_host_id;
