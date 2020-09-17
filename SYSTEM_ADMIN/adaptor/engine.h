#pragma once
#include "common_types.h"

extern void engine_init(const char *mount_path, const char *domainlist_path, const char *aliasaddress_path, const char *backup_path, const char *unchkusr_path, const char *collector_path, const char *subsystem_path);
extern int engine_run(void);
extern int engine_stop(void);
