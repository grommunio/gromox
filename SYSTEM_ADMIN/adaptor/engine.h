#pragma once
#include <gromox/common_types.hpp>

extern void engine_init(const char *mount_path, const char *domainlist_path, const char *aliasaddress_path, const char *unchkusr_path);
extern int engine_run(void);
extern int engine_stop(void);
