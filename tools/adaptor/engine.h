#pragma once
#include <gromox/common_types.hpp>

extern void engine_init(const char *domainlist_path, const char *aliasaddress_path, const char *unchkusr_path);
extern int engine_run();
extern int engine_stop();
