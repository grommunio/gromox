#pragma once
#include <gromox/common_types.hpp>

extern int system_services_run();
extern int system_services_stop();
extern void (*system_services_log_info)(int, const char *, ...);
