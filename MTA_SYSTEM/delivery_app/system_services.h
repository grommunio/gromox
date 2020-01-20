#pragma once
#include "common_types.h"

extern void system_services_init(void);
extern int system_services_run(void);
extern int system_services_stop(void);
extern void system_services_free(void);
extern void (*system_services_log_info)(int, const char *, ...);
