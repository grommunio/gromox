#ifndef _H_SYSTEM_SERVICES_
#define _H_SYSTEM_SERVICES_

#include "common_types.h"

void system_services_init();

int system_services_run();

int system_services_stop();

void system_services_free();

extern void (*system_services_log_info)(int, char*, ...);

#endif /* _H_SYSTEM_SERVICES_ */
