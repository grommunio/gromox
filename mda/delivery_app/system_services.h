#pragma once
#include <gromox/common_types.hpp>

#ifdef __cplusplus
extern "C" {
#endif

extern int system_services_run(void);
extern int system_services_stop(void);
extern void (*system_services_log_info)(int, const char *, ...);

#ifdef __cplusplus
} /* extern "C" */
#endif
