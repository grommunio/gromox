#pragma once
#include <gromox/common_types.hpp>

enum{
    SERVICE_AUTH_ERROR,       /* auth session fail  */
	SERVICE_AUTH_CONTINUE,    /* auth session processed OK, continue */
    SERVICE_AUTH_FINISH       /* auth session processed OK, finished */

};

extern int system_services_run();
extern void system_services_stop();

extern BOOL (*system_services_judge_user)(const char*);
extern BOOL (*system_services_add_user_into_temp_list)(const char *, int);
extern bool (*system_services_check_user)(const char *, char *, size_t);
extern BOOL (*system_services_check_full)(const char*);
extern void (*system_services_log_info)(unsigned int, const char *, ...);
