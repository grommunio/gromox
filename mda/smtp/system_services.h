#pragma once
#include <gromox/common_types.hpp>

enum{
    SERVICE_AUTH_ERROR,       /* auth session fail  */
	SERVICE_AUTH_CONTINUE,    /* auth session processed OK, continue */
    SERVICE_AUTH_FINISH       /* auth session processed OK, finished */

};

extern int system_services_run();
extern int system_services_stop();

extern BOOL (*system_services_judge_ip)(const char*);
extern BOOL (*system_services_add_ip_into_temp_list)(const char *, int);
extern BOOL (*system_services_container_add_ip)(const char*);
extern BOOL (*system_services_container_remove_ip)(const char*);
extern BOOL (*system_services_judge_user)(const char*);
extern BOOL (*system_services_add_user_into_temp_list)(const char *, int);
extern BOOL (*system_services_check_domain)(const char*);
extern BOOL (*system_services_check_user)(const char*, char*);
extern BOOL (*system_services_check_full)(const char*);
extern void (*system_services_log_info)(int, const char *, ...);
