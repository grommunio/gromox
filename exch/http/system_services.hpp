#pragma once
#include <gromox/authmgr.hpp>
#include <gromox/common_types.hpp>

extern int system_services_run();
extern void system_services_stop();

extern BOOL (*system_services_judge_ip)(const char*);
extern BOOL (*system_services_container_add_ip)(const char*);
extern BOOL (*system_services_container_remove_ip)(const char*);
extern BOOL (*system_services_judge_user)(const char*);
extern BOOL (*system_services_add_user_into_temp_list)(const char *, int);
extern authmgr_login_t system_services_auth_login;
extern void (*system_services_log_info)(unsigned int, const char *, ...) __attribute__((format(printf, 2, 3)));
