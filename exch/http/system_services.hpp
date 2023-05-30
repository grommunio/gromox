#pragma once
#include <string>
#include <gromox/authmgr.hpp>
#include <gromox/common_types.hpp>

extern int system_services_run();
extern void system_services_stop();

extern bool (*system_services_judge_ip)(const char *host, std::string &reason);
extern BOOL (*system_services_judge_user)(const char*);
extern BOOL (*system_services_add_user_into_temp_list)(const char *, int);
extern authmgr_login_t system_services_auth_login;
extern bool (*ss_dnsbl_check)(const char *host);
