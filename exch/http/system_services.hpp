#pragma once
#include <string>
#include <gromox/authmgr.hpp>
#include <gromox/common_types.hpp>

extern int system_services_run();
extern bool (*system_services_judge_addr)(const char *host, std::string &reason);
extern bool (*system_services_judge_user)(const char *);
extern void (*system_services_ban_user)(const char *, int);
extern authmgr_login_t system_services_auth_login;
extern bool (*ss_dnsbl_check)(const char *host);
