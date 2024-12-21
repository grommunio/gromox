#pragma once
#include <gromox/authmgr.hpp>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>

extern BOOL (*system_services_lang_to_charset)(const char*, char*);
extern authmgr_login_t system_services_auth_login;
extern authmgr_login_t2 system_services_auth_login_token;
extern int (*system_services_add_timer)(const char *, int);
