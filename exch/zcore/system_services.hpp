#pragma once
#include <gromox/authmgr.hpp>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include "../mysql_adaptor/mysql_adaptor.h"
#include "../mysql_adaptor/sql2.hpp"

extern int system_services_run();
extern void system_services_stop();

extern BOOL (*system_services_lang_to_charset)(const char*, char*);
extern authmgr_login_t system_services_auth_login;
#define E(s) extern decltype(mysql_adaptor_ ## s) *system_services_ ## s;
E(check_same_org)
E(get_class_users)
E(get_domain_groups)
E(get_domain_ids)
E(get_domain_info)
E(get_domain_users)
E(get_group_classes)
E(get_group_users)
E(get_homedir)
E(get_id_from_username)
E(get_maildir)
E(get_mlist_ids)
E(get_mlist_memb)
E(get_org_domains)
E(get_sub_classes)
E(get_timezone)
E(get_user_displayname)
E(get_user_ids)
E(get_user_lang)
E(get_user_privilege_bits)
E(get_username_from_id)
E(set_timezone)
E(set_user_lang)
E(setpasswd)
E(scndstore_hints)
#undef E
extern int (*system_services_add_timer)(const char *, int);
extern void (*system_services_log_info)(unsigned int, const char *, ...) __attribute__((format(printf, 2, 3)));
