// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <gromox/authmgr.hpp>
#include <gromox/defs.h>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include "system_services.hpp"

using namespace gromox;

decltype(system_services_auth_login) system_services_auth_login;
decltype(system_services_auth_login_token) system_services_auth_login_token;
#define E(s) decltype(system_services_ ## s) system_services_ ## s;
E(check_same_org)
E(get_domain_groups)
E(get_domain_ids)
E(get_domain_info)
E(get_domain_users)
E(get_group_users)
E(get_homedir)
E(get_id_from_username)
E(get_maildir)
E(get_mlist_ids)
E(get_mlist_memb)
E(get_org_domains)
E(get_timezone)
E(get_user_displayname)
E(get_user_ids)
E(get_user_lang)
E(get_user_privilege_bits)
E(get_username_from_id)
E(setpasswd)
E(set_timezone)
E(set_user_lang)
E(scndstore_hints)
E(meta)
#undef E
int (*system_services_add_timer)(const char *, int);

int system_services_run()
{
#define E(f, s) do { \
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(*(f)))); \
	if ((f) == nullptr) { \
		mlog(LV_ERR, "system_services: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)

	E(system_services_get_user_lang, "get_user_lang");
	E(system_services_set_user_lang, "set_user_lang");
	E(system_services_get_maildir, "get_maildir");
	E(system_services_get_homedir, "get_homedir");
	E(system_services_get_timezone, "get_timezone");
	E(system_services_set_timezone, "set_timezone");
	E(system_services_get_username_from_id, "get_username_from_id");
	E(system_services_get_id_from_username, "get_id_from_username");
	E(system_services_get_domain_ids, "get_domain_ids");
	E(system_services_get_user_ids, "get_user_ids");
	E(system_services_auth_login, "auth_login_gen");
	E(system_services_auth_login_token, "auth_login_token");
	E(system_services_get_user_displayname, "get_user_displayname");
	E(system_services_get_org_domains, "get_org_domains");
	E(system_services_get_domain_info, "get_domain_info");
	E(system_services_get_domain_groups, "get_domain_groups");
	E(system_services_get_group_users, "get_group_users");
	E(system_services_get_domain_users, "get_domain_users");
	E(system_services_get_mlist_ids, "get_mlist_ids");
	E(system_services_get_mlist_memb, "get_mlist_memb");
	E(system_services_check_same_org, "check_same_org");
	E(system_services_setpasswd, "set_password");
	E(system_services_get_user_privilege_bits, "get_user_privilege_bits");
	E(system_services_add_timer, "add_timer");
	E(system_services_scndstore_hints, "scndstore_hints");
	return 0;
#undef E
}

void system_services_stop()
{
#define E(b) service_release(b, "system")
	E("get_user_lang");
	E("set_user_lang");
	E("get_maildir");
	E("get_homedir");
	E("get_timezone");
	E("set_timezone");
	E("get_username_from_id");
	E("get_id_from_username");
	E("get_domain_ids");
	E("get_user_ids");
	E("auth_login_gen");	
	E("auth_login_token");
	E("get_user_displayname");
	E("get_org_domains");
	E("get_domain_info");
	E("get_domain_groups");
	E("get_group_users");
	E("get_domain_users");
	E("get_mlist_ids");
	E("get_mlist_memb");
	E("check_same_org");
	E("set_password");
	E("get_user_privilege_bits");
	E("add_timer");
	E("scndstore_hints");
#undef E
}
