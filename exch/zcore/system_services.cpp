// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <gromox/defs.h>
#include <gromox/svc_loader.hpp>
#include "system_services.hpp"
#include "../exch/authmgr.hpp"

BOOL (*system_services_lang_to_charset)(const char*, char*);
const char* (*system_services_cpid_to_charset)(uint32_t);
uint32_t (*system_services_charset_to_cpid)(const char*);
uint32_t (*system_services_ltag_to_lcid)(const char*);
const char* (*system_services_mime_to_extension)(const char*);
const char* (*system_services_extension_to_mime)(const char*);
decltype(system_services_auth_login) system_services_auth_login;
#define E(s) decltype(system_services_ ## s) system_services_ ## s;
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
E(get_org_domains)
E(get_sub_classes)
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
#undef E
BOOL (*system_services_get_lang)(uint32_t, const char*, char*, int);
int (*system_services_add_timer)(const char *, int);
void (*system_services_log_info)(unsigned int, const char *, ...);

int system_services_run()
{
#define E(f, s) do { \
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(*(f)))); \
	if ((f) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "system_services", (s)); \
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
	E(system_services_lang_to_charset, "lang_to_charset");
	E(system_services_cpid_to_charset, "cpid_to_charset");
	E(system_services_charset_to_cpid, "charset_to_cpid");
	E(system_services_ltag_to_lcid, "ltag_to_lcid");
	E(system_services_mime_to_extension, "mime_to_extension");
	E(system_services_extension_to_mime, "extension_to_mime");
	E(system_services_auth_login, "auth_login_gen");
	E(system_services_get_user_displayname, "get_user_displayname");
	E(system_services_get_org_domains, "get_org_domains");
	E(system_services_get_domain_info, "get_domain_info");
	E(system_services_get_domain_groups, "get_domain_groups");
	E(system_services_get_group_classes, "get_group_classes");
	E(system_services_get_sub_classes, "get_sub_classes");
	E(system_services_get_class_users, "get_class_users");
	E(system_services_get_group_users, "get_group_users");
	E(system_services_get_domain_users, "get_domain_users");
	E(system_services_get_mlist_ids, "get_mlist_ids");
	E(system_services_get_lang, "get_lang");
	E(system_services_check_same_org, "check_same_org");
	E(system_services_log_info, "log_info");
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
	E("lang_to_charset");
	E("cpid_to_charset");
	E("charset_to_cpid");
	E("ltag_to_lcid");
	E("mime_to_extension");
	E("extension_to_mime");
	E("auth_login_gen");
	E("get_user_displayname");
	E("get_org_domains");
	E("get_domain_info");
	E("get_domain_groups");
	E("get_group_classes");
	E("get_sub_classes");
	E("get_class_users");
	E("get_group_users");
	E("get_domain_users");
	E("get_mlist_ids");
	E("get_lang");
	E("check_same_org");
	E("log_info");
	E("set_password");
	E("get_user_privilege_bits");
	E("add_timer");
#undef E
}
