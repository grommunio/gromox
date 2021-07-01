// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <typeinfo>
#include <gromox/svc_common.h>
#include "mysql_adaptor.h"
#include <cstdio>
#include "sql2.hpp"

DECLARE_API();

static BOOL svc_mysql_adaptor(int reason, void** ppdata)
{
    switch(reason) {
	case PLUGIN_INIT: {
		LINK_API(ppdata);
		if (!mysql_adaptor_reload_config(get_config_path(),
		    get_host_ID(), get_prog_id()))
			return false;
		if (0 != mysql_adaptor_run()) {
			printf("[mysql_adaptor]: failed to run mysql adaptor\n");
			return FALSE;
		}

#define E(f, s) do { \
	if (!register_service((s), f)) { \
		printf("[%s]: failed to register the \"%s\" service\n", "mysql_adaptor", (s)); \
		return false; \
	} \
} while (false)
		E(mysql_adaptor_meta, "mysql_auth_meta");
		E(mysql_adaptor_login2, "mysql_auth_login2");
		E(mysql_adaptor_setpasswd, "set_password");
		E(mysql_adaptor_get_username_from_id, "get_username_from_id");
		E(mysql_adaptor_get_id_from_username, "get_id_from_username");
		E(mysql_adaptor_get_id_from_maildir, "get_id_from_maildir");
		E(mysql_adaptor_get_user_displayname, "get_user_displayname");
		E(mysql_adaptor_get_user_privilege_bits, "get_user_privilege_bits");
		E(mysql_adaptor_get_user_lang, "get_user_lang");
		E(mysql_adaptor_set_user_lang, "set_user_lang");
		E(mysql_adaptor_get_timezone, "get_timezone");
		E(mysql_adaptor_set_timezone, "set_timezone");
		E(mysql_adaptor_get_maildir, "get_maildir");
		E(mysql_adaptor_get_domainname_from_id, "get_domainname_from_id");
		E(mysql_adaptor_get_homedir, "get_homedir");
		E(mysql_adaptor_get_homedir_by_id, "get_homedir_by_id");
		E(mysql_adaptor_get_id_from_homedir, "get_id_from_homedir");
		E(mysql_adaptor_get_user_ids, "get_user_ids");
		E(mysql_adaptor_get_domain_ids, "get_domain_ids");
		E(mysql_adaptor_get_mlist_ids, "get_mlist_ids");
		E(mysql_adaptor_get_org_domains, "get_org_domains");
		E(mysql_adaptor_get_domain_info, "get_domain_info");
		E(mysql_adaptor_check_same_org, "check_same_org");
		E(mysql_adaptor_get_domain_groups, "get_domain_groups");
		E(mysql_adaptor_get_group_classes, "get_group_classes");
		E(mysql_adaptor_get_sub_classes, "get_sub_classes");
		E(mysql_adaptor_get_class_users, "get_class_users");
		E(mysql_adaptor_get_group_users, "get_group_users");
		E(mysql_adaptor_get_domain_users, "get_domain_users");
		E(mysql_adaptor_check_mlist_include, "check_mlist_include");
		E(mysql_adaptor_check_same_org2, "check_same_org2");
		E(mysql_adaptor_check_user, "check_user");
		E(mysql_adaptor_get_mlist, "get_mail_list");
		E(mysql_adaptor_get_user_info, "get_user_info");
#undef E
        return TRUE;
        }

    case PLUGIN_FREE:
		mysql_adaptor_stop();
        return TRUE;
    }
	return TRUE;
}
SVC_ENTRY(svc_mysql_adaptor);
