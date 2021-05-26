// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <typeinfo>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/svc_common.h>
#include "mysql_adaptor.h"
#include <gromox/util.hpp>
#include <gromox/config_file.hpp>
#include <cstring>
#include <cstdio>

DECLARE_API();

static BOOL svc_mysql_adaptor(int reason, void** ppdata)
{
	char file_name[256];
	char config_path[256];
	char uncheck_path[256], *psearch;
	char mysql_host[256], mysql_user[256], db_name[256]; 
	int conn_num, mysql_port, timeout;

    switch(reason) {
	case PLUGIN_INIT: {
		LINK_API(ppdata);
		gx_strlcpy(file_name, get_plugin_name(), GX_ARRAY_SIZE(file_name));
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		snprintf(config_path, GX_ARRAY_SIZE(config_path), "%s.cfg", file_name);
		sprintf(uncheck_path, "%s/uncheck_domains.txt", get_state_path());
		auto pfile = config_file_initd(config_path, get_config_path());
		if (NULL == pfile) {
			printf("[mysql_adaptor]: config_file_initd %s: %s\n",
			       config_path, strerror(errno));
			return FALSE;
		}
		auto str_value = config_file_get_value(pfile, "CONNECTION_NUM");
		if (NULL == str_value) {
			conn_num = 8;
			config_file_set_value(pfile, "CONNECTION_NUM", "8");
		} else {
			conn_num = atoi(str_value);
			if (conn_num < 0) {
				conn_num = 8;
				config_file_set_value(pfile, "CONNECTION_NUM", "8");
			}
		}
		printf("[mysql_adaptor]: mysql connection number is %d\n", conn_num);

		str_value = config_file_get_value(pfile, "MYSQL_HOST");
		if (NULL == str_value) {
			strcpy(mysql_host, "localhost");
			config_file_set_value(pfile, "MYSQL_HOST", "localhost");
		} else {
			gx_strlcpy(mysql_host, str_value, GX_ARRAY_SIZE(mysql_host));
		}

		str_value = config_file_get_value(pfile, "MYSQL_PORT");
		if (NULL == str_value) {
			mysql_port = 3306;
			config_file_set_value(pfile, "MYSQL_PORT", "3306");
		} else {
			mysql_port = atoi(str_value);
			if (mysql_port <= 0) {
				mysql_port = 3306;
				config_file_set_value(pfile, "MYSQL_PORT", "3306");
			}
		}
		printf("[mysql_adaptor]: mysql address is [%s]:%d\n",
		       *mysql_host == '\0' ? "*" : mysql_host, mysql_port);

		str_value = config_file_get_value(pfile, "MYSQL_USERNAME");
		gx_strlcpy(mysql_user, str_value != nullptr ? str_value : "root", GX_ARRAY_SIZE(mysql_user));
		auto mysql_passwd = config_file_get_value(pfile, "MYSQL_PASSWORD");
		str_value = config_file_get_value(pfile, "MYSQL_DBNAME");
		if (NULL == str_value) {
			strcpy(db_name, "email");
			config_file_set_value(pfile, "MYSQL_DBNAME", "email");
		} else {
			gx_strlcpy(db_name, str_value, GX_ARRAY_SIZE(db_name));
		}
		printf("[mysql_adaptor]: mysql database name is %s\n", db_name);

		str_value = config_file_get_value(pfile, "MYSQL_RDWR_TIMEOUT");
		if (NULL == str_value) {
			timeout = 0;
		} else {
			timeout = atoi(str_value);
			if (timeout < 0) {
				timeout = 0;
			}
		}
		if (timeout > 0) {
			printf("[mysql_adaptor]: mysql read write timeout is %d\n",
				timeout);
		}

		str_value = config_file_get_value(pfile, "schema_upgrades");
		enum sql_schema_upgrade upg = S_SKIP;
		auto prog_id = get_prog_id();
		if (str_value != nullptr && strncmp(str_value, "host:", 5) == 0 &&
		    prog_id != nullptr && strcmp(prog_id, "http") == 0 &&
		    strcmp(str_value + 5, get_host_ID()) == 0) {
			upg = S_AUTOUP;
		} else if (str_value != nullptr && strcmp(str_value, "skip") == 0) {
			upg = S_SKIP;
		} else if (str_value != nullptr && strcmp(str_value, "autoupgrade") == 0) {
			upg = S_AUTOUP;
		}

		str_value = config_file_get_value(pfile, "enable_firsttime_password");
		bool firsttimepw = str_value != nullptr && strcmp(str_value, "yes") == 0;
		
		mysql_adaptor_init({mysql_host, mysql_user, mysql_passwd,
			db_name, mysql_port, conn_num, timeout, upg, firsttimepw});
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
