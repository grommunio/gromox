// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <gromox/defs.h>
#include <gromox/svc_common.h>
#include "mysql_adaptor.h"
#include <gromox/util.hpp>
#include <gromox/config_file.hpp>
#include <cstring>
#include <cstdio>
#include <pthread.h>

DECLARE_API;

static char g_config_path[256];

BOOL SVC_LibMain(int reason, void** ppdata)
{
	CONFIG_FILE  *pfile;
	char file_name[256];
	char config_path[256];
	char uncheck_path[256];
	char *str_value, *psearch;
	char mysql_host[256], mysql_user[256];
	char *mysql_passwd, db_name[256]; 
	int conn_num, mysql_port, timeout;

    switch(reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);

		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(config_path, "%s/%s.cfg", get_config_path(), file_name);
		strcpy(g_config_path, config_path);
		sprintf(uncheck_path, "%s/uncheck_domains.txt", get_state_path());
		pfile = config_file_init2(NULL, config_path);
		if (NULL == pfile) {
			printf("[mysql_adaptor]: config_file_init %s: %s\n", config_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pfile, "CONNECTION_NUM");
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
			strcpy(mysql_host, str_value);
		}
		printf("[mysql_adaptor]: mysql host is %s\n", mysql_host);

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
		printf("[mysql_adaptor]: mysql port is %d\n", mysql_port);

		str_value = config_file_get_value(pfile, "MYSQL_USERNAME");
		if (NULL == str_value) {
			mysql_user[0] = '\0';
			printf("[mysql_adaptor]: cannot find mysql username in config "
				"file, use current unix login name\n");
		} else {
			strcpy(mysql_user, str_value);
			printf("[mysql_adaptor]: mysql username is %s\n", mysql_user);
		}
		
		mysql_passwd = config_file_get_value(pfile, "MYSQL_PASSWORD");
		if (NULL == mysql_passwd) {
			printf("[mysql_adaptor]: use empty password as mysql password\n");
		} else {
			if ('\0' == mysql_passwd[0]) {
				printf("[mysql_adaptor]: use empty password as mysql password\n");
			} else {
				printf("[mysql_adaptor]: mysql password is ********\n");
			}
		}

		str_value = config_file_get_value(pfile, "MYSQL_DBNAME");
		if (NULL == str_value) {
			strcpy(db_name, "email");
			config_file_set_value(pfile, "MYSQL_DBNAME", "email");
		} else {
			strcpy(db_name, str_value);
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
		enum sql_schema_upgrade upg;
		if (str_value != nullptr && strcmp(str_value, "skip") == 0)
			upg = S_SKIP;
		else if (str_value != nullptr && strcmp(str_value, "autoupgrade") == 0)
			upg = S_AUTOUP;
		
		mysql_adaptor_init({mysql_host, mysql_user, mysql_passwd,
			db_name, mysql_port, conn_num, timeout, upg});
		config_file_free(pfile);
		
		if (0 != mysql_adaptor_run()) {
			printf("[mysql_adaptor]: failed to run mysql adaptor\n");
			return FALSE;
		}

#define E(f, s) do { \
	if (!register_service((s), reinterpret_cast<void *>(f))) { \
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
		E(mysql_adaptor_get_username, "get_username");
#undef E
        return TRUE;

    case PLUGIN_FREE:
		mysql_adaptor_stop();
		mysql_adaptor_free();
        return TRUE;
    }
    return FALSE;
}
