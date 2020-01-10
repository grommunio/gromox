#include <errno.h>
#include <gromox/svc_common.h>
#include "cdner_agent.h"
#include "mysql_adaptor.h"
#include "../../../MTA_SYSTEM/service_plugins/esmtp_auth/service_auth.h"
#include "uncheck_domains.h"
#include "util.h"
#include "config_file.h"
#include <string.h>
#include <stdio.h>
#include <pthread.h>

DECLARE_API;

static char g_config_path[256];

static void console_talk(int argc, char **argv, char *result, int length);

static bool is_mta()
{
	const char *i = query_service("_program_identifier");
	return strcmp(i, "smtp") == 0 || strcmp(i, "delivery") == 0;
}

BOOL SVC_LibMain(int reason, void** ppdata)
{
	CONFIG_FILE  *pfile;
	char file_name[256];
	char config_path[256];
	char uncheck_path[256];
	char temp_buff[128];
	char *str_value, *psearch, cdner_host_ip[16];
	char mysql_host[256], mysql_user[256];
	char *mysql_passwd, db_name[256]; 
	int conn_num, scan_interval, mysql_port, timeout;
	int cdner_conn_num, cdner_host_port;

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
		sprintf(uncheck_path, "%s/uncheck_domains.txt", get_data_path());
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

		str_value = config_file_get_value(pfile, "SCAN_INTERVAL");
		if (NULL == str_value) {
			scan_interval = 60;
			config_file_set_value(pfile, "SCAN_INTERVAL", "1minute");
		} else {
			scan_interval = atoitvl(str_value);
			if (scan_interval <= 0) {
				scan_interval = 60;
				config_file_set_value(pfile, "SCAN_INTERVAL", "1minute");
			}
		}
		itvltoa(scan_interval, temp_buff);
		printf("[mysql_adaptor]: reconnecting thread scanning interval is %s\n",
			temp_buff);

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
		
		str_value = config_file_get_value(pfile, "CDNER_CONNECTION_NUM");
		if (str_value == nullptr) {
			cdner_conn_num = 0;
		} else {
			cdner_conn_num = atoi(str_value);
			if (cdner_conn_num < 0 || cdner_conn_num > 20)
				cdner_conn_num = 0;
		}
		if (cdner_conn_num == 0)
			printf("[mysql_adaptor]: cdner agent is switched off\n");
		else
			printf("[mysql_adaptor]: cdner connection number is %d\n", cdner_conn_num);

		str_value = config_file_get_value(pfile, "CDNER_HOST_IP");
		if (str_value == nullptr)
			strcpy(cdner_host_ip, "127.0.0.1");
		else
			strcpy(cdner_host_ip, str_value);
		if (cdner_conn_num > 0)
			printf("[mysql_adaptor]: cdner host is %s\n", cdner_host_ip);

		str_value = config_file_get_value(pfile, "CDNER_HOST_PORT");
		if (str_value == nullptr) {
			cdner_host_port = 10001;
			config_file_set_value(pfile, "CDNER_HOST_PORT", "10001");
		} else {
			cdner_host_port = atoi(str_value);
			if (cdner_host_port <= 0) {
				cdner_host_port = 10001;
				config_file_set_value(pfile, "CDNER_HOST_PORT", "10001");
			}
		}
		if (cdner_conn_num > 0)
			printf("[mysql_adaptor]: cdner port is %d\n", cdner_host_port);

		cdner_agent_init(cdner_conn_num, cdner_host_ip, cdner_host_port);
		uncheck_domains_init(uncheck_path);
		mysql_adaptor_init(conn_num, scan_interval, mysql_host,
			mysql_port, mysql_user, mysql_passwd, db_name, timeout);
		if (is_mta())
			service_auth_init(get_context_num(), mysql_adaptor_login_smtp);
		config_file_free(pfile);
		
		if (cdner_agent_run() != 0) {
			printf("[mysql_adaptor]: failed to run cdner agent\n");
			return false;
		}
		if (uncheck_domains_run() != 0) {
			printf("[mysql_adaptor]: failed to run uncheck domains\n");
			return false;
		}
		if (0 != mysql_adaptor_run()) {
			printf("[mysql_adaptor]: failed to run mysql adaptor\n");
			return FALSE;
		}
		if (is_mta() && service_auth_run() != 0) {
			printf("[mysql_adaptor]: failed to run service auth\n");
			return false;
		}
		if (FALSE == register_service("auth_login_exch", mysql_adaptor_login_exch)) {
			printf("[mysql_adaptor]: failed to register \"auth_login_exch\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("auth_login_pop3", mysql_adaptor_login_pop3)) {
			printf("[mysql_adaptor]: failed to register \"auth_login_pop3\" service\n");
			return false;
		}
		if (FALSE == register_service("set_password",
			mysql_adaptor_setpasswd)) {
			printf("[mysql_adaptor]: failed to register"
						" \"set_password\" service\n");
			return FALSE;	
		}
		if (FALSE == register_service("get_username_from_id",
			mysql_adaptor_get_username_from_id)) {
			printf("[mysql_adaptor]: failed to register"
				" \"get_username_from_id\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_id_from_username",
			mysql_adaptor_get_id_from_username)) {
			printf("[mysql_adaptor]: failed to register"
				" \"get_id_from_username\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_id_from_maildir",
			mysql_adaptor_get_id_from_maildir)) {
			printf("[mysql_adaptor]: failed to register"
				" \"get_id_from_maildir\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_user_displayname",
			mysql_adaptor_get_user_displayname)) {
			printf("[mysql_adaptor]: failed to register"
				" \"get_user_displayname\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_user_privilege_bits",
			mysql_adaptor_get_user_privilege_bits)) {
			printf("[mysql_adaptor]: failed to register "
				"\"get_user_privilege_bits\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_user_lang",
			mysql_adaptor_get_user_lang)) {
			printf("[mysql_adaptor]: failed to register"
						" \"get_user_lang\" service\n");
			return FALSE;	
		}
		if (FALSE == register_service("set_user_lang",
			mysql_adaptor_set_user_lang)) {
			printf("[mysql_adaptor]: failed to register"
						" \"set_user_lang\" service\n");
			return FALSE;	
		}
		if (FALSE == register_service("get_timezone",
			mysql_adaptor_get_timezone)) {
			printf("[mysql_adaptor]: failed to register"
						" \"get_timezone\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("set_timezone",
			mysql_adaptor_set_timezone)) {
			printf("[mysql_adaptor]: failed to register"
						" \"set_timezone\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_maildir",
			mysql_adaptor_get_maildir)) {
			printf("[mysql_adaptor]: failed to register"
						" \"get_maildir\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_domainname_from_id",
			mysql_adaptor_get_domainname_from_id)) {
			printf("[mysql_adaptor]: failed to register "
				"\"get_domainname_from_id\" service\n");
			return FALSE;	
		}
		if (FALSE == register_service("get_homedir",
			mysql_adaptor_get_homedir)) {
			printf("[mysql_adaptor]: failed to register"
						" \"get_homedir\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_domain_homedir", mysql_adaptor_get_domain_homedir)) {
			printf("[mysql_adaptor]: failed to register service \"get_domain_homedir\"\n");
			return false;
		}
		if (FALSE == register_service("get_homedir_by_id",
			mysql_adaptor_get_homedir_by_id)) {
			printf("[mysql_adaptor]: failed to register "
					"\"get_homedir_by_id\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_id_from_homedir",
			mysql_adaptor_get_id_from_homedir)) {
			printf("[mysql_adaptor]: failed to register"
				" \"get_id_from_homedir\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_user_ids",
			mysql_adaptor_get_user_ids)) {
			printf("[mysql_adaptor]: failed to register"
						" \"get_user_ids\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_domain_ids",
			mysql_adaptor_get_domain_ids)) {
			printf("[mysql_adaptor]: failed to register "
						"\"get_domain_ids\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_mlist_ids",
			mysql_adaptor_get_mlist_ids)) {
			printf("[mysql_adaptor]: failed to register "
						"\"get_mlist_ids\" service\n");
			return FALSE;	
		}
		if (FALSE == register_service("get_org_domains",
			mysql_adaptor_get_org_domains)) {
			printf("[mysql_adaptor]: failed to register"
					" \"get_org_domains\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_domain_info",
			mysql_adaptor_get_domain_info)) {
			printf("[mysql_adaptor]: failed to register"
					" \"get_domain_info\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("check_same_org",
			mysql_adaptor_check_same_org)) {
			printf("[mysql_adaptor]: failed to register "
						"\"check_same_org\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_domain_groups",
			mysql_adaptor_get_domain_groups)) {
			printf("[mysql_adaptor]: failed to register "
					"\"get_domain_groups\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_group_classes",
			mysql_adaptor_get_group_classes)) {
			printf("[mysql_adaptor]: failed to register "
					"\"get_group_classes\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_sub_classes",
			mysql_adaptor_get_sub_classes)) {
			printf("[mysql_adaptor]: failed to register"
					" \"get_sub_classes\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_class_users",
			mysql_adaptor_get_class_users)) {
			printf("[mysql_adaptor]: failed to register"
					" \"get_class_users\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_group_users",
			mysql_adaptor_get_group_users)) {
			printf("[mysql_adaptor]: failed to register"
					" \"get_group_users\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("get_domain_users",
			mysql_adaptor_get_domain_users)) {
			printf("[mysql_adaptor]: failed to register"
					" \"get_domain_users\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("check_mlist_include",
			mysql_adaptor_check_mlist_include)) {
			printf("[mysql_adaptor]: failed to register"
				" \"check_mlist_include\" service\n");
			return FALSE;
		}
		if (!register_service("check_same_org2", mysql_adaptor_check_same_org2)) {
			printf("[mysql_adaptor]: failed to register service \"check_same_org2\"\n");
			return false;
		}
		if (!register_service("check_user", mysql_adaptor_check_user)) {
			printf("[mysql_adaptor]: failed to register service \"check_user\"\n");
			return false;
		}
		if (!register_service("check_virtual_mailbox", mysql_adaptor_check_virtual)) {
			printf("[mysql_adaptor]: failed to register service \"check_virtual_mailbox\"\n");
			return false;
		}
		if (!register_service("get_forward_address", mysql_adaptor_get_forward)) {
			printf("[mysql_adaptor]: failed to register service \"get_forward_address\"\n");
			return false;
		}
		if (!register_service("get_user_groupname", mysql_adaptor_get_groupname)) {
			printf("[mysql_adaptor]: failed to register service \"get_groupname\"\n");
			return false;
		}
		if (!register_service("get_mail_list", mysql_adaptor_get_mlist)) {
			printf("[mysql_adaptor]: failed to register service \"get_mail_list\"\n");
			return false;
		}
		if (!register_service("get_user_info", mysql_adaptor_get_user_info)) {
			printf("[mysql_adaptor]: failed to register service \"get_user_info\"\n");
			return false;
		}
		if (!register_service("get_username", mysql_adaptor_get_username)) {
			printf("[mysql_adaptor]: failed to register service \"get_user_name\"\n");
			return false;
		}
		if (!register_service("disable_smtp", mysql_adaptor_disable_smtp)) {
			printf("[mysql_adaptor]: failed to register service \"disable_smtp\"\n");
			return false;
		}
		if (!register_service("auth_ehlo", service_auth_ehlo) ||
		    !register_service("auth_process", service_auth_process) ||
		    !register_service("auth_retrieve", service_auth_retrieve)||
		    !register_service("auth_clear", service_auth_clear)) {
			printf("[mysql_adaptor]: failed to register auth services\n");
			return false;
		}
		register_talk(console_talk);
        return TRUE;

    case PLUGIN_FREE:
		mysql_adaptor_stop();
		mysql_adaptor_free();
        return TRUE;
    }
    return FALSE;
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	CONFIG_FILE *pfile;
	int scan_interval, offset;
	char help_string[] = "250 mysql auth help information:\r\n"
						 "\t%s info\r\n"
						 "\t    --print the module information\r\n"
						 "\t%s set scan-interval <interval>\r\n"
						 "\t    --set reconnecting thread's scanning interval";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0]);
		result[length - 1] = '\0';
		return;
	}

	if (2 == argc && 0 == strcmp("info", argv[1])) {
		offset = snprintf(result, length,
					"250 mysql auth information:\r\n"
					"\ttotal mysql connections    %d\r\n"
					"\talive mysql connections    %d\r\n"
					"\tscan interval              ",
					mysql_adaptor_get_param(MYSQL_ADAPTOR_CONNECTION_NUMBER),
					mysql_adaptor_get_param(MYSQL_ADAPTOR_ALIVECONN_NUMBER));
		itvltoa(mysql_adaptor_get_param(MYSQL_ADAPTOR_SCAN_INTERVAL),
			result + offset);
		return;
	}

	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("scan-interval", argv[2])) {
		scan_interval = atoitvl(argv[3]);
		if (scan_interval <= 0) {
			snprintf(result, length, "550 interval should larger than 0");
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 fail to open config file");
			return;
		}
		config_file_set_value(pfile, "SCAN_INTERVAL", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		mysql_adaptor_set_param(MYSQL_ADAPTOR_SCAN_INTERVAL, scan_interval);
		snprintf(result, length, "250 scan-interval set OK");
		return;
	}

	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

