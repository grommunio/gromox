#include <sys/stat.h>
#include <libHX/string.h>
#include <gromox/paths.h>
#include <gromox/system_log.h>
#include <gromox/acl_control.h>
#include "midb_client.h"
#include "message_lookup.h"
#include "admin_ui.h"
#include "data_source.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

int main(int argc, const char **argv)
{
	int hash_num;
	int valid_days;
	const char *str_value;
	char temp_path[256];
	char cidb_path[256];
	char data_path[256];
	char token_path[256];
	char acl_path[256];
	char lang_path[256];
	int timeout;
	char mysql_host[256];
	int mysql_port;
	char mysql_user[256];
	char *mysql_passwd;
	char db_name[256];
	CONFIG_FILE *pconfig;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	umask(0);
	HX_strlcpy(temp_path, PKGSYSCONFDIR "/sa.cfg", sizeof(temp_path));
	pconfig = config_file_init2(NULL, temp_path);
	if (NULL == pconfig) {
		return 1;
	}
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(data_path, PKGDATASADIR, sizeof(data_path));
	} else {
		strcpy(data_path, str_value);
	}
	snprintf(temp_path, sizeof(temp_path), "%s/midb_list.txt", data_path);
	midb_client_init(temp_path);

	str_value = config_file_get_value(pconfig, "BACKUP_HASH_NUM");
	if (NULL == str_value) {
		hash_num = 10;
	} else {
		hash_num = atoi(str_value);
		if (hash_num < 1) {
			hash_num = 10;
		}
	}
	snprintf(cidb_path, sizeof(cidb_path), "%s/cidb_list.txt", data_path);
	message_lookup_init(cidb_path);
	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		str_value = PKGLOGDIR "/sa.log";
	}
	system_log_init(str_value);
	str_value = config_file_get_value(pconfig, "TOKEN_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(token_path, PKGRUNSADIR, sizeof(token_path));
	} else {
		strcpy(token_path, str_value);
	}
	snprintf(temp_path, sizeof(temp_path), "%s/session.shm", token_path);
	snprintf(acl_path, sizeof(acl_path), "%s/system_users.txt", data_path);
	str_value = config_file_get_value(pconfig, "UI_TIMEOUT");
	if (NULL == str_value) {
		timeout = 600;
	} else {
		timeout = atoitvl(str_value);
		if (timeout <= 0) {
			timeout = 600;
		}
	}
	acl_control_init(temp_path, acl_path, timeout);
	str_value = config_file_get_value(pconfig, "MYSQL_HOST");
	if (NULL == str_value) {
		strcpy(mysql_host, "localhost");
	} else {
		strcpy(mysql_host, str_value);
	}

	str_value = config_file_get_value(pconfig, "MYSQL_PORT");
	if (NULL == str_value) {
		mysql_port = 3306;
	} else {
		mysql_port = atoi(str_value);
		if (mysql_port <= 0) {
			mysql_port = 3306;
		}
	}

	str_value = config_file_get_value(pconfig, "MYSQL_USERNAME");
	if (NULL == str_value) {
		mysql_user[0] = '\0';
	} else {
		strcpy(mysql_user, str_value);
	}

	mysql_passwd = config_file_get_value(pconfig, "MYSQL_PASSWORD");

	str_value = config_file_get_value(pconfig, "MYSQL_DBNAME");
	if (NULL == str_value) {
		strcpy(db_name, "email");
	} else {
		strcpy(db_name, str_value);
	}
	
	data_source_init(mysql_host, mysql_port, mysql_user, mysql_passwd, db_name);
	
	str_value = config_file_get_value(pconfig, "BACKUP_VALID_DAYS");
	if (NULL == str_value) {
		valid_days = 30;
	} else {
		valid_days = atoi(str_value);
		if (valid_days < 1) {
			valid_days = 30;
		}
	}
	str_value = config_file_get_value(pconfig, "LOGO_LINK");
	if (NULL == str_value) {
		str_value = DFL_LOGOLINK;
	}
	snprintf(lang_path, sizeof(lang_path), "%s/admin_archive", data_path);
	admin_ui_init(valid_days, str_value, cidb_path, lang_path);
	config_file_free(pconfig);
	if (0 != system_log_run()) {
		return 2;
	}
	if (0 != acl_control_run()) {
		return 3;
	}
	if (0 != data_source_run()) {
		return 4;
	}
	if (0 != midb_client_run()) {
		return 5;
	}
	if (0 != message_lookup_run()) {
		return 6;
	}
	if (0 != admin_ui_run()) {
		return 7;
	}
	admin_ui_stop();
	admin_ui_free();
	message_lookup_stop();
	message_lookup_free();
	midb_client_stop();
	midb_client_free();
	data_source_stop();
	data_source_free();
	acl_control_stop();
	acl_control_free();
	system_log_stop();
	system_log_free();
	exit(0);
}

