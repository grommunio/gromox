#include <libHX/string.h>
#include <gromox/paths.h>
#include "util.h"
#include "midb_tool.h"
#include "upload_ui.h"
#include <gromox/system_log.h>
#include "exmdb_tool.h"
#include "config_file.h"
#include "exmdb_client.h"
#include <gromox/locker_client.h>
#include <gromox/session_client.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int argc, const char **argv)
{
	const char *str_value;
	char locker_ip[16];
	char temp_path[256];
	char data_path[256];
	char lang_path[256];
	char list_path[256];
	char session_ip[16];
	char thumbnail_path[256];
	int locker_port;
	int session_port, max_file;
	int max_interval;
	char mysql_host[256];
	int mysql_port;
	char mysql_user[256];
	char *mysql_passwd;
	char db_name[256];
	CONFIG_FILE *pconfig;

	umask(0);
	HX_strlcpy(temp_path, PKGSYSCONFDIR "/da.cfg", sizeof(temp_path));
	pconfig = config_file_init2(NULL, temp_path);
	if (NULL == pconfig) {
		return 2;
	}
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(data_path, PKGDATADADIR, sizeof(data_path));
	} else {
		strcpy(data_path, str_value);
	}
	snprintf(temp_path, sizeof(temp_path), "%s/exmdb_list.txt", data_path);
	exmdb_client_init(temp_path);
	
	exmdb_tool_init(data_path);
	midb_tool_init(data_path);

	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		str_value = PKGLOGDIR "/da.log";
	}
	system_log_init(str_value);
	snprintf(list_path, sizeof(list_path), "%s/area_list.txt", data_path);

	str_value = config_file_get_value(pconfig, "SESSION_LISTEN_IP");
	if (NULL == str_value) {
		strcpy(session_ip, "127.0.0.1");
	} else {
		strncpy(session_ip, str_value, 16);
	}

	str_value = config_file_get_value(pconfig, "SESSION_LISTEN_PORT");
	if (NULL == str_value) {
		session_port = 9999;
	} else {
		session_port = atoi(str_value);
		if (session_port <= 0) {
			session_port = 9999;
		}
	}
	session_client_init(session_ip, session_port);
	

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


	str_value = config_file_get_value(pconfig, "LOCKER_LISTEN_IP");
	if (NULL == str_value) {
		strcpy(locker_ip, "127.0.0.1");
	} else {
		strncpy(locker_ip, str_value, 16);
	}

	str_value = config_file_get_value(pconfig, "LOCKER_LISTEN_PORT");
	if (NULL == str_value) {
		locker_port = 7777;
	} else {
		locker_port = atoi(str_value);
		if (locker_port <= 0) {
			locker_port = 7777;
		}
	}

	str_value = config_file_get_value(pconfig, "LOCKER_MAXIMUM_INTERVAL");
	if (NULL == str_value) {
		max_interval = 180;
	} else {
		max_interval = atoitvl(str_value);
		if (max_interval <= 0) {
			max_interval = 180;
		}
	}
	
	locker_client_init(locker_ip, locker_port, max_interval);

	str_value = config_file_get_value(pconfig, "MAXIMUM_MAILDIR_FILES");
	if (NULL == str_value) {
		max_file = 2000000;
	} else {
		max_file = atoi(str_value);
		if (max_file <= 0) {
			max_file = 5000;
		}
	}
	
	str_value = config_file_get_value(pconfig, "LOGO_LINK");
	if (NULL == str_value) {
		str_value = DFL_LOGOLINK;
	}
	snprintf(lang_path, sizeof(lang_path), "%s/group_binput", data_path);
	snprintf(thumbnail_path, sizeof(thumbnail_path), "%s/thumbnail", data_path);
	upload_ui_init(list_path, max_file, str_value, mysql_host, mysql_port,
		mysql_user, mysql_passwd, db_name, lang_path, thumbnail_path);
	config_file_free(pconfig);
	
	if (0 != system_log_run()) {
		return 2;
	}
	if (0 != session_client_run()) {
		return 3;
	}
	if (0 != locker_client_run()) {
		return 4;
	}
	if (0 != exmdb_client_run()) {
		return 5;
	}
	if (0 != exmdb_tool_run()) {
		return 6;
	}
	if (0 != midb_tool_run()) {
		return 7;
	}
	if (0 != upload_ui_run()) {
		return 8;
	}
	upload_ui_stop();
	upload_ui_free();
	exmdb_client_stop();
	exmdb_client_free();
	midb_tool_stop();
	midb_tool_free();
	exmdb_tool_stop();
	exmdb_tool_free();
	locker_client_stop();
	locker_client_free();
	session_client_stop();
	session_client_free();
	system_log_stop();
	system_log_free();
	exit(0);
}
