#include <libHX/string.h>
#include <gromox/paths.h>
#include <gromox/system_log.h>
#include <gromox/session_client.h>
#include "list_ui.h"
#include "data_source.h"
#include "config_file.h"
#include <gromox/locker_client.h>
#include "util.h"
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char **argv)
{
	const char *str_value;
	char locker_ip[16];
	char temp_path[256];
	char data_path[256];
	char lang_path[256];
	char session_ip[16];
	time_t current_time;
	int locker_port;
	int session_port;
	int max_interval;
	char mysql_host[256];
	int mysql_port;
	char mysql_user[256];
	char *mysql_passwd;
	char db_name[256];
	CONFIG_FILE *pconfig;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	umask(0);
	HX_strlcpy(temp_path, PKGSYSCONFDIR "/da.cfg", sizeof(temp_path));
	pconfig = config_file_init2(NULL, temp_path);
	if (NULL == pconfig) {
		return 1;
	}
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(data_path, PKGDATADADIR, sizeof(data_path));
	} else {
		strcpy(data_path, str_value);
	}
	time(&current_time);
	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		str_value = PKGLOGDIR "/da.log";
	}
	system_log_init(str_value);

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

	data_source_init(mysql_host, mysql_port, mysql_user, mysql_passwd, db_name);

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
	
	str_value = config_file_get_value(pconfig, "LOGO_LINK");
	if (NULL == str_value) {
		str_value = DFL_LOGOLINK;
	}
	snprintf(lang_path, sizeof(lang_path), "%s/group_clists", data_path);
	list_ui_init(str_value, lang_path);
	config_file_free(pconfig);
	
	if (0 != system_log_run()) {
		return 2;
	}
	if (0 != session_client_run()) {
		return 3;
	}
	if (0 != data_source_run()) {
		return 4;
	}
	if (0 != locker_client_run()) {
		return 5;
	}
	if (0 != list_ui_run()) {
		return 6;
	}
	list_ui_stop();
	list_ui_free();
	locker_client_stop();
	locker_client_free();
	data_source_stop();
	data_source_free();
	session_client_stop();
	session_client_free();
	system_log_stop();
	system_log_free();
	exit(0);
}

