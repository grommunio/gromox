#include "util.h"
#include "smtp.h"
#include "message.h"
#include "system_log.h"
#include "data_source.h"
#include "midb_client.h"
#include "locker_client.h"
#include "engine.h"
#include "config_file.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define SCANNER_VERSION		"1.0"

static BOOL g_notify_stop = FALSE;

static void term_handler(int signo);

int main(int argc, char **argv)
{
	int log_days;
	int valid_days;
	int mysql_port;
	int locker_port;
	char *str_value;
	int max_interval;
	char db_name[256];
	char *mysql_passwd;
	char locker_ip[16];
	char log_path[256];
	char data_path[256];
	char logo_path[256];
	char logo_link[256];
	char area_path[256];
	char midb_path[256];
	char temp_buff[128];
	char mysql_user[256];
	char mysql_host[256];
	CONFIG_FILE *pconfig;
	char backup_path[256];
	BOOL freetime_scanning;
	BOOL parellel_scanning;
	char admin_mailbox[256];
	char default_domain[256];
	char background_path[256];

	if (2 != argc) {
		printf("%s <cfg file>\n", argv[0]);
		return -10;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("%s <cfg file>\n", argv[0]);
		return 0;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", SCANNER_VERSION);
		return 0;
	}
	umask(0);
	pconfig = config_file_init(argv[1]);
	if (NULL == pconfig) {
		printf("[system]: fail to open config file %s\n", argv[1]);
		return -1;
	}
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		strcpy(data_path, "../data");
		config_file_set_value(pconfig, "DATA_FILE_PATH", "../data");
	} else {
		strcpy(data_path, str_value);
	}

	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		strcpy(log_path, "../logs/athena_log.txt");
		config_file_set_value(pconfig, "LOG_FILE_PATH",
			"../logs/athena_log.txt");
	} else {
		strcpy(log_path, str_value);
	}
	printf("[system]: log path is %s\n", log_path);
	
	str_value = config_file_get_value(pconfig, "LOGO_LINK");
	if (NULL == str_value) {
		strcpy(logo_link, "http://www.gridware.com.cn");
	} else {
		strcpy(logo_link, str_value);
	}
	printf("[system]: data path is %s\n", data_path);
	sprintf(logo_path, "%s/picture/logo_bb.gif", data_path);
	sprintf(background_path, "%s/picture/di1.gif", data_path);
	sprintf(area_path, "%s/area_list.txt", data_path);
	sprintf(midb_path, "%s/midb_list.txt", data_path);

	
	str_value = config_file_get_value(pconfig, "ADMIN_MAILBOX");
	if (NULL == str_value) {
		strcpy(admin_mailbox, "admin@gridware.com.cn");
		config_file_set_value(pconfig, "ADMIN_MAILBOX", "admin@gridware.com.cn");
	} else {
		strcpy(admin_mailbox, str_value);
	}
	printf("[system]: administrator mailbox is %s\n", admin_mailbox);

	str_value = config_file_get_value(pconfig, "DEFAULT_DOMAIN");
	if (NULL == str_value) {
		strcpy(default_domain, "herculiz.com");
		config_file_set_value(pconfig, "DEFAULT_DOMAIN", "herculiz.com");
	} else {
		strcpy(default_domain, str_value);
	}
	printf("[system]: default domain is %s\n", default_domain);

	str_value = config_file_get_value(pconfig, "BACKUP_VALID_DAYS");
	if (NULL == str_value) {
		valid_days = 90;
		config_file_set_value(pconfig, "BACKUP_VALID_DAYS", "90");
	} else {
		valid_days = atoi(str_value);
		if (valid_days <= 0) {
			valid_days = 90;
			config_file_set_value(pconfig, "BACKUP_VALID_DAYS", "90");
		}
	}
	printf("[system]: mail backup valid days is %d\n", valid_days);

	str_value = config_file_get_value(pconfig, "LOG_VALID_DAYS");
	if (NULL == str_value) {
		log_days = 30;
		config_file_set_value(pconfig, "LOG_VALID_DAYS", "30");
	} else {
		log_days = atoi(str_value);
		if (log_days <= 0) {
			log_days = 30;
			config_file_set_value(pconfig, "LOG_VALID_DAYS", "30");
		}
	}
	printf("[system]: log valid days is %d\n", log_days);
	
	str_value = config_file_get_value(pconfig, "PARELLEL_SCANNING");
	if (NULL == str_value) {
		parellel_scanning = FALSE;
		config_file_set_value(pconfig, "PARELLEL_SCANNING", "FALSE");
	} else {
		if (0 == strcasecmp(str_value, "TRUE") ||
			0 == strcasecmp(str_value, "ON")) {
			parellel_scanning = TRUE;
		} else if (0 == strcasecmp(str_value, "FALSE")
			|| 0 == strcasecmp(str_value, "OFF")) {
			parellel_scanning = FALSE;
		} else {
			parellel_scanning = FALSE;
			config_file_set_value(pconfig, "PARELLEL_SCANNING", "FALSE");
		}
	}
	
	str_value = config_file_get_value(pconfig, "FREETIME_SCANNING");
	if (NULL == str_value) {
		freetime_scanning = TRUE;
		config_file_set_value(pconfig, "FREETIME_SCANNING", "TRUE");
	} else {
		if (0 == strcasecmp(str_value, "TRUE") ||
			0 == strcasecmp(str_value, "ON")) {
			freetime_scanning = TRUE;
		} else if (0 == strcasecmp(str_value, "FALSE")
			|| 0 == strcasecmp(str_value, "OFF")) {
			freetime_scanning = FALSE;
		} else {
			freetime_scanning = TRUE;
			config_file_set_value(pconfig, "FREETIME_SCANNING", "TRUE");
		}
	}
	
	str_value = config_file_get_value(pconfig, "MYSQL_HOST");
	if (NULL == str_value) {
		strcpy(mysql_host, "localhost");
		config_file_set_value(pconfig, "MYSQL_HOST", "localhost");
	} else {
		strcpy(mysql_host, str_value);
	}
	printf("[system]: mysql host is %s\n", mysql_host);

	str_value = config_file_get_value(pconfig, "MYSQL_PORT");
	if (NULL == str_value) {
		mysql_port = 3306;
		config_file_set_value(pconfig, "MYSQL_PORT", "3306");
	} else {
		mysql_port = atoi(str_value);
		if (mysql_port <= 0) {
			mysql_port = 3306;
			config_file_set_value(pconfig, "MYSQL_PORT", "3306");
		}
	}
	printf("[system]: mysql port is %d\n", mysql_port);

	str_value = config_file_get_value(pconfig, "MYSQL_USERNAME");
	if (NULL == str_value) {
		mysql_user[0] = '\0';
		printf("[system]: cannot find mysql username in config "
			"file, use current unix login name\n");
	} else {
		strcpy(mysql_user, str_value);
		printf("[system]: mysql username is %s\n", mysql_user);
	}

	mysql_passwd = config_file_get_value(pconfig, "MYSQL_PASSWORD");
	if (NULL == mysql_passwd) {
		printf("[system]: use empty password as mysql password\n");
	} else {
		if ('\0' == mysql_passwd[0]) {
			printf("[system]: use empty password as mysql password\n");
		} else {
			printf("[system]: mysql password is ********\n");
		}
	}

	str_value = config_file_get_value(pconfig, "MYSQL_DBNAME");
	if (NULL == str_value) {
		strcpy(db_name, "email");
		config_file_set_value(pconfig, "MYSQL_DBNAME", "email");
	} else {
		strcpy(db_name, str_value);
	}
	printf("[system]: mysql database name is %s\n", db_name);

	str_value = config_file_get_value(pconfig, "MYSQL_BACKUP_PATH");
	if (NULL == str_value) {
		strcpy(backup_path, "/tmp");
		config_file_set_value(pconfig, "MYSQL_BACKUP_PATH", "/tmp");
	} else {
		strcpy(backup_path, str_value);
	}
	printf("[system]: mysql bckup path is %s\n", backup_path);

	
	str_value = config_file_get_value(pconfig, "LOCKER_LISTEN_IP");
	if (NULL == str_value) {
		strcpy(locker_ip, "127.0.0.1");
		config_file_set_value(pconfig, "LOCKER_LISTEN_IP", "127.0.0.1");
	} else {
		strncpy(locker_ip, str_value, 16);
	}
	printf("[system]: locker listen ip is %s\n", locker_ip);

	str_value = config_file_get_value(pconfig, "LOCKER_LISTEN_PORT");
	if (NULL == str_value) {
		locker_port = 7777;
		config_file_set_value(pconfig, "LOCKER_LISTEN_PORT", "7777");
	} else {
		locker_port = atoi(str_value);
		if (locker_port <= 0) {
			locker_port = 7777;
			config_file_set_value(pconfig, "LOCKER_LISTEN_PORT", "7777");
		}
	}
	printf("[system]: locker listen port is %d\n", locker_port);

	str_value = config_file_get_value(pconfig, "LOCKER_MAXIMUM_INTERVAL");
	if (NULL == str_value) {
		max_interval = 180;
		config_file_set_value(pconfig, "LOCKER_MAXIMUM_INTERVAL", "3minutes");
	} else {
		max_interval = atoitvl(str_value);
		if (max_interval <= 0) {
			max_interval = 180;
			config_file_set_value(pconfig, "LOCKER_MAXIMUM_INTERVAL",
				"3minutes");
		}
	}
	itvltoa(max_interval, temp_buff);
	printf("[system]: locker maximum interval is %s\n", temp_buff);

	
	system_log_init(log_path);
	
	smtp_init();
	
	message_init(background_path, logo_path, logo_link);
	
	data_source_init(mysql_host, mysql_port,
		mysql_user, mysql_passwd, db_name);
	
	locker_client_init(locker_ip, locker_port, max_interval);

	midb_client_init(midb_path);
	
	engine_init(area_path, log_days, valid_days, default_domain,
		admin_mailbox, db_name, backup_path, parellel_scanning,
		freetime_scanning);

	config_file_save(pconfig);
	config_file_free(pconfig);
	
	if (0 != system_log_run()) {
		printf("[system]: fail to run system log\n");
		return -2;
	}
	
	if (0 != smtp_run()) {
		printf("[system]: fail to run smtp\n");
		return -3;
	}
	
	if (0 != message_run()) {
		printf("[system]: fail to run message\n");
		return -4;
	}
	if (0 != data_source_run()) {
		printf("[system]: fail to run data source\n");
		return -5;
	}

	if (0 != locker_client_run()) {
		printf("[system]: fail to run locker client\n");
		return -6;
	}

	if (0 != midb_client_run()) {
		printf("[system]: fail to run midb client\n");
		return -7;
	}

	if (0 != engine_run()) {
		printf("[system]: fail to run engine\n");
		return -8;
	}
	
	printf("[system]: SCANNER is now running\n");
	
	signal(SIGTERM, term_handler);
	while (TRUE != g_notify_stop) {
		sleep(1);
	}
	engine_stop();
	engine_free();
	midb_client_stop();
	midb_client_free();
	locker_client_stop();
	locker_client_free();
	data_source_stop();
	data_source_free();
	message_stop();
	message_free();
	smtp_stop();
	smtp_free();
	system_log_stop();
	system_log_free();
	return 0;
}

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}

