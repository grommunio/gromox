#include "util.h"
#include "engine.h"
#include "data_source.h"
#include "file_operation.h"
#include "system_log.h"
#include "gateway_control.h"
#include "config_file.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define ADAPTOR_VERSION		"1.0"

static BOOL g_notify_stop = FALSE;

static void term_handler(int signo);

int main(int argc, char **argv)
{
	char *str_value;
	char data_path[256];
	char mount_path[256];
	char log_path[256];
	char domainlist_path[256];
	char aliasaddress_path[256];
	char aliasdomain_path[256];
	char backup_path[256];
	char unchkusr_path[256];
	char collector_path[256];
	char subsystem_path[256];
	char console_path[256];
	char mysql_host[256];
	int mysql_port;
	char mysql_user[256];
	char *mysql_passwd;
	char db_name[256];
	CONFIG_FILE *pconfig;

	if (2 != argc) {
		printf("%s <cfg file>\n", argv[0]);
		return -10;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("%s <cfg file>\n", argv[0]);
		return 0;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", ADAPTOR_VERSION);
		return 0;
	}
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
	printf("[system]: data path is %s\n", data_path);
	sprintf(domainlist_path, "%s/domain_list.txt", data_path);
	sprintf(aliasaddress_path, "%s/alias_addresses.txt", data_path);
	sprintf(aliasdomain_path, "%s/alias_domains.txt", data_path);
	sprintf(backup_path, "%s/backup_list.txt", data_path);
	sprintf(unchkusr_path, "%s/uncheck_domains.txt", data_path);
	sprintf(collector_path, "%s/mailbox_collector.txt", data_path);
	sprintf(subsystem_path, "%s/domain_subsystem.txt", data_path);
	sprintf(console_path, "%s/console_table.txt", data_path);

	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		strcpy(log_path, "../logs/athena_log.txt");
		config_file_set_value(pconfig, "LOG_FILE_PATH",
			"../logs/athena_log.txt");
	} else {
		strcpy(log_path, str_value);
	}
	printf("[system]: log path is %s\n", log_path);

	str_value = config_file_get_value(pconfig, "GATEWAY_MOUNT_PATH");
	if (NULL == str_value) {
		strcpy(mount_path, "../gateway");
		config_file_set_value(pconfig, "GATEWAY_MOUNT_PATH", "../gateway");
	} else {
		strcpy(mount_path, str_value);
	}
	printf("[system]: gateway mount path is %s\n", mount_path);
	
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

	file_operation_init(mount_path);

	system_log_init(log_path);
	
	gateway_control_init(console_path);
	
	data_source_init(mysql_host, mysql_port, mysql_user, mysql_passwd, db_name);
	
	engine_init(mount_path, domainlist_path,
		aliasaddress_path, aliasdomain_path, backup_path,
		unchkusr_path, collector_path, subsystem_path);


	config_file_save(pconfig);
	config_file_free(pconfig);
	
	if (0 != file_operation_run()) {
		printf("[system]: fail to run file operation\n");
		return -2;
	}

	if (0 != system_log_run()) {
		printf("[system]: fail to run system log\n");
		return -3;
	}
	
	if (0 != gateway_control_run()) {
		printf("[system]: fail to run gateway control\n");
		return -4;
	}
	if (0 != data_source_run()) {
		printf("[system]: fail to run data source\n");
		return -5;
	}

	if (0 != engine_run()) {
		printf("[system]: fail to run engine\n");
		return -6;
	}
	
	printf("[system]: ADAPTOR is now running\n");
	
	signal(SIGTERM, term_handler);
	while (TRUE != g_notify_stop) {
		sleep(1);
	}

	engine_stop();
	engine_free();
	data_source_stop();
	data_source_free();
	gateway_control_stop();
	gateway_control_free();
	system_log_stop();
	system_log_free();
	file_operation_stop();
	file_operation_free();
	return 0;
}

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}

