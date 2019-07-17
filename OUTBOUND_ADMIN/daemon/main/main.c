#include "log_flusher.h"
#include "log_analyzer.h"
#include "system_log.h"
#include "keyword_cleaning.h"
#include "file_operation.h"
#include "smtp_sender.h"
#include "auto_backup.h"
#include "config_file.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DAEMON_VERSION		"2.0"

int main(int argc, char **argv)
{
	char *str_value;
	time_t now_time;
	CONFIG_FILE *pconfig;
	char console_path[256];
	char data_path[256];
	char mount_path[256];
	char log_path[256];
	char admin_mailbox[256];
	char default_domain[256];
	char backend_path[256];
	char system_backup_path[256];
	char group_path[256];
	char kstatisitic_path[256];
	char statistic_path[256];

	if (2 != argc) {
		printf("%s <cfg file>\n", argv[0]);
		return -10;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("%s <cfg file>\n", argv[0]);
		return 0;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", DAEMON_VERSION);
		return 0;
	}
	time(&now_time);	
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
	str_value = config_file_get_value(pconfig, "GATEWAY_MOUNT_PATH");
	if (NULL == str_value) {
		strcpy(mount_path, "../gateway");
		config_file_set_value(pconfig, "GATEWAY_MOUNT_PATH", "../gateway");
	} else {
		strcpy(mount_path, str_value);
	}
	printf("[system]: gateway mount path is %s\n", mount_path);
	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		strcpy(log_path, "../logs/athena_log.txt");
		config_file_set_value(pconfig, "LOG_FILE_PATH",
				"../logs/athena_log.txt");
	} else {
		strcpy(log_path, str_value);
	}
	printf("[system]: log path is %s\n", log_path);

	str_value = config_file_get_value(pconfig, "SYSTEM_BACKUP_PATH");
	if (NULL == str_value) {
		strcpy(system_backup_path, "../sys_backup");
	} else {
		strcpy(system_backup_path, str_value);
	}
	printf("[system]: system backup path is %s\n", system_backup_path);

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
	
	config_file_save(pconfig);
	config_file_free(pconfig);
	sprintf(statistic_path, "%s/mail_statistic.txt", data_path);
	sprintf(console_path, "%s/console_table.txt", data_path);
	sprintf(backend_path, "%s/backend_table.txt", data_path);
	sprintf(group_path, "%s/keyword_group.txt", data_path);
	sprintf(kstatisitic_path, "%s/keyword_statistic.txt", data_path);
	system_log_init(log_path);
	log_flusher_init(console_path);
	log_analyzer_init(now_time, statistic_path, mount_path);
	keyword_cleaning_init(now_time, group_path, console_path, kstatisitic_path);
	file_operation_init();
	smtp_sender_init(backend_path);
	auto_backup_init(argv[1], data_path, system_backup_path,
		admin_mailbox, default_domain);
	if (0 != system_log_run()) {
		printf("[system]: fail to run system log\n");
		return -1;
	}
	if (0 != log_flusher_run()) {
		printf("[system]: fail to run log flusher\n");
		return -2;
	}
	if (0 != log_analyzer_run()) {
		printf("[system]: fail to run domain classifier\n");
		return -3;
	}
	if (0 != keyword_cleaning_run()) {
		printf("[system]: fail to run keyword cleaning\n");
		return -4;
	}
	if (0 != file_operation_run()) {
		printf("[system]: fail to run file operation\n");
		return -5;
	}
	if (0 != smtp_sender_run()) {
		printf("[system]: fail to run smtp sender\n");
		return -6;
	}
	if (0 != auto_backup_run()) {
		printf("[system]: fail to run config backup\n");
		return -7;
	}

	system_log_stop();
	log_flusher_stop();
	log_analyzer_stop();
	keyword_cleaning_stop();
	file_operation_stop();
	smtp_sender_stop();
	auto_backup_stop();

	system_log_free();
	log_flusher_free();
	log_analyzer_free();
	keyword_cleaning_free();
	file_operation_free();
	smtp_sender_free();
	auto_backup_free();
	printf("[system]: DAEMON run OK\n");
	return 0;
}
