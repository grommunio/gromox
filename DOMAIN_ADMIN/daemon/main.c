#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <errno.h>
#include "log_flusher.h"
#include "domain_classifier.h"
#include "data_source.h"
#include "item_sorter.h"
#include "smtp_sender.h"
#include <gromox/system_log.h>
#include "config_file.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char **argv)
{
	int cache_size;
	char *str_value;
	time_t now_time;
	CONFIG_FILE *pconfig;
	char url_link[256];
	char data_path[256];
	char resource_path[256];
	char console_path[256];
	char mount_path[256];
	char log_path[256];
	char mysql_host[256];
	int mysql_port;
	char mysql_user[256];
	char *mysql_passwd;
	char db_name[256];

	if (2 != argc) {
		printf("%s <cfg file>\n", argv[0]);
		return 10;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("%s <cfg file>\n", argv[0]);
		return 0;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	time(&now_time);	
	pconfig = config_file_init(argv[1]);
	if (NULL == pconfig) {
		printf("[system]: config_file_init %s: %s\n", argv[1], strerror(errno));
		return 1;
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
	str_value = config_file_get_value(pconfig, "FILE_CACHE_SIZE");
	if (NULL == str_value) {
		cache_size = 5000;
		config_file_set_value(pconfig, "FILE_CACHE_SIZE", "5000");
	} else {
		cache_size = atoi(str_value);
		if (cache_size <= 0) {
			cache_size = 5000;
			config_file_set_value(pconfig, "FILE_CACHE_SIZE", "5000");
		}
	}
	printf("[system]: file cache size is %d\n", cache_size);
	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		strcpy(log_path, "../logs/posidon_log.txt");
		config_file_set_value(pconfig, "LOG_FILE_PATH",
				"../logs/posidon_log.txt");
	} else {
		strcpy(log_path, str_value);
	}
	printf("[system]: log path is %s\n", log_path);
	str_value = config_file_get_value(pconfig, "LOGO_LINK");
	if (NULL == str_value) {
		strcpy(url_link, "http://www.gridware.com.cn");
		config_file_set_value(pconfig, "LOGO_LINK", url_link);
	} else {
		strcpy(url_link, str_value);
	}
	printf("[system]: log link url is %s\n", url_link);

	sprintf(resource_path, "%s/daemon", data_path);
	sprintf(console_path, "%s/console_table.txt", data_path);
	system_log_init(log_path);
	log_flusher_init(console_path);

	smtp_sender_init();

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
	
	data_source_init(mysql_host, mysql_port, mysql_user, mysql_passwd, db_name);
	
	domain_classifier_init(now_time, mount_path, 100, cache_size);
	item_sorter_init(now_time, data_path, url_link, resource_path);

	config_file_save(pconfig);
	config_file_free(pconfig);
	
	if (0 != system_log_run()) {
		printf("[system]: fail to run system log\n");
		return 1;
	}
	if (0 != log_flusher_run()) {
		printf("[system]: fail to run log flusher\n");
		return 2;
	}
	if (0 != smtp_sender_run()) {
		printf("[system]: fail to run smtp sender\n");
		return 3;
	}
	if (0 != data_source_run()) {
		printf("[system]: fail to run data source\n");
		return 4;
	}
	if (0 != domain_classifier_run()) {
		printf("[system]: fail to run domain classifier\n");
		return 5;
	}
	if (0 != item_sorter_run()) {
		printf("[system]: fail to run item sorter\n");
		return 6;
	}
	item_sorter_stop();
	domain_classifier_stop();
	data_source_stop();
	smtp_sender_stop();
	log_flusher_stop();
	system_log_stop();

	item_sorter_free();
	domain_classifier_free();
	data_source_free();
	smtp_sender_free();
	log_flusher_free();
	system_log_free();
	printf("[system]: DAEMON run OK\n");
	return 0;
}
