#include "domain_list.h"
#include "file_operation.h"
#include "gateway_control.h"
#include "url_downloader.h"
#include "config_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#define ADAPTOR_VERSION      "1.0"

static BOOL g_notify_stop = FALSE;

static void term_handler(int signo);

int main(int argc, char **argv)
{
	char *str_value;
	CONFIG_FILE *pconfig;
	char *domain_url;
	char temp_buff[256];
	char data_path[256];
	char log_path[256];
	char list_path[256];
	char console_path[256];
	char mount_path[256];
	BOOL b_noop;

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
	str_value = config_file_get_value(pconfig, "GATEWAY_MOUNT_PATH");
	if (NULL == str_value) {
		strcpy(mount_path, "../gateway");
		config_file_set_value(pconfig, "GATEWAY_MOUNT_PATH", "../gateway");
	} else {
		strcpy(mount_path, str_value);
	}
	printf("[system]: gateway mount path is %s\n", mount_path);

	str_value = config_file_get_value(pconfig, "LOCAL_SETUP_TYPE");
	if (NULL == str_value) {
		b_noop = TRUE;
	} else {
		if (1 == atoi(str_value)) {
			b_noop = FALSE;
		} else {
			b_noop = TRUE;
		}
	}
	domain_url = config_file_get_value(pconfig, "DOMAINLIST_URL_PATH");
	
	if (TRUE == b_noop || NULL == domain_url) {
		printf("[system]: web adaptor will not work\n");
	} else {
		printf("[system]: web adaptor will work\n");
	}
	
	
	sprintf(console_path, "%s/console_table.txt", data_path);
	sprintf(list_path, "%s/web_adaptor.txt", data_path);
	
	
	url_downloader_init();
	gateway_control_init(console_path);
	file_operation_init(mount_path);
	domain_list_init(domain_url, list_path, b_noop);
	
	config_file_save(pconfig);
	config_file_free(pconfig);
	
	if (0 != url_downloader_run()) {
		printf("[system]: fail to run url downloader\n");
		return -1;
	}
	if (0 != gateway_control_run()) {
		printf("[system]: fail to run gateway control\n");
		return -2;
	}
	if (0 != file_operation_run()) {
		printf("[system]: fail to run file operation\n");
		return -3;
	}
	if (0 != domain_list_run()) {
		printf("[system]: fail to run domain list\n");
		return -4;
	}
	printf("[system]: WEB ADAPTOR run OK\n");
	
	signal(SIGTERM, term_handler);
	while (TRUE != g_notify_stop) {
		sleep(1);
	}
	
	domain_list_stop();
	file_operation_stop();
	gateway_control_stop();
	url_downloader_stop();

	url_downloader_free();
	gateway_control_free();
	file_operation_free();
	domain_list_free();
	return 0;
}

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}
