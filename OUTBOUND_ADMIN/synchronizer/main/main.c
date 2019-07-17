#include "processing_engine.h"
#include "file_operation.h"
#include "gateway_control.h"
#include "url_downloader.h"
#include "config_file.h"
#include "mail_func.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#define SYNCHRONIZER_VERSION      "1.0"

static BOOL g_notify_stop = FALSE;

static void term_handler(int signo);

int main(int argc, char **argv)
{
	BOOL b_noop;
	char *str_value;
	char master_ip[16];
	char mask_string[21];
	char temp_buff[256];
	char data_path[256];
	char log_path[256];
	char token_path[256];
	char file_path[256];
	char shm_path[256];
	char list_path[256];
	char console_path[256];
	char mount_path[256];
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
		printf("version: %s\n", SYNCHRONIZER_VERSION);
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

	str_value = config_file_get_value(pconfig, "TOKEN_FILE_PATH");
	if (NULL == str_value) {
		strcpy(token_path, "../token");
		config_file_set_value(pconfig, "TOKEN_FILE_PATH", "../token");
	} else {
		strcpy(token_path, str_value);
	}
	printf("[system]: token path is %s\n", token_path);
	
	str_value = config_file_get_value(pconfig, "GATEWAY_MOUNT_PATH");
	if (NULL == str_value) {
		strcpy(mount_path, "../gateway");
		config_file_set_value(pconfig, "GATEWAY_MOUNT_PATH", "../gateway");
	} else {
		strcpy(mount_path, str_value);
	}
	printf("[system]: gateway mount path is %s\n", mount_path);

	str_value = config_file_get_value(pconfig, "SYNC_SWITCH");
	if (NULL == str_value) {
		b_noop = TRUE;
	} else {
		if (0 == strcasecmp(str_value, "TRUE")) {
			b_noop = FALSE;
		} else {
			b_noop = TRUE;
		}
	}
	
	str_value = config_file_get_value(pconfig, "MASTER_ADDRESS");
	memset(master_ip, 0, sizeof(master_ip));
	if (NULL == str_value) {
		b_noop = TRUE;
	} else if (NULL == extract_ip(str_value, master_ip)) {
		b_noop = TRUE;
	}
	
	if (TRUE == b_noop) {
		printf("[system]: web adaptor will not work\n");
	} else {
		printf("[system]: web adaptor will work\n");
	}
	str_value = config_file_get_value(pconfig, "SYNC_MASK_STRING");
	memset(mask_string, '0', sizeof(mask_string));
	if (NULL != str_value) {
		strcpy(mask_string, str_value);
	}
	
	config_file_save(pconfig);
	config_file_free(pconfig);
	
	sprintf(console_path, "%s/console_table.txt", data_path);
	sprintf(file_path, "%s/control.msg", token_path);
	sprintf(shm_path, "%s/sessions.shm", token_path);
	
	
	url_downloader_init();
	gateway_control_init(console_path);
	file_operation_init(mount_path);
	processing_engine_init(master_ip, data_path, argv[1], file_path,
		shm_path, mask_string, b_noop);
	
	
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
	if (0 != processing_engine_run()) {
		printf("[system]: fail to processing engine\n");
		return -4;
	}
	printf("[system]: SYNCHRONIZER run OK\n");
	
	signal(SIGTERM, term_handler);
	while (TRUE != g_notify_stop) {
		sleep(1);
	}
	
	processing_engine_stop();
	file_operation_stop();
	gateway_control_stop();
	url_downloader_stop();

	url_downloader_free();
	gateway_control_free();
	file_operation_free();
	processing_engine_free();
	return 0;
}

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}
