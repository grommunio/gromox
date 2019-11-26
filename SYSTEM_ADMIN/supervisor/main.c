#include "util.h"
#include "smtp.h"
#include "pop3.h"
#include "scheduler.h"
#include "message.h"
#include "config_file.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define SUPERVISOR_VERSION		"1.0"

static BOOL g_notify_stop = FALSE;

static void term_handler(int signo);

int main(int argc, char **argv)
{
	char *str_value;
	CONFIG_FILE *pconfig;
	char data_path[256];
	char list_path[256];
	char failure_path[256];
	char admin_mailbox[256];
	char default_domain[256];
	char temp_buff[128];
	int supervise_interval;

	if (2 != argc) {
		printf("%s <cfg file>\n", argv[0]);
		return -10;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("%s <cfg file>\n", argv[0]);
		return 0;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", SUPERVISOR_VERSION);
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
	sprintf(list_path, "%s/supervising_list.txt", data_path);
	sprintf(failure_path, "%s/supervising_failure.txt", data_path);
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
	
	str_value = config_file_get_value(pconfig, "SUPERVISE_INTERVAL");
	if (NULL == str_value) {
		supervise_interval = 360;
		config_file_set_value(pconfig, "SUPERVISE_INTERVAL", "6minutes");
	} else {
		supervise_interval = atoitvl(str_value);
		if (supervise_interval < 180) {
			supervise_interval = 180;
			config_file_set_value(pconfig, "SUPERVISE_INTERVAL", "3minutes");
		}
	}
	itvltoa(supervise_interval, temp_buff);
	printf("[system]: supervise interval is %s\n", temp_buff);
	config_file_save(pconfig);
	config_file_free(pconfig);

	message_init();
	smtp_init();
	pop3_init();
	scheduler_init(list_path, failure_path, default_domain, admin_mailbox,
		supervise_interval);
	
	if (0 != message_run()) {
		printf("[system]: fail to run message\n");
		return -2;
	}
	if (0 != smtp_run()) {
		printf("[system]: fail to run smtp\n");
		return -3;
	}
	if (0 != pop3_run()) {
		printf("[system]: fail to run pop3\n");
		return -4;
	}
	if (0 != scheduler_run()) {
		printf("[system]: fail to scheduler\n");
		return -5;
	}
	printf("[system]: SUPERVISOR is now running\n");
	signal(SIGTERM, term_handler);
	while (TRUE != g_notify_stop) {
		sleep(1);
	}

	scheduler_stop();
	pop3_stop();
	smtp_stop();
	message_stop();
	return 0;
}

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}

