#include "system_log.h"
#include "match_engine.h"
#include "admin_ui.h"
#include "acl_control.h"
#include "log_flusher.h"
#include "config_file.h"
#include "util.h"
#include <unistd.h>
#include <string.h>
#include <time.h>


int main(int argc, char **argv)
{
	char *str_value;
	char work_path[256];
	char temp_path[256];
	char data_path[256];
	char token_path[256];
	char acl_path[256];
	int timeout;
	int valid_days;
	CONFIG_FILE *pconfig;

	if (NULL == getcwd(work_path, 256)) {
		exit(-1);
	}
	sprintf(temp_path, "%s/../config/athena.cfg", work_path);
	pconfig = config_file_init(temp_path);
	if (NULL == pconfig) {
		exit(-1);
	}
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		strcpy(data_path, "../data");
	} else {
		strcpy(data_path, str_value);
	}
	sprintf(temp_path, "%s/%s/console_table.txt", work_path, data_path);
	log_flusher_init(temp_path);
	str_value = config_file_get_value(pconfig, "GATEWAY_MOUNT_PATH");
	if (NULL == str_value) {
		str_value = "../gateway";
	}
	sprintf(temp_path, "%s/%s", work_path, str_value);
	match_engine_init(temp_path);
	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		str_value = "../logs/athena_log.txt";
	}
	sprintf(temp_path, "%s/%s", work_path, str_value);
	system_log_init(temp_path);
	str_value = config_file_get_value(pconfig, "TOKEN_FILE_PATH");
	if (NULL == str_value) {
		strcpy(token_path, "../token");
	} else {
		strcpy(token_path, str_value);
	}
	sprintf(temp_path, "%s/%s/session.shm", work_path, token_path);
	sprintf(acl_path, "%s/%s/system_users.txt", work_path, data_path);
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
	str_value = config_file_get_value(pconfig, "LOG_VALID_DAYS");
	if (NULL == str_value) {
		valid_days = 30;
	} else {
		valid_days = atoi(str_value);
		if (valid_days <= 0) {
			valid_days = 30;
		}
	}
	str_value = config_file_get_value(pconfig, "LOGO_LINK");
	if (NULL == str_value) {
		str_value = "http://www.gridware.com.cn";
	}
	sprintf(temp_path, "%s/%s/admin_log", work_path, data_path);
	admin_ui_init(valid_days, str_value, temp_path);
	str_value = config_file_get_value(pconfig, "HTTP_ACCEPT_LANGUAGE");
	if (NULL != str_value && '\0' != str_value) {
		setenv("HTTP_ACCEPT_LANGUAGE", str_value, 1);
	}
	config_file_free(pconfig);
	if (0 != system_log_run()) {
		exit(-2);
	}
	if (0 != acl_control_run()) {
		exit(-3);
	}
	if (0 != log_flusher_run()) {
		exit(-4);
	}
	if (0 != match_engine_run()) {
		exit(-5);
	}
	if (0 != admin_ui_run()) {
		exit(-6);
	}
	admin_ui_stop();
	admin_ui_free();
	match_engine_stop();
	match_engine_free();
	log_flusher_stop();
	log_flusher_free();
	acl_control_stop();
	acl_control_free();
	system_log_stop();
	system_log_free();
	exit(0);
}

