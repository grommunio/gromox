#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libHX/string.h>
#include <gromox/paths.h>
#include <gromox/system_log.h>
#include "match_engine.h"
#include "admin_ui.h"
#include <gromox/acl_control.h>
#include "log_flusher.h"
#include "config_file.h"
#include "util.h"
#include <unistd.h>
#include <string.h>
#include <time.h>

int main(int argc, const char **argv)
{
	const char *str_value;
	char temp_path[256];
	char data_path[256];
	char token_path[256];
	char acl_path[256];
	int timeout;
	int valid_days;
	CONFIG_FILE *pconfig;

	HX_strlcpy(temp_path, PKGSYSCONFDIR "/sa.cfg", sizeof(temp_path));
	pconfig = config_file_init2(NULL, temp_path);
	if (NULL == pconfig) {
		return 1;
	}
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(data_path, PKGDATASADIR, sizeof(data_path));
	} else {
		strcpy(data_path, str_value);
	}
	snprintf(temp_path, sizeof(temp_path), "%s/console_table.txt", data_path);
	log_flusher_init(temp_path);
	str_value = config_file_get_value(pconfig, "GATEWAY_MOUNT_PATH");
	if (NULL == str_value) {
		str_value = PKGSTATEGATEWAYDIR;
	}
	match_engine_init(str_value);
	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		str_value = PKGLOGDIR "/sa.log";
	}
	system_log_init(str_value);
	str_value = config_file_get_value(pconfig, "TOKEN_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(token_path, PKGRUNSADIR, sizeof(token_path));
	} else {
		strcpy(token_path, str_value);
	}
	snprintf(temp_path, sizeof(temp_path), "%s/session.shm", token_path);
	snprintf(acl_path, sizeof(temp_path), "%s/system_users.txt", data_path);
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
		str_value = DFL_LOGOLINK;
	}
	snprintf(temp_path, sizeof(temp_path), "%s/admin_log", data_path);
	admin_ui_init(valid_days, str_value, temp_path);
	str_value = config_file_get_value(pconfig, "HTTP_ACCEPT_LANGUAGE");
	if (str_value != NULL && *str_value != '\0')
		setenv("HTTP_ACCEPT_LANGUAGE", str_value, 1);
	config_file_free(pconfig);
	if (0 != system_log_run()) {
		return 2;
	}
	if (0 != acl_control_run()) {
		return 3;
	}
	if (0 != log_flusher_run()) {
		return 4;
	}
	if (0 != match_engine_run()) {
		return 5;
	}
	if (0 != admin_ui_run()) {
		return 6;
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

