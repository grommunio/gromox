#include <sys/stat.h>
#include <libHX/string.h>
#include <gromox/paths.h>
#include <gromox/system_log.h>
#include "ui_main.h"
#include <gromox/acl_control.h>
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

int main(int argc, const char **argv)
{
	int timeout;
	const char *str_value;
	char temp_path[256];
	char data_path[256];
	char token_path[256];
	char acl_path[256];
	CONFIG_FILE *pconfig;

	umask(0);
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
	snprintf(acl_path, sizeof(acl_path), "%s/system_users.txt", data_path);
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
	str_value = config_file_get_value(pconfig, "LOGO_LINK");
	if (NULL == str_value) {
		str_value = DFL_LOGOLINK;
	}
	snprintf(temp_path, sizeof(temp_path), "%s/admin_main", data_path);
	ui_main_init(str_value, temp_path);
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
	if (0 != ui_main_run()) {
		return 4;
	}
	ui_main_stop();
	ui_main_free();
	acl_control_stop();
	acl_control_free();
	system_log_stop();
	system_log_free();
	exit(0);
}

