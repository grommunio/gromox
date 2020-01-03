#include <libHX/string.h>
#include <gromox/paths.h>
#include <gromox/system_log.h>
#include "table_ui.h"
#include <gromox/acl_control.h>
#include "reload_control.h"
#include "config_file.h"
#include "util.h"
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char **argv)
{
	const char *str_value, *mount_path;
	char temp_path[256];
	char data_path[256];
	char token_path[256];
	char acl_path[256];
	char lang_path[256];
	int timeout;
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
	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		str_value = PKGLOGDIR "/sa.log";
	}
	system_log_init(str_value);
	snprintf(temp_path, sizeof(temp_path), "%s/console_table.txt", data_path);
	reload_control_init(temp_path);
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
	mount_path = config_file_get_value(pconfig, "GATEWAY_MOUNT_PATH");
	if (NULL == mount_path) {
		mount_path = PKGSTATEGATEWAYDIR;
	}
	str_value = config_file_get_value(pconfig, "LOGO_LINK");
	if (NULL == str_value) {
		str_value = DFL_LOGOLINK;
	}
	snprintf(temp_path, sizeof(temp_path), "%s/forward_table.txt", data_path);
	snprintf(lang_path, sizeof(lang_path), "%s/forward_table", data_path);
	table_ui_init(temp_path, mount_path, str_value, lang_path);
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
	if (0 != reload_control_run()) {
		return 4;
	}
	if (0 != table_ui_run()) {
		return 5;
	}
	table_ui_stop();
	table_ui_free();
	reload_control_stop();
	reload_control_free();
	acl_control_stop();
	acl_control_free();
	system_log_stop();
	system_log_free();
	exit(0);
}

