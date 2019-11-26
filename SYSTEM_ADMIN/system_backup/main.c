#include <libHX/string.h>
#include <gromox/paths.h>
#include <gromox/system_log.h>
#include "backup_ui.h"
#include <gromox/acl_control.h>
#include "file_operation.h"
#include <gromox/gateway_control.h>
#include "config_file.h"
#include "util.h"
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char **argv)
{
	const char *str_value;
	char config_path[256];
	char mount_path[256];
	char token_path[256];
	char temp_path[256];
	char data_path[256];
	char file_path[256];
	char backup_path[256];
	char acl_path[256];
	char lang_path[256];
	int timeout;
	CONFIG_FILE *pconfig;

	HX_strlcpy(config_path, PKGSYSCONFDIR "/athena.cfg", sizeof(config_path));
	pconfig = config_file_init2(NULL, config_path);
	if (NULL == pconfig) {
		return 1;
	}
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(data_path, PKGDATASADIR, sizeof(data_path));
	} else {
		strcpy(data_path, str_value);
	}
	str_value = config_file_get_value(pconfig, "GATEWAY_MOUNT_PATH");
	if (NULL == str_value) {
		strcpy(mount_path, "../gateway");
	} else {
		strcpy(mount_path, str_value);
	}
	str_value = config_file_get_value(pconfig, "TOKEN_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(token_path, PKGRUNSADIR, sizeof(token_path));
	} else {
		strcpy(token_path, str_value);
	}
	str_value = config_file_get_value(pconfig, "SYSTEM_BACKUP_PATH");
	if (NULL == str_value) {
		strcpy(backup_path, "../sys_backup");
	} else {
		strcpy(backup_path, str_value);
	}
	file_operation_init(mount_path);
	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		str_value = PKGLOGDIR "/athena_log.txt";
	}
	system_log_init(str_value);
	snprintf(temp_path, sizeof(temp_path), "%s/console_table.txt", data_path);
	gateway_control_init(temp_path);
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
		str_value = "http://www.gridware.com.cn";
	}
	snprintf(file_path, sizeof(file_path), "%s/control.msg", token_path);
	snprintf(lang_path, sizeof(lang_path), "%s/system_backup", data_path);
	backup_ui_init(backup_path, config_path, data_path, mount_path,
		file_path, str_value, lang_path);
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
	if (0 != gateway_control_run()) {
		return 4;
	}
	if (0 != file_operation_run()) {
		return 5;
	}
	if (0 != backup_ui_run()) {
		return 6;
	}
	backup_ui_stop();
	backup_ui_free();
	file_operation_stop();
	file_operation_free();
	gateway_control_stop();
	gateway_control_free();
	acl_control_stop();
	acl_control_free();
	system_log_stop();
	system_log_free();
	exit(0);
}

