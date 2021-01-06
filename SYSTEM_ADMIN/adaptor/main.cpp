// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <errno.h>
#include <unistd.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/paths.h>
#include "util.h"
#include "engine.h"
#include "data_source.h"
#include "file_operation.h"
#include <gromox/system_log.h>
#include <gromox/gateway_control.h>
#include "config_file.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

static BOOL g_notify_stop = FALSE;
static char *opt_config_file;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{"version", 0, HXTYPE_NONE, &opt_show_version, nullptr, nullptr, 0, "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static void term_handler(int signo);

int main(int argc, const char **argv)
{
	char *str_value;
	char mount_path[256];
	char log_path[256];
	char state_dir[256], domainlist_path[256];
	char aliasaddress_path[256];
	char unchkusr_path[256];
	char console_path[256];
	char mysql_host[256];
	int mysql_port;
	char mysql_user[256];
	char *mysql_passwd;
	char db_name[256];
	CONFIG_FILE *pconfig;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	pconfig = config_file_init2(opt_config_file, config_default_path("adaptor.cfg"));
	if (opt_config_file != nullptr && pconfig == nullptr) {
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return 1;
	}
	str_value = config_file_get_value(pconfig, "STATE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(state_dir, PKGSTATEDIR, sizeof(state_dir));
		config_file_set_value(pconfig, "STATE_PATH", state_dir);
	} else {
		HX_strlcpy(state_dir, str_value, sizeof(state_dir));
	}
	printf("[system]: state path is %s\n", state_dir);
	snprintf(domainlist_path, sizeof(domainlist_path), "%s/domain_list.txt", state_dir);
	snprintf(aliasaddress_path, sizeof(aliasaddress_path), "%s/alias_addresses.txt", state_dir);
	snprintf(console_path, sizeof(console_path), "%s/console_table.txt", state_dir);

	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(log_path, PKGLOGDIR "/sa.log", sizeof(log_path));
		config_file_set_value(pconfig, "LOG_FILE_PATH", log_path);
	} else {
		strcpy(log_path, str_value);
	}
	printf("[system]: log path is %s\n", log_path);

	str_value = config_file_get_value(pconfig, "GATEWAY_MOUNT_PATH");
	if (NULL == str_value) {
		strcpy(mount_path, PKGSTATEGATEWAYDIR);
		config_file_set_value(pconfig, "GATEWAY_MOUNT_PATH", mount_path);
	} else {
		strcpy(mount_path, str_value);
	}
	printf("[system]: gateway mount path is %s\n", mount_path);
	
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

	file_operation_init(mount_path);

	system_log_init(log_path);
	
	gateway_control_init(console_path);
	
	data_source_init(mysql_host, mysql_port, mysql_user, mysql_passwd, db_name);
	engine_init(mount_path, domainlist_path, aliasaddress_path, unchkusr_path);
	config_file_free(pconfig);
	
	if (0 != system_log_run()) {
		printf("[system]: failed to run system log\n");
		return 3;
	}
	
	if (0 != gateway_control_run()) {
		printf("[system]: failed to run gateway control\n");
		return 4;
	}
	if (0 != engine_run()) {
		printf("[system]: failed to run engine\n");
		return 6;
	}
	
	printf("[system]: ADAPTOR is now running\n");
	
	signal(SIGTERM, term_handler);
	while (TRUE != g_notify_stop) {
		sleep(1);
	}

	engine_stop();
	gateway_control_stop();
	gateway_control_free();
	system_log_stop();
	system_log_free();
	return 0;
}

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}

