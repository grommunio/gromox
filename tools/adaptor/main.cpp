// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <atomic>
#include <cerrno>
#include <unistd.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "engine.h"
#include "data_source.h"
#include "file_operation.h"
#include <gromox/system_log.h>
#include <gromox/gateway_control.h>
#include <gromox/config_file.hpp>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <csignal>

using namespace gromox;

static std::atomic<bool> g_notify_stop{false};
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
	char log_path[256];
	char state_dir[256], domainlist_path[256];
	char aliasaddress_path[256];
	char unchkusr_path[256];
	char console_path[256];
	char mysql_host[256];
	int mysql_port;
	char mysql_user[256];
	char db_name[256];

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	auto pconfig = config_file_prg(opt_config_file, "adaptor.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr) {
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return 1;
	}
	auto str_value = config_file_get_value(pconfig, "STATE_PATH");
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
		HX_strlcpy(log_path, str_value, GX_ARRAY_SIZE(log_path));
	}
	printf("[system]: log path is %s\n", log_path);

	str_value = config_file_get_value(pconfig, "MYSQL_HOST");
	if (NULL == str_value) {
		strcpy(mysql_host, "localhost");
		config_file_set_value(pconfig, "MYSQL_HOST", "localhost");
	} else {
		HX_strlcpy(mysql_host, str_value, GX_ARRAY_SIZE(mysql_host));
	}

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
	printf("[system]: mysql host is [%s]:%d\n", mysql_host, mysql_port);

	str_value = config_file_get_value(pconfig, "MYSQL_USERNAME");
	HX_strlcpy(mysql_user, str_value != nullptr ? str_value : "root", GX_ARRAY_SIZE(mysql_user));
	auto mysql_passwd = config_file_get_value(pconfig, "MYSQL_PASSWORD");
	str_value = config_file_get_value(pconfig, "MYSQL_DBNAME");
	if (NULL == str_value) {
		strcpy(db_name, "email");
		config_file_set_value(pconfig, "MYSQL_DBNAME", "email");
	} else {
		HX_strlcpy(db_name, str_value, GX_ARRAY_SIZE(db_name));
	}
	printf("[system]: mysql database name is %s\n", db_name);
	system_log_init(log_path);
	auto cl_0 = make_scope_exit(system_log_free);
	gateway_control_init(console_path);
	
	data_source_init(mysql_host, mysql_port, mysql_user, mysql_passwd, db_name);
	engine_init(domainlist_path, aliasaddress_path, unchkusr_path);
	
	if (0 != system_log_run()) {
		printf("[system]: failed to run system log\n");
		return 3;
	}
	auto cl_1 = make_scope_exit(system_log_stop);
	if (0 != gateway_control_run()) {
		printf("[system]: failed to run gateway control\n");
		return 4;
	}
	if (0 != engine_run()) {
		printf("[system]: failed to run engine\n");
		return 6;
	}
	auto cl_2 = make_scope_exit(engine_stop);
	
	printf("[system]: ADAPTOR is now running\n");
	struct sigaction sact{};
	sigemptyset(&sact.sa_mask);
	sact.sa_handler = [](int) {};
	sigaction(SIGALRM, &sact, nullptr);
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESETHAND;
	sigaction(SIGTERM, &sact, nullptr);
	while (!g_notify_stop) {
		sleep(1);
	}
	return 0;
}

static void term_handler(int signo)
{
	g_notify_stop = true;
}

