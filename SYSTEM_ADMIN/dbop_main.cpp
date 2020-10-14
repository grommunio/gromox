/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <mysql.h>
#include <libHX/option.h>
#include <gromox/dbop.h>
#include <gromox/paths.h>
#include "config_file.h"

using namespace std::string_literals;

enum {
	OP_CREATE_ZERO = 1,
	OP_CREATE_RECENT,
	OP_UPGRADE,
};

struct db_deleter {
	void operator()(MYSQL *m) { mysql_close(m); }
};

static char *opt_config_file;
static unsigned int g_action;

static struct HXoption g_options_table[] = {
	{nullptr, 'C', HXTYPE_VAL, &g_action, nullptr, nullptr, OP_CREATE_RECENT, "Create MySQL database tables"},
	{nullptr, 'U', HXTYPE_VAL, &g_action, nullptr, nullptr, OP_UPGRADE, "Upgrade MySQL database tables"},
	{"create-old", 0, HXTYPE_VAL, &g_action, nullptr, nullptr, OP_CREATE_ZERO, "Create MySQL database tables version n0"},
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, const char **argv)
{
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;

	CONFIG_FILE *pconfig = nullptr;
	if (opt_config_file == nullptr) {
		auto http_config = config_file_init2(nullptr, config_default_path("http.cfg"));
		const char *http_cfgdir = http_config != nullptr ?
			config_file_get_value(http_config, "CONFIG_FILE_PATH") : nullptr;
		if (http_cfgdir == nullptr)
			http_cfgdir = PKGSYSCONFDIR "/http";
		auto mysql_cfile = http_cfgdir + "/mysql_adaptor.cfg"s;
		pconfig = config_file_init2(nullptr, mysql_cfile.c_str());
		if (pconfig == nullptr) {
			fprintf(stderr, "%s: %s\n", mysql_cfile.c_str(), strerror(errno));
			return EXIT_FAILURE;
		}
	} else {
		pconfig = config_file_init2(opt_config_file, config_default_path("http.cfg"));
		if (pconfig == nullptr) {
			fprintf(stderr, "%s: %s\n", opt_config_file, strerror(errno));
			return EXIT_FAILURE;
		}
	}

	std::unique_ptr<MYSQL, db_deleter> pmysql(mysql_init(nullptr));
	if (pmysql == nullptr)
		abort();
	auto mysql_host = config_file_get_value(pconfig, "mysql_host");
	auto mysql_user = config_file_get_value(pconfig, "mysql_username");
	auto mysql_pass = config_file_get_value(pconfig, "mysql_password");
	auto mysql_dbname = config_file_get_value(pconfig, "mysql_dbname");
	auto str = config_file_get_value(pconfig, "mysql_port");
	auto mysql_port = str != nullptr ? strtoul(str, nullptr, 0) : 0;

	if (mysql_real_connect(pmysql.get(), mysql_host, mysql_user, mysql_pass,
	    mysql_dbname, mysql_port, nullptr, 0) == nullptr) {
		fprintf(stderr, "mysql_connect: %s\n", mysql_error(pmysql.get()));
		return EXIT_FAILURE;
	}
	int ret = EXIT_FAILURE;
	if (g_action == OP_CREATE_ZERO)
		ret = dbop_mysql_create_0(pmysql.get());
	else if (g_action == OP_CREATE_RECENT)
		ret = dbop_mysql_create_top(pmysql.get());
	else if (g_action == OP_UPGRADE)
		ret = dbop_mysql_upgrade(pmysql.get());
	else
		fprintf(stderr, "No action selected\n");
	return ret;
}
