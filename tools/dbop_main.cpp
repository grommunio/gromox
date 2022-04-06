// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mysql.h>
#include <string>
#include <libHX/option.h>
#include <gromox/config_file.hpp>
#include <gromox/dbop.h>
#include <gromox/paths.h>

using namespace std::string_literals;
using namespace gromox;

enum {
	OP_CREATE_ZERO = 1,
	OP_CREATE_RECENT,
	OP_UPGRADE,
};

namespace {

struct db_deleter {
	void operator()(MYSQL *m) { mysql_close(m); }
};

}

static char *opt_config_file;
static unsigned int g_action;

static struct HXoption g_options_table[] = {
	{nullptr, 'C', HXTYPE_VAL, &g_action, nullptr, nullptr, OP_CREATE_RECENT, "Create MySQL database tables"},
	{nullptr, 'U', HXTYPE_VAL, &g_action, nullptr, nullptr, OP_UPGRADE, "Upgrade MySQL database tables"},
	{"create-old", 0, HXTYPE_VAL, &g_action, nullptr, nullptr, OP_CREATE_ZERO, "Create MySQL database tables version 0"},
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, const char **argv)
{
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;

	std::shared_ptr<CONFIG_FILE> pconfig;
	if (opt_config_file == nullptr) {
		auto http_config = config_file_prg(nullptr, "http.cfg", nullptr);
		if (http_config == nullptr)
			return EXIT_FAILURE;
		auto http_cfgdir = http_config->get_value("CONFIG_FILE_PATH");
		if (http_cfgdir == nullptr)
			http_cfgdir = PKGSYSCONFDIR "/http:" PKGSYSCONFDIR;
		pconfig = config_file_initd("mysql_adaptor.cfg", http_cfgdir, nullptr);
		if (pconfig == nullptr) {
			fprintf(stderr, "config_file_initd mysql_adaptor.cfg: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
	} else {
		pconfig = config_file_prg(opt_config_file, "http.cfg", nullptr);
		if (pconfig == nullptr) {
			fprintf(stderr, "%s: %s\n", opt_config_file, strerror(errno));
			return EXIT_FAILURE;
		}
	}

	std::unique_ptr<MYSQL, db_deleter> pmysql(mysql_init(nullptr));
	if (pmysql == nullptr)
		abort();
	auto mysql_host = pconfig->get_value("mysql_host");
	auto mysql_user = pconfig->get_value("mysql_username");
	if (mysql_user == nullptr)
		/* keep aligned with mysql_adaptor/main.cpp */
		mysql_user = "root";
	auto mysql_pass = pconfig->get_value("mysql_password");
	auto mysql_dbname = pconfig->get_value("mysql_dbname");
	if (mysql_dbname == nullptr)
		mysql_dbname = "email";
	auto str = pconfig->get_value("mysql_port");
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
