// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <string>
#include <unistd.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/atomic.hpp>
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

using namespace std::string_literals;
using namespace gromox;

static gromox::atomic_bool g_notify_stop{false}, g_hup_signalled{false};
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
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv,
	    HXOPT_USAGEONERR | HXOPT_KEEP_ARGV) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	auto pconfig = config_file_prg(opt_config_file, "adaptor.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return 1;

	static constexpr cfg_directive cfg_default_values[] = {
		{"log_file_path", PKGLOGDIR "/sa.log"},
		{"mysql_dbname", "email"},
		{"mysql_host", "localhost"},
		{"mysql_port", "3306"},
		{"mysql_username", "root"},
		{"state_path", PKGSTATEDIR},
		{},
	};
	config_file_apply(*pconfig, cfg_default_values);

	auto state_dir = pconfig->get_value("state_path");
	auto domainlist_path = state_dir + "/domain_list.txt"s;
	auto aliasaddress_path = state_dir + "/alias_addresses.txt"s;
	auto console_path = state_dir + "/console_table.txt"s;

	system_log_init(pconfig->get_value("log_file_path"));
	auto cl_0 = make_scope_exit(system_log_free);
	gateway_control_init(console_path.c_str());
	data_source_init(pconfig->get_value("mysql_host"),
		strtol(pconfig->get_value("mysql_port"), nullptr, 0),
		pconfig->get_value("mysql_username"), pconfig->get_value("mysql_password"),
		pconfig->get_value("mysql_dbname"));
	engine_init(domainlist_path.c_str(), aliasaddress_path.c_str());
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
	sact.sa_handler = [](int) { g_hup_signalled = true; };
	sigaction(SIGHUP, &sact, nullptr);
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESETHAND;
	sigaction(SIGINT, &sact, nullptr);
	sigaction(SIGTERM, &sact, nullptr);
	while (!g_notify_stop) {
		sleep(1);
		if (g_hup_signalled.exchange(false))
			engine_trig();
	}
	return 0;
}

static void term_handler(int signo)
{
	g_notify_stop = true;
}

