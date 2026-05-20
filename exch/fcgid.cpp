// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025–2026 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/fileio.h>
#include <gromox/oxcmail.hpp>
#include <gromox/paths.h>
#include <gromox/plugin.hpp>
#include <gromox/process.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static constexpr HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, {}, {}, {}, 0, "Config file to read", "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr cfg_directive gromox_cfg_defaults[] = {
	{"config_file_path", PKGSYSCONFDIR "/fcgid:" PKGSYSCONFDIR},
	{"daemons_fd_limit", "fcigd_fd_limit", CFG_ALIAS},
	{"data_file_path", PKGDATADIR "/fcgid:" PKGDATADIR},
	{"fcgid_fd_limit", "0", CFG_SIZE},
	{"fcgid_log_file", "-"},
	{"fcgid_log_level", "4" /* LV_NOTICE */},
	{"running_identity", RUNNING_IDENTITY},
	CFG_TABLE_END,
};

static gromox::atomic_bool g_notify_stop, g_hup_signalled;
static std::shared_ptr<config_file> g_config_file;
static const char *opt_config_file;

static bool fcgid_reload_config(std::shared_ptr<config_file> cfg = nullptr)
{
	if (cfg == nullptr)
		cfg = config_file_prg(opt_config_file, "gromox.cfg", gromox_cfg_defaults);
	if (opt_config_file != nullptr && cfg == nullptr) {
		mlog(LV_ERR, "config_file_init %s: %s", opt_config_file, strerror(errno));
		return false;
	}
	if (cfg == nullptr)
		return false;
	mlog_init("gromox-fcgid", cfg->get_value("fcgid_log_file"),
		cfg->get_ll("fcgid_log_level"), cfg->get_value("running_identity"));
	return true;
}

static void term_handler(int signo)
{
	g_notify_stop = true;
}

int main(int argc, char **argv)
{
	int retcode = EXIT_FAILURE;
	HXopt6_auto_result argp;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt6(g_options_table, argc, argv, &argp,
	    HXOPT_USAGEONERR | HXOPT_ITER_OPTS) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	for (int i = 0; i < argp.nopts; ++i)
		if (argp.desc[i]->sh == 'c')
			opt_config_file = argp.oarg[i];

	startup_banner("gromox-fcgid");
	setup_signal_defaults();
	struct sigaction sact{};
	sigemptyset(&sact.sa_mask);
	sact.sa_handler = [](int) { g_hup_signalled = true; };
	sigaction(SIGHUP, &sact, nullptr);
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESETHAND;
	sigaction(SIGINT, &sact, nullptr);
	sigaction(SIGTERM, &sact, nullptr);
	sact.sa_handler = SIG_IGN;
	sact.sa_flags   = SA_RESTART;
	sigaction(SIGPIPE, &sact, nullptr);

	auto cfg = g_config_file = config_file_prg(opt_config_file, "gromox.cfg", gromox_cfg_defaults);
	if (opt_config_file != nullptr && cfg == nullptr)
		mlog(LV_ERR, "%s: %s", opt_config_file, strerror(errno));
	if (cfg == nullptr)
		return EXIT_FAILURE; /* e.g. permission error */
	if (!fcgid_reload_config(g_config_file))
		return EXIT_FAILURE;

	auto str = cfg->get_value("host_id");
	if (str == nullptr) {
		std::string hn;
		auto ret = canonical_hostname(hn);
		if (ret != 0)
			return EXIT_FAILURE;
		cfg->set_value("host_id", hn.c_str());
		str = cfg->get_value("host_id");
	}
	mlog(LV_INFO, "istore: host ID is \"%s\"", str);

	filedes_limit_bump(cfg->get_ll("fcgid_fd_limit"));
	service_init({cfg, {}, 1, "fcgid"});
	auto cl_0 = HX::make_scope_exit(service_stop);
	if (switch_user_exec(*cfg, argv) != 0)
		return EXIT_FAILURE;
	setup_utf8_locale();
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	textmaps_init();
	if (service_run() != 0)
		return EXIT_FAILURE;

	struct dlfuncs dlf{};
	ENTRYPOINT(PLUGIN_INIT, dlf);

	retcode = EXIT_SUCCESS;
	mlog(LV_INFO, "FCGI server is running");
	while (!g_notify_stop) {
		sleep(86400); /* interrupts on signal */
		if (g_hup_signalled.exchange(false)) {
			fcgid_reload_config();
			service_trigger_all(PLUGIN_RELOAD);
		}
	}

	ENTRYPOINT(PLUGIN_FREE, {});
	return retcode;
}
