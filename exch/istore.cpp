// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025–2026 grommunio GmbH
// This file is part of Gromox.
/*
 * Standalone launcher program for the Information Store (which is a shared
 * object, and can be loaded either into gromox-http or gromox-istore).
 */
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <typeinfo>
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
	{nullptr, 'x', HXTYPE_STRING, {}, {}, {}, 0, "Single-user mode", "DIR"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr cfg_directive gromox_cfg_defaults[] = {
	{"config_file_path", PKGSYSCONFDIR "/istore:" PKGSYSCONFDIR},
	{"daemons_fd_limit", "istore_fd_limit", CFG_ALIAS},
	{"data_file_path", PKGDATADIR "/istore:" PKGDATADIR},
	{"istore_fd_limit", "0", CFG_SIZE},
	{"istore_log_file", "-"},
	{"istore_log_level", "4" /* LV_NOTICE */},
	{"istore_standalone", "0"},
	{"running_identity", RUNNING_IDENTITY},
	CFG_TABLE_END,
};

static constexpr generic_module g_dfl_svc_plugins[] = {
	{"libgxs_exmdb_provider.so", SVC_exmdb_provider},
};

static gromox::atomic_bool g_istore_stop, g_hup_signalled;
static std::shared_ptr<config_file> g_config_file;
static const char *opt_config_file;

static bool istore_reload_config(std::shared_ptr<config_file> cfg = nullptr)
{
	if (cfg == nullptr)
		cfg = config_file_prg(opt_config_file, "gromox.cfg", gromox_cfg_defaults);
	if (opt_config_file != nullptr && cfg == nullptr) {
		mlog(LV_ERR, "config_file_init %s: %s", opt_config_file, strerror(errno));
		return false;
	}
	if (cfg == nullptr)
		return false;
	mlog_init("gromox-istore", cfg->get_value("istore_log_file"),
		cfg->get_ll("istore_log_level"), cfg->get_value("running_identity"));
	return true;
}

static void term_handler(int signo)
{
	g_istore_stop = true;
}

int main(int argc, char **argv)
{
	int retcode = EXIT_FAILURE;
	HXopt6_auto_result argp;
	const char *opt_single_user = nullptr;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt6(g_options_table, argc, argv, &argp,
	    HXOPT_USAGEONERR | HXOPT_ITER_OPTS) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	for (int i = 0; i < argp.nopts; ++i) {
		if (argp.desc[i]->sh == 'c')
			opt_config_file = argp.oarg[i];
		else if (argp.desc[i]->sh == 'x')
			opt_single_user = argp.oarg[i];
	}

	startup_banner("gromox-istore");
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
	if (!istore_reload_config(g_config_file))
		return EXIT_FAILURE;

	std::string prog_id = "istore-director";
	if (opt_single_user != nullptr) {
		mlog(LV_NOTICE, "istore single-store mode for %s", opt_single_user);
		prog_id = std::string("istore-worker:") + opt_single_user;
		if (setenv("ISTORE_USER", opt_single_user, true) != 0)
			return EXIT_FAILURE;
	} else if (!(cfg->get_ll("istore_standalone") & ISTORE_SPLIT_DIRECTOR)) {
		mlog(LV_NOTICE, "istore↔http separation not enabled (gromox.cfg:istore_standalone). Quitting.");
		return 6; /* EXIT_NOTCONFIGURED */
	} else {
		unsetenv("ISTORE_USER");
	}
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

	filedes_limit_bump(cfg->get_ll("istore_fd_limit"));
	service_init({cfg, g_dfl_svc_plugins, 1, prog_id.c_str(), argv[0]});
	auto cl_0 = HX::make_scope_exit(service_stop);
	if (service_run_early() != 0)
		return EXIT_FAILURE;
	if (switch_user_exec(*cfg, argv) != 0)
		return EXIT_FAILURE;
	setup_utf8_locale();
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	textmaps_init();
	if (service_run() != 0)
		return EXIT_FAILURE;
	retcode = EXIT_SUCCESS;
	mlog(LV_INFO, "Information Store is running");
	bool is_worker = getenv("ISTORE_USER");
	int (*exmdb_pickup)(int) = nullptr;
	if (is_worker) {
		exmdb_pickup = reinterpret_cast<decltype(exmdb_pickup)>(service_query("exmdb_pickup",
		               typeid(*exmdb_pickup)));
		if (exmdb_pickup == nullptr) {
			mlog(LV_ERR, "exmdb_pickup not found");
			return EXIT_FAILURE;
		}
	}
	while (!g_istore_stop) {
		if (is_worker) {
			if (exmdb_pickup(STDIN_FILENO) < 0)
				break;
		} else {
			sleep(1);
		}
		if (g_hup_signalled.exchange(false)) {
			istore_reload_config();
			service_trigger_all(PLUGIN_RELOAD);
		}
	}
	return retcode;
}
