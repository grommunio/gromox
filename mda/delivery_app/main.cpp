// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2024 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/misc.h>
#include <libHX/option.h>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <sys/types.h>
#include <vmime/utility/url.hpp>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/process.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include "delivery.hpp"

using namespace gromox;

gromox::atomic_bool g_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
std::string g_outgoing_smtp_url;
static char *opt_config_file;
static gromox::atomic_bool g_hup_signalled;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr static_module g_dfl_mpc_plugins[] = {
	{"libgxm_alias_resolve.so", HOOK_alias_resolve},
	{"libgxm_exmdb_local.so", HOOK_exmdb_local},
};
static constexpr static_module g_dfl_svc_plugins[] = {
	{"libgxs_mysql_adaptor.so", SVC_mysql_adaptor},
	{"libgromox_auth.so/ldap", SVC_ldap_adaptor},
	{"libgromox_auth.so/mgr", SVC_authmgr},
	{"libgxs_ruleproc.so", SVC_ruleproc},
};

static constexpr cfg_directive gromox_cfg_defaults[] = {
	{"daemons_fd_limit", "lda_fd_limit", CFG_ALIAS},
	{"lda_fd_limit", "0", CFG_SIZE},
	CFG_TABLE_END,
};

static constexpr cfg_directive delivery_cfg_defaults[] = {
	{"admin_mailbox", ""},
	{"config_file_path", PKGSYSCONFDIR "/delivery:" PKGSYSCONFDIR},
	{"data_file_path", PKGDATADIR "/delivery:" PKGDATADIR},
	{"dequeue_maximum_mem", "1G", CFG_SIZE, "1"},
	{"dequeue_path", PKGSTATEQUEUEDIR},
	{"lda_log_file", "-"},
	{"lda_log_level", "4" /* LV_NOTICE */},
	{"running_identity", RUNNING_IDENTITY},
	{"work_threads_max", "5", CFG_SIZE, "1"},
	{"work_threads_min", "1", CFG_SIZE, "1"},
	CFG_TABLE_END,
};

static void term_handler(int signo);

static bool delivery_reload_config(std::shared_ptr<CONFIG_FILE> cfg)
{
	if (cfg == nullptr)
		cfg = config_file_prg(opt_config_file, "delivery.cfg",
		      delivery_cfg_defaults);
	if (opt_config_file != nullptr && cfg == nullptr) {
		mlog(LV_ERR, "config_file_init %s: %s", opt_config_file, strerror(errno));
		return false;
	}
	mlog_init("gromox-delivery", cfg->get_value("lda_log_file"),
		cfg->get_ll("lda_log_level"), cfg->get_value("running_identity"));
	return true;
}

int main(int argc, char **argv)
{ 
	int retcode = EXIT_FAILURE;
	char temp_buff[256];

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt5(g_options_table, argv, nullptr, nullptr,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;

	startup_banner("gromox-delivery");
	setup_sigalrm();
	struct sigaction sact{};
	sigemptyset(&sact.sa_mask);
	sact.sa_handler = [](int) { g_hup_signalled = true; };
	sigaction(SIGHUP, &sact, nullptr);
	sact.sa_handler = SIG_IGN;
	sact.sa_flags   = SA_RESTART;
	sigaction(SIGPIPE, &sact, nullptr);
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESETHAND;
	sigaction(SIGINT, &sact, nullptr);
	sigaction(SIGTERM, &sact, nullptr);
	g_config_file = config_file_prg(opt_config_file, "delivery.cfg",
	                delivery_cfg_defaults);
	if (opt_config_file != nullptr && g_config_file == nullptr)
		mlog(LV_ERR, "resource: config_file_init %s: %s", opt_config_file, strerror(errno));
	auto gxconfig = config_file_prg(opt_config_file, "gromox.cfg", gromox_cfg_defaults);
	if (opt_config_file != nullptr && gxconfig == nullptr)
		mlog(LV_ERR, "%s: %s", opt_config_file, strerror(errno));
	if (g_config_file == nullptr || !delivery_reload_config(g_config_file))
		return EXIT_FAILURE;

	auto str_val = g_config_file->get_value("host_id");
	if (str_val == NULL) {
		std::string hn;
		auto ret = canonical_hostname(hn);
		if (ret != 0)
			return EXIT_FAILURE;
		g_config_file->set_value("host_id", hn.c_str());
		str_val = g_config_file->get_value("host_id");
	}
	mlog(LV_NOTICE, "system: host ID is \"%s\"", str_val);

	unsigned int threads_min = g_config_file->get_ll("work_threads_min");
	unsigned int threads_max = g_config_file->get_ll("work_threads_max");
	if (threads_min > threads_max)
		threads_min = threads_max;
	mlog(LV_INFO, "system: worker threads: between %u and %u",
		threads_min, threads_max);

	unsigned int free_contexts = threads_max;
	if (g_config_file->get_value("free_context_num") != nullptr) {
		free_contexts = g_config_file->get_ll("free_context_num");
		if (free_contexts < threads_max) {
			free_contexts = threads_max; 
			g_config_file->set_value("free_context_num", std::to_string(free_contexts).c_str());
		}
	}
	mlog(LV_INFO, "system: free contexts number is %d", free_contexts);

	size_t max_mem = g_config_file->get_ll("dequeue_maximum_mem");
	HX_unit_size(temp_buff, std::size(temp_buff), max_mem, 1024, 0);
	mlog(LV_INFO, "message_dequeue: maximum allocated memory is %s", temp_buff);

	str_val = gxconfig->get_value("outgoing_smtp_url");
	if (str_val != nullptr) {
		try {
			g_outgoing_smtp_url = vmime::utility::url(str_val);
		} catch (const vmime::exceptions::malformed_url &e) {
			mlog(LV_ERR, "Malformed URL: outgoing_smtp_url=\"%s\": %s",
				str_val, e.what());
			return EXIT_FAILURE;
		}
	} else {
		static constexpr cfg_directive rd_dfl[] = {
			{"mx_host", "::1"},
			{"mx_port", "25", 0, "1", "65535"},
			CFG_TABLE_END,
		};
		auto cfg = config_file_initd("remote_delivery.cfg", PKGSYSCONFDIR, rd_dfl);
		if (cfg != nullptr) {
			str_val = cfg->get_value("mx_host");
			uint16_t port = cfg->get_ll("mx_port");
			try {
				g_outgoing_smtp_url = vmime::utility::url("smtp",
					cfg->get_value("mx_host"), cfg->get_ll("mx_port"));
			} catch (const vmime::exceptions::malformed_url &e) {
				mlog(LV_ERR, "Malformed outgoing SMTP: [%s]:%hu: %s",
					str_val, port, e.what());
				return EXIT_FAILURE;
			}
		}
	}
	mlog(LV_NOTICE, "delivery: remote_delivery SMTP server is %s", g_outgoing_smtp_url.c_str());

	filedes_limit_bump(gxconfig->get_ll("lda_fd_limit"));
	service_init({g_config_file, g_dfl_svc_plugins, threads_max + free_contexts});
	if (service_run_early() != 0) {
		mlog(LV_ERR, "system: failed to run PLUGIN_EARLY_INIT");
		return EXIT_FAILURE;
	}
	if (switch_user_exec(*g_config_file, argv) != 0)
		return EXIT_FAILURE;
    if (0 != service_run()) {
		mlog(LV_ERR, "system: failed to start services");
		return EXIT_FAILURE;
    }
	auto cleanup_4 = make_scope_exit(service_stop);

	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	auto dummy_sk = HX_local_listen(PKGRUNDIR "/da-runcheck");
	if (dummy_sk < 0) {
		mlog(LV_ERR, "gromox-delivery is already running");
		return EXIT_FAILURE;
	}

	message_dequeue_init(g_config_file->get_value("dequeue_path"), max_mem);
    if (0 != message_dequeue_run()) { 
		mlog(LV_ERR, "system: failed to start message dequeue");
		return EXIT_FAILURE;
    }
	auto cleanup_8 = make_scope_exit(message_dequeue_stop);

	transporter_init(PKGLIBDIR, g_dfl_mpc_plugins, threads_min, threads_max,
		free_contexts, false);
	auto cleanup_12 = make_scope_exit(transporter_stop);
    if (0 != transporter_run()) { 
		mlog(LV_ERR, "system: failed to start transporter");
		return EXIT_FAILURE;
    }

	retcode = EXIT_SUCCESS;
	mlog(LV_INFO, "system: LDA is now running");
	while (!g_notify_stop) {
        sleep(3);
		if (g_hup_signalled.exchange(false)) {
			delivery_reload_config(nullptr);
			service_trigger_all(PLUGIN_RELOAD);
			transporter_trigger_all(PLUGIN_RELOAD);
		}
    }
	return retcode;
}

static void term_handler(int signo)
{
	g_notify_stop = true;
}
