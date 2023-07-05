// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
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
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include "delivery.hpp"

using namespace gromox;

gromox::atomic_bool g_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static gromox::atomic_bool g_hup_signalled;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static std::vector<std::string> g_dfl_mpc_plugins = {
	"libgxm_alias_resolve.so",
	"libgxm_exmdb_local.so",
	"libgxm_mlist_expand.so",
	"libgxm_remote_delivery.so",
};
static std::vector<std::string> g_dfl_svc_plugins = {
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_authmgr.so",
};

static constexpr cfg_directive delivery_cfg_defaults[] = {
	{"admin_mailbox", "root@localhost"},
	{"config_file_path", PKGSYSCONFDIR "/delivery:" PKGSYSCONFDIR},
	{"context_average_mime", "8", CFG_SIZE, "1"},
	{"data_file_path", PKGDATADIR "/delivery:" PKGDATADIR},
	{"dequeue_maximum_mem", "1G", CFG_SIZE, "1"},
	{"dequeue_path", PKGSTATEQUEUEDIR},
	{"lda_log_file", "-"},
	{"lda_log_level", "4" /* LV_NOTICE */},
	{"running_identity", RUNNING_IDENTITY},
	{"state_path", PKGSTATEDIR},
	{"work_threads_max", "5", CFG_SIZE, "1"},
	{"work_threads_min", "1", CFG_SIZE, "1"},
	CFG_TABLE_END,
};

static void term_handler(int signo);

int main(int argc, const char **argv) try
{ 
	int retcode = EXIT_FAILURE;
	char temp_buff[256];

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv,
	    HXOPT_USAGEONERR | HXOPT_KEEP_ARGV) != HXOPT_ERR_SUCCESS)
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
	if (g_config_file == nullptr)
		return EXIT_FAILURE;

	mlog_init(g_config_file->get_value("lda_log_file"), g_config_file->get_ll("lda_log_level"));
	auto str_val = g_config_file->get_value("host_id");
	if (str_val == NULL) {
		memset(temp_buff, '\0', std::size(temp_buff));
		gethostname(temp_buff, std::size(temp_buff));
		temp_buff[std::size(temp_buff)-1] = '\0';
		g_config_file->set_value("host_id", temp_buff);
		str_val = temp_buff;
	}
	mlog(LV_NOTICE, "system: host ID is \"%s\"", str_val);

	str_val = g_config_file->get_value("default_domain");
	if (str_val == NULL) {
		memset(temp_buff, '\0', std::size(temp_buff));
		getdomainname(temp_buff, std::size(temp_buff));
		g_config_file->set_value("default_domain", temp_buff);
		str_val = temp_buff;
		mlog(LV_WARN, "system: Cannot find default domain. OS domain name "
			"will be used as default domain.");
	}
	mlog(LV_NOTICE, "system: default domain is \"%s\"", str_val);

	unsigned int threads_min = g_config_file->get_ll("work_threads_min");
	unsigned int threads_max = g_config_file->get_ll("work_threads_max");
	if (threads_min > threads_max)
		threads_min = threads_max;
	mlog(LV_INFO, "system: worker threads: between %u and %u",
		threads_min, threads_max);

	unsigned int free_contexts = threads_max;
	if (g_config_file->get_uint("free_context_num", &free_contexts)) {
		if (free_contexts < threads_max) {
			free_contexts = threads_max; 
			g_config_file->set_int("free_context_num", free_contexts);
		}
	}
	mlog(LV_INFO, "system: free contexts number is %d", free_contexts);
    
	unsigned int mime_ratio = g_config_file->get_ll("context_average_mime");
	mlog(LV_INFO, "system: average mimes number for one context is %d",
		mime_ratio);

	size_t max_mem = g_config_file->get_ll("dequeue_maximum_mem");
	HX_unit_size(temp_buff, std::size(temp_buff), max_mem, 1024, 0);
	mlog(LV_INFO, "message_dequeue: maximum allocated memory is %s", temp_buff);
    
	service_init({g_config_file->get_value("config_file_path"),
		g_config_file->get_value("data_file_path"),
		g_config_file->get_value("state_path"),
		std::move(g_dfl_svc_plugins), threads_max + free_contexts});
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
    if (0 != system_services_run()) { 
		mlog(LV_ERR, "system: failed to start system services");
		return EXIT_FAILURE;
    }
	auto cleanup_6 = make_scope_exit(system_services_stop);
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

	transporter_init(PKGLIBDIR,
		std::move(g_dfl_mpc_plugins), threads_min, threads_max,
		free_contexts, mime_ratio, false);
    if (0 != transporter_run()) { 
		mlog(LV_ERR, "system: failed to start transporter");
		return EXIT_FAILURE;
    }
	auto cleanup_12 = make_scope_exit(transporter_stop);

	retcode = EXIT_SUCCESS;
	mlog(LV_NOTICE, "system: LDA is now running");
	while (!g_notify_stop) {
        sleep(3);
		if (g_hup_signalled.exchange(false))
			service_trigger_all(PLUGIN_RELOAD);
    }
	return retcode;
} catch (const cfg_error &) {
	return EXIT_FAILURE;
}

static void term_handler(int signo)
{
	g_notify_stop = true;
}
