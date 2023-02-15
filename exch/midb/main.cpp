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
#include <libHX/string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "cmd_parser.h"
#include "common_util.h"
#include "exmdb_client.h"
#include "listener.h"
#include "mail_engine.hpp"
#include "system_services.hpp"

using namespace gromox;

gromox::atomic_bool g_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static unsigned int opt_show_version;
static gromox::atomic_bool g_hup_signalled;

static constexpr HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{"version", 0, HXTYPE_NONE, &opt_show_version, nullptr, nullptr, 0, "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static std::vector<std::string> g_dfl_svc_plugins = {
	"libgxs_event_proxy.so",
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_authmgr.so",
};

static constexpr cfg_directive midb_cfg_defaults[] = {
	{"config_file_path", PKGSYSCONFDIR "/midb:" PKGSYSCONFDIR},
	{"data_path", PKGDATADIR "/midb:" PKGDATADIR},
	{"default_charset", "windows-1252"},
	{"midb_cache_interval", "30min", CFG_TIME, "1min", "1year"},
	{"midb_cmd_debug", "0"},
	{"midb_listen_ip", "::1"},
	{"midb_listen_port", "5555"},
	{"midb_log_file", "-"},
	{"midb_log_level", "4" /* LV_NOTICE */},
	{"midb_mime_number", "4096", CFG_SIZE, "1024"},
	{"midb_reload_interval", "60min", CFG_TIME, "1min", "1year"},
	{"midb_schema_upgrades", "auto"},
	{"midb_table_size", "5000", CFG_SIZE, "100", "50000"},
	{"midb_threads_num", "100", CFG_SIZE, "20", "1000"},
	{"notify_stub_threads_num", "10", CFG_SIZE, "1", "200"},
	{"rpc_proxy_connection_num", "10", CFG_SIZE, "1", "200"},
	{"sqlite_debug", "0"},
	{"sqlite_mmap_size", "0", CFG_SIZE},
	{"sqlite_synchronous", "off", CFG_BOOL},
	{"sqlite_wal_mode", "true", CFG_BOOL},
	{"state_path", PKGSTATEDIR},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

static void term_handler(int signo)
{
	g_notify_stop = true;
}

static bool midb_reload_config(std::shared_ptr<CONFIG_FILE> pconfig)
{
	if (pconfig == nullptr)
		pconfig = config_file_prg(opt_config_file, "midb.cfg",
		          midb_cfg_defaults);
	if (opt_config_file != nullptr && pconfig == nullptr) {
		mlog(LV_ERR, "config_file_init %s: %s", opt_config_file, strerror(errno));
		return false;
	}
	mlog_init(pconfig->get_value("midb_log_file"), pconfig->get_ll("midb_log_level"));
	g_cmd_debug = pconfig->get_ll("midb_cmd_debug");
	g_midb_cache_interval = pconfig->get_ll("midb_cache_interval");
	g_midb_reload_interval = pconfig->get_ll("midb_reload_interval");
	auto s = pconfig->get_value("midb_schema_upgrades");
	if (strcmp(s, "auto") == 0)
		g_midb_schema_upgrades = MIDB_UPGRADE_AUTO;
	else if (strcmp(s, "yes") == 0)
		g_midb_schema_upgrades = MIDB_UPGRADE_YES;
	else
		g_midb_schema_upgrades = MIDB_UPGRADE_NO;
	return true;
}

int main(int argc, const char **argv) try
{
	struct rlimit rl;
	char temp_buff[45];
	std::shared_ptr<CONFIG_FILE> pconfig;
	
	exmdb_rpc_alloc = common_util_alloc;
	exmdb_rpc_free = [](void *) {};
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv,
	    HXOPT_USAGEONERR | HXOPT_KEEP_ARGV) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	startup_banner("gromox-midb");
	if (opt_show_version)
		return EXIT_SUCCESS;
	setup_sigalrm();
	struct sigaction sact{};
	sigemptyset(&sact.sa_mask);
	sact.sa_handler = [](int) { g_hup_signalled = true; };
	sigaction(SIGHUP, &sact, nullptr);
	sact.sa_handler = SIG_IGN;
	sact.sa_flags   = SA_RESTART;
	sigaction(SIGPIPE, &sact, nullptr);
	g_config_file = pconfig = config_file_prg(opt_config_file, "midb.cfg",
	                midb_cfg_defaults);
	if (opt_config_file != nullptr && pconfig == nullptr)
		mlog(LV_ERR, "system: config_file_init %s: %s", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return 2;
	if (!midb_reload_config(pconfig))
		return EXIT_FAILURE;

	int proxy_num = pconfig->get_ll("rpc_proxy_connection_num");
	mlog(LV_INFO, "system: exmdb proxy connection number is %d", proxy_num);
	
	int stub_num = pconfig->get_ll("notify_stub_threads_num");
	mlog(LV_INFO, "system: exmdb notify stub threads number is %d", stub_num);
	
	auto listen_ip = pconfig->get_value("midb_listen_ip");
	uint16_t listen_port = pconfig->get_ll("midb_listen_port");
	mlog(LV_NOTICE, "system: listen address is [%s]:%hu",
	       *listen_ip == '\0' ? "*" : listen_ip, listen_port);

	unsigned int threads_num = pconfig->get_ll("midb_threads_num");
	mlog(LV_INFO, "system: connection threads number is %d", threads_num);

	size_t table_size = pconfig->get_ll("midb_table_size");
	mlog(LV_INFO, "system: hash table size is %zu", table_size);

	int cache_interval = pconfig->get_ll("midb_cache_interval");
	HX_unit_seconds(temp_buff, arsizeof(temp_buff), cache_interval, 0);
	mlog(LV_INFO, "system: cache interval is %s", temp_buff);
	
	int mime_num = pconfig->get_ll("midb_mime_number");
	mlog(LV_INFO, "system: mime number is %d", mime_num);

	gx_sqlite_debug = pconfig->get_ll("sqlite_debug");
	uint64_t mmap_size = pconfig->get_ll("sqlite_mmap_size");
	if (0 == mmap_size) {
		mlog(LV_INFO, "system: sqlite mmap_size is disabled");
	} else {
		HX_unit_size(temp_buff, arsizeof(temp_buff), mmap_size, 1024, 0);
		mlog(LV_INFO, "system: sqlite mmap_size is %s", temp_buff);
	}
	
	if (0 != getrlimit(RLIMIT_NOFILE, &rl)) {
		mlog(LV_ERR, "getrlimit: %s", strerror(errno));
	} else {
		rlim_t tb5 = 5 * table_size;
		if (rl.rlim_cur < tb5 || rl.rlim_max < tb5) {
			rl.rlim_cur = tb5;
			rl.rlim_max = tb5;
			if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
				mlog(LV_WARN, "setrlimit RLIMIT_NFILE %zu: %s",
					static_cast<size_t>(rl.rlim_max), strerror(errno));
			else
				mlog(LV_NOTICE, "system: FD limit set to %zu",
					static_cast<size_t>(rl.rlim_cur));
		}
	}

	unsigned int cmd_debug = pconfig->get_ll("midb_cmd_debug");
	service_init({g_config_file->get_value("config_file_path"),
		g_config_file->get_value("data_path"),
		g_config_file->get_value("state_path"),
		std::move(g_dfl_svc_plugins), threads_num});
	auto cl_0 = make_scope_exit(service_stop);
	
	exmdb_client_init(proxy_num, stub_num);
	auto cl_6 = make_scope_exit(exmdb_client_stop);
	listener_init(listen_ip, listen_port);
	auto cl_3 = make_scope_exit(listener_stop);
	mail_engine_init(g_config_file->get_value("default_charset"),
		g_config_file->get_value("x500_org_name"), table_size,
		parse_bool(g_config_file->get_value("sqlite_synchronous")) ? TRUE : false,
		parse_bool(g_config_file->get_value("sqlite_wal_mode")) ? TRUE : false,
		mmap_size, mime_num);
	auto cl_5 = make_scope_exit(mail_engine_stop);

	cmd_parser_init(threads_num, SOCKET_TIMEOUT, cmd_debug);
	auto cl_4 = make_scope_exit(cmd_parser_stop);

	if (service_run_early() != 0) {
		mlog(LV_ERR, "system: failed to run PLUGIN_EARLY_INIT");
		return 3;
	}
	if (listener_run(g_config_file->get_value("config_file_path")) != 0) {
		mlog(LV_ERR, "system: failed to start TCP listener");
		return 6;
	}
	if (switch_user_exec(*pconfig, argv) != 0)
		return EXIT_FAILURE;
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	textmaps_init();
	if (0 != service_run()) {
		mlog(LV_ERR, "system: failed to start services");
		return 3;
	}
	auto cl_1 = make_scope_exit(system_services_stop);
	if (0 != system_services_run()) {
		mlog(LV_ERR, "system: failed to start system services");
		return 4;
	}
	if (0 != cmd_parser_run()) {
		mlog(LV_ERR, "system: failed to start command parser");
		return 7;
	}
	if (0 != mail_engine_run()) {
		mlog(LV_ERR, "system: failed to start mail engine");
		return 8;
	}
	if (exmdb_client_run_front(g_config_file->get_value("config_file_path")) != 0) {
		mlog(LV_ERR, "system: failed to start exmdb client");
		return 9;
	}
	if (0 != listener_trigger_accept()) {
		mlog(LV_ERR, "system: failed to start TCP listener");
		return 11;
	}
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESETHAND;
	sigaction(SIGINT, &sact, nullptr);
	sigaction(SIGTERM, &sact, nullptr);
	mlog(LV_NOTICE, "system: MIDB is now running");
	while (!g_notify_stop) {
		sleep(1);
		if (g_hup_signalled.exchange(false)) {
			midb_reload_config(nullptr);
			service_trigger_all(PLUGIN_RELOAD);
		}
	}
	return 0;
} catch (const cfg_error &) {
	return EXIT_FAILURE;
}
