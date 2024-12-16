// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <netdb.h>
#include <pthread.h>
#include <string>
#include <typeinfo>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/io.h>
#include <libHX/misc.h>
#include <libHX/option.h>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/common_types.hpp>
#include <gromox/config_file.hpp>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/paths.h>
#include <gromox/process.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "cmd_parser.hpp"
#include "common_util.hpp"
#include "exmdb_client.hpp"
#include "mail_engine.hpp"
#include "system_services.hpp"

using namespace gromox;

void (*system_services_broadcast_event)(const char*);

static gromox::atomic_bool g_main_notify_stop, g_listener_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static unsigned int opt_show_version;
static gromox::atomic_bool g_hup_signalled;
static uint16_t g_listen_port;
static char g_listen_ip[40];
static int g_listen_sockd = -1;
static std::vector<std::string> g_acl_list;
static void (*exmdb_client_event_proc)(const char *dir, BOOL table, uint32_t notify_id, const DB_NOTIFY *);

static constexpr HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{"version", 0, HXTYPE_NONE, &opt_show_version, nullptr, nullptr, 0, "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr static_module g_dfl_svc_plugins[] = {
	{"libgxs_event_proxy.so", SVC_event_proxy},
	{"libgxs_mysql_adaptor.so", SVC_mysql_adaptor},
	{"libgromox_auth.so/ldap", SVC_ldap_adaptor},
	{"libgromox_auth.so/mgr", SVC_authmgr},
};

static constexpr cfg_directive gromox_cfg_defaults[] = {
	{"daemons_fd_limit", "midb_fd_limit", CFG_ALIAS},
	{"midb_fd_limit", "0", CFG_SIZE},
	CFG_TABLE_END,
};

static constexpr cfg_directive midb_cfg_defaults[] = {
	{"config_file_path", PKGSYSCONFDIR "/midb:" PKGSYSCONFDIR},
	{"data_path", PKGDATADIR "/midb:" PKGDATADIR},
	{"default_charset", "windows-1252"},
	{"midb_cache_interval", "30min", CFG_TIME, "1min", "1year"},
	{"midb_cmd_debug", "0"},
	{"midb_hosts_allow", ""}, /* ::1 default set later during startup */
	{"midb_listen_ip", "::1"},
	{"midb_listen_port", "5555"},
	{"midb_log_file", "-"},
	{"midb_log_level", "4" /* LV_NOTICE */},
	{"midb_reload_interval", "60min", CFG_TIME, "1min", "1year"},
	{"midb_schema_upgrades", "auto"},
	{"midb_table_size", "5000", CFG_SIZE, "100", "50000"},
	{"midb_threads_num", "100", CFG_SIZE, "20", "1000"},
	{"notify_stub_threads_num", "10", CFG_SIZE, "1", "200"},
	{"rpc_proxy_connection_num", "10", CFG_SIZE, "1", "200"},
	{"sqlite_debug", "0"},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

static void term_handler(int signo)
{
	g_main_notify_stop = true;
}

static bool midb_reload_config(std::shared_ptr<config_file> gxconfig = nullptr,
    std::shared_ptr<config_file> pconfig = nullptr)
{
	if (pconfig == nullptr)
		pconfig = config_file_prg(opt_config_file, "midb.cfg",
		          midb_cfg_defaults);
	if (opt_config_file != nullptr && pconfig == nullptr) {
		mlog(LV_ERR, "config_file_init %s: %s", opt_config_file, strerror(errno));
		return false;
	}
	mlog_init("gromox-midb", pconfig->get_value("midb_log_file"),
		pconfig->get_ll("midb_log_level"),
		pconfig->get_value("running_identity"));
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

static void buildenv(const remote_svr &)
{
	common_util_build_environment("");
}

static void event_proc(const char *dir, BOOL thing,
    uint32_t notify_id, const DB_NOTIFY *notify)
{
	common_util_set_maildir(dir);
	exmdb_client_event_proc(dir, thing, notify_id, notify);
}

static int exmdb_client_run_front(const char *dir)
{
	return exmdb_client_run(dir, EXMDB_CLIENT_SKIP_PUBLIC |
	       EXMDB_CLIENT_SKIP_REMOTE | EXMDB_CLIENT_ASYNC_CONNECT, buildenv,
	       common_util_free_environment, event_proc);
}

void exmdb_client_register_proc(void *pproc)
{
	exmdb_client_event_proc = reinterpret_cast<decltype(exmdb_client_event_proc)>(pproc);
}

static int system_services_run()
{
#define E(f, s) do { \
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(*(f)))); \
	if ((f) == nullptr) { \
		mlog(LV_ERR, "system_services: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)
	E(system_services_broadcast_event, "broadcast_event");
	return 0;
#undef E
}

static void system_services_stop()
{
	service_release("broadcast_event", "system");
}

static void *midls_thrwork(void *param)
{
	while (!g_listener_notify_stop) {
		auto gco = generic_connection::accept(g_listen_sockd, false, &g_listener_notify_stop);
		if (gco.sockd == -2)
			break;
		else if (gco.sockd < 0)
			continue;
		if (std::find(g_acl_list.cbegin(), g_acl_list.cend(),
		    gco.client_ip) == g_acl_list.cend()) {
			if (HXio_fullwrite(gco.sockd, "FALSE Access denied\r\n", 19) < 0)
				/* ignore */;
			continue;
		}
		auto holder = cmd_parser_make_conn();
		if (holder.size() == 0) {
			if (HXio_fullwrite(gco.sockd, "FALSE Maximum Connection Reached!\r\n", 35) < 0)
				/* ignore */;
			continue;
		}
		auto &conn = holder.front();
		static_cast<generic_connection &>(conn) = std::move(gco);
		conn.is_selecting = FALSE;
		if (HXio_fullwrite(conn.sockd, "OK\r\n", 4) < 0)
			continue;
		cmd_parser_insert_conn(std::move(holder));
	}
	return nullptr;
}

static void listener_init(const char *ip, uint16_t port)
{
	if (*ip != '\0')
		gx_strlcpy(g_listen_ip, ip, std::size(g_listen_ip));
	else
		g_listen_ip[0] = '\0';
	g_listen_port = port;
	g_listen_sockd = -1;
	g_listener_notify_stop = true;
}

static int listener_run(const char *configdir, const char *hosts_allow)
{
	g_listen_sockd = HX_inet_listen(g_listen_ip, g_listen_port);
	if (g_listen_sockd < 0) {
		mlog(LV_ERR, "listener: failed to create listen socket: %s", strerror(-g_listen_sockd));
		return -1;
	}
	gx_reexec_record(g_listen_sockd);
	auto &acl = g_acl_list;
	if (hosts_allow != nullptr)
		acl = gx_split(hosts_allow, ' ');
	auto ret = list_file_read_fixedstrings("midb_acl.txt", configdir, acl);
	if (ret == ENOENT) {
	} else if (ret != 0) {
		mlog(LV_ERR, "listener: list_file_initd \"midb_acl.txt\": %s", strerror(errno));
		close(g_listen_sockd);
		return -5;
	}
	std::sort(acl.begin(), acl.end());
	acl.erase(std::remove(acl.begin(), acl.end(), ""), acl.end());
	acl.erase(std::unique(acl.begin(), acl.end()), acl.end());
	if (acl.size() == 0) {
		mlog(LV_NOTICE, "system: defaulting to implicit access ACL containing ::1.");
		acl = {"::1"};
	}
	return 0;
}

static int listener_trigger_accept()
{
	pthread_t thr_id;

	g_listener_notify_stop = false;
	auto ret = pthread_create4(&thr_id, nullptr, midls_thrwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "listener: failed to create listener thread: %s", strerror(ret));
		return -1;
	}
	pthread_setname_np(thr_id, "listener");
	return 0;
}

static void listener_stop()
{
	g_listener_notify_stop = true;
	if (g_listen_sockd >= 0) {
		close(g_listen_sockd);
		g_listen_sockd = -1;
	}
}

int main(int argc, char **argv)
{
	char temp_buff[45];
	std::shared_ptr<CONFIG_FILE> pconfig;
	
	exmdb_rpc_alloc = common_util_alloc;
	exmdb_rpc_free = [](void *) {};
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt5(g_options_table, argv, nullptr, nullptr,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
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
		return EXIT_FAILURE;
	auto gxconfig = config_file_prg(opt_config_file, "gromox.cfg", gromox_cfg_defaults);
	if (opt_config_file != nullptr && gxconfig == nullptr)
		mlog(LV_ERR, "%s: %s", opt_config_file, strerror(errno));
	if (!midb_reload_config(gxconfig, pconfig))
		return EXIT_FAILURE;

	int proxy_num = pconfig->get_ll("rpc_proxy_connection_num");
	mlog(LV_INFO, "system: exmdb proxy connection number is %d", proxy_num);
	
	int stub_num = pconfig->get_ll("notify_stub_threads_num");
	mlog(LV_INFO, "system: exmdb notify stub threads number is %d", stub_num);
	
	auto listen_ip = pconfig->get_value("midb_listen_ip");
	uint16_t listen_port = pconfig->get_ll("midb_listen_port");
	mlog(LV_INFO, "system: listen address is [%s]:%hu",
	       *listen_ip == '\0' ? "*" : listen_ip, listen_port);

	unsigned int threads_num = pconfig->get_ll("midb_threads_num");
	mlog(LV_INFO, "system: connection threads number is %d", threads_num);

	size_t table_size = pconfig->get_ll("midb_table_size");
	mlog(LV_INFO, "system: hash table size is %zu", table_size);

	int cache_interval = pconfig->get_ll("midb_cache_interval");
	HX_unit_seconds(temp_buff, std::size(temp_buff), cache_interval, 0);
	mlog(LV_INFO, "system: cache interval is %s", temp_buff);
	
	filedes_limit_bump(gxconfig->get_ll("midb_fd_limit"));
	gx_sqlite_debug = pconfig->get_ll("sqlite_debug");
	unsigned int cmd_debug = pconfig->get_ll("midb_cmd_debug");
	service_init({g_config_file, g_dfl_svc_plugins, threads_num});
	auto cl_0 = make_scope_exit(service_stop);
	
	exmdb_client_init(proxy_num, stub_num);
	auto cl_6 = make_scope_exit(exmdb_client_stop);
	listener_init(listen_ip, listen_port);
	auto cl_3 = make_scope_exit(listener_stop);
	mail_engine_init(g_config_file->get_value("default_charset"),
		g_config_file->get_value("x500_org_name"), table_size);
	auto cl_5 = make_scope_exit(mail_engine_stop);

	cmd_parser_init(threads_num, SOCKET_TIMEOUT, cmd_debug);
	auto cl_4 = make_scope_exit(cmd_parser_stop);

	if (service_run_early() != 0) {
		mlog(LV_ERR, "system: failed to run PLUGIN_EARLY_INIT");
		return EXIT_FAILURE;
	}
	if (listener_run(g_config_file->get_value("config_file_path"),
	    g_config_file->get_value("midb_hosts_allow")) != 0) {
		mlog(LV_ERR, "system: failed to start TCP listener");
		return EXIT_FAILURE;
	}
	if (switch_user_exec(*pconfig, argv) != 0)
		return EXIT_FAILURE;
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	textmaps_init();
	if (0 != service_run()) {
		mlog(LV_ERR, "system: failed to start services");
		return EXIT_FAILURE;
	}
	auto cl_1 = make_scope_exit(system_services_stop);
	if (0 != system_services_run()) {
		mlog(LV_ERR, "system: failed to start system services");
		return EXIT_FAILURE;
	}
	if (0 != cmd_parser_run()) {
		mlog(LV_ERR, "system: failed to start command parser");
		return EXIT_FAILURE;
	}
	if (0 != mail_engine_run()) {
		mlog(LV_ERR, "system: failed to start mail engine");
		return EXIT_FAILURE;
	}
	if (exmdb_client_run_front(g_config_file->get_value("config_file_path")) != 0) {
		mlog(LV_ERR, "system: failed to start exmdb client");
		return EXIT_FAILURE;
	}
	if (0 != listener_trigger_accept()) {
		mlog(LV_ERR, "system: failed to start TCP listener");
		return EXIT_FAILURE;
	}
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESETHAND;
	sigaction(SIGINT, &sact, nullptr);
	sigaction(SIGTERM, &sact, nullptr);
	mlog(LV_INFO, "system: MIDB is now running");
	while (!g_main_notify_stop) {
		sleep(1);
		if (g_hup_signalled.exchange(false)) {
			midb_reload_config();
			service_trigger_all(PLUGIN_RELOAD);
		}
	}
	return EXIT_SUCCESS;
}
