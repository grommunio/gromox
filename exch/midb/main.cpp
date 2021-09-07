// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <atomic>
#include <cerrno>
#include <memory>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "service.h"
#include "listener.h"
#include <gromox/mail_func.hpp>
#include "cmd_parser.h"
#include "common_util.h"
#include <gromox/config_file.hpp>
#include "mail_engine.h"
#include "exmdb_client.h"
#include "console_cmd_handler.h"
#include <gromox/console_server.hpp>
#include "system_services.h"
#include <cstdio>
#include <unistd.h>
#include <cstring>
#include <csignal>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>

using namespace gromox;

std::atomic<bool> g_notify_stop{false};
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static unsigned int opt_show_version;
static std::atomic<bool> g_hup_signalled{false};

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{"version", 0, HXTYPE_NONE, &opt_show_version, nullptr, nullptr, 0, "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static const char *const g_dfl_svc_plugins[] = {
	"libgxs_event_proxy.so",
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_textmaps.so",
	"libgxs_authmgr.so",
	NULL,
};

static void term_handler(int signo)
{
	g_notify_stop = true;
}

int main(int argc, const char **argv)
{
	struct rlimit rl;
	char temp_buff[45];
	std::shared_ptr<CONFIG_FILE> pconfig;
	
	exmdb_rpc_alloc = common_util_alloc;
	exmdb_rpc_free = [](void *) {};
	exmdb_rpc_exec = exmdb_client_do_rpc;
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	struct sigaction sact{};
	sigemptyset(&sact.sa_mask);
	sact.sa_handler = [](int) {};
	sigaction(SIGALRM, &sact, nullptr);
	sact.sa_handler = [](int) { g_hup_signalled = true; };
	sigaction(SIGHUP, &sact, nullptr);
	sact.sa_handler = SIG_IGN;
	sact.sa_flags   = SA_RESTART;
	sigaction(SIGPIPE, &sact, nullptr);
	g_config_file = pconfig = config_file_prg(opt_config_file, "midb.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return 2;

	static constexpr cfg_directive cfg_default_values[] = {
		{"config_file_path", PKGSYSCONFDIR "/midb:" PKGSYSCONFDIR},
		{"console_server_ip", "::1"},
		{"console_server_port", "9900"},
		{"data_path", PKGDATADIR "/midb:" PKGDATADIR},
		{"default_charset", "windows-1252"},
		{"default_timezone", "Asia/Shanghai"},
		{"midb_cache_interval", "30min", CFG_TIME},
		{"midb_listen_ip", "::1"},
		{"midb_listen_port", "5555"},
		{"midb_mime_number", "4096", CFG_SIZE},
		{"midb_table_size", "5000", CFG_SIZE},
		{"midb_threads_num", "100", CFG_SIZE},
		{"notify_stub_threads_num", "10", CFG_SIZE},
		{"rpc_proxy_connection_num", "10", CFG_SIZE},
		{"service_plugin_path", PKGLIBDIR},
		{"sqlite_mmap_size", "0", CFG_SIZE},
		{"sqlite_synchronous", "off", CFG_BOOL},
		{"sqlite_wal_mode", "true", CFG_BOOL},
		{"state_path", PKGSTATEDIR},
		{"x500_org_name", "Gromox default"},
		{},
	};
	config_file_apply(*g_config_file, cfg_default_values);
	auto str_value = pconfig->get_value("SERVICE_PLUGIN_LIST");
	const char *const *service_plugin_list = NULL;
	if (str_value != NULL) {
		service_plugin_list = const_cast<const char * const *>(read_file_by_line(str_value));
		if (service_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			return 2;
		}
	}

	int proxy_num = 10;
	str_value = pconfig->get_value("RPC_PROXY_CONNECTION_NUM");
	if (str_value != nullptr) {
		proxy_num = atoi(str_value);
		if (proxy_num <= 0 || proxy_num > 200) {
			pconfig->set_value("RPC_PROXY_CONNECTION_NUM", "10");
			proxy_num = 10;
		}
	}
	printf("[system]: exmdb proxy connection number is %d\n", proxy_num);
	
	int stub_num = 10;
	str_value = pconfig->get_value("NOTIFY_STUB_THREADS_NUM");
	if (str_value != nullptr) {
		stub_num = atoi(str_value);
		if (stub_num <= 0 || stub_num > 200) {
			stub_num = 10;
			pconfig->set_value("NOTIFY_STUB_THREADS_NUM", "10");
		}
	}
	printf("[system]: exmdb notify stub threads number is %d\n", stub_num);
	
	auto listen_ip = pconfig->get_value("midb_listen_ip");
	int listen_port = strtoul(pconfig->get_value("midb_listen_port"), nullptr, 0);
	printf("[system]: listen address is [%s]:%d\n",
	       *listen_ip == '\0' ? "*" : listen_ip, listen_port);

	unsigned int threads_num = 0;
	if (pconfig->get_uint("midb_threads_num", &threads_num)) {
		if (threads_num < 20) {
			threads_num = 20;
			pconfig->set_value("MIDB_THREADS_NUM", "20");
		} else if (threads_num > 1000) {
			threads_num = 1000;
			pconfig->set_value("MIDB_THREADS_NUM", "1000");
		}
	}
	printf("[system]: connection threads number is %d\n", threads_num);

	size_t table_size = 0;
	str_value = pconfig->get_value("MIDB_TABLE_SIZE");
	if (str_value != nullptr) {
		table_size = atoi(str_value);
		if (table_size < 100) {
			table_size = 100;
			pconfig->set_value("MIDB_TABLE_SIZE", "100");
		} else if (table_size > 50000) {
			table_size = 50000;
			pconfig->set_value("MIDB_TABLE_SIZE", "50000");
		}
	}
	printf("[system]: hash table size is %zu\n", table_size);

	int cache_interval = 1800;
	str_value = pconfig->get_value("MIDB_CACHE_INTERVAL");
	if (str_value != nullptr) {
		cache_interval = atoitvl(str_value);
		if (cache_interval < 60 || cache_interval > 1800) {
			cache_interval = 600;
			pconfig->set_value("MIDB_CACHE_INTERVAL", "10minutes");
		}
	}
	itvltoa(cache_interval, temp_buff);
	printf("[system]: cache interval is %s\n", temp_buff);
	
	int mime_num = 4096;
	str_value = pconfig->get_value("MIDB_MIME_NUMBER");
	if (str_value != nullptr) {
		mime_num = atoi(str_value);
		if (mime_num < 1024) {
			mime_num = 4096;
			pconfig->set_value("MIDB_MIME_NUMBER", "4096");
		}
	}
	printf("[system]: mime number is %d\n", mime_num);
	
	uint64_t mmap_size = 0;
	str_value = pconfig->get_value("SQLITE_MMAP_SIZE");
	if (NULL != str_value) {
		mmap_size = atobyte(str_value);
	}
	if (0 == mmap_size) {
		printf("[system]: sqlite mmap_size is disabled\n");
	} else {
		bytetoa(mmap_size, temp_buff);
		printf("[system]: sqlite mmap_size is %s\n", temp_buff);
	}
	auto console_ip = pconfig->get_value("console_server_ip");
	int console_port = 9000;
	str_value = pconfig->get_value("CONSOLE_SERVER_PORT");
	if (str_value != nullptr) {
		console_port = atoi(str_value);
		if (console_port <= 0) {
			console_port = 9900;
			pconfig->set_value("CONSOLE_SERVER_PORT", "9900");
		}
	}
	printf("[system]: console server address is [%s]:%d\n",
	       *console_ip == '\0' ? "*" : console_ip, console_port);
	
	if (0 != getrlimit(RLIMIT_NOFILE, &rl)) {
		printf("[system]: fail to get file limitation\n");
	} else {
		if (rl.rlim_cur < 5*table_size ||
			rl.rlim_max < 5*table_size) {
			rl.rlim_cur = 5*table_size;
			rl.rlim_max = 5*table_size;
			if (0 != setrlimit(RLIMIT_NOFILE, &rl)) {
				printf("[system]: fail to set file limitation\n");
			} else {
				printf("[system]: set file limitation to %zu\n", 5 * table_size);
			}
		}
	}

	str_value = pconfig->get_value("midb_cmd_debug");
	auto cmd_debug = str_value != nullptr ? strtoul(str_value, nullptr, 0) : 0;

	service_init({g_config_file->get_value("service_plugin_path"),
		g_config_file->get_value("config_file_path"),
		g_config_file->get_value("data_path"),
		g_config_file->get_value("state_path"),
		service_plugin_list != NULL ? service_plugin_list : g_dfl_svc_plugins,
		parse_bool(g_config_file->get_value("service_plugin_ignore_errors")),
		threads_num});
	common_util_init();
	auto cl_0a = make_scope_exit([&]() { common_util_free(); });
	
	exmdb_client_init(proxy_num, stub_num);
	listener_init(listen_ip, listen_port);
	auto cl_0b = make_scope_exit([&]() { listener_free(); });
	mail_engine_init(g_config_file->get_value("default_charset"),
		g_config_file->get_value("default_timezone"),
		g_config_file->get_value("x500_org_name"), table_size,
		parse_bool(g_config_file->get_value("sqlite_synchronous")) ? TRUE : false,
		parse_bool(g_config_file->get_value("sqlite_wal_mode")) ? TRUE : false,
		mmap_size, cache_interval, mime_num);

	cmd_parser_init(threads_num, SOCKET_TIMEOUT, cmd_debug);
	auto cleanup_2 = make_scope_exit(cmd_parser_free);

	console_server_init(console_ip, console_port);
	console_server_register_command("midb", cmd_handler_midb_control);
	console_server_register_command("system", cmd_handler_system_control);
	console_server_register_command("help", cmd_handler_help);
	console_server_register_command(nullptr, cmd_handler_service_plugins);

	if (0 != service_run()) {
		printf("[system]: failed to run service\n");
		return 3;
	}
	auto cl_0 = make_scope_exit(service_stop);
	if (0 != system_services_run()) {
		printf("[system]: failed to run system services\n");
		return 4;
	}
	auto cl_1 = make_scope_exit(system_services_stop);
	if (listener_run(g_config_file->get_value("config_file_path")) != 0) {
		printf("[system]: failed to run tcp listener\n");
		return 6;
	}
	auto cl_3 = make_scope_exit(listener_stop);
	if (0 != cmd_parser_run()) {
		printf("[system]: failed to run command parser\n");
		return 7;
	}
	auto cl_4 = make_scope_exit(cmd_parser_stop);
	if (0 != mail_engine_run()) {
		printf("[system]: failed to run mail engine\n");
		return 8;
	}
	auto cl_5 = make_scope_exit(mail_engine_stop);
	if (exmdb_client_run(g_config_file->get_value("config_file_path")) != 0) {
		printf("[system]: failed to run exmdb client\n");
		return 9;
	}
	auto cl_6 = make_scope_exit(exmdb_client_stop);
	if (0 != console_server_run()) {
		printf("[system]: failed to run console server\n");
		return 10;
	}
	auto cl_7 = make_scope_exit(console_server_stop);
	if (0 != listener_trigger_accept()) {
		printf("[system]: fail to trigger tcp listener\n");
		return 11;
	}
	auto cl_8 = make_scope_exit(listener_stop);
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESETHAND;
	sigaction(SIGINT, &sact, nullptr);
	sigaction(SIGTERM, &sact, nullptr);
	printf("[system]: MIDB is now running\n");
	while (!g_notify_stop) {
		sleep(1);
		if (g_hup_signalled.exchange(false))
			service_reload_all();
	}
	return 0;
}
