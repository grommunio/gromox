// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <memory>
#include <libHX/option.h>
#include <libHX/string.h>
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

BOOL g_notify_stop = FALSE;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static unsigned int opt_show_version;

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
	g_notify_stop = TRUE;
}

int main(int argc, const char **argv)
{
	BOOL b_wal;
	BOOL b_async;
	int stub_num;
	int mime_num;
	int proxy_num;
	int table_size;
	int listen_port;
	int threads_num;
	struct rlimit rl;
	char charset[32];
	int console_port;
	char timezone[64];
	char org_name[256];
	int cache_interval;
	char temp_buff[45];
	char listen_ip[40], console_ip[40];
	uint64_t mmap_size;
	char data_path[256], state_dir[256];
	std::shared_ptr<CONFIG_FILE> pconfig;
	char config_path[256];
	char service_path[256];
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	signal(SIGPIPE, SIG_IGN);
	g_config_file = pconfig = config_file_prg(opt_config_file, "midb.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr) {
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return 2;
	}

	auto str_value = config_file_get_value(pconfig, "SERVICE_PLUGIN_PATH");
	if (NULL == str_value) {
		strcpy(service_path, PKGLIBDIR);
		config_file_set_value(pconfig, "SERVICE_PLUGIN_PATH", service_path);
	} else {
		strcpy(service_path, str_value);
	}
	printf("[system]: service plugin path is %s\n", service_path);
	str_value = config_file_get_value(pconfig, "SERVICE_PLUGIN_LIST");
	const char *const *service_plugin_list = NULL;
	if (str_value != NULL) {
		service_plugin_list = const_cast<const char * const *>(read_file_by_line(str_value));
		if (service_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			return 2;
		}
	}

	str_value = config_file_get_value(pconfig, "CONFIG_FILE_PATH");
	if (NULL == str_value) {
		strcpy(config_path, PKGSYSCONFDIR "/midb:" PKGSYSCONFDIR);
		config_file_set_value(pconfig, "config_file_path", config_path);
	} else {
		strcpy(config_path, str_value);
	}
	printf("[system]: config path is %s\n", config_path);
	
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		strcpy(data_path, PKGDATADIR "/midb:" PKGDATADIR);
	} else {
		strcpy(data_path, str_value);
	}
	printf("[system]: data path is %s\n", data_path);
	
	str_value = config_file_get_value(pconfig, "STATE_PATH");
	HX_strlcpy(state_dir, str_value != nullptr ? str_value : PKGSTATEDIR, sizeof(state_dir));
	printf("[system]: state path is %s\n", state_dir);
	
	str_value = config_file_get_value(pconfig, "RPC_PROXY_CONNECTION_NUM");
	if (NULL == str_value) {
		proxy_num = 10;
		config_file_set_value(pconfig, "RPC_PROXY_CONNECTION_NUM", "10");
	} else {
		proxy_num = atoi(str_value);
		if (proxy_num <= 0 || proxy_num > 200) {
			config_file_set_value(pconfig, "RPC_PROXY_CONNECTION_NUM", "10");
			proxy_num = 10;
		}
	}
	printf("[system]: exmdb proxy connection number is %d\n", proxy_num);
	
	str_value = config_file_get_value(pconfig, "NOTIFY_STUB_THREADS_NUM");
	if (NULL == str_value) {
		stub_num = 10;
		config_file_set_value(pconfig, "NOTIFY_STUB_THREADS_NUM", "10");
	} else {
		stub_num = atoi(str_value);
		if (stub_num <= 0 || stub_num > 200) {
			stub_num = 10;
			config_file_set_value(pconfig, "NOTIFY_STUB_THREADS_NUM", "10");
		}
	}
	printf("[system]: exmdb notify stub threads number is %d\n", stub_num);
	
	str_value = config_file_get_value(pconfig, "MIDB_LISTEN_IP");
	HX_strlcpy(listen_ip, str_value != nullptr ? nullptr : "::1",
	           GX_ARRAY_SIZE(listen_ip));
	str_value = config_file_get_value(pconfig, "MIDB_LISTEN_PORT");
	if (NULL == str_value) {
		listen_port = 5555;
		config_file_set_value(pconfig, "MIDB_LISTEN_PORT", "5555");
	} else {
		listen_port = atoi(str_value);
		if (listen_port <= 0) {
			listen_port = 5555;
			config_file_set_value(pconfig, "MIDB_LISTEN_PORT", "5555");
		}
	}
	printf("[system]: listen address is [%s]:%d\n",
	       *listen_ip == '\0' ? "*" : listen_ip, listen_port);

	str_value = config_file_get_value(pconfig, "MIDB_THREADS_NUM");
	if (NULL == str_value) {
		threads_num = 100;
		config_file_set_value(pconfig, "MIDB_THREADS_NUM", "100");
	} else {
		threads_num = atoi(str_value);
		if (threads_num < 20) {
			threads_num = 20;
			config_file_set_value(pconfig, "MIDB_THREADS_NUM", "20");
		} else if (threads_num > 1000) {
			threads_num = 1000;
			config_file_set_value(pconfig, "MIDB_THREADS_NUM", "1000");
		}
	}
	printf("[system]: connection threads number is %d\n", threads_num);
	
	str_value = config_file_get_value(pconfig, "MIDB_TABLE_SIZE");
	if (NULL == str_value) {
		table_size = 5000;
		config_file_set_value(pconfig, "MIDB_TABLE_SIZE", "5000");
	} else {
		table_size = atoi(str_value);
		if (table_size < 100) {
			table_size = 100;
			config_file_set_value(pconfig, "MIDB_TABLE_SIZE", "100");
		} else if (table_size > 50000) {
			table_size = 50000;
			config_file_set_value(pconfig, "MIDB_TABLE_SIZE", "50000");
		}
	}
	printf("[system]: hash table size is %d\n", table_size);

	str_value = config_file_get_value(pconfig, "MIDB_CACHE_INTERVAL");
	if (NULL == str_value) {
		cache_interval = 60 * 30;
		config_file_set_value(pconfig, "MIDB_CACHE_INTERVAL", "30minutes");
	} else {
		cache_interval = atoitvl(str_value);
		if (cache_interval < 60 || cache_interval > 1800) {
			cache_interval = 600;
			config_file_set_value(pconfig, "MIDB_CACHE_INTERVAL", "10minutes");
		}
	}
	itvltoa(cache_interval, temp_buff);
	printf("[system]: cache interval is %s\n", temp_buff);
	
	str_value = config_file_get_value(pconfig, "MIDB_MIME_NUMBER");
	if (NULL == str_value) {
		mime_num = 4096;
		config_file_set_value(pconfig, "MIDB_MIME_NUMBER", "4096");
	} else {
		mime_num = atoi(str_value);
		if (mime_num < 1024) {
			mime_num = 4096;
			config_file_set_value(pconfig, "MIDB_MIME_NUMBER", "4096");
		}
	}
	printf("[system]: mime number is %d\n", mime_num);
	
	
	str_value = config_file_get_value(pconfig, "X500_ORG_NAME");
	if (NULL == str_value) {
		HX_strlcpy(org_name, "Gromox default", sizeof(org_name));
		config_file_set_value(pconfig, "X500_ORG_NAME", org_name);
	} else {
		strcpy(org_name, str_value);
	}
	printf("[system]: x500 org name is \"%s\"\n", org_name);
	
	str_value = config_file_get_value(pconfig, "DEFAULT_CHARSET");
	if (NULL == str_value) {
		strcpy(charset, "windows-1252");
		config_file_set_value(pconfig, "DEFAULT_CHARSET", charset);
	} else {
		strcpy(charset, str_value);
	}
	printf("[system]: default charset is \"%s\"\n", charset);

	str_value = config_file_get_value(pconfig, "DEFAULT_TIMEZONE");
	if (NULL == str_value) {
		strcpy(timezone, "Asia/Shanghai");
		config_file_set_value(pconfig, "DEFAULT_TIMEZONE", timezone);
	} else {
		strcpy(timezone, str_value);
	}
	printf("[system]: default timezone is \"%s\"\n", timezone);
	
	str_value = config_file_get_value(pconfig, "SQLITE_SYNCHRONOUS");
	if (NULL == str_value) {
		b_async = FALSE;
		config_file_set_value(pconfig, "SQLITE_SYNCHRONOUS", "OFF");
	} else {
		if (0 == strcasecmp(str_value, "OFF") ||
			0 == strcasecmp(str_value, "FALSE")) {
			b_async = FALSE;
		} else {
			b_async = TRUE;
		}
	}
	if (FALSE == b_async) {
		printf("[system]: sqlite synchronous PRAGMA is OFF\n");
	} else {
		printf("[system]: sqlite synchronous PRAGMA is ON\n");
	}
	
	str_value = config_file_get_value(pconfig, "SQLITE_WAL_MODE");
	if (NULL == str_value) {
		b_wal = TRUE;
		config_file_set_value(pconfig, "SQLITE_WAL_MODE", "ON");
	} else {
		if (0 == strcasecmp(str_value, "OFF") ||
			0 == strcasecmp(str_value, "FALSE")) {
			b_wal = FALSE;	
		} else {
			b_wal = TRUE;
		}
	}
	if (FALSE == b_wal) {
		printf("[system]: sqlite journal mode is DELETE\n");
	} else {
		printf("[system]: sqlite journal mode is WAL\n");
	}
	str_value = config_file_get_value(pconfig, "SQLITE_MMAP_SIZE");
	if (NULL != str_value) {
		mmap_size = atobyte(str_value);
	} else {
		mmap_size = 0;
	}
	if (0 == mmap_size) {
		printf("[system]: sqlite mmap_size is disabled\n");
	} else {
		bytetoa(mmap_size, temp_buff);
		printf("[system]: sqlite mmap_size is %s\n", temp_buff);
	}
	str_value = config_file_get_value(pconfig, "CONSOLE_SERVER_IP");
	HX_strlcpy(console_ip, str_value != nullptr ? str_value : "::1",
	           GX_ARRAY_SIZE(console_ip));
	str_value = config_file_get_value(pconfig, "CONSOLE_SERVER_PORT");
	if (NULL == str_value) {
		console_port = 9900;
		config_file_set_value(pconfig, "CONSOLE_SERVER_PORT", "9900");
	} else {
		console_port = atoi(str_value);
		if (console_port <= 0) {
			console_port = 9900;
			config_file_set_value(pconfig, "CONSOLE_SERVER_PORT", "9900");
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
				printf("[system]: set file limitation to %d\n", 5*table_size);
			}
		}
	}

	service_init({service_path, config_path, data_path, state_dir,
		service_plugin_list != NULL ? service_plugin_list : g_dfl_svc_plugins,
		parse_bool(config_file_get_value(g_config_file, "service_plugin_ignore_errors")),
		threads_num});
	common_util_init();
	
	exmdb_client_init(proxy_num, stub_num);
	listener_init(listen_ip, listen_port);
	mail_engine_init(charset, timezone, org_name, table_size,
		b_async, b_wal, mmap_size, cache_interval, mime_num);
	auto cleanup_1 = make_scope_exit(mail_engine_free);

	cmd_parser_init(threads_num, SOCKET_TIMEOUT);
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
	
	if (0 != system_services_run()) {
		printf("[system]: failed to run system services\n");
		return 4;
	}
	
	if (0 != common_util_run()) {
		system_services_stop();
		service_stop();
		printf("[system]: failed to run common util\n");
		return 5;
	}
	if (listener_run(config_path) != 0) {
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: failed to run tcp listener\n");
		return 6;
	}

	if (0 != cmd_parser_run()) {
		listener_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: failed to run command parser\n");
		return 7;
	}

	if (0 != mail_engine_run()) {
		cmd_parser_stop();
		listener_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: failed to run mail engine\n");
		return 8;
	}
	if (exmdb_client_run(config_path) != 0) {
		mail_engine_stop();
		cmd_parser_stop();
		listener_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: failed to run exmdb client\n");
		return 9;
	}

	
	if (0 != console_server_run()) {
		exmdb_client_stop();
		mail_engine_stop();
		cmd_parser_stop();
		listener_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: failed to run console server\n");
		return 10;
	}

	if (0 != listener_trigger_accept()) {
		console_server_stop();
		exmdb_client_stop();
		mail_engine_stop();
		cmd_parser_stop();
		listener_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: fail to trigger tcp listener\n");
		return 11;
	}
	
	signal(SIGTERM, term_handler);
	printf("[system]: MIDB is now running\n");
	while (FALSE == g_notify_stop) {
		sleep(1);
	}
	listener_stop();
	console_server_stop();
	cmd_parser_stop();
	exmdb_client_stop();
	mail_engine_stop();
	common_util_stop();
	system_services_stop();
	service_stop();
	return 0;
}
