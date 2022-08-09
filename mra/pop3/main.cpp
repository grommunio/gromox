// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <chrono>
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
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "pop3.hpp"

using namespace gromox;

gromox::atomic_bool g_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static gromox::atomic_bool g_hup_signalled;

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static std::vector<std::string> g_dfl_svc_plugins = {
	"libgxs_event_proxy.so",
	"libgxs_logthru.so",
	"libgxs_midb_agent.so",
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_authmgr.so",
	"libgxs_user_filter.so",
};

static constexpr cfg_directive pop3_cfg_defaults[] = {
	{"block_interval_auths", "1min", CFG_TIME, "1s"},
	{"config_file_path", PKGSYSCONFDIR "/pop3:" PKGSYSCONFDIR},
	{"context_average_mem", "512K", CFG_SIZE, "128K"},
	{"context_average_units", "5000", CFG_SIZE, "256"},
	{"context_max_mem", "2M", CFG_SIZE},
	{"context_num", "400", CFG_SIZE},
	{"data_file_path", PKGDATADIR "/pop3:" PKGDATADIR},
	{"listen_port", "pop3_listen_port", CFG_ALIAS},
	{"listen_ssl_port", "pop3_listen_tls_port", CFG_ALIAS},
	{"pop3_auth_times", "10", CFG_SIZE, "1"},
	{"pop3_cmd_debug", "0"},
	{"pop3_conn_timeout", "3min", CFG_TIME, "1s"},
	{"pop3_force_stls", "false", CFG_BOOL},
	{"pop3_listen_addr", "::"},
	{"pop3_listen_port", "110"},
	{"pop3_listen_tls_port", "0"},
	{"pop3_support_stls", "false", CFG_BOOL},
	{"pop3_thread_charge_num", "20", CFG_SIZE, "4"},
	{"pop3_thread_init_num", "5", CFG_SIZE},
	{"running_identity", "gromox"},
	{"state_path", PKGSTATEDIR},
	{"thread_charge_num", "pop3_thread_charge_num", CFG_ALIAS},
	{"thread_init_num", "pop3_threaD_init_num", CFG_ALIAS},
	{"tls_min_proto", "tls1.2"},
	CFG_TABLE_END,
};

static void term_handler(int signo)
{
	g_notify_stop = true;
}

static bool pop3_reload_config(std::shared_ptr<CONFIG_FILE> pconfig)
{
	if (pconfig == nullptr)
		pconfig = config_file_prg(opt_config_file, "pop3.cfg",
		          pop3_cfg_defaults);
	if (opt_config_file != nullptr && pconfig == nullptr) {
		printf("config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return false;
	}
	g_popcmd_debug = pconfig->get_ll("pop3_cmd_debug");
	return true;
}

int main(int argc, const char **argv) try
{ 
	int retcode = EXIT_FAILURE;
	struct rlimit rl;
	char temp_buff[256];

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv,
	    HXOPT_USAGEONERR | HXOPT_KEEP_ARGV) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	startup_banner("gromox-pop3");
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
	g_config_file = config_file_prg(opt_config_file, "pop3.cfg",
	                pop3_cfg_defaults);
	if (opt_config_file != nullptr && g_config_file == nullptr)
		printf("[resource]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (g_config_file == nullptr)
		return EXIT_FAILURE;
	if (!pop3_reload_config(g_config_file))
		return EXIT_FAILURE;

	auto str_val = g_config_file->get_value("host_id");
	if (str_val == NULL) {
		memset(temp_buff, 0, arsizeof(temp_buff));
		gethostname(temp_buff, arsizeof(temp_buff));
		temp_buff[arsizeof(temp_buff)-1] = '\0';
		resource_set_string("HOST_ID", temp_buff);
		str_val = temp_buff;
	}
	printf("[system]: host ID is %s\n", str_val);
	
	str_val = resource_get_string("DEFAULT_DOMAIN");
	if (str_val == NULL) {
		memset(temp_buff, 0, arsizeof(temp_buff));
		getdomainname(temp_buff, arsizeof(temp_buff));
		resource_set_string("DEFAULT_DOMAIN", temp_buff);
		str_val = temp_buff;
		printf("[system]: warning! cannot find default domain, OS domain name "
			"will be used as default domain\n");
	}
	printf("[system]: default domain is %s\n", str_val);

	unsigned int context_num = g_config_file->get_ll("context_num");
	unsigned int thread_charge_num = g_config_file->get_ll("pop3_thread_charge_num");
	if (thread_charge_num % 4 != 0) {
		thread_charge_num = thread_charge_num / 4 * 4;
		resource_set_integer("pop3_thread_charge_num", thread_charge_num);
	}
	printf("[system]: one thread is in charge of %d contexts\n",
		thread_charge_num);

	unsigned int thread_init_num = g_config_file->get_ll("pop3_thread_init_num");
	if (thread_init_num * thread_charge_num > context_num) {
		thread_init_num = context_num / thread_charge_num;
		if (0 == thread_init_num) {
			thread_init_num = 1;
			context_num = thread_charge_num;
			resource_set_integer("CONTEXT_NUM", context_num);
			printf("[system]: rectify contexts number %d\n", context_num);
		}
		resource_set_integer("pop3_thread_init_num", thread_init_num);
	}
	printf("[system]: threads pool initial threads number is %d\n",
		thread_init_num);

	unsigned int context_aver_mem = g_config_file->get_ll("context_average_mem") / (64 * 1024);
	HX_unit_size(temp_buff, arsizeof(temp_buff), context_aver_mem * 64 * 1024, 1024, 0);
	printf("[pop3]: context average memory is %s\n", temp_buff);
 
	size_t context_max_mem = g_config_file->get_ll("context_max_mem") / (64 * 1024);
	if (context_max_mem < context_aver_mem) {
		context_max_mem = context_aver_mem;
		HX_unit_size(temp_buff, arsizeof(temp_buff), context_max_mem * 64 * 1024, 1024, 0);
		resource_set_string("CONTEXT_MAX_MEM", temp_buff);
	} 
	context_max_mem *= 64*1024;
	HX_unit_size(temp_buff, arsizeof(temp_buff), context_max_mem, 1024, 0);
	printf("[pop3]: context maximum memory is %s\n", temp_buff);

	unsigned int context_aver_units = g_config_file->get_ll("context_average_units");
	printf("[pop3]: context average units number is %d\n", context_aver_units);
	
	std::chrono::seconds pop3_conn_timeout(g_config_file->get_ll("pop3_conn_timeout"));
	HX_unit_seconds(temp_buff, arsizeof(temp_buff), pop3_conn_timeout.count(), 0);
	printf("[pop3]: pop3 socket read write timeout is %s\n", temp_buff);
 
	int pop3_auth_times = g_config_file->get_ll("pop3_auth_times");
	printf("[pop3]: maximum authentication failure times is %d\n", 
			pop3_auth_times);

	int block_interval_auth = g_config_file->get_ll("block_interval_auths");
	HX_unit_seconds(temp_buff, arsizeof(temp_buff), block_interval_auth, 0);
	printf("[pop3]: block client %s when authentication failure count "
			"is exceeded\n", temp_buff);

	auto pop3_support_stls = parse_bool(g_config_file->get_value("pop3_support_stls"));
	auto certificate_path = g_config_file->get_value("pop3_certificate_path");
	auto cb_passwd = g_config_file->get_value("pop3_certificate_passwd");
	auto private_key_path = g_config_file->get_value("pop3_private_key_path");
	if (pop3_support_stls) {
		if (NULL == certificate_path || NULL == private_key_path) {
			pop3_support_stls = false;
			printf("[pop3]: turn off TLS support because certificate or "
				"private key path is empty\n");
		} else {
			printf("[pop3]: pop3 support TLS mode\n");
		}
	} else {
		printf("[pop3]: pop3 doesn't support TLS mode\n");
	}
	
	auto pop3_force_stls = parse_bool(g_config_file->get_value("pop3_force_stls"));
	if (pop3_support_stls && pop3_force_stls)
		printf("[pop3]: pop3 MUST running in TLS mode\n");
	uint16_t listen_tls_port = g_config_file->get_ll("pop3_listen_tls_port");
	if (!pop3_support_stls && listen_tls_port > 0)
		listen_tls_port = 0;
	if (listen_tls_port > 0)
		printf("[system]: system TLS listening port %d\n", listen_tls_port);

	if (resource_run() != 0) {
		printf("[system]: Failed to load resource\n");
		return EXIT_FAILURE;
	}
	auto cleanup_2 = make_scope_exit(resource_stop);
	uint16_t listen_port = g_config_file->get_ll("pop3_listen_port");
	listener_init(g_config_file->get_value("pop3_listen_addr"),
		listen_port, listen_tls_port);
	if (0 != listener_run()) {
		printf("[system]: fail to start listener\n");
		return EXIT_FAILURE;
	}
	auto cleanup_4 = make_scope_exit(listener_stop);

	if (0 != getrlimit(RLIMIT_NOFILE, &rl)) {
		printf("[system]: fail to get file limitation\n");
		return EXIT_FAILURE;
	}
	if (rl.rlim_cur < 2*context_num + 128 ||
		rl.rlim_max < 2*context_num + 128) {
		rl.rlim_cur = 2*context_num + 128;
		rl.rlim_max = 2*context_num + 128;
		if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
			printf("[system]: fail to set file limitation\n");
		else
			printf("[system]: set file limitation to %zu\n", static_cast<size_t>(rl.rlim_cur));
	}
	service_init({g_config_file->get_value("config_file_path"),
		g_config_file->get_value("data_file_path"),
		g_config_file->get_value("state_path"),
		std::move(g_dfl_svc_plugins), context_num});
	printf("--------------------------- service plugins begin"
		   "---------------------------\n");
	if (service_run_early() != 0) {
		printf("[system]: failed to run PLUGIN_EARLY_INIT\n");
		return EXIT_FAILURE;
	}
	if (switch_user_exec(*g_config_file, argv) != 0)
		return EXIT_FAILURE;
	if (0 != service_run()) { 
		printf("---------------------------- service plugins end"
		   "----------------------------\n");
		printf("[system]: failed to run service\n");
		return EXIT_FAILURE;
	} else {
		printf("---------------------------- service plugins end"
		   "----------------------------\n");
	}
	auto cleanup_6 = make_scope_exit(service_stop);
	
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	if (0 != system_services_run()) { 
		printf("[system]: failed to run system service\n");
		return EXIT_FAILURE;
	}
	auto cleanup_8 = make_scope_exit(system_services_stop);
	g_blocks_allocator = alloc_limiter<stream_block>(context_num * context_aver_mem,
	                     "pop3_blocks_allocator",
	                     "pop3.cfg:context_num,context_average_mem");
	pop3_parser_init(context_num, context_max_mem, pop3_conn_timeout,
		pop3_auth_times, block_interval_auth, pop3_support_stls,
		pop3_force_stls, certificate_path, cb_passwd,
		private_key_path);
 
	if (0 != pop3_parser_run()) { 
		printf("[system]: failed to run pop3 parser\n");
		return EXIT_FAILURE;
	}
	auto cleanup_14 = make_scope_exit(pop3_parser_stop);
	
	contexts_pool_init(pop3_parser_get_contexts_list(), context_num,
		pop3_parser_get_context_socket,
		pop3_parser_get_context_timestamp,
		thread_charge_num, pop3_conn_timeout); 
 
	if (0 != contexts_pool_run()) { 
		printf("[system]: failed to run contexts pool\n");
		return EXIT_FAILURE;
	}
	auto cleanup_16 = make_scope_exit(contexts_pool_stop);

	threads_pool_init(thread_init_num, reinterpret_cast<int (*)(SCHEDULE_CONTEXT *)>(pop3_parser_process));
	threads_pool_register_event_proc(pop3_parser_threads_event_proc);
	if (threads_pool_run("pop3.cfg:pop3_thread_init_num") != 0) {
		printf("[system]: failed to run threads pool\n");
		return EXIT_FAILURE;
	}
	auto cleanup_20 = make_scope_exit(threads_pool_stop);

	/* accept the connection */
	if (listener_trigger_accept() != 0) {
		printf("[system]: fail trigger accept\n");
		return EXIT_FAILURE;
	}
	
	retcode = EXIT_SUCCESS;
	printf("[system]: POP3 DAEMON is now running\n");
	while (!g_notify_stop) {
		sleep(3);
		if (g_hup_signalled.exchange(false)) {
			pop3_reload_config(nullptr);
			service_trigger_all(PLUGIN_RELOAD);
		}
	}
	listener_stop_accept();
	return retcode;
} catch (const cfg_error &) {
	return EXIT_FAILURE;
}
