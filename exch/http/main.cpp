// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <cassert>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <typeinfo>
#include <unistd.h>
#include <libHX/misc.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "blocks_allocator.h"
#include "hpm_processor.h"
#include "http_parser.h"
#include "listener.h"
#include "mod_cache.h"
#include "mod_fastcgi.h"
#include "mod_rewrite.h"
#include "pdu_processor.h"
#include "resource.h"
#include "service.h"
#include "system_services.h"
#define PDU_PROCESSOR_RATIO			10

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

static constexpr const char *g_dfl_hpm_plugins[] = {
	"libgxh_mh_emsmdb.so",
	"libgxh_mh_nsp.so",
	NULL,
};
static constexpr const char *g_dfl_proc_plugins[] = {
	"libgxp_exchange_emsmdb.so",
	"libgxp_exchange_nsp.so",
	"libgxp_exchange_rfr.so",
	NULL,
};
static constexpr const char *g_dfl_svc_plugins[] = {
	"libgxs_abktplug.so",
	"libgxs_codepage_lang.so",
	"libgxs_exmdb_provider.so",
	"libgxs_logthru.so",
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_authmgr.so",
	"libgxs_textmaps.so",
	"libgxs_timer_agent.so",
	"libgxs_user_filter.so",
	NULL,
};

static void term_handler(int signo);

static constexpr cfg_directive http_cfg_defaults[] = {
	{"block_interval_auths", "1min", CFG_TIME, "1s"},
	{"config_file_path", PKGSYSCONFDIR "/http:" PKGSYSCONFDIR},
	{"context_average_mem", "256K", CFG_SIZE, "192K"},
	{"context_num", "400", CFG_SIZE},
	{"data_file_path", PKGDATADIR "/http:" PKGDATADIR},
	{"fastcgi_cache_size", "256K", CFG_SIZE, "64K"},
	{"fastcgi_exec_timeout", "10min", CFG_TIME, "1min"},
	{"fastcgi_max_size", "4M", CFG_SIZE, "64K"},
	{"hpm_cache_size", "512K", CFG_SIZE, "64K"},
	{"hpm_max_size", "4M", CFG_SIZE, "64K"},
	{"hpm_plugin_ignore_errors", "false", CFG_BOOL},
	{"hpm_plugin_path", PKGLIBDIR},
	{"http_auth_times", "10", CFG_SIZE, "1"},
	{"http_conn_timeout", "3min", CFG_TIME, "30s"},
	{"http_debug", "0"},
	{"http_support_ssl", "false", CFG_BOOL},
	{"listen_port", "80"},
	{"listen_ssl_port", "0"},
	{"msrpc_debug", "0"},
	{"proc_plugin_ignore_errors", "false", CFG_BOOL},
	{"proc_plugin_path", PKGLIBDIR},
	{"request_max_mem", "4M", CFG_SIZE, "1M"},
	{"running_identity", "gromox"},
	{"service_plugin_ignore_errors", "false", CFG_BOOL},
	{"service_plugin_path", PKGLIBDIR},
	{"state_path", PKGSTATEDIR},
	{"tcp_max_segment", "0", CFG_SIZE},
	{"thread_charge_num", "20", CFG_SIZE, "4"},
	{"thread_init_num", "5", CFG_SIZE},
	{"user_default_lang", "en"},
	CFG_TABLE_END,
};

static bool http_reload_config(std::shared_ptr<CONFIG_FILE> cfg)
{
	if (cfg == nullptr)
		cfg = config_file_prg(opt_config_file, "http.cfg");
	if (opt_config_file != nullptr && cfg == nullptr) {
		printf("config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return false;
	}
	config_file_apply(*cfg, http_cfg_defaults);
	return true;
}

int main(int argc, const char **argv) try
{
	struct rlimit rl;
	char temp_buff[256];
	int retcode = EXIT_FAILURE;
	char host_name[UDOM_SIZE], *ptoken;
	const char *dns_name, *dns_domain, *netbios_name;
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv,
	    HXOPT_USAGEONERR | HXOPT_KEEP_ARGV) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;

	startup_banner("gromox-http");
	setup_sigalrm();
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
	g_config_file = config_file_prg(opt_config_file, "http.cfg");
	if (opt_config_file != nullptr && g_config_file == nullptr)
		printf("[resource]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (g_config_file == nullptr || !http_reload_config(g_config_file))
		return EXIT_FAILURE;

	auto str_val = resource_get_string("HOST_ID");
	if (str_val == NULL) {
		memset(temp_buff, 0, arsizeof(temp_buff));
		gethostname(temp_buff, arsizeof(temp_buff));
		temp_buff[arsizeof(temp_buff)-1] = '\0';
		resource_set_string("HOST_ID", temp_buff);
		str_val = temp_buff;
		printf("[system]: warning! cannot find host ID, OS host name will be "
			"used as host ID\n");
	}
	printf("[system]: host ID is %s\n", str_val);
	gx_strlcpy(host_name, str_val, GX_ARRAY_SIZE(host_name));
	dns_name = str_val;
	
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

	ptoken = strchr(host_name, '.');
	netbios_name = host_name;
	if (NULL == ptoken) {
		dns_domain = str_val; 
	} else {
		*ptoken = '\0';
		dns_domain = ptoken + 1;
	}

	unsigned int thread_charge_num = g_config_file->get_ll("thread_charge_num");
	if (thread_charge_num % 4 != 0) {
		thread_charge_num = thread_charge_num / 4 * 4;
		resource_set_integer("THREAD_CHARGE_NUM", thread_charge_num);
	}
	printf("[system]: one thread is in charge of %d contexts\n",
		thread_charge_num);

	unsigned int context_num = g_config_file->get_ll("context_num");
	unsigned int thread_init_num = g_config_file->get_ll("thread_init_num");
	if (thread_init_num * thread_charge_num > context_num) {
		thread_init_num = context_num / thread_charge_num;
		if (0 == thread_init_num) {
			thread_init_num = 1;
			context_num = thread_charge_num;
			resource_set_integer("CONTEXT_NUM", context_num);
			printf("[system]: rectify contexts number %d\n", context_num);
		}
		resource_set_integer("THREAD_INIT_NUM", thread_init_num);
	}
	printf("[system]: threads pool initial threads number is %d\n",
		thread_init_num);

	unsigned int context_aver_mem = g_config_file->get_ll("context_average_mem") / (64 * 1024);
	bytetoa(context_aver_mem*64*1024, temp_buff);
	printf("[http]: context average memory is %s\n", temp_buff);
	
	std::chrono::seconds http_conn_timeout{g_config_file->get_ll("http_conn_timeout")};
	itvltoa(http_conn_timeout.count(), temp_buff);
	printf("[http]: http socket read write time out is %s\n", temp_buff);
 
	int http_auth_times = g_config_file->get_ll("http_auth_times");
	printf("[http]: maximum authentification failure times is %d\n", 
			http_auth_times);

	int block_interval_auth = g_config_file->get_ll("block_interval_auths");
	itvltoa(block_interval_auth, temp_buff);
	printf("[http]: block client %s when authentification failure times "
			"is exceeded\n", temp_buff);
	
	auto http_support_ssl = parse_bool(g_config_file->get_value("http_support_ssl"));
	auto certificate_path = g_config_file->get_value("http_certificate_path");
	auto cb_passwd = g_config_file->get_value("http_certificate_passwd");
	auto private_key_path = g_config_file->get_value("http_private_key_path");
	if (http_support_ssl) {
		if (NULL == certificate_path || NULL == private_key_path) {
			http_support_ssl = false;
			printf("[http]: turn off TLS support because certificate or "
				"private key path is empty\n");
		} else {
			printf("[http]: http support TLS mode\n");
		}
	} else {
		printf("[http]: http doesn't support TLS mode\n");
	}

	uint16_t listen_ssl_port = g_config_file->get_ll("listen_ssl_port");
	if (!http_support_ssl && listen_ssl_port > 0)
		listen_ssl_port = 0;
	if (listen_ssl_port > 0) {
		printf("[system]: system SSL listening port %hu\n", listen_ssl_port);
	}
	
	size_t max_request_mem = g_config_file->get_ll("request_max_mem");
	bytetoa(max_request_mem, temp_buff);
	printf("[pdu_processor]: maximum request memory is %s\n", temp_buff);

	auto str_value = g_config_file->get_value("service_plugin_list");
	char **proc_plugin_list = nullptr, **hpm_plugin_list = nullptr, **service_plugin_list = nullptr;
	auto cl_0 = make_scope_exit([&]() {
		HX_zvecfree(service_plugin_list);
		HX_zvecfree(hpm_plugin_list);
		HX_zvecfree(proc_plugin_list);
	});
	if (str_value != NULL) {
		proc_plugin_list = read_file_by_line(str_value);
		if (proc_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			return EXIT_FAILURE;
		}
	}
	
	str_value = resource_get_string("HPM_PLUGIN_LIST");
	if (str_value != NULL) {
		hpm_plugin_list = read_file_by_line(str_value);
		if (hpm_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			return EXIT_FAILURE;
		}
	}
	
	uint64_t hpm_cache_size = g_config_file->get_ll("hpm_cache_size");
	bytetoa(hpm_cache_size, temp_buff);
	printf("[hpm_processor]: fastcgi cache size is %s\n", temp_buff);
	
	uint64_t hpm_max_size = g_config_file->get_ll("hpm_max_size");
	bytetoa(hpm_max_size, temp_buff);
	printf("[hpm_processor]: hpm maximum size is %s\n", temp_buff);

	str_value = resource_get_string("SERVICE_PLUGIN_LIST");
	if (str_value != NULL) {
		service_plugin_list = read_file_by_line(str_value);
		if (service_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			return EXIT_FAILURE;
		}
	}

	uint64_t fastcgi_cache_size = g_config_file->get_ll("fastcgi_cache_size");
	bytetoa(fastcgi_cache_size, temp_buff);
	printf("[mod_fastcgi]: fastcgi cache size is %s\n", temp_buff);
	
	uint64_t fastcgi_max_size = g_config_file->get_ll("fastcgi_max_size");
	bytetoa(fastcgi_max_size, temp_buff);
	printf("[mod_fastcgi]: fastcgi maximum size is %s\n", temp_buff);
	
	std::chrono::seconds fastcgi_exec_timeout{g_config_file->get_ll("fastcgi_exec_timeout")};
	itvltoa(fastcgi_exec_timeout.count(), temp_buff);
	printf("[http]: fastcgi excution time out is %s\n", temp_buff);
	uint16_t listen_port = g_config_file->get_ll("listen_port");
	unsigned int mss_size = g_config_file->get_ll("tcp_max_segment");
	listener_init(listen_port, listen_ssl_port, mss_size);
	auto cleanup_4 = make_scope_exit(listener_stop);
	if (0 != listener_run()) {
		printf("[system]: fail to start listener\n");
		return EXIT_FAILURE;
	}

	if (0 != getrlimit(RLIMIT_NOFILE, &rl)) {
		printf("[system]: fail to get file limitation\n");
		return EXIT_FAILURE;
	}
	if (rl.rlim_cur < 5*context_num + 256 ||
		rl.rlim_max < 5*context_num + 256) {
		rl.rlim_cur = 5*context_num + 256;
		rl.rlim_max = 5*context_num + 256;
		if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
			printf("[system]: fail to set file limitation\n");
		else
			printf("[system]: set file limitation to %zu\n", static_cast<size_t>(rl.rlim_cur));
	}
	service_init({g_config_file->get_value("service_plugin_path"),
		g_config_file->get_value("config_file_path"),
		g_config_file->get_value("data_file_path"),
		g_config_file->get_value("state_path"),
		service_plugin_list != NULL ? service_plugin_list : g_dfl_svc_plugins,
		parse_bool(g_config_file->get_value("service_plugin_ignore_errors")),
		context_num, "http"});
	auto cleanup_6 = make_scope_exit(service_stop);
	if (!service_register_service("ndr_stack_alloc",
	    reinterpret_cast<void *>(pdu_processor_ndr_stack_alloc),
	    typeid(*pdu_processor_ndr_stack_alloc))) {
		printf("service_register ndr_stack_alloc failed\n");
		return EXIT_FAILURE;
	}
	printf("--------------------------- service plugins begin"
		   "---------------------------\n");
	if (service_run_early() != 0) {
		printf("[system]: failed to run PLUGIN_EARLY_INIT\n");
		return EXIT_FAILURE;
	}
	auto ret = switch_user_exec(*g_config_file, argv);
	if (ret < 0)
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

	auto cleanup_8 = make_scope_exit(system_services_stop);
	if (0 != system_services_run()) { 
		printf("[system]: failed to run system service\n");
		return EXIT_FAILURE;
	}

	blocks_allocator_init(context_num * context_aver_mem);     
	auto cleanup_8b = make_scope_exit(blocks_allocator_stop);
 
	if (0 != blocks_allocator_run()) { 
		printf("[system]: can not run blocks allocator\n"); 
		return EXIT_FAILURE;
	}

	pdu_processor_init(context_num, PDU_PROCESSOR_RATIO, netbios_name,
		dns_name, dns_domain, TRUE, max_request_mem,
		g_config_file->get_value("proc_plugin_path"),
		proc_plugin_list != NULL ? proc_plugin_list : g_dfl_proc_plugins,
		parse_bool(g_config_file->get_value("proc_plugin_ignore_errors")));
	auto cleanup_12 = make_scope_exit(pdu_processor_stop);
	printf("---------------------------- proc plugins begin "
		   "----------------------------\n");
	if (0 != pdu_processor_run()) {
		printf("----------------------------- proc plugins end "
		   "-----------------------------\n");
		printf("[system]: can not run pdu processor\n");
		return EXIT_FAILURE;
	} else {
		printf("----------------------------- proc plugins end "
		   "-----------------------------\n");
	}

	hpm_processor_init(context_num, g_config_file->get_value("hpm_plugin_path"),
		hpm_plugin_list != NULL ? hpm_plugin_list : g_dfl_hpm_plugins,
		hpm_cache_size, hpm_max_size,
		parse_bool(g_config_file->get_value("hpm_plugin_ignore_errors")));
	auto cleanup_14 = make_scope_exit(hpm_processor_stop);
	printf("---------------------------- hpm plugins begin "
		   "----------------------------\n");
	if (0 != hpm_processor_run()) {
		printf("----------------------------- hpm plugins end "
		   "-----------------------------\n");
		printf("[system]: can not run hpm processor\n");
		return EXIT_FAILURE;
	} else {
		printf("----------------------------- hpm plugins end "
		   "-----------------------------\n");
	}

	if (mod_rewrite_run(resource_get_string("config_file_path")) != 0) {
		printf("[system]: failed to run mod rewrite\n");
		return EXIT_FAILURE;
	}
	mod_fastcgi_init(context_num, fastcgi_cache_size,
		fastcgi_max_size, fastcgi_exec_timeout); 
	auto cleanup_18 = make_scope_exit(mod_fastcgi_stop);
	if (0 != mod_fastcgi_run()) { 
		printf("[system]: failed to run mod fastcgi\n");
		return EXIT_FAILURE;
	}

	mod_cache_init(context_num);
	auto cleanup_20 = make_scope_exit(mod_cache_stop);
	if (0 != mod_cache_run()) {
		printf("[system]: failed to run mod cache\n");
		return EXIT_FAILURE;
	}

	http_parser_init(context_num, http_conn_timeout,
		http_auth_times, block_interval_auth, http_support_ssl ? TRUE : false,
		certificate_path, cb_passwd, private_key_path,
		g_config_file->get_ll("http_debug"));
	auto cleanup_22 = make_scope_exit(http_parser_stop);
	if (0 != http_parser_run()) { 
		printf("[system]: failed to run http parser\n");
		return EXIT_FAILURE;
	}

	contexts_pool_init(http_parser_get_contexts_list(),
		context_num,
		http_parser_get_context_socket,
		http_parser_get_context_timestamp,
		thread_charge_num, http_conn_timeout); 
	auto cleanup_24 = make_scope_exit(contexts_pool_stop);
	if (0 != contexts_pool_run()) { 
		printf("[system]: failed to run contexts pool\n");
		return EXIT_FAILURE;
	}
 
	threads_pool_init(thread_init_num, reinterpret_cast<int (*)(SCHEDULE_CONTEXT *)>(http_parser_process));
	auto cleanup_28 = make_scope_exit(threads_pool_stop);
	threads_pool_register_event_proc(http_parser_threads_event_proc);
	if (0 != threads_pool_run()) {
		printf("[system]: failed to run threads pool\n");
		return EXIT_FAILURE;
	}

	/* accept the connection */
	if (listener_trigger_accept() != 0) {
		printf("[system]: fail trigger accept\n");
		return EXIT_FAILURE;
	}
	auto cleanup_29 = make_scope_exit(listener_stop_accept);
	
	retcode = EXIT_SUCCESS;
	printf("[system]: HTTP DAEMON is now running\n");
	while (!g_notify_stop) {
		sleep(3);
		if (g_hup_signalled.exchange(false)) {
			http_reload_config(nullptr);
			service_reload_all();
			hpm_processor_reload();
			pdu_processor_reload();
		}
	}
	return retcode;
} catch (const cfg_error &) {
	return EXIT_FAILURE;
}

static void term_handler(int signo)
{
	http_parser_shutdown_async();
	g_notify_stop = true;
}
