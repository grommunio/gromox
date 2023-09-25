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
#include <string>
#include <typeinfo>
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
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/oxcmail.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "hpm_processor.h"
#include "http_parser.h"
#include "listener.h"
#include "mod_cache.hpp"
#include "mod_fastcgi.h"
#include "mod_rewrite.h"
#include "pdu_processor.h"
#include "resource.h"
#include "system_services.hpp"

using namespace gromox;

gromox::atomic_bool g_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static gromox::atomic_bool g_hup_signalled, g_usr_signalled;

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static std::vector<std::string> g_dfl_hpm_plugins = {
	"libgxh_ews.so",
	"libgxh_mh_emsmdb.so",
	"libgxh_mh_nsp.so",
	"libgxh_oxdisco.so",
	"libgxh_oab.so",
};
static std::vector<std::string> g_dfl_proc_plugins = {
	"libgxp_exchange_emsmdb.so",
	"libgxp_exchange_nsp.so",
	"libgxp_exchange_rfr.so",
};
static std::vector<std::string> g_dfl_svc_plugins = {
	"libgxs_dnsbl_filter.so",
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_authmgr.so",
	"libgxs_timer_agent.so",
	"libgxs_user_filter.so",
	"libgxs_exmdb_provider.so",
};

static void term_handler(int signo);

static constexpr cfg_directive http_cfg_defaults[] = {
	{"block_interval_auths", "1min", CFG_TIME, "1s"},
	{"config_file_path", PKGSYSCONFDIR "/http:" PKGSYSCONFDIR},
	{"context_average_mem", "256K", CFG_SIZE, "192K"},
	{"context_num", "400", CFG_SIZE},
	{"data_file_path", PKGDATADIR "/http:" PKGDATADIR},
	{"fastcgi_exec_timeout", "10min", CFG_TIME, "1min"},
	{"http_auth_times", "10", CFG_SIZE, "1"},
	{"http_conn_timeout", "3min", CFG_TIME, "30s"},
	{"http_debug", "0"},
	{"http_listen_addr", "::"},
	{"http_listen_port", "80"},
	{"http_listen_tls_port", "0"},
	{"http_log_file", "-"},
	{"http_log_level", "4" /* LV_NOTICE */},
	{"http_old_php_handler", "0", CFG_BOOL},
	{"http_rqbody_flush_size", "512K", CFG_SIZE, "0"},
	{"http_rqbody_max_size", "4M", CFG_SIZE, "1"},
	{"http_support_ssl", "http_support_tls", CFG_ALIAS},
	{"http_support_tls", "false", CFG_BOOL},
	{"http_thread_charge_num", "20", CFG_SIZE, "4"},
	{"http_thread_init_num", "5", CFG_SIZE},
	{"listen_port", "http_listen_port", CFG_ALIAS},
	{"listen_ssl_port", "http_listen_tls_port", CFG_ALIAS},
	{"msrpc_debug", "0"},
	{"oxcical_allday_ymd", "1", CFG_BOOL},
	{"request_max_mem", "4M", CFG_SIZE, "1M"},
	{"running_identity", RUNNING_IDENTITY},
	{"state_path", PKGSTATEDIR},
	{"tcp_max_segment", "0", CFG_SIZE},
	{"thread_charge_num", "http_thread_charge_num", CFG_ALIAS},
	{"thread_init_num", "http_thread_init_num", CFG_ALIAS},
	{"tls_min_proto", "tls1.2"},
	{"user_default_lang", "en"},
	CFG_TABLE_END,
};

static bool http_reload_config(std::shared_ptr<CONFIG_FILE> cfg)
{
	if (cfg == nullptr)
		cfg = config_file_prg(opt_config_file, "http.cfg", http_cfg_defaults);
	if (opt_config_file != nullptr && cfg == nullptr) {
		mlog(LV_ERR, "config_file_init %s: %s", opt_config_file, strerror(errno));
		return false;
	}
	mlog_init(cfg->get_value("http_log_file"), cfg->get_ll("http_log_level"));
	g_http_debug = cfg->get_ll("http_debug");
	g_msrpc_debug = cfg->get_ll("msrpc_debug");
	g_oxcical_allday_ymd = cfg->get_ll("oxcical_allday_ymd");
	g_http_php = cfg->get_ll("http_old_php_handler");
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
	sact.sa_handler = [](int) { g_usr_signalled = true; };
	sigaction(SIGUSR1, &sact, nullptr);
	sact.sa_handler = [](int) { g_hup_signalled = true; };
	sigaction(SIGHUP, &sact, nullptr);
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESETHAND;
	sigaction(SIGINT, &sact, nullptr);
	sigaction(SIGTERM, &sact, nullptr);
	sact.sa_handler = SIG_IGN;
	sact.sa_flags   = SA_RESTART;
	sigaction(SIGPIPE, &sact, nullptr);
	g_config_file = config_file_prg(opt_config_file, "http.cfg", http_cfg_defaults);
	if (opt_config_file != nullptr && g_config_file == nullptr)
		mlog(LV_ERR, "resource: config_file_init %s: %s",
			opt_config_file, strerror(errno));
	if (g_config_file == nullptr || !http_reload_config(g_config_file))
		return EXIT_FAILURE;

	auto str_val = g_config_file->get_value("host_id");
	if (str_val == NULL) {
		memset(temp_buff, 0, std::size(temp_buff));
		gethostname(temp_buff, std::size(temp_buff));
		temp_buff[std::size(temp_buff)-1] = '\0';
		g_config_file->set_value("host_id", temp_buff);
		str_val = temp_buff;
		if (strchr(str_val, '.') == nullptr)
			mlog(LV_NOTICE, "System hostname \"%s\" has no dot, which may point to a misconfiguration", str_val);
	}
	mlog(LV_INFO, "system: host ID is \"%s\"", str_val);
	gx_strlcpy(host_name, str_val, std::size(host_name));
	dns_name = str_val;
	
	str_val = g_config_file->get_value("default_domain");
	if (str_val == NULL) {
		memset(temp_buff, 0, std::size(temp_buff));
		if (getdomainname(temp_buff, std::size(temp_buff)) < 0)
			*temp_buff = '\0';
		g_config_file->set_value("default_domain", temp_buff);
		str_val = temp_buff;
		mlog(LV_WARN, "system: No domain name set. "
			"OS domain name will be used as default domain.");
	}
	mlog(LV_NOTICE, "system: default domain is \"%s\"", str_val);

	ptoken = strchr(host_name, '.');
	netbios_name = host_name;
	if (NULL == ptoken) {
		dns_domain = str_val; 
	} else {
		*ptoken = '\0';
		dns_domain = ptoken + 1;
	}

	unsigned int thread_charge_num = g_config_file->get_ll("http_thread_charge_num");
	if (thread_charge_num % 4 != 0) {
		thread_charge_num = thread_charge_num / 4 * 4;
		g_config_file->set_int("http_thread_charge_num", thread_charge_num);
	}
	mlog(LV_INFO, "system: one thread is in charge of %d contexts",
		thread_charge_num);

	unsigned int context_num = g_config_file->get_ll("context_num");
	unsigned int thread_init_num = g_config_file->get_ll("http_thread_init_num");
	if (thread_init_num * thread_charge_num > context_num) {
		thread_init_num = context_num / thread_charge_num;
		if (0 == thread_init_num) {
			thread_init_num = 1;
			context_num = thread_charge_num;
			g_config_file->set_int("context_num", context_num);
			mlog(LV_NOTICE, "system: rectified contexts number to %d", context_num);
		}
		g_config_file->set_int("http_thread_init_num", thread_init_num);
	}
	mlog(LV_INFO, "system: threads pool initial threads number is %d",
		thread_init_num);

	unsigned int context_aver_mem = g_config_file->get_ll("context_average_mem") / (64 * 1024);
	HX_unit_size(temp_buff, std::size(temp_buff), context_aver_mem * 64 * 1024, 1024, 0);
	mlog(LV_INFO, "http: context average memory is %s", temp_buff);
	
	std::chrono::seconds http_conn_timeout{g_config_file->get_ll("http_conn_timeout")};
	HX_unit_seconds(temp_buff, std::size(temp_buff), http_conn_timeout.count(), 0);
	mlog(LV_INFO, "http: http socket read write timeout is %s", temp_buff);
 
	int http_auth_times = g_config_file->get_ll("http_auth_times");
	mlog(LV_INFO, "http: maximum authentication failure count is %d",
			http_auth_times);

	int block_interval_auth = g_config_file->get_ll("block_interval_auths");
	HX_unit_seconds(temp_buff, std::size(temp_buff), block_interval_auth, 0);
	mlog(LV_INFO, "http: blocking clients for %s when authentication "
		"failure count is exceeded", temp_buff);
	
	auto http_support_tls = parse_bool(g_config_file->get_value("http_support_tls"));
	auto certificate_path = g_config_file->get_value("http_certificate_path");
	auto cb_passwd = g_config_file->get_value("http_certificate_passwd");
	auto private_key_path = g_config_file->get_value("http_private_key_path");
	if (http_support_tls) {
		if (NULL == certificate_path || NULL == private_key_path) {
			http_support_tls = false;
			mlog(LV_NOTICE, "http: TLS support deactivated because certificate or "
				"private key path is empty");
		} else {
			mlog(LV_INFO, "http: TLS support enabled");
		}
	} else {
		mlog(LV_NOTICE, "http: TLS support deactivated via config");
	}

	uint16_t listen_tls_port = g_config_file->get_ll("http_listen_tls_port");
	if (!http_support_tls && listen_tls_port > 0)
		listen_tls_port = 0;
	if (listen_tls_port > 0)
		mlog(LV_NOTICE, "system: system TLS listening port %hu", listen_tls_port);
	
	size_t max_request_mem = g_config_file->get_ll("request_max_mem");
	HX_unit_size(temp_buff, std::size(temp_buff), max_request_mem, 1024, 0);
	mlog(LV_INFO, "pdu_processor: maximum request memory is %s", temp_buff);

	uint64_t val = g_config_file->get_ll("http_rqbody_flush_size");
	HX_unit_size(temp_buff, std::size(temp_buff), val, 1024, 0);
	mlog(LV_INFO, "http: request bodies to disk when exceeding %s", temp_buff);
	g_rqbody_flush_size = val;
	
	val = g_config_file->get_ll("http_rqbody_max_size");
	HX_unit_size(temp_buff, std::size(temp_buff), val, 1024, 0);
	mlog(LV_INFO, "hpm_processor: HPM maximum size is %s", temp_buff);
	g_rqbody_max_size = val;

	std::chrono::seconds fastcgi_exec_timeout{g_config_file->get_ll("fastcgi_exec_timeout")};
	HX_unit_seconds(temp_buff, std::size(temp_buff), fastcgi_exec_timeout.count(), 0);
	mlog(LV_INFO, "http: fastcgi execution timeout is %s", temp_buff);
	uint16_t listen_port = g_config_file->get_ll("http_listen_port");
	unsigned int mss_size = g_config_file->get_ll("tcp_max_segment");
	listener_init(g_config_file->get_value("http_listen_addr"),
		listen_port, listen_tls_port, mss_size);
	auto cleanup_4 = make_scope_exit(listener_stop);
	if (0 != listener_run()) {
		mlog(LV_ERR, "system: failed to start listener");
		return EXIT_FAILURE;
	}

	if (0 != getrlimit(RLIMIT_NOFILE, &rl)) {
		mlog(LV_ERR, "getrlimit: %s", strerror(errno));
		return EXIT_FAILURE;
	}
	if (rl.rlim_cur < 5*context_num + 256 ||
		rl.rlim_max < 5*context_num + 256) {
		rl.rlim_cur = 5*context_num + 256;
		rl.rlim_max = 5*context_num + 256;
		if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
			mlog(LV_WARN, "setrlimit RLIMIT_NFILE %zu: %s",
				static_cast<size_t>(rl.rlim_max), strerror(errno));
		else
			mlog(LV_NOTICE, "system: FD limit set to %zu",
				static_cast<size_t>(rl.rlim_cur));
	}
	service_init({g_config_file->get_value("config_file_path"),
		g_config_file->get_value("data_file_path"),
		g_config_file->get_value("state_path"),
		std::move(g_dfl_svc_plugins), context_num, "http"});
	auto cleanup_6 = make_scope_exit(service_stop);
	if (!service_register_service("ndr_stack_alloc",
	    reinterpret_cast<void *>(pdu_processor_ndr_stack_alloc),
	    typeid(*pdu_processor_ndr_stack_alloc))) {
		mlog(LV_ERR, "service_register ndr_stack_alloc failed");
		return EXIT_FAILURE;
	}
	if (service_run_early() != 0) {
		mlog(LV_ERR, "system: failed to run PLUGIN_EARLY_INIT");
		return EXIT_FAILURE;
	}
	if (switch_user_exec(*g_config_file, argv) != 0)
		return EXIT_FAILURE;
	if (0 != service_run()) { 
		mlog(LV_ERR, "system: failed to run services");
		return EXIT_FAILURE;
	}

	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	textmaps_init();
	auto cleanup_8 = make_scope_exit(system_services_stop);
	if (0 != system_services_run()) { 
		mlog(LV_ERR, "system: failed to run system services");
		return EXIT_FAILURE;
	}

	g_blocks_allocator = alloc_limiter<stream_block>(context_num * context_aver_mem,
	                     "http_blocks_allocator",
	                     "http.cfg:context_num,context_average_mem");
	pdu_processor_init(context_num, netbios_name,
		dns_name, dns_domain, TRUE, max_request_mem,
		std::move(g_dfl_proc_plugins));
	auto cleanup_12 = make_scope_exit(pdu_processor_stop);
	if (0 != pdu_processor_run()) {
		mlog(LV_ERR, "system: could not start PDU processor");
		return EXIT_FAILURE;
	}

	hpm_processor_init(context_num, std::move(g_dfl_hpm_plugins));
	auto cleanup_14 = make_scope_exit(hpm_processor_stop);
	if (0 != hpm_processor_run()) {
		mlog(LV_ERR, "system: could not start HPM processor");
		return EXIT_FAILURE;
	}

	if (mod_rewrite_run(g_config_file->get_value("config_file_path")) != 0) {
		mlog(LV_ERR, "system: failed to start mod_rewrite");
		return EXIT_FAILURE;
	}
	mod_fastcgi_init(context_num, fastcgi_exec_timeout); 
	auto cleanup_18 = make_scope_exit(mod_fastcgi_stop);
	if (0 != mod_fastcgi_run()) { 
		mlog(LV_ERR, "system: failed to start mod_fastcgi");
		return EXIT_FAILURE;
	}

	mod_cache_init(context_num);
	auto cleanup_20 = make_scope_exit(mod_cache_stop);
	if (0 != mod_cache_run()) {
		mlog(LV_ERR, "system: failed to start mod_cache");
		return EXIT_FAILURE;
	}

	http_parser_init(context_num, http_conn_timeout,
		http_auth_times, block_interval_auth, http_support_tls,
		certificate_path, cb_passwd, private_key_path);
	auto cleanup_22 = make_scope_exit(http_parser_stop);
	if (0 != http_parser_run()) { 
		mlog(LV_ERR, "system: failed to start HTTP parser");
		return EXIT_FAILURE;
	}

	contexts_pool_init(http_parser_get_contexts_list(),
		context_num,
		http_parser_get_context_socket,
		http_parser_get_context_timestamp,
		thread_charge_num, http_conn_timeout); 
	auto cleanup_24 = make_scope_exit(contexts_pool_stop);
	if (0 != contexts_pool_run()) { 
		mlog(LV_ERR, "system: failed to start context_pool");
		return EXIT_FAILURE;
	}
 
	threads_pool_init(thread_init_num, http_parser_process);
	auto cleanup_28 = make_scope_exit(threads_pool_stop);
	threads_pool_register_event_proc(http_parser_threads_event_proc);
	if (threads_pool_run("http.cfg:http_thread_init_num") != 0) {
		mlog(LV_ERR, "system: failed to start thread pool");
		return EXIT_FAILURE;
	}

	/* accept the connection */
	if (listener_trigger_accept() != 0) {
		mlog(LV_ERR, "system: failed listening socket setup");
		return EXIT_FAILURE;
	}
	auto cleanup_29 = make_scope_exit(listener_stop_accept);
	
	retcode = EXIT_SUCCESS;
	mlog(LV_NOTICE, "system: HTTP daemon is now running");
	while (!g_notify_stop) {
		sleep(3);
		if (g_hup_signalled.exchange(false)) {
			http_reload_config(nullptr);
			service_trigger_all(PLUGIN_RELOAD);
			hpm_processor_trigger(PLUGIN_RELOAD);
			pdu_processor_trigger(PLUGIN_RELOAD);
		}
		if (g_usr_signalled.exchange(false)) {
			extern void http_report();
			http_report();
			service_trigger_all(PLUGIN_REPORT);
			hpm_processor_trigger(PLUGIN_REPORT);
			pdu_processor_trigger(PLUGIN_REPORT);
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
