// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <typeinfo>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/io.h>
#include <libHX/misc.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/defs.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/listener_ctx.hpp>
#include <gromox/paths.h>
#include <gromox/process.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "pop3.hpp"

using namespace gromox;

#define E(s) decltype(system_services_ ## s) system_services_ ## s;
E(judge_addr)
E(judge_user)
E(ban_user)
E(auth_login)
E(broadcast_event)
#undef E

gromox::atomic_bool g_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
static const char *opt_config_file;
static gromox::atomic_bool g_hup_signalled;
static thread_local std::unique_ptr<alloc_context> g_alloc_mgr;
static thread_local unsigned int g_amgr_refcount;
uint16_t g_listener_port, g_listener_ssl_port;
static unsigned int g_haproxy_level;

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr generic_module g_dfl_svc_plugins[] = {
	{"libgxs_event_proxy.so", SVC_event_proxy},
	{"libgxs_midb_agent.so", SVC_midb_agent},
	{"libgxs_mysql_adaptor.so", SVC_mysql_adaptor},
	{"libgromox_auth.so/ldap", SVC_ldap_adaptor},
	{"libgromox_auth.so/mgr", SVC_authmgr},
	{"libgromox_authz.so/dnsbl", SVC_dnsbl_filter},
	{"libgromox_authz.so/user", SVC_user_filter},
};

static constexpr cfg_directive gromox_cfg_defaults[] = {
	{"daemons_fd_limit", "pop3_fd_limit", CFG_ALIAS},
	{"pop3_fd_limit", "0", CFG_SIZE},
	{"pop3_accept_haproxy", "0", CFG_SIZE},
	CFG_TABLE_END,
};

static constexpr cfg_directive pop3_cfg_defaults[] = {
	{"block_interval_auths", "1min", CFG_TIME, "1s"},
	{"config_file_path", PKGSYSCONFDIR "/pop3:" PKGSYSCONFDIR},
	{"context_average_mem", "512K", CFG_SIZE, "64K"},
	{"context_average_units", "5000", CFG_SIZE, "1"},
	{"context_max_mem", "2M", CFG_SIZE},
	{"context_num", "400", CFG_SIZE, "1"},
	{"data_file_path", PKGDATADIR "/pop3:" PKGDATADIR},
	{"listen_port", "pop3_listen_port", CFG_ALIAS},
	{"listen_ssl_port", "pop3_listen_tls_port", CFG_ALIAS},
	{"pop3_auth_times", "10", CFG_SIZE, "1"},
	{"pop3_cmd_debug", "0"},
	{"pop3_conn_timeout", "3min", CFG_TIME, "1s"},
	{"pop3_force_stls", "pop3_force_tls", CFG_ALIAS},
	{"pop3_force_tls", "false", CFG_BOOL},
	{"pop3_listen_addr", "::"},
	{"pop3_listen_port", "110"},
	{"pop3_listen_tls_port", "0"},
	{"pop3_log_file", "-"},
	{"pop3_log_level", "4" /* LV_NOTICE */},
	{"pop3_support_stls", "pop3_support_tls", CFG_ALIAS},
	{"pop3_support_tls", "false", CFG_BOOL},
	{"pop3_thread_charge_num", "20", CFG_SIZE, "4"},
	{"pop3_thread_init_num", "5", CFG_SIZE},
	{"running_identity", RUNNING_IDENTITY},
	{"thread_charge_num", "pop3_thread_charge_num", CFG_ALIAS},
	{"thread_init_num", "pop3_threaD_init_num", CFG_ALIAS},
	{"tls_min_proto", "tls1.2"},
	CFG_TABLE_END,
};

static void term_handler(int signo)
{
	g_notify_stop = true;
}

static bool pop3_reload_config(std::shared_ptr<config_file> gxcfg = nullptr,
    std::shared_ptr<config_file> pconfig = nullptr)
{
	if (pconfig == nullptr)
		pconfig = config_file_prg(opt_config_file, "pop3.cfg",
		          pop3_cfg_defaults);
	if (opt_config_file != nullptr && pconfig == nullptr) {
		printf("config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return false;
	}
	if (pconfig == nullptr)
		return false;
	mlog_init("gromox-pop3", pconfig->get_value("pop3_log_file"),
		pconfig->get_ll("pop3_log_level"),
		pconfig->get_value("running_identity"));
	g_popcmd_debug = pconfig->get_ll("pop3_cmd_debug");

	if (gxcfg == nullptr)
		gxcfg = config_file_prg(opt_config_file, "gromox.cfg", gromox_cfg_defaults);
	if (opt_config_file != nullptr && gxcfg == nullptr) {
		mlog(LV_ERR, "config_file_init %s: %s", opt_config_file, strerror(errno));
		return false;
	}
	if (gxcfg == nullptr)
		return false;
	g_haproxy_level = gxcfg->get_ll("pop3_accept_haproxy");
	if (g_haproxy_level > 0)
		mlog(LV_NOTICE, "All incoming connections must be HAPROXY type %u", g_haproxy_level);
	return true;
}

static int system_services_run()
{
#define E(f, s) do { \
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(*(f)))); \
	if ((f) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "system_services", (s)); \
		return -1; \
	} \
} while (false)

	E(system_services_judge_addr, "ip_filter_judge");
	E(system_services_judge_user, "user_filter_judge");
	E(system_services_ban_user, "user_filter_ban");
	E(system_services_auth_login, "auth_login_gen");
	E(system_services_broadcast_event, "broadcast_event");
	return 0;
#undef E
}

static void system_services_stop()
{
	service_release("ip_filter_judge", "system");
	service_release("user_filter_judge", "system");
	service_release("user_filter_ban", "system");
	service_release("auth_login_gen", "system");
	service_release("broadcast_event", "system");
}

static int p3ls_thrwork(generic_connection &&conn)
{
	const bool use_tls = conn.mark == M_TLS_CONN;
	
		if (fcntl(conn.sockd, F_SETFL, O_NONBLOCK) < 0)
			mlog(LV_WARN, "W-1405: fctnl: %s", strerror(errno));
		static constexpr int flag = 1;
		if (setsockopt(conn.sockd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
			mlog(LV_WARN, "W-1339: setsockopt: %s", strerror(errno));
		auto ctx = static_cast<pop3_context *>(contexts_pool_get_context(sctx_status::free));
		/* there's no context available in contexts pool, close the connection*/
		if (ctx == nullptr) {
			/* 421 <domain> Service not available */
			size_t sl = 0;
			auto str = resource_get_pop3_code(1713, 1, &sl);
			auto str2 = resource_get_pop3_code(1713, 2, &sl);
			auto host_ID = znul(g_config_file->get_value("host_id"));
			char buff[1024];
			auto len = gx_snprintf(buff, std::size(buff), "%s%s%s",
			           str, host_ID, str2);
			if (HXio_fullwrite(conn.sockd, buff, len) < 0)
				/* ignore */;
			return 0;
		}
		ctx->type = sctx_status::constructing;
		/* pass the client ipaddr into the ipaddr filter */
		std::string reason;
		if (!system_services_judge_addr(conn.client_addr, reason)) {
			/* access denied */
			size_t sl = 0;
			auto str = resource_get_pop3_code(1712, 1, &sl);
			auto str2 = resource_get_pop3_code(1712, 2, &sl);
			char buff[1024];
			auto len = gx_snprintf(buff, std::size(buff), "%s%s%s",
			           str, conn.client_addr, str2);
			if (HXio_fullwrite(conn.sockd, buff, len) < 0)
				/* ignore */;
			mlog(LV_DEBUG, "Connection %s is denied by ipaddr filter", conn.client_addr);
			/* release the context */
			contexts_pool_insert(ctx, sctx_status::free);
			return 0;
		}

		if (!use_tls) {
			/* +OK <domain> Service ready */
			size_t sl = 0;
			auto str = resource_get_pop3_code(1711, 1, &sl);
			auto str2 = resource_get_pop3_code(1711, 2, &sl);
			auto host_ID = znul(g_config_file->get_value("host_id"));
			char buff[1024];
			auto len = gx_snprintf(buff, std::size(buff), "%s%s%s",
			           str, host_ID, str2);
			if (HXio_fullwrite(conn.sockd, buff, len) < 0)
				/* ignore */;
		}
		ctx->connection = std::move(conn);
		ctx->is_stls = use_tls;
		/*
		 * Valid the context and wake up one thread if there are some threads
		 * block on the condition variable.
		 */
		ctx->polling_mask = POLLING_READ;
		contexts_pool_insert(ctx, sctx_status::polling);

	return 0;
}

void xrpc_build_env()
{
	if (g_alloc_mgr == nullptr)
		g_alloc_mgr = std::make_unique<alloc_context>();
	++g_amgr_refcount;
}

static void xrpc_build_env1(const remote_svr &)
{
	xrpc_build_env();
}

void xrpc_free_env()
{
	if (--g_amgr_refcount == 0)
		g_alloc_mgr.reset();
}

static void *xrpc_alloc(size_t z)
{
	return g_alloc_mgr->alloc(z);
}

int main(int argc, char **argv)
{ 
	char temp_buff[256];
	HXopt6_auto_result argp;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt6(g_options_table, argc, argv, &argp,
	    HXOPT_USAGEONERR | HXOPT_ITER_OPTS) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	for (int i = 0; i < argp.nopts; ++i)
		if (argp.desc[i]->sh == 'c')
			opt_config_file = argp.oarg[i];

	startup_banner("gromox-pop3");
	setup_signal_defaults();
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
	auto gxconfig = config_file_prg(opt_config_file, "gromox.cfg", gromox_cfg_defaults);
	if (opt_config_file != nullptr && gxconfig == nullptr)
		mlog(LV_ERR, "%s: %s", opt_config_file, strerror(errno));
	if (g_config_file == nullptr || gxconfig == nullptr)
		return EXIT_FAILURE; /* e.g. permission error */
	if (!pop3_reload_config(gxconfig, g_config_file))
		return EXIT_FAILURE;
	setup_utf8_locale();

	auto str_val = g_config_file->get_value("host_id");
	if (str_val == NULL) {
		std::string hn;
		auto ret = canonical_hostname(hn);
		if (ret != 0)
			return EXIT_FAILURE;
		g_config_file->set_value("host_id", hn.c_str());
		str_val = g_config_file->get_value("host_id");
	}
	printf("[system]: host ID is %s\n", str_val);
	
	unsigned int context_num = g_config_file->get_ll("context_num");
	unsigned int thread_charge_num = g_config_file->get_ll("pop3_thread_charge_num");
	if (thread_charge_num % 4 != 0) {
		thread_charge_num = thread_charge_num / 4 * 4;
		g_config_file->set_value("pop3_thread_charge_num", std::to_string(thread_charge_num).c_str());
	}
	printf("[system]: one thread is in charge of %d contexts\n",
		thread_charge_num);

	unsigned int thread_init_num = g_config_file->get_ll("pop3_thread_init_num");
	if (thread_init_num * thread_charge_num > context_num) {
		thread_init_num = context_num / thread_charge_num;
		if (0 == thread_init_num) {
			thread_init_num = 1;
			context_num = thread_charge_num;
			g_config_file->set_value("context_num", std::to_string(context_num).c_str());
			printf("[system]: rectify contexts number %d\n", context_num);
		}
		g_config_file->set_value("pop3_thread_init_num", std::to_string(thread_init_num).c_str());
	}
	printf("[system]: threads pool initial threads number is %d\n",
		thread_init_num);

	unsigned int context_aver_mem = g_config_file->get_ll("context_average_mem") / (64 * 1024);
	HX_unit_size(temp_buff, std::size(temp_buff), context_aver_mem * 64 * 1024, 1024, 0);
	printf("[pop3]: context average memory is %s\n", temp_buff);
 
	size_t context_max_mem = g_config_file->get_ll("context_max_mem") / (64 * 1024);
	if (context_max_mem < context_aver_mem) {
		context_max_mem = context_aver_mem;
		HX_unit_size(temp_buff, std::size(temp_buff), context_max_mem * 64 * 1024, 1024, 0);
		g_config_file->set_value("context_max_mem", temp_buff);
	} 
	context_max_mem *= 64*1024;
	HX_unit_size(temp_buff, std::size(temp_buff), context_max_mem, 1024, 0);
	printf("[pop3]: context maximum memory is %s\n", temp_buff);

	unsigned int context_aver_units = g_config_file->get_ll("context_average_units");
	printf("[pop3]: context average units number is %d\n", context_aver_units);
	
	std::chrono::seconds pop3_conn_timeout(g_config_file->get_ll("pop3_conn_timeout"));
	HX_unit_seconds(temp_buff, std::size(temp_buff), pop3_conn_timeout.count(), 0);
	printf("[pop3]: pop3 socket read write timeout is %s\n", temp_buff);
 
	int pop3_auth_times = g_config_file->get_ll("pop3_auth_times");
	printf("[pop3]: maximum authentication failure times is %d\n", 
			pop3_auth_times);

	int block_interval_auth = g_config_file->get_ll("block_interval_auths");
	HX_unit_seconds(temp_buff, std::size(temp_buff), block_interval_auth, 0);
	printf("[pop3]: block client %s when authentication failure count "
			"is exceeded\n", temp_buff);

	auto pop3_support_tls = parse_bool(g_config_file->get_value("pop3_support_tls"));
	auto certificate_path = g_config_file->get_value("pop3_certificate_path");
	auto cb_passwd = g_config_file->get_value("pop3_certificate_passwd");
	auto private_key_path = g_config_file->get_value("pop3_private_key_path");
	if (pop3_support_tls) {
		if (NULL == certificate_path || NULL == private_key_path) {
			pop3_support_tls = false;
			printf("[pop3]: TLS support deactivated because certificate or "
				"private key path is empty\n");
		} else {
			printf("[pop3]: TLS support enabled\n");
		}
	} else {
		printf("[pop3]: TLS support deactivated via config\n");
	}
	
	auto pop3_force_tls = parse_bool(g_config_file->get_value("pop3_force_tls"));
	if (pop3_support_tls && pop3_force_tls)
		printf("[pop3]: pop3 MUST be running with TLS\n");
	uint16_t listen_tls_port = g_config_file->get_ll("pop3_listen_tls_port");
	if (!pop3_support_tls && listen_tls_port > 0)
		listen_tls_port = 0;
	if (listen_tls_port > 0)
		printf("[system]: system TLS listening port %d\n", listen_tls_port);

	if (resource_run() != 0) {
		printf("[system]: Failed to load resource\n");
		return EXIT_FAILURE;
	}
	auto cleanup_2 = HX::make_scope_exit(resource_stop);
	uint16_t listen_port = g_config_file->get_ll("pop3_listen_port");

	listener_ctx listener;
	auto laddr = g_config_file->get_value("pop3_listen_addr");
	if (listen_port != 0 &&
	    listener.add_inet(laddr, listen_port, M_UNENCRYPTED_CONN) != 0)
		return EXIT_FAILURE;
	if (listen_tls_port != 0 &&
	    listener.add_inet(laddr, listen_tls_port, M_TLS_CONN) != 0)
		return EXIT_FAILURE;
	listener.m_haproxy_level = g_haproxy_level;
	listener.m_thread_name   = "accept";

	filedes_limit_bump(gxconfig->get_ll("pop3_fd_limit"));
	service_init({g_config_file, g_dfl_svc_plugins, context_num});
	if (service_run_early() != 0) {
		printf("[system]: failed to run PLUGIN_EARLY_INIT\n");
		return EXIT_FAILURE;
	}
	if (switch_user_exec(*g_config_file, argv) != 0)
		return EXIT_FAILURE;
	if (0 != service_run()) { 
		printf("[system]: failed to run service\n");
		return EXIT_FAILURE;
	}
	auto cleanup_6 = HX::make_scope_exit(service_stop);
	
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	if (0 != system_services_run()) { 
		printf("[system]: failed to run system service\n");
		return EXIT_FAILURE;
	}
	auto cleanup_8 = HX::make_scope_exit(system_services_stop);
	pop3_parser_init(context_num, context_max_mem, pop3_conn_timeout,
		pop3_auth_times, block_interval_auth, pop3_support_tls,
		pop3_force_tls, certificate_path, cb_passwd,
		private_key_path);
 
	if (0 != pop3_parser_run()) { 
		printf("[system]: failed to run pop3 parser\n");
		return EXIT_FAILURE;
	}
	auto cleanup_14 = HX::make_scope_exit(pop3_parser_stop);
	
	contexts_pool_init(pop3_parser_get_contexts_list(), context_num,
		pop3_parser_get_context_socket,
		pop3_parser_get_context_timestamp,
		thread_charge_num, pop3_conn_timeout); 
 
	if (0 != contexts_pool_run()) { 
		printf("[system]: failed to run contexts pool\n");
		return EXIT_FAILURE;
	}
	auto cleanup_16 = HX::make_scope_exit(contexts_pool_stop);

	threads_pool_init(thread_init_num, pop3_parser_process);
	threads_pool_register_event_proc(pop3_parser_threads_event_proc);
	if (threads_pool_run("pop3.cfg:pop3_thread_init_num") != 0) {
		printf("[system]: failed to run threads pool\n");
		return EXIT_FAILURE;
	}
	auto cleanup_20 = HX::make_scope_exit(threads_pool_stop);

	/* accept the connection */
	auto err = listener.watch_start(g_notify_stop, p3ls_thrwork);
	if (err != 0) {
		mlog(LV_ERR, "listener.thread_start: %s", strerror(err));
		return EXIT_FAILURE;
	}
	
	exmdb_rpc_alloc = xrpc_alloc;
	exmdb_rpc_free = [](void *) {};
	exmdb_client.emplace(UINT_MAX, UINT_MAX);
	auto cl_0 = HX::make_scope_exit([]() { exmdb_client.reset(); });
	if (exmdb_client_run(g_config_file->get_value("config_file_path"),
	    EXMDB_CLIENT_ASYNC_CONNECT, xrpc_build_env1, xrpc_free_env, nullptr) != 0) {
		mlog(LV_ERR, "Failed to start exmdb_client");
		return EXIT_FAILURE;
	}

	printf("[system]: POP3 DAEMON is now running\n");
	while (!g_notify_stop) {
		sleep(3);
		if (g_hup_signalled.exchange(false)) {
			pop3_reload_config();
			service_trigger_all(PLUGIN_RELOAD);
		}
	}
	return EXIT_SUCCESS;
}
