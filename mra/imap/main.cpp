// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
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
#include <libHX/scope.hpp>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/defs.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/process.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "imap.hpp"

using namespace gromox;

#define E(s) decltype(system_services_ ## s) system_services_ ## s;
E(judge_addr)
E(judge_user)
E(ban_user)
E(auth_login)
E(install_event_stub)
E(broadcast_event)
E(broadcast_select)
E(broadcast_unselect)
#undef E

bool g_rfc9051_enable;
gromox::atomic_bool g_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static gromox::atomic_bool g_hup_signalled;
static thread_local std::unique_ptr<alloc_context> g_alloc_mgr;
static thread_local unsigned int g_amgr_refcount;
static pthread_t g_thr_id, g_ssl_thr_id;
static gromox::atomic_bool g_stop_accept;
static std::string g_listener_addr;
static int g_listener_sock = -1, g_listener_ssl_sock = -1;
static uint16_t g_listener_port;
static unsigned int g_haproxy_level;
uint16_t g_listener_ssl_port;

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr static_module g_dfl_svc_plugins[] = {
	{"libgxs_event_proxy.so", SVC_event_proxy},
	{"libgxs_event_stub.so", SVC_event_stub},
	{"libgxs_midb_agent.so", SVC_midb_agent},
	{"libgxs_mysql_adaptor.so", SVC_mysql_adaptor},
	{"libgromox_auth.so/ldap", SVC_ldap_adaptor},
	{"libgromox_auth.so/mgr", SVC_authmgr},
	{"libgromox_authz.so/dnsbl", SVC_dnsbl_filter},
	{"libgromox_authz.so/user", SVC_user_filter},
};

static constexpr cfg_directive gromox_cfg_defaults[] = {
	{"daemons_fd_limit", "imap_fd_limit", CFG_ALIAS},
	{"imap_fd_limit", "0", CFG_SIZE},
	{"imap_accept_haproxy", "0", CFG_SIZE},
	CFG_TABLE_END,
};

static constexpr cfg_directive imap_cfg_defaults[] = {
	{"block_interval_auths", "1min", CFG_TIME, "1s"},
	{"config_file_path", PKGSYSCONFDIR "/imap:" PKGSYSCONFDIR},
	{"context_average_mem", "128K", CFG_SIZE, "128K"},
	{"context_average_mitem", "64K", CFG_SIZE, "1"},
	{"context_num", "400", CFG_SIZE},
	{"data_file_path", PKGDATADIR "/imap:" PKGDATADIR},
	{"default_lang", "en"},
	{"imap_auth_times", "10", CFG_SIZE, "1"},
	{"imap_autologout_time", "30min", CFG_TIME, "1s"},
	{"imap_cmd_debug", "0"},
	{"imap_conn_timeout", "3min", CFG_TIME, "1s"},
	{"imap_force_starttls", "imap_force_tls", CFG_ALIAS},
	{"imap_force_tls", "false", CFG_BOOL},
	{"imap_listen_addr", "::"},
	{"imap_listen_port", "143"},
	{"imap_listen_tls_port", "0"},
	{"imap_log_file", "-"},
	{"imap_log_level", "4" /* LV_NOTICE */},
	{"imap_rfc9051", "1", CFG_BOOL},
	{"imap_support_starttls", "imap_support_tls", CFG_ALIAS},
	{"imap_support_tls", "false", CFG_BOOL},
	{"imap_thread_charge_num", "20", CFG_SIZE, "4"},
	{"imap_thread_init_num", "5", CFG_SIZE},
	{"listen_port", "imap_listen_port", CFG_ALIAS},
	{"listen_ssl_port", "imap_listen_tls_port", CFG_ALIAS},
	{"running_identity", RUNNING_IDENTITY},
	{"thread_charge_num", "imap_thread_charge_num", CFG_ALIAS},
	{"thread_init_num", "imap_thread_init_num", CFG_ALIAS},
	{"tls_min_proto", "tls1.2"},
	CFG_TABLE_END,
};
static void term_handler(int signo);

static bool imap_reload_config(std::shared_ptr<config_file> gxcfg = nullptr,
    std::shared_ptr<config_file> cfg = nullptr)
{
	if (cfg == nullptr)
		cfg = config_file_prg(opt_config_file, "imap.cfg", imap_cfg_defaults);
	if (opt_config_file != nullptr && cfg == nullptr) {
		fprintf(stderr, "config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return false;
	}
	mlog_init("gromox-imap", cfg->get_value("imap_log_file"),
		cfg->get_ll("imap_log_level"), cfg->get_value("running_identity"));
	g_imapcmd_debug = cfg->get_ll("imap_cmd_debug");
	g_rfc9051_enable = cfg->get_ll("imap_rfc9051");

	if (gxcfg == nullptr)
		gxcfg = config_file_prg(opt_config_file, "gromox.cfg", gromox_cfg_defaults);
	if (opt_config_file != nullptr && gxcfg == nullptr) {
		fprintf(stderr, "config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return false;
	}
	g_haproxy_level = gxcfg->get_ll("imap_accept_haproxy");
	if (g_haproxy_level > 0)
		mlog(LV_NOTICE, "All incoming connections must be HAPROXY type %u", g_haproxy_level);
	return true;
}

static int system_services_run()
{
#define E(f, s) do { \
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(decltype(*(f))))); \
	if ((f) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "system_services", (s)); \
		return -1; \
	} \
} while (false)

	E(system_services_judge_addr, "ip_filter_judge");
	E(system_services_judge_user, "user_filter_judge");
	E(system_services_ban_user, "user_filter_ban");
	E(system_services_auth_login, "auth_login_gen");
	E(system_services_install_event_stub, "install_event_stub");
	E(system_services_broadcast_event, "broadcast_event");
	E(system_services_broadcast_select, "broadcast_select");
	E(system_services_broadcast_unselect, "broadcast_unselect");
	return 0;
#undef E
}

static void system_services_stop()
{
	service_release("ip_filter_judge", "system");
	service_release("user_filter_judge", "system");
	service_release("user_filter_ban", "system");
	service_release("auth_login_gen", "system");
	service_release("install_event_stub", "system");
	service_release("broadcast_event", "system");
	service_release("broadcast_select", "system");
	service_release("broadcast_unselect", "system");
}

static void *imls_thrwork(void *arg)
{
	const bool use_tls = reinterpret_cast<uintptr_t>(arg);
	auto sv_sock = use_tls ? g_listener_ssl_sock : g_listener_sock;
	while (true) {
		auto conn = generic_connection::accept(sv_sock, g_haproxy_level, &g_stop_accept);
		if (conn.sockd == -2)
			break;
		else if (conn.sockd < 0)
			continue;
		if (fcntl(conn.sockd, F_SETFL, O_NONBLOCK) < 0)
			mlog(LV_WARN, "W-1416: fcntl: %s", strerror(errno));
		static constexpr int flag = 1;
		if (setsockopt(conn.sockd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
			mlog(LV_WARN, "W-1417: setsockopt: %s", strerror(errno));
		auto ctx = static_cast<imap_context *>(contexts_pool_get_context(sctx_status::free));
		/* there's no context available in contexts pool, close the connection*/
		if (ctx == nullptr) {
			/* IMAP_CODE_2180015: BAD Service not available */
			size_t string_length = 0;
			auto imap_reply_str = resource_get_imap_code(1815, 1, &string_length);
			if (HXio_fullwrite(conn.sockd, "* ", 2) < 0 ||
			    HXio_fullwrite(conn.sockd, imap_reply_str, string_length) < 0 ||
			    HXio_fullwrite(conn.sockd, "\r\n", 2) < 0)
				/* ignore */;
			continue;
		}
		ctx->type = sctx_status::constructing;
		/* pass the client ipaddr into the ipaddr filter */
		std::string reason;
		if (!system_services_judge_addr(conn.client_addr, reason)) {
			/* IMAP_CODE_2180016: BAD access is denied from your IP address <remote_ip> */
			auto imap_reply_str = resource_get_imap_code(1816, 1);
			auto imap_reply_str2 = resource_get_imap_code(1816, 2);
			char buff[1024];
			auto len = snprintf(buff, std::size(buff), "* %s%s%s",
			           imap_reply_str, conn.client_addr, imap_reply_str2);
			if (HXio_fullwrite(conn.sockd, buff, len) != len)
				/* ignore */;
			mlog(LV_DEBUG, "Connection %s is denied by ipaddr filter: %s",
				conn.client_addr, reason.c_str());
			/* release the context */
			contexts_pool_insert(ctx, sctx_status::free);
			continue;
		}
		if (!use_tls) {
			char caps[128];
			capability_list(caps, std::size(caps), ctx);
			if (HXio_fullwrite(conn.sockd, "* OK [CAPABILITY ", 17) < 0 ||
			    HXio_fullwrite(conn.sockd, caps, strlen(caps)) < 0 ||
			    HXio_fullwrite(conn.sockd, "] Service ready\r\n", 17) < 0)
				/* ignore - error will be on next write (again) */;
		}
		ctx->connection = std::move(conn);
		ctx->sched_stat = use_tls ? isched_stat::stls : isched_stat::rdcmd;
		/*
		 * Validate the context and wake up one thread if there are
		 * some threads block on the condition variable.
		 */
		ctx->polling_mask = POLLING_READ;
		contexts_pool_insert(ctx, sctx_status::polling);
	}
	return nullptr;
}

static void listener_init(const char *addr, uint16_t port, uint16_t ssl_port)
{
	g_listener_addr = addr;
	g_listener_port = port;
	g_listener_ssl_port = ssl_port;
	g_stop_accept = false;
}

static int listener_run()
{
	g_listener_sock = HX_inet_listen(g_listener_addr.c_str(), g_listener_port);
	if (g_listener_sock < 0) {
		printf("[listener]: failed to create socket [*]:%hu: %s\n",
		       g_listener_port, strerror(-g_listener_sock));
		return -1;
	}
	gx_reexec_record(g_listener_sock);
	if (g_listener_ssl_port > 0) {
		g_listener_ssl_sock = HX_inet_listen(g_listener_addr.c_str(), g_listener_ssl_port);
		if (g_listener_ssl_sock < 0) {
			printf("[listener]: failed to create socket [*]:%hu: %s\n",
			       g_listener_ssl_port, strerror(-g_listener_ssl_sock));
			return -1;
		}
		gx_reexec_record(g_listener_ssl_sock);
	}
	return 0;
}

static int listener_trigger_accept()
{
	auto ret = pthread_create4(&g_thr_id, nullptr, imls_thrwork,
	           reinterpret_cast<void *>(uintptr_t(false)));
	if (ret != 0) {
		printf("[listener]: failed to create listener thread: %s\n", strerror(ret));
		return -1;
	}
	pthread_setname_np(g_thr_id, "accept");
	if (g_listener_ssl_port > 0) {
		ret = pthread_create4(&g_ssl_thr_id, nullptr, imls_thrwork,
		      reinterpret_cast<void *>(uintptr_t(true)));
		if (ret != 0) {
			printf("[listener]: failed to create listener thread: %s\n", strerror(ret));
			return -2;
		}
		pthread_setname_np(g_ssl_thr_id, "tls_accept");
	}
	return 0;
}

static void listener_stop_accept()
{
	g_stop_accept = true;
	if (g_listener_sock >= 0)
		shutdown(g_listener_sock, SHUT_RDWR); /* closed in listener_stop */
	if (!pthread_equal(g_thr_id, {})) {
		pthread_kill(g_thr_id, SIGALRM);
		pthread_join(g_thr_id, nullptr);
	}
	if (g_listener_ssl_sock >= 0)
		shutdown(g_listener_ssl_sock, SHUT_RDWR);
	if (!pthread_equal(g_ssl_thr_id, {})) {
		pthread_kill(g_ssl_thr_id, SIGALRM);
		pthread_join(g_ssl_thr_id, nullptr);
	}
}

char *capability_list(char *dst, size_t z, imap_context *ctx)
{
	gx_strlcpy(dst, "IMAP4rev1 XLIST SPECIAL-USE UNSELECT UIDPLUS IDLE AUTH=LOGIN LITERAL+ LITERAL-", z);
	bool offer_tls = g_support_tls;
	if (ctx != nullptr) {
		if (ctx->connection.ssl != nullptr || ctx->is_authed())
			offer_tls = false;
	}
	if (offer_tls)
		HX_strlcat(dst, " STARTTLS", z);
	if (parse_bool(g_config_file->get_value("enable_rfc2971_commands")))
		HX_strlcat(dst, " ID", z);
	return dst;
}

static void listener_stop()
{
	if (g_listener_sock >= 0) {
		close(g_listener_sock);
		g_listener_sock = -1;
	}
	if (g_listener_ssl_sock >= 0) {
		close(g_listener_ssl_sock);
		g_listener_ssl_sock = -1;
	}
}

void imrpc_build_env()
{
	if (g_alloc_mgr == nullptr)
		g_alloc_mgr = std::make_unique<alloc_context>();
	++g_amgr_refcount;
}

static void imrpc_build_env1(const remote_svr &)
{
	imrpc_build_env();
}

void imrpc_free_env()
{
	if (--g_amgr_refcount == 0)
		g_alloc_mgr.reset();
}

static void *imrpc_alloc(size_t z)
{
	return g_alloc_mgr->alloc(z);
}

int main(int argc, char **argv)
{ 
	int retcode = EXIT_FAILURE;
	char temp_buff[256];

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt5(g_options_table, argv, nullptr, nullptr,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;

	startup_banner("gromox-imap");
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
	g_config_file = config_file_prg(opt_config_file, "imap.cfg",
	                imap_cfg_defaults);
	if (opt_config_file != nullptr && g_config_file == nullptr)
		printf("[resource]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (g_config_file == nullptr)
		return EXIT_FAILURE;
	auto gxconfig = config_file_prg(opt_config_file, "gromox.cfg", gromox_cfg_defaults);
	if (opt_config_file != nullptr && gxconfig == nullptr)
		mlog(LV_ERR, "%s: %s", opt_config_file, strerror(errno));
	if (!imap_reload_config(gxconfig, g_config_file))
		return EXIT_FAILURE;

	uint16_t listen_port = g_config_file->get_ll("imap_listen_port");
	uint16_t listen_tls_port = g_config_file->get_ll("imap_listen_tls_port");
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
	unsigned int thread_charge_num = g_config_file->get_ll("imap_thread_charge_num");
	if (thread_charge_num % 4 != 0) {
		thread_charge_num = thread_charge_num / 4 * 4;
		g_config_file->set_value("imap_thread_charge_num", std::to_string(thread_charge_num).c_str());
	}
	printf("[system]: one thread is in charge of %d contexts\n",
		thread_charge_num);
	
	unsigned int thread_init_num = g_config_file->get_ll("imap_thread_init_num");
	if (thread_init_num * thread_charge_num > context_num) {
		thread_init_num = context_num / thread_charge_num;
		if (0 == thread_init_num) {
			thread_init_num = 1;
			context_num = thread_charge_num;
			g_config_file->set_value("context_num", std::to_string(context_num).c_str());
			printf("[system]: rectify contexts number %d\n", context_num);
		}
		g_config_file->set_value("imap_thread_init_num", std::to_string(thread_init_num).c_str());
	}
	printf("[system]: threads pool initial threads number is %d\n",
		thread_init_num);

	unsigned int context_aver_mem = g_config_file->get_ll("context_average_mem") / (64 * 1024);
	HX_unit_size(temp_buff, std::size(temp_buff), context_aver_mem * 64 * 1024, 1024, 0);
	printf("[imap]: context average memory is %s\n", temp_buff);
 
	unsigned int context_aver_mitem = g_config_file->get_ll("context_average_mitem");
	printf("[imap]: context average mitem number is %d\n", context_aver_mitem);
	
	std::chrono::seconds imap_conn_timeout(g_config_file->get_ll("imap_conn_timeout"));
	HX_unit_seconds(temp_buff, std::size(temp_buff), imap_conn_timeout.count(), 0);
	printf("[imap]: imap socket read write timeout is %s\n", temp_buff);
 
	std::chrono::seconds autologout_time(g_config_file->get_ll("imap_autologout_time"));
	HX_unit_seconds(temp_buff, std::size(temp_buff), autologout_time.count(), 0);
	printf("[imap]: imap session autologout time is %s\n", temp_buff);
 
	int imap_auth_times = g_config_file->get_ll("imap_auth_times");
	printf("[imap]: maximum authentication failure times is %d\n", 
			imap_auth_times);

	int block_interval_auth = g_config_file->get_ll("block_interval_auths");
	HX_unit_seconds(temp_buff, std::size(temp_buff), block_interval_auth, 0);
	printf("[imap]: block client %s when authentication failure count "
			"is exceeded\n", temp_buff);

	auto imap_support_tls = parse_bool(g_config_file->get_value("imap_support_tls"));
	auto certificate_path = g_config_file->get_value("imap_certificate_path");
	auto cb_passwd = g_config_file->get_value("imap_certificate_passwd");
	auto private_key_path = g_config_file->get_value("imap_private_key_path");
	if (imap_support_tls) {
		if (NULL == certificate_path || NULL == private_key_path) {
			imap_support_tls = false;
			printf("[imap]: TLS support deactivated because certificate or "
				"private key path is empty\n");
		} else {
			printf("[imap]: TLS support enabled\n");
		}
	} else {
		printf("[imap]: TLS support deactivated via config\n");
	}
	
	auto imap_force_tls = parse_bool(g_config_file->get_value("imap_force_tls"));
	if (imap_support_tls && imap_force_tls)
		printf("[imap]: imap MUST be running with TLS\n");
	if (!imap_support_tls && listen_tls_port > 0)
		listen_tls_port = 0;
	if (listen_tls_port > 0)
		printf("[system]: system TLS listening port %d\n", listen_tls_port);

	if (resource_run() != 0) {
		printf("[system]: Failed to load resource\n");
		return EXIT_FAILURE;
	}
	auto cleanup_2 = HX::make_scope_exit(resource_stop);
	listener_init(g_config_file->get_value("imap_listen_addr"),
		listen_port, listen_tls_port);
	if (0 != listener_run()) {
		printf("[system]: fail to start listener\n");
		return EXIT_FAILURE;
	}
	auto cleanup_4 = HX::make_scope_exit(listener_stop);

	filedes_limit_bump(gxconfig->get_ll("imap_fd_limit"));
	service_init({g_config_file, g_dfl_svc_plugins, context_num});
	if (service_run_early() != 0) {
		printf("[system]: failed to run PLUGIN_EARLY_INIT\n");
		return EXIT_FAILURE;
	}
	if (switch_user_exec(*g_config_file, argv) != 0)
		return EXIT_FAILURE;
	textmaps_init();
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
	imap_parser_init(context_num, context_aver_mitem,
		imap_conn_timeout, autologout_time, imap_auth_times,
		block_interval_auth, imap_support_tls, imap_force_tls,
		certificate_path, cb_passwd, private_key_path);  
 
	if (0 != imap_parser_run()) { 
		printf("[system]: failed to run imap parser\n");
		return EXIT_FAILURE;
	}
	auto cleanup_12 = HX::make_scope_exit(imap_parser_stop);
	
	contexts_pool_init(imap_parser_get_contexts_list(),  
		context_num,
		imap_parser_get_context_socket,
		imap_parser_get_context_timestamp,
		thread_charge_num, imap_conn_timeout); 
 
	if (0 != contexts_pool_run()) { 
		printf("[system]: failed to run contexts pool\n");
		return EXIT_FAILURE;
	}
	auto cleanup_14 = HX::make_scope_exit(contexts_pool_stop);

	exmdb_rpc_alloc = imrpc_alloc;
	exmdb_rpc_free = [](void *) {};
	exmdb_client.emplace(UINT_MAX, UINT_MAX);
	auto cl_0 = HX::make_scope_exit([]() { exmdb_client.reset(); });
	if (exmdb_client_run(g_config_file->get_value("config_file_path"),
	    EXMDB_CLIENT_ASYNC_CONNECT, imrpc_build_env1, imrpc_free_env, nullptr) != 0) {
		mlog(LV_ERR, "Failed to start exmdb_client");
		return EXIT_FAILURE;
	}

	threads_pool_init(thread_init_num, imap_parser_process);
	threads_pool_register_event_proc(imap_parser_threads_event_proc);
	if (threads_pool_run("imap.cfg:imap_thread_init_num") != 0) {
		printf("[system]: failed to run threads pool\n");
		return EXIT_FAILURE;
	}
	auto cleanup_18 = HX::make_scope_exit(threads_pool_stop);

	/* accept the connection */
	if (listener_trigger_accept() != 0) {
		printf("[system]: fail trigger accept\n");
		return EXIT_FAILURE;
	}
	
	retcode = EXIT_SUCCESS;
	printf("[system]: IMAP DAEMON is now running\n");
	while (!g_notify_stop) {
		sleep(3);
		if (g_hup_signalled.exchange(false)) {
			imap_reload_config();
			service_trigger_all(PLUGIN_RELOAD);
		}
	}
	listener_stop_accept();
	return retcode;
}

static void term_handler(int signo)
{
	g_notify_stop = true;
}
