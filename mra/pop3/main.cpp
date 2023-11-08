// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
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
#include <libHX/socket.h>
#include <libHX/string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/resource.h>
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
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "pop3.hpp"

using namespace gromox;

#define E(s) decltype(system_services_ ## s) system_services_ ## s;
E(judge_ip)
E(judge_user)
E(add_user_into_temp_list)
E(auth_login)
E(auth_meta)
E(list_mail)
E(delete_mail)
E(broadcast_event)
#undef E

gromox::atomic_bool g_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static gromox::atomic_bool g_hup_signalled;
static thread_local std::unique_ptr<alloc_context> g_alloc_mgr;
static thread_local unsigned int g_amgr_refcount;
static pthread_t g_thr_id;
static gromox::atomic_bool g_stop_accept;
static std::string g_listener_addr;
static int g_listener_sock = -1, g_listener_ssl_sock = -1;
uint16_t g_listener_port, g_listener_ssl_port;
static pthread_t g_ssl_thr_id;

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static std::vector<std::string> g_dfl_svc_plugins = {
	"libgxs_dnsbl_filter.so",
	"libgxs_event_proxy.so",
	"libgxs_midb_agent.so",
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_authmgr.so",
	"libgxs_user_filter.so",
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
	{"pop3_force_stls", "pop3_force_stls", CFG_ALIAS},
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
	mlog_init(pconfig->get_value("pop3_log_file"), pconfig->get_ll("pop3_log_level"));
	g_popcmd_debug = pconfig->get_ll("pop3_cmd_debug");
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
#define E2(f, s) \
	((f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(*(f)))))

	E2(system_services_judge_ip, "ip_filter_judge");
	E2(system_services_judge_user, "user_filter_judge");
	E2(system_services_add_user_into_temp_list, "user_filter_add");
	E(system_services_auth_login, "auth_login_gen");
	E(system_services_auth_meta, "mysql_auth_meta");
	E(system_services_list_mail, "list_mail");
	E(system_services_delete_mail, "delete_mail");
	E2(system_services_broadcast_event, "broadcast_event");
	return 0;
#undef E
#undef E2
}

static void system_services_stop()
{
	service_release("ip_filter_judge", "system");
	service_release("user_filter_judge", "system");
	service_release("user_filter_add", "system");
	service_release("mysql_auth_meta", "system");
	service_release("auth_login_gen", "system");
	service_release("list_mail", "system");
	service_release("delete_mail", "system");
	service_release("broadcast_event", "system");
}

static void *p3ls_thrwork(void *arg)
{
	const bool use_tls = reinterpret_cast<uintptr_t>(arg);
	
	while (true) {
		struct sockaddr_storage fact_addr, client_peer;
		socklen_t addrlen = sizeof(client_peer);
		char client_hostip[40], client_txtport[8], server_hostip[40];
		/* wait for an incoming connection */
		auto sockd2 = accept4(use_tls ? g_listener_ssl_sock : g_listener_sock,
		              reinterpret_cast<struct sockaddr *>(&client_peer),
		              &addrlen, SOCK_CLOEXEC);
		if (g_stop_accept) {
			if (sockd2 >= 0)
				close(sockd2);
			return nullptr;
		}
		if (sockd2 == -1)
			continue;
		int ret = getnameinfo(reinterpret_cast<sockaddr *>(&client_peer),
		          addrlen, client_hostip, sizeof(client_hostip),
		          client_txtport, sizeof(client_txtport),
		          NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			printf("getnameinfo: %s\n", gai_strerror(ret));
			close(sockd2);
			continue;
		}
		addrlen = sizeof(fact_addr); 
		ret = getsockname(sockd2, reinterpret_cast<sockaddr *>(&fact_addr), &addrlen);
		if (ret != 0) {
			printf("getsockname: %s\n", strerror(errno));
			close(sockd2);
			continue;
		}
		ret = getnameinfo(reinterpret_cast<sockaddr *>(&fact_addr),
		      addrlen, server_hostip, sizeof(server_hostip),
		      nullptr, 0, NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			printf("getnameinfo: %s\n", gai_strerror(ret));
			close(sockd2);
			continue;
		}
		uint16_t client_port = strtoul(client_txtport, nullptr, 0);
		if (fcntl(sockd2, F_SETFL, O_NONBLOCK) < 0)
			mlog(LV_WARN, "W-1405: fctnl: %s", strerror(errno));
		static constexpr int flag = 1;
		if (setsockopt(sockd2, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
			mlog(LV_WARN, "W-1339: setsockopt: %s", strerror(errno));
		auto ctx = static_cast<POP3_CONTEXT *>(contexts_pool_get_context(CONTEXT_FREE));
		/* there's no context available in contexts pool, close the connection*/
		if (ctx == nullptr) {
			/* 421 <domain> Service not available */
			size_t sl = 0;
			auto str = resource_get_pop3_code(1713, 1, &sl);
			auto str2 = resource_get_pop3_code(1713, 2, &sl);
			auto host_ID = znul(g_config_file->get_value("host_id"));
			char buff[1024];
			auto len = snprintf(buff, std::size(buff), "%s%s%s",
			           str, host_ID, str2);
			if (HXio_fullwrite(sockd2, buff, len) < 0)
				/* ignore */;
			close(sockd2);
			continue;
		}
		ctx->type = CONTEXT_CONSTRUCTING;
		/* pass the client ipaddr into the ipaddr filter */
		std::string reason;
		if (system_services_judge_ip != nullptr &&
		    !system_services_judge_ip(client_hostip, reason)) {
			/* access denied */
			size_t sl = 0;
			auto str = resource_get_pop3_code(1712, 1, &sl);
			auto str2 = resource_get_pop3_code(1712, 2, &sl);
			char buff[1024];
			auto len = snprintf(buff, std::size(buff), "%s%s%s",
			           str, client_hostip, str2);
			if (HXio_fullwrite(sockd2, buff, len) < 0)
				/* ignore */;
			mlog(LV_DEBUG, "Connection %s is denied by ipaddr filter",
				client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context(ctx, CONTEXT_FREE);
			continue;
		}

		if (!use_tls) {
			/* +OK <domain> Service ready */
			size_t sl = 0;
			auto str = resource_get_pop3_code(1711, 1, &sl);
			auto str2 = resource_get_pop3_code(1711, 2, &sl);
			auto host_ID = znul(g_config_file->get_value("host_id"));
			char buff[1024];
			auto len = snprintf(buff, std::size(buff), "%s%s%s",
			           str, host_ID, str2);
			if (HXio_fullwrite(sockd2, buff, len) < 0)
				/* ignore */;
		}
		/* construct the context object */
		ctx->connection.last_timestamp = tp_now();
		ctx->connection.sockd          = sockd2;
		ctx->is_stls                   = use_tls;
		ctx->connection.client_port    = client_port;
		ctx->connection.server_port    = use_tls ? g_listener_ssl_port : g_listener_port;
		gx_strlcpy(ctx->connection.client_ip, client_hostip, std::size(ctx->connection.client_ip));
		gx_strlcpy(ctx->connection.server_ip, server_hostip, std::size(ctx->connection.server_ip));
		/*
		 * Valid the context and wake up one thread if there are some threads
		 * block on the condition variable.
		 */
		ctx->polling_mask = POLLING_READ;
		contexts_pool_put_context(ctx, CONTEXT_POLLING);
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
	auto ret = pthread_create4(&g_thr_id, nullptr, p3ls_thrwork,
	           reinterpret_cast<void *>(uintptr_t(false)));
	if (ret != 0) {
		printf("[listener]: failed to create listener thread: %s\n", strerror(ret));
		return -1;
	}
	pthread_setname_np(g_thr_id, "accept");
	if (g_listener_ssl_port > 0) {
		ret = pthread_create4(&g_ssl_thr_id, nullptr, p3ls_thrwork,
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
		pthread_join(g_thr_id, NULL);
	}
	if (g_listener_ssl_sock >= 0)
		shutdown(g_listener_ssl_sock, SHUT_RDWR);
	if (!pthread_equal(g_ssl_thr_id, {})) {
		pthread_kill(g_ssl_thr_id, SIGALRM);
		pthread_join(g_ssl_thr_id, NULL);
	}
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
		memset(temp_buff, 0, std::size(temp_buff));
		gethostname(temp_buff, std::size(temp_buff));
		temp_buff[std::size(temp_buff)-1] = '\0';
		g_config_file->set_value("host_id", temp_buff);
		str_val = temp_buff;
	}
	printf("[system]: host ID is %s\n", str_val);
	
	unsigned int context_num = g_config_file->get_ll("context_num");
	unsigned int thread_charge_num = g_config_file->get_ll("pop3_thread_charge_num");
	if (thread_charge_num % 4 != 0) {
		thread_charge_num = thread_charge_num / 4 * 4;
		g_config_file->set_int("pop3_thread_charge_num", thread_charge_num);
	}
	printf("[system]: one thread is in charge of %d contexts\n",
		thread_charge_num);

	unsigned int thread_init_num = g_config_file->get_ll("pop3_thread_init_num");
	if (thread_init_num * thread_charge_num > context_num) {
		thread_init_num = context_num / thread_charge_num;
		if (0 == thread_init_num) {
			thread_init_num = 1;
			context_num = thread_charge_num;
			g_config_file->set_int("context_num", context_num);
			printf("[system]: rectify contexts number %d\n", context_num);
		}
		g_config_file->set_int("pop3_thread_init_num", thread_init_num);
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
		pop3_auth_times, block_interval_auth, pop3_support_tls,
		pop3_force_tls, certificate_path, cb_passwd,
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

	threads_pool_init(thread_init_num, pop3_parser_process);
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
	
	exmdb_rpc_alloc = xrpc_alloc;
	exmdb_rpc_free = [](void *) {};
	exmdb_client_init(1, 0);
	if (exmdb_client_run(g_config_file->get_value("config_file_path"),
	    EXMDB_CLIENT_ASYNC_CONNECT, xrpc_build_env1, xrpc_free_env, nullptr) != 0) {
		mlog(LV_ERR, "Failed to start exmdb_client");
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
