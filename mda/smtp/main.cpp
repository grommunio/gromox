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
#include <sys/socket.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "smtp_aux.hpp"
#include "smtp_parser.h"

using namespace gromox;

#define E(s) decltype(system_services_ ## s) system_services_ ## s;
E(judge_user)
E(add_user_into_temp_list)
E(check_user)
#undef E

gromox::atomic_bool g_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
std::string g_rcpt_delimiter;
static char *opt_config_file;
static gromox::atomic_bool g_hup_signalled;
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
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_authmgr.so",
	"libgxs_user_filter.so",
};

static constexpr cfg_directive smtp_cfg_defaults[] = {
	{"command_protocol", "both"},
	{"config_file_path", PKGSYSCONFDIR "/smtp:" PKGSYSCONFDIR},
	{"context_average_mem", "256K", CFG_SIZE, "64K"},
	{"context_max_mem", "2M", CFG_SIZE},
	{"data_file_path", PKGDATADIR "/smtp:" PKGDATADIR},
	{"lda_listen_addr", "::"},
	{"lda_listen_port", "25"},
	{"lda_listen_tls_port", "0"},
	{"lda_log_file", "-"},
	{"lda_log_level", "4" /* LV_NOTICE */},
	{"lda_thread_charge_num", "400", CFG_SIZE, "4"},
	{"lda_thread_init_num", "5", CFG_SIZE},
	{"listen_port", "lda_listen_port", CFG_ALIAS},
	{"listen_ssl_port", "lda_listen_tls_port", CFG_ALIAS},
	{"mail_max_length", "64M", CFG_SIZE, "1"},
	{"running_identity", RUNNING_IDENTITY},
	{"smtp_conn_timeout", "3min", CFG_TIME, "1s"},
	{"smtp_force_starttls", "false", CFG_BOOL},
	{"smtp_support_pipeline", "true", CFG_BOOL},
	{"smtp_support_starttls", "false", CFG_BOOL},
	{"state_path", PKGSTATEDIR},
	{"thread_charge_num", "lda_thread_charge_num", CFG_ALIAS},
	{"thread_init_num", "lda_thread_init_num", CFG_ALIAS},
	{"tls_min_proto", "tls1.2"},
	CFG_TABLE_END,
};

static void term_handler(int signo);

static constexpr const cfg_directive dq_gxcfg_dflt[] = {
	{"lda_recipient_delimiter", ""},
	CFG_TABLE_END,
};

static bool dq_reload_config(std::shared_ptr<CONFIG_FILE> gxcfg = nullptr,
    std::shared_ptr<CONFIG_FILE> pconfig = nullptr)
{
	if (gxcfg == nullptr)
		gxcfg = config_file_prg(opt_config_file, "gromox.cfg", dq_gxcfg_dflt);
	if (opt_config_file != nullptr && gxcfg == nullptr) {
		mlog(LV_ERR, "config_file_init %s: %s", opt_config_file, strerror(errno));
		return false;
	}
	g_rcpt_delimiter = znul(gxcfg->get_value("lda_recipient_delimiter"));
	return true;
}

static int system_services_run()
{
#define E(f, s) do { \
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(decltype(*(f))))); \
	if ((f) == nullptr) { \
		mlog(LV_ERR, "system_services: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)

	E(system_services_judge_user, "user_filter_judge");
	E(system_services_add_user_into_temp_list, "user_filter_add");
	E(system_services_check_user, "check_user");
	return 0;
#undef E
}

static void system_services_stop()
{
	service_release("ip_filter_judge", "system");
	service_release("user_filter_judge", "system");
	service_release("user_filter_add", "system");
	service_release("check_user", "system");
}

static void *smls_thrwork(void *arg)
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
		auto ret = getnameinfo(reinterpret_cast<sockaddr *>(&client_peer),
		           addrlen, client_hostip, sizeof(client_hostip),
		           client_txtport, sizeof(client_txtport),
		           NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			mlog(LV_ERR, "getnameinfo: %s", gai_strerror(ret));
			close(sockd2);
			continue;
		}
		addrlen = sizeof(fact_addr);
		ret = getsockname(sockd2, reinterpret_cast<sockaddr *>(&fact_addr), &addrlen);
		if (ret != 0) {
			mlog(LV_ERR, "getsockname: %s", strerror(errno));
			close(sockd2);
			continue;
		}
		ret = getnameinfo(reinterpret_cast<sockaddr *>(&fact_addr),
		      addrlen, server_hostip, sizeof(server_hostip),
		      nullptr, 0, NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			mlog(LV_ERR, "getnameinfo: %s", gai_strerror(ret));
			close(sockd2);
			continue;
		}
		uint16_t client_port = strtoul(client_txtport, nullptr, 0);
		if (fcntl(sockd2, F_SETFL, O_NONBLOCK) < 0)
			mlog(LV_WARN, "W-1412: fcntl: %s", strerror(errno));
		static constexpr int flag = 1;
		if (setsockopt(sockd2, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
			mlog(LV_WARN, "W-1413: setsockopt: %s", strerror(errno));
		auto ctx = static_cast<smtp_context *>(contexts_pool_get_context(CONTEXT_FREE));
		/* there's no context available in contexts pool, close the connection*/
		if (ctx == nullptr) {
			/* 421 <domain> Service not available */
			size_t sl = 0;
			auto str = resource_get_smtp_code(401, 1, &sl);
			auto str2 = resource_get_smtp_code(401, 2, &sl);
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
		if (!use_tls) {
			/* 220 <domain> Service ready */
			size_t sl = 0;
			auto str = resource_get_smtp_code(202, 1, &sl);
			auto str2 = resource_get_smtp_code(202, 2, &sl);
			auto host_ID = znul(g_config_file->get_value("host_id"));
			char buff[1024];
			auto len = snprintf(buff, std::size(buff), "%s%s%s",
			           str, host_ID, str2);
			if (HXio_fullwrite(sockd2, buff, len) < 0)
				/* ignore */;
		}
		/* construct the context object */
		ctx->connection.last_timestamp = tp_now();
		ctx->connection.sockd             = sockd2;
		ctx->last_cmd                  = use_tls ? T_STARTTLS_CMD : 0;
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
		mlog(LV_ERR, "listener: failed to create socket [*]:%hu: %s",
		       g_listener_port, strerror(-g_listener_sock));
		return -1;
	}
	gx_reexec_record(g_listener_sock);
	if (g_listener_ssl_port > 0) {
		g_listener_ssl_sock = HX_inet_listen(g_listener_addr.c_str(), g_listener_ssl_port);
		if (g_listener_ssl_sock < 0) {
			mlog(LV_ERR, "listener: failed to create socket [*]:%hu: %s",
			       g_listener_ssl_port, strerror(-g_listener_ssl_sock));
			return -1;
		}
		gx_reexec_record(g_listener_ssl_sock);
	}
	return 0;
}

static int listener_trigger_accept()
{
	auto ret = pthread_create4(&g_thr_id, nullptr, smls_thrwork,
	           reinterpret_cast<void *>(uintptr_t(false)));
	if (ret != 0) {
		mlog(LV_ERR, "listener: failed to create listener thread: %s", strerror(ret));
		return -1;
	}
	pthread_setname_np(g_thr_id, "accept");
	if (g_listener_ssl_port > 0) {
		ret = pthread_create4(&g_ssl_thr_id, nullptr, smls_thrwork,
		      reinterpret_cast<void *>(uintptr_t(true)));
		if (ret != 0) {
			mlog(LV_ERR, "listener: failed to create listener thread: %s", strerror(ret));
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

int main(int argc, const char **argv)
{ 
	int retcode = EXIT_FAILURE;
	char temp_buff[256];
	smtp_param scfg;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv,
	    HXOPT_USAGEONERR | HXOPT_KEEP_ARGV) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	startup_banner("gromox-delivery-queue");
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
	g_config_file = config_file_prg(opt_config_file, "smtp.cfg",
	                smtp_cfg_defaults);
	if (opt_config_file != nullptr && g_config_file == nullptr)
		mlog(LV_ERR, "resource: config_file_init %s: %s",
			opt_config_file, strerror(errno));
	if (g_config_file == nullptr)
		return EXIT_FAILURE;
	auto gxconfig = config_file_prg(opt_config_file, "gromox.cfg", dq_gxcfg_dflt);
	if (opt_config_file != nullptr && gxconfig == nullptr)
		mlog(LV_ERR, "%s: %s", opt_config_file, strerror(errno));
	if (!dq_reload_config(gxconfig, g_config_file))
		return EXIT_FAILURE;

	mlog_init(g_config_file->get_value("lda_log_file"), g_config_file->get_ll("lda_log_level"));
	if (0 != resource_run()) { 
		mlog(LV_ERR, "system: failed to load resources");
		return EXIT_FAILURE;
	}
	auto cleanup_2 = make_scope_exit(resource_stop);

	auto str_val = g_config_file->get_value("host_id");
	if (str_val == NULL) {
		memset(temp_buff, '\0', std::size(temp_buff));
		gethostname(temp_buff, std::size(temp_buff));
		temp_buff[std::size(temp_buff)-1] = '\0';
		g_config_file->set_value("host_id", temp_buff);
		str_val = temp_buff;
	}
	mlog(LV_NOTICE, "system: host ID is \"%s\"", str_val);
	
	scfg.context_num = g_config_file->get_ll("context_num");
	unsigned int thread_charge_num = g_config_file->get_ll("lda_thread_charge_num");
		if (thread_charge_num % 4 != 0) {
			thread_charge_num = ((int)(thread_charge_num / 4)) * 4;
			g_config_file->set_value("lda_thread_charge_num", std::to_string(thread_charge_num).c_str());
		}
	mlog(LV_INFO, "system: one thread is in charge of %d contexts",
		thread_charge_num);
	
	unsigned int thread_init_num = g_config_file->get_ll("lda_thread_init_num");
	if (thread_init_num * thread_charge_num > scfg.context_num) {
		thread_init_num = scfg.context_num / thread_charge_num;
		if (0 == thread_init_num) {
			thread_init_num = 1;
			scfg.context_num = thread_charge_num;
			g_config_file->set_value("context_num", std::to_string(scfg.context_num).c_str());
			mlog(LV_NOTICE, "system: rectified contexts number to %d", scfg.context_num);
		}
		g_config_file->set_value("lda_thread_init_num", std::to_string(thread_init_num).c_str());
	}
	mlog(LV_INFO, "system: threads pool initial threads number is %d",
		thread_init_num);

	size_t context_aver_mem = g_config_file->get_ll("context_average_mem") / (64 * 1024);
	HX_unit_size(temp_buff, std::size(temp_buff), context_aver_mem * 64 * 1024, 1024, 0);
	mlog(LV_INFO, "dq: context average memory is %s", temp_buff);
 
	scfg.flushing_size = g_config_file->get_ll("context_max_mem") / (64 * 1024);
	if (scfg.flushing_size < context_aver_mem) {
		scfg.flushing_size = context_aver_mem;
		HX_unit_size(temp_buff, std::size(temp_buff), scfg.flushing_size * 64 * 1024, 1024, 0);
		g_config_file->set_value("context_max_mem", temp_buff);
	} 
	scfg.flushing_size *= 64 * 1024;
	HX_unit_size(temp_buff, std::size(temp_buff), scfg.flushing_size, 1024, 0);
	mlog(LV_INFO, "dq: context maximum memory is %s", temp_buff);
 
	scfg.timeout = std::chrono::seconds(g_config_file->get_ll("smtp_conn_timeout"));
	HX_unit_seconds(temp_buff, std::size(temp_buff), std::chrono::duration_cast<std::chrono::seconds>(scfg.timeout).count(), 0);
	mlog(LV_INFO, "dq: SMTP socket read write timeout is %s", temp_buff);

	scfg.support_pipeline = parse_bool(g_config_file->get_value("smtp_support_pipeline"));
	scfg.support_starttls = parse_bool(g_config_file->get_value("smtp_support_starttls")) ? TRUE : false;
	str_val = g_config_file->get_value("smtp_certificate_path");
	if (str_val != nullptr)
		scfg.cert_path = str_val;
	str_val = g_config_file->get_value("smtp_certificate_passwd");
	if (str_val != nullptr)
		scfg.cert_passwd = str_val;
	str_val = g_config_file->get_value("smtp_private_key_path");
	if (str_val != nullptr)
		scfg.key_path = str_val;
	if (scfg.support_starttls) {
		if (scfg.cert_path.size() == 0 || scfg.key_path.size() == 0) {
			scfg.support_starttls = false;
			mlog(LV_ERR, "dq: turning off TLS support because certificate or "
				"private key path is empty");
		} else {
			mlog(LV_NOTICE, "dq: STARTTLS support is available");
		}
	} else {
		mlog(LV_NOTICE, "dq: STARTTLS support is off");
	}

	scfg.force_starttls = parse_bool(g_config_file->get_value("smtp_force_starttls"));
	if (scfg.support_starttls && scfg.force_starttls)
		mlog(LV_NOTICE, "dq: clients are required to use STARTTLS");
	uint16_t listen_port = g_config_file->get_ll("lda_listen_port");
	uint16_t listen_tls_port = g_config_file->get_ll("lda_listen_tls_port");
	if (!scfg.support_starttls && listen_tls_port > 0)
		listen_tls_port = 0;
	if (listen_tls_port > 0)
		mlog(LV_NOTICE, "system: system TLS listening port %hu", listen_tls_port);

	scfg.max_mail_length = g_config_file->get_ll("mail_max_length");
	HX_unit_size(temp_buff, std::size(temp_buff), scfg.max_mail_length, 1024, 0);
	mlog(LV_NOTICE, "dq: maximum mail length is %s", temp_buff);

	str_val = g_config_file->get_value("command_protocol");
	if (strcasecmp(str_val, "both") == 0)
		scfg.cmd_prot = HT_LMTP | HT_SMTP;
	else if (strcasecmp(str_val, "lmtp") == 0)
		scfg.cmd_prot = HT_LMTP;
	else if (strcasecmp(str_val, "smtp") == 0)
		scfg.cmd_prot = HT_SMTP;
	else
		scfg.cmd_prot = 0;

	listener_init(g_config_file->get_value("lda_listen_addr"),
		listen_port, listen_tls_port);
	if (0 != listener_run()) {
		mlog(LV_ERR, "system: failed to start listener");
		return EXIT_FAILURE;
	}
	auto cleanup_4 = make_scope_exit(listener_stop);

	filedes_limit_bump(gxconfig->get_ll("lda_fd_limit"));
	service_init({g_config_file->get_value("config_file_path"),
		g_config_file->get_value("data_file_path"),
		g_config_file->get_value("state_path"),
		std::move(g_dfl_svc_plugins), scfg.context_num});
	if (service_run_early() != 0) {
		mlog(LV_ERR, "system: failed to run PLUGIN_EARLY_INIT");
		return EXIT_FAILURE;
	}
	if (switch_user_exec(*g_config_file, argv) != 0)
		return EXIT_FAILURE;
	if (0 != service_run()) { 
		mlog(LV_ERR, "system: failed to start services");
		return EXIT_FAILURE;
	}
	auto cleanup_6 = make_scope_exit(service_stop);
	
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	if (0 != system_services_run()) { 
		mlog(LV_ERR, "system: failed to start system service");
		return EXIT_FAILURE;
	}
	auto cleanup_8 = make_scope_exit(system_services_stop);

	smtp_parser_init(scfg);
	if (0 != smtp_parser_run()) { 
		mlog(LV_ERR, "system: failed to start SMTP parser");
		return EXIT_FAILURE;
	}
	auto cleanup_16 = make_scope_exit(smtp_parser_stop);
	
	contexts_pool_init(smtp_parser_get_contexts_list(), scfg.context_num,
		smtp_parser_get_context_socket,
		smtp_parser_get_context_timestamp,
		thread_charge_num, scfg.timeout);
 
	if (0 != contexts_pool_run()) { 
		mlog(LV_ERR, "system: failed to start context pool");
		return EXIT_FAILURE;
	}
	auto cleanup_18 = make_scope_exit(contexts_pool_stop);

	flusher_init(scfg.context_num);
	if (0 != flusher_run()) {
		mlog(LV_ERR, "system: failed to start flusher");
		return EXIT_FAILURE;
	}
	auto cleanup_20 = make_scope_exit(flusher_stop);

	threads_pool_init(thread_init_num, smtp_parser_process);
	threads_pool_register_event_proc(smtp_parser_threads_event_proc);
	if (threads_pool_run("smtp.cfg:lda_thread_init_num")) {
		mlog(LV_ERR, "system: failed to run thread pool");
		return EXIT_FAILURE;
	}
	auto cleanup_26 = make_scope_exit(threads_pool_stop);

	/* accept the connection */
	if (listener_trigger_accept() != 0) {
		mlog(LV_ERR, "system: failed accept()");
		return EXIT_FAILURE;
	}
	
	retcode = EXIT_SUCCESS;
	mlog(LV_NOTICE, "system: delivery-queue / SMTP daemon is now running");
	while (!g_notify_stop) {
		sleep(3);
		if (g_hup_signalled.exchange(false)) {
			dq_reload_config();
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
