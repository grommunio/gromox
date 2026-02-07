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
#include <netdb.h>
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
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/listener_ctx.hpp>
#include <gromox/paths.h>
#include <gromox/process.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "aux.hpp"
#include "parser.hpp"

using namespace gromox;

gromox::atomic_bool g_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
std::string g_rcpt_delimiter;
static const char *opt_config_file;
static gromox::atomic_bool g_hup_signalled;
static unsigned int g_haproxy_level;

static constexpr HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, {}, {}, {}, 0, "Config file to read", "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr generic_module g_dfl_svc_plugins[] = {
	{"libgxs_mysql_adaptor.so", SVC_mysql_adaptor},
	{"libgromox_auth.so/mgr", SVC_authmgr},
	{"libgromox_authz.so/dnsbl", SVC_dnsbl_filter},
	{"libgromox_authz.so/user", SVC_user_filter},
};

static constexpr cfg_directive gromox_cfg_defaults[] = {
	{"daemons_fd_limit", "lda_fd_limit", CFG_ALIAS},
	{"lda_fd_limit", "0", CFG_SIZE},
	{"lda_recipient_delimiter", ""},
	{"lda_accept_haproxy", "0", CFG_SIZE},
	CFG_TABLE_END,
};

static constexpr cfg_directive smtp_cfg_defaults[] = {
	{"command_protocol", "both"},
	{"config_file_path", PKGSYSCONFDIR "/smtp:" PKGSYSCONFDIR},
	{"context_average_mem", "256K", CFG_SIZE, "64K"},
	{"context_max_mem", "2M", CFG_SIZE},
	{"context_num", "0", CFG_SIZE},
	{"data_file_path", PKGDATADIR "/smtp:" PKGDATADIR},
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
	{"thread_charge_num", "lda_thread_charge_num", CFG_ALIAS},
	{"thread_init_num", "lda_thread_init_num", CFG_ALIAS},
	{"tls_min_proto", "tls1.2"},
	CFG_TABLE_END,
};

static void term_handler(int signo);

static bool dq_reload_config(std::shared_ptr<CONFIG_FILE> gxcfg = nullptr,
    std::shared_ptr<CONFIG_FILE> pconfig = nullptr)
{
	if (gxcfg == nullptr)
		gxcfg = config_file_prg(opt_config_file, "gromox.cfg", gromox_cfg_defaults);
	if (opt_config_file != nullptr && gxcfg == nullptr) {
		mlog(LV_ERR, "config_file_init %s: %s", opt_config_file, strerror(errno));
		return false;
	}
	if (gxcfg == nullptr)
		return false;
	g_rcpt_delimiter = znul(gxcfg->get_value("lda_recipient_delimiter"));
	g_haproxy_level = gxcfg->get_ll("lda_accept_haproxy");
	if (g_haproxy_level > 0)
		mlog(LV_NOTICE, "All incoming connections must be HAPROXY type %u", g_haproxy_level);
	return true;
}

static int smls_thrwork(generic_connection &&conn)
{
	const bool use_tls = conn.mark == M_TLS_CONN;
	
		if (fcntl(conn.sockd, F_SETFL, O_NONBLOCK) < 0)
			mlog(LV_WARN, "W-1412: fcntl: %s", strerror(errno));
		static constexpr int flag = 1;
		if (setsockopt(conn.sockd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
			/* ignore */;
		auto ctx = static_cast<smtp_context *>(contexts_pool_get_context(sctx_status::free));
		/* there's no context available in contexts pool, close the connection*/
		if (ctx == nullptr) {
			/* 421 <domain> Service not available */
			size_t sl = 0;
			auto str = resource_get_smtp_code(401, 1, &sl);
			auto str2 = resource_get_smtp_code(401, 2, &sl);
			auto host_ID = znul(g_config_file->get_value("host_id"));
			char buff[1024];
			auto len = gx_snprintf(buff, std::size(buff), "%s%s%s",
			           str, host_ID, str2);
			if (HXio_fullwrite(conn.sockd, buff, len) < 0)
				/* ignore */;
			return 0;
		}
		ctx->type = sctx_status::constructing;
		if (!use_tls) {
			/* 220 <domain> Service ready */
			size_t sl = 0;
			auto str = resource_get_smtp_code(202, 1, &sl);
			auto str2 = resource_get_smtp_code(202, 2, &sl);
			auto host_ID = znul(g_config_file->get_value("host_id"));
			char buff[1024];
			auto len = gx_snprintf(buff, std::size(buff), "%s%s%s",
			           str, host_ID, str2);
			if (HXio_fullwrite(conn.sockd, buff, len) < 0)
				/* ignore */;
		}
		ctx->connection = std::move(conn);
		ctx->last_cmd                  = use_tls ? T_STARTTLS_CMD : 0;
		/*
		 * Valid the context and wake up one thread if there are some threads
		 * block on the condition variable.
		 */
		ctx->polling_mask = POLLING_READ;
		contexts_pool_insert(ctx, sctx_status::polling);

	return 0;
}

static int smtp_parse_binds(listener_ctx &ctx, const config_file &gxcfg,
    const char *gxkey, const config_file &oldcfg, const char *oldkey,
    const char *oldportkey, unsigned int mark)
{
	auto line = gxcfg.get_value(gxkey);
	if (line != nullptr)
		return ctx.add_bunch(line, mark);
	auto host = oldcfg.get_value(oldkey);
	if (host != nullptr)
		mlog(LV_NOTICE, "%s:%s is deprecated in favor of %s:%s",
			oldcfg.m_filename.c_str(), oldkey,
			gxcfg.m_filename.c_str(), gxkey);
	else
		host = "::";
	auto ps = oldcfg.get_value(oldportkey);
	uint16_t port = mark == M_UNENCRYPTED_CONN ? 25 : 465;
	if (ps != nullptr) {
		mlog(LV_NOTICE, "%s:%s is deprecated in favor of %s:%s",
			oldcfg.m_filename.c_str(), oldportkey,
			gxcfg.m_filename.c_str(), gxkey);
		port = strtoul(ps, nullptr, 0);
	}
	if (port != 0 &&
	    ctx.add_inet(host, port, mark) != 0)
		return -1;
	return 0;
}

int main(int argc, char **argv)
{ 
	char temp_buff[256];
	smtp_param scfg;
	HXopt6_auto_result argp;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt6(g_options_table, argc, argv, &argp,
	    HXOPT_USAGEONERR | HXOPT_ITER_OPTS) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	for (int i = 0; i < argp.nopts; ++i)
		if (argp.desc[i]->sh == 'c')
			opt_config_file = argp.oarg[i];

	startup_banner("gromox-delivery-queue");
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
	g_config_file = config_file_prg(opt_config_file, "smtp.cfg",
	                smtp_cfg_defaults);
	if (opt_config_file != nullptr && g_config_file == nullptr)
		mlog(LV_ERR, "resource: config_file_init %s: %s",
			opt_config_file, strerror(errno));
	auto gxconfig = config_file_prg(opt_config_file, "gromox.cfg", gromox_cfg_defaults);
	if (opt_config_file != nullptr && gxconfig == nullptr)
		mlog(LV_ERR, "%s: %s", opt_config_file, strerror(errno));
	if (g_config_file == nullptr || gxconfig == nullptr)
		return EXIT_FAILURE; /* e.g. permission error */
	if (!dq_reload_config(gxconfig, g_config_file))
		return EXIT_FAILURE;
	setup_utf8_locale();

	mlog_init("gromox-delivery-queue", g_config_file->get_value("lda_log_file"),
		g_config_file->get_ll("lda_log_level"),
		g_config_file->get_value("running_identity"));
	if (0 != resource_run()) { 
		mlog(LV_ERR, "system: failed to load resources");
		return EXIT_FAILURE;
	}
	auto cleanup_2 = HX::make_scope_exit(resource_stop);

	auto str_val = g_config_file->get_value("host_id");
	if (str_val == NULL) {
		std::string hn;
		auto ret = canonical_hostname(hn);
		if (ret != 0)
			return EXIT_FAILURE;
		g_config_file->set_value("host_id", hn.c_str());
		str_val = g_config_file->get_value("host_id");
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

	listener_ctx listener;
	if (smtp_parse_binds(listener, *gxconfig, "lda_listen", *g_config_file,
	    "lda_listen_addr", "lda_listen_port", M_UNENCRYPTED_CONN) != 0)
		return EXIT_FAILURE;
	if (scfg.support_starttls &&
	    smtp_parse_binds(listener, *gxconfig, "lda_listen_tls", *g_config_file,
	    "lda_listen_addr", "lda_listen_tls_port", M_TLS_CONN) != 0)
		return EXIT_FAILURE;
	listener.m_haproxy_level = g_haproxy_level;
	listener.m_thread_name   = "accept";

	filedes_limit_bump(gxconfig->get_ll("lda_fd_limit"));
	service_init({g_config_file, g_dfl_svc_plugins, scfg.context_num});
	if (switch_user_exec(*g_config_file, argv) != 0)
		return EXIT_FAILURE;
	if (0 != service_run()) { 
		mlog(LV_ERR, "system: failed to start services");
		return EXIT_FAILURE;
	}
	auto cleanup_6 = HX::make_scope_exit(service_stop);
	
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	smtp_parser_init(scfg);
	if (0 != smtp_parser_run()) { 
		mlog(LV_ERR, "system: failed to start SMTP parser");
		return EXIT_FAILURE;
	}
	auto cleanup_16 = HX::make_scope_exit(smtp_parser_stop);
	
	contexts_pool_init(smtp_parser_get_contexts_list(), scfg.context_num,
		smtp_parser_get_context_socket,
		smtp_parser_get_context_timestamp,
		thread_charge_num, scfg.timeout);
 
	if (0 != contexts_pool_run()) { 
		mlog(LV_ERR, "system: failed to start context pool");
		return EXIT_FAILURE;
	}
	auto cleanup_18 = HX::make_scope_exit(contexts_pool_stop);

	flusher_init(scfg.context_num);
	if (0 != flusher_run()) {
		mlog(LV_ERR, "system: failed to start flusher");
		return EXIT_FAILURE;
	}
	auto cleanup_20 = HX::make_scope_exit(flusher_stop);

	threads_pool_init(thread_init_num, smtp_parser_process);
	threads_pool_register_event_proc(smtp_parser_threads_event_proc);
	if (threads_pool_run("smtp.cfg:lda_thread_init_num")) {
		mlog(LV_ERR, "system: failed to run thread pool");
		return EXIT_FAILURE;
	}
	auto cleanup_26 = HX::make_scope_exit(threads_pool_stop);

	/* accept the connection */
	auto err = listener.watch_start(g_notify_stop, smls_thrwork);
	if (err != 0) {
		mlog(LV_ERR, "listener.thread_start: %s", strerror(err));
		return EXIT_FAILURE;
	}
	
	mlog(LV_INFO, "system: delivery-queue / SMTP daemon is now running");
	while (!g_notify_stop) {
		sleep(3);
		if (g_hup_signalled.exchange(false)) {
			dq_reload_config();
			service_trigger_all(PLUGIN_RELOAD);
		}
	}
	return EXIT_SUCCESS;
}

static void term_handler(int signo)
{
	g_notify_stop = true;
}
