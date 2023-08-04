// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include <libHX/misc.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <memory>
#include "smtp_parser.h" 
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include "smtp_aux.hpp"

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

int main(int argc, const char **argv) try
{ 
	int retcode = EXIT_FAILURE;
	struct rlimit rl;
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
	
	str_val = g_config_file->get_value("default_domain");
	if (str_val == NULL) {
		memset(temp_buff, '\0', std::size(temp_buff));
		getdomainname(temp_buff, std::size(temp_buff));
		g_config_file->set_value("default_domain", temp_buff);
		str_val = temp_buff;
		mlog(LV_WARN, "system: Cannot find default domain. OS domain name "
			"will be used as default domain.");
	}
	mlog(LV_NOTICE, "system: default domain is \"%s\"", str_val);
	
	g_config_file->get_uint("context_num", &scfg.context_num);
	unsigned int thread_charge_num = g_config_file->get_ll("lda_thread_charge_num");
		if (thread_charge_num % 4 != 0) {
			thread_charge_num = ((int)(thread_charge_num / 4)) * 4;
			g_config_file->set_int("lda_thread_charge_num", thread_charge_num);
		}
	mlog(LV_INFO, "system: one thread is in charge of %d contexts",
		thread_charge_num);
	
	unsigned int thread_init_num = g_config_file->get_ll("lda_thread_init_num");
	if (thread_init_num * thread_charge_num > scfg.context_num) {
		thread_init_num = scfg.context_num / thread_charge_num;
		if (0 == thread_init_num) {
			thread_init_num = 1;
			scfg.context_num = thread_charge_num;
			g_config_file->set_int("context_num", scfg.context_num);
			mlog(LV_NOTICE, "system: rectified contexts number to %d", scfg.context_num);
		}
		g_config_file->set_int("lda_thread_init_num", thread_init_num);
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

	if (0 != getrlimit(RLIMIT_NOFILE, &rl)) {
		mlog(LV_ERR, "getrlimit: %s", strerror(errno));
		return EXIT_FAILURE;
	}
	if (rl.rlim_cur < scfg.context_num + 128 ||
	    rl.rlim_max < scfg.context_num + 128) {
		rl.rlim_cur = scfg.context_num + 128;
		rl.rlim_max = scfg.context_num + 128;
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

	g_blocks_allocator = alloc_limiter<stream_block>(scfg.context_num * context_aver_mem,
	                     "smtp_blocks_alloc", "smtp.cfg:context_num,context_aver_mem");
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
		if (g_hup_signalled.exchange(false))
			service_trigger_all(PLUGIN_RELOAD);
	}
	listener_stop_accept();
	return retcode;
} catch (const cfg_error &) {
	return EXIT_FAILURE;
}

static void term_handler(int signo)
{
	g_notify_stop = true;
}
