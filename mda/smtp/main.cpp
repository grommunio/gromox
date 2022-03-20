// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include "blocks_allocator.h" 
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "flusher.h" 
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/fileio.h>
#include <gromox/lib_buffer.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include <libHX/misc.h>
#include <libHX/option.h>
#include "listener.h" 
#include <memory>
#include "resource.h" 
#include "service.h" 
#include "smtp_parser.h" 
#include <sys/resource.h>
#include "system_services.h"
#include <sys/types.h>
#include <unistd.h>
#include <utility>

using namespace gromox;

gromox::atomic_bool g_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static gromox::atomic_bool g_hup_signalled;
std::unique_ptr<LIB_BUFFER> g_files_allocator;

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr const char *g_dfl_svc_plugins[] = {
	"libgxs_logthru.so",
	"libgxs_midb_agent.so",
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_authmgr.so",
	"libgxs_user_filter.so",
	NULL,
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
	g_config_file = config_file_prg(opt_config_file, "smtp.cfg");
	if (opt_config_file != nullptr && g_config_file == nullptr)
		printf("[resource]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (g_config_file == nullptr)
		return EXIT_FAILURE;

	static constexpr cfg_directive smtp_cfg_defaults[] = {
		{"block_interval_auths", "1min", CFG_TIME, "1s"},
		{"block_interval_session", "1min", CFG_TIME, "1s"},
		{"command_protocol", "both"},
		{"config_file_path", PKGSYSCONFDIR "/smtp:" PKGSYSCONFDIR},
		{"context_average_mem", "256K", CFG_SIZE, "64K"},
		{"context_max_mem", "2M", CFG_SIZE},
		{"data_file_path", PKGDATADIR "/smtp:" PKGDATADIR},
		{"listen_port", "25"},
		{"listen_ssl_port", "0"},
		{"mail_max_length", "64M", CFG_SIZE, "1"},
		{"running_identity", "gromox"},
		{"service_plugin_ignore_errors", "false", CFG_BOOL},
		{"service_plugin_path", PKGLIBDIR},
		{"smtp_auth_times", "3", CFG_SIZE, "1"},
		{"smtp_conn_timeout", "3min", CFG_TIME, "1s"},
		{"smtp_force_starttls", "false", CFG_BOOL},
		{"smtp_max_mail_num", "100", CFG_SIZE},
		{"smtp_need_auth", "false", CFG_BOOL},
		{"smtp_support_pipeline", "true", CFG_BOOL},
		{"smtp_support_starttls", "false", CFG_BOOL},
		{"state_path", PKGSTATEDIR},
		{"thread_charge_num", "400", CFG_SIZE, "4"},
		CFG_TABLE_END,
	};
	config_file_apply(*g_config_file, smtp_cfg_defaults);

	if (0 != resource_run()) { 
		printf("[system]: Failed to load resource\n");
		return EXIT_FAILURE;
	}
	auto cleanup_2 = make_scope_exit(resource_stop);

	auto str_val = g_config_file->get_value("host_id");
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
	
	g_config_file->get_uint("context_num", &scfg.context_num);
	unsigned int thread_charge_num = 20;
	if (g_config_file->get_uint("thread_charge_num", &thread_charge_num)) {
		if (thread_charge_num % 4 != 0) {
			thread_charge_num = ((int)(thread_charge_num / 4)) * 4;
			resource_set_integer("THREAD_CHARGE_NUM", thread_charge_num);
		}
	}
	printf("[system]: one thread is in charge of %d contexts\n",
		thread_charge_num);
	
	unsigned int thread_init_num = 5;
	g_config_file->get_uint("thread_init_num", &thread_init_num);
	if (thread_init_num * thread_charge_num > scfg.context_num) {
		thread_init_num = scfg.context_num / thread_charge_num;
		if (0 == thread_init_num) {
			thread_init_num = 1;
			scfg.context_num = thread_charge_num;
			resource_set_integer("CONTEXT_NUM", scfg.context_num);
			printf("[system]: rectify contexts number %d\n", scfg.context_num);
		}
		resource_set_integer("THREAD_INIT_NUM", thread_init_num);
	}
	printf("[system]: threads pool initial threads number is %d\n",
		thread_init_num);

	size_t context_aver_mem = g_config_file->get_ll("context_average_mem") / (64 * 1024);
	bytetoa(context_aver_mem*64*1024, temp_buff);
	printf("[smtp]: context average memory is %s\n", temp_buff);
 
	scfg.flushing_size = g_config_file->get_ll("context_max_mem") / (64 * 1024);
	if (scfg.flushing_size < context_aver_mem) {
		scfg.flushing_size = context_aver_mem;
		bytetoa(scfg.flushing_size * 64 * 1024, temp_buff);
		resource_set_string("CONTEXT_MAX_MEM", temp_buff);
	} 
	scfg.flushing_size *= 64 * 1024;
	bytetoa(scfg.flushing_size, temp_buff);
	printf("[smtp]: context maximum memory is %s\n", temp_buff);
 
	scfg.timeout = std::chrono::seconds(g_config_file->get_ll("smtp_conn_timeout"));
	itvltoa(std::chrono::duration_cast<std::chrono::seconds>(scfg.timeout).count(), temp_buff);
	printf("[smtp]: smtp socket read write time out is %s\n", temp_buff);

	scfg.support_pipeline = parse_bool(g_config_file->get_value("smtp_support_pipeline"));
	scfg.support_starttls = parse_bool(g_config_file->get_value("smtp_support_starttls")) ? TRUE : false;
	str_val = resource_get_string("SMTP_CERTIFICATE_PATH");
	if (str_val != nullptr)
		scfg.cert_path = str_val;
	str_val = resource_get_string("SMTP_CERTIFICATE_PASSWD");
	if (str_val != nullptr)
		scfg.cert_passwd = str_val;
	str_val = resource_get_string("SMTP_PRIVATE_KEY_PATH");
	if (str_val != nullptr)
		scfg.key_path = str_val;
	if (scfg.support_starttls) {
		if (scfg.cert_path.size() == 0 || scfg.key_path.size() == 0) {
			scfg.support_starttls = false;
			printf("[smtp]: turn off TLS support because certificate or "
				"private key path is empty\n");
		} else {
			printf("[smtp]: smtp support esmtp TLS mode\n");
		}
	} else {
		printf("[smtp]: smtp doesn't support esmtp TLS mode\n");
	}

	scfg.force_starttls = parse_bool(g_config_file->get_value("smtp_force_starttls"));
	if (scfg.support_starttls && scfg.force_starttls)
		printf("[smtp]: smtp MUST running in TLS mode\n");
	uint16_t listen_port = g_config_file->get_ll("listen_port");
	uint16_t listen_ssl_port = g_config_file->get_ll("listen_ssl_port");
	if (!scfg.support_starttls && listen_ssl_port > 0)
		listen_ssl_port = 0;
	if (listen_ssl_port > 0) {
		printf("[system]: system SSL listening port %hu\n", listen_ssl_port);
	}

	scfg.need_auth = parse_bool(g_config_file->get_value("smtp_need_auth")) ? TRUE : false;
	printf("[smtp]: auth_needed is %s\n", scfg.need_auth ? "ON" : "OFF");

	scfg.auth_times = g_config_file->get_ll("smtp_auth_times");
	printf("[smtp]: maximum authentification failure times is %d\n", 
	       scfg.auth_times);

	scfg.blktime_auths = g_config_file->get_ll("block_interval_auths");
	itvltoa(scfg.blktime_auths, temp_buff);
	printf("[smtp]: block client %s when authentification failure times "
			"is exceeded\n", temp_buff);

	scfg.max_mail_length = g_config_file->get_ll("mail_max_length");
	bytetoa(scfg.max_mail_length, temp_buff);
	printf("[smtp]: maximum mail length is %s\n", temp_buff);

	scfg.max_mail_sessions = g_config_file->get_ll("smtp_max_mail_num");
	scfg.blktime_sessions = g_config_file->get_ll("block_interval_session");
	itvltoa(scfg.blktime_sessions, temp_buff);
	printf("[smtp]: block remote side %s when mails number is exceed for one "
			"session\n", temp_buff);
	
	const char *str_value = resource_get_string("SERVICE_PLUGIN_LIST");
	char **service_plugin_list = nullptr;
	auto cl_0 = make_scope_exit([&]() { HX_zvecfree(service_plugin_list); });
	if (str_value != NULL) {
		service_plugin_list = read_file_by_line(str_value);
		if (service_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			return EXIT_FAILURE;
		}
	}

	str_val = resource_get_string("command_protocol");
	if (strcasecmp(str_val, "both") == 0)
		scfg.cmd_prot = HT_LMTP | HT_SMTP;
	else if (strcasecmp(str_val, "lmtp") == 0)
		scfg.cmd_prot = HT_LMTP;
	else if (strcasecmp(str_val, "smtp") == 0)
		scfg.cmd_prot = HT_SMTP;
	else
		scfg.cmd_prot = 0;

	listener_init(listen_port, listen_ssl_port);
	if (0 != listener_run()) {
		printf("[system]: fail to start listener\n");
		return EXIT_FAILURE;
	}
	auto cleanup_4 = make_scope_exit(listener_stop);

	if (0 != getrlimit(RLIMIT_NOFILE, &rl)) {
		printf("[system]: fail to get file limitation\n");
		return EXIT_FAILURE;
	}
	if (rl.rlim_cur < scfg.context_num + 128 ||
	    rl.rlim_max < scfg.context_num + 128) {
		rl.rlim_cur = scfg.context_num + 128;
		rl.rlim_max = scfg.context_num + 128;
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
		scfg.context_num});
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
	auto cleanup_6 = make_scope_exit(service_stop);
	
	if (0 != system_services_run()) { 
		printf("[system]: failed to run system service\n");
		return EXIT_FAILURE;
	}
	auto cleanup_8 = make_scope_exit(system_services_stop);

	size_t fa_blocks_num = scfg.context_num * 128;
	g_files_allocator = LIB_BUFFER::create(FILE_ALLOC_SIZE, fa_blocks_num, TRUE);
	if (g_files_allocator == nullptr) {
		printf("[system]: can not run file allocator\n"); 
		return EXIT_FAILURE;
	}
	auto cleanup_9 = make_scope_exit([&]() { g_files_allocator.reset(); });

	blocks_allocator_init(scfg.context_num * context_aver_mem);
	if (0 != blocks_allocator_run()) { 
		printf("[system]: can not run blocks allocator\n"); 
		return EXIT_FAILURE;
	}
	auto cleanup_12 = make_scope_exit(blocks_allocator_stop);

	smtp_parser_init(std::move(scfg));
	if (0 != smtp_parser_run()) { 
		printf("[system]: failed to run smtp parser\n");
		return EXIT_FAILURE;
	}
	auto cleanup_16 = make_scope_exit(smtp_parser_stop);
	
	contexts_pool_init(smtp_parser_get_contexts_list(), scfg.context_num,
		smtp_parser_get_context_socket,
		smtp_parser_get_context_timestamp,
		thread_charge_num, scfg.timeout);
 
	if (0 != contexts_pool_run()) { 
		printf("[system]: failed to run contexts pool\n");
		return EXIT_FAILURE;
	}
	auto cleanup_18 = make_scope_exit(contexts_pool_stop);

	flusher_init(scfg.context_num);
	if (0 != flusher_run()) {
		printf("[system]: failed to run flusher\n");
		return EXIT_FAILURE;
	}
	auto cleanup_20 = make_scope_exit(flusher_stop);

	threads_pool_init(thread_init_num, reinterpret_cast<int (*)(SCHEDULE_CONTEXT *)>(smtp_parser_process));
	threads_pool_register_event_proc(smtp_parser_threads_event_proc);
	if (0 != threads_pool_run()) {
		printf("[system]: failed to run threads pool\n");
		return EXIT_FAILURE;
	}
	auto cleanup_26 = make_scope_exit(threads_pool_stop);

	/* accept the connection */
	if (listener_trigger_accept() != 0) {
		printf("[system]: fail trigger accept\n");
		return EXIT_FAILURE;
	}
	
	retcode = EXIT_SUCCESS;
	printf("[system]: SMTP DAEMON is now running\n");
	while (!g_notify_stop) {
		sleep(3);
		if (g_hup_signalled.exchange(false))
			service_reload_all();
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
