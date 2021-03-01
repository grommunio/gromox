// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <libHX/option.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/config_file.hpp>
#include "listener.h" 
#include "resource.h" 
#include "flusher.h" 
#include "smtp_parser.h" 
#include <gromox/files_allocator.hpp>
#include "blocks_allocator.h" 
#include <gromox/threads_pool.hpp>
#include "console_cmd_handler.h"
#include <gromox/console_server.hpp>
#include <gromox/contexts_pool.hpp>
#include "service.h" 
#include "system_services.h"
#include <gromox/util.hpp>
#include <gromox/lib_buffer.hpp>
#include <pwd.h>
#include <cstdio>
#include <unistd.h>
#include <csignal>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

using namespace gromox;

BOOL g_notify_stop = FALSE;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static const char *const g_dfl_as_plugins[] = {
	NULL,
};

static const char *const g_dfl_svc_plugins[] = {
	"libgxs_domain_list.so",
	"libgxs_logthru.so",
	"libgxs_midb_agent.so",
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_authmgr.so",
	"libgxs_user_filter.so",
	NULL,
};

typedef void (*STOP_FUNC)();

static void term_handler(int signo);

int main(int argc, const char **argv)
{ 
	int retcode = EXIT_FAILURE, listen_port, listen_ssl_port;
	int context_num;
	size_t max_mail_len;
	size_t context_aver_mem, context_max_mem;
	int smtp_max_mail_num;
	int smtp_auth_times, smtp_conn_timeout;
	BOOL smtp_need_auth, smtp_support_pipeline,
		smtp_support_starttls, smtp_force_starttls;
	int thread_init_num, thread_charge_num, threads_max_num; 
	const char *certificate_path, *cb_passwd, *private_key_path;
	const char *service_plugin_path; 
	const char *console_server_ip, *flusher_plugin_path, *user_name;
	int block_interval_auth, block_interval_sessions;
	int console_server_port; 
	struct rlimit rl;
	struct passwd *puser_pass;
	const char *str_val;
	char temp_buff[256];
	BOOL smtp_auth_needed;
	BOOL domainlist_valid;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, term_handler);
	g_config_file = config_file_prg(opt_config_file, "smtp.cfg");
	if (opt_config_file != nullptr && g_config_file == nullptr) {
		printf("[resource]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return EXIT_FAILURE;
	}

	resource_init();
	if (0 != resource_run()) { 
		printf("[system]: Failed to load resource\n");
		return EXIT_FAILURE;
	}
	auto cleanup_1 = make_scope_exit(resource_free);
	auto cleanup_2 = make_scope_exit(resource_stop);
	
	if (!resource_get_integer("LISTEN_PORT", &listen_port)) {
		listen_port = 25; 
		resource_set_integer("LISTEN_PORT", listen_port);
	}
	printf("[system]: system listening port %d\n", listen_port);

	if (!resource_get_integer("LISTEN_SSL_PORT", &listen_ssl_port))
		listen_ssl_port = 0;

	str_val = resource_get_string("HOST_ID");
	if (str_val == NULL) {
		memset(temp_buff, 0, 256);
		gethostname(temp_buff, 256);
		resource_set_string("HOST_ID", temp_buff);
		str_val = temp_buff;
		printf("[system]: warning! cannot find host ID, OS host name will be "
			"used as host ID\n");
	}
	printf("[system]: host ID is %s\n", str_val);
	
	str_val = resource_get_string("DEFAULT_DOMAIN");
	if (str_val == NULL) {
		memset(temp_buff, 0, 256);
		getdomainname(temp_buff, 256);
		resource_set_string("DEFAULT_DOMAIN", temp_buff);
		str_val = temp_buff;
		printf("[system]: warning! cannot find default domain, OS domain name "
			"will be used as default domain\n");
	}
	printf("[system]: default domain is %s\n", str_val);
	
	user_name = resource_get_string("RUNNING_IDENTITY");
	if (user_name == NULL)
		user_name = "gromox";
	if (*user_name == '\0')
		printf("[system]: running identity will not be changed\n");
	else
		printf("[system]: running identity of process will be %s\n", user_name);

	if (!resource_get_integer("CONTEXT_NUM", &context_num)) {
		context_num = 400;
		resource_set_integer("CONTEXT_NUM", context_num);
	}
	printf("[system]: total contexts number is %d\n", context_num);

	if (!resource_get_integer("THREAD_CHARGE_NUM", &thread_charge_num)) {
		thread_charge_num = 20;
		resource_set_integer("THREAD_CHARGE_NUM", thread_charge_num);
	} else {
		if (thread_charge_num < 4) {
			thread_charge_num = 20;	
			resource_set_integer("THREAD_CHARGE_NUM", thread_charge_num);
		} else if (thread_charge_num % 4 != 0) {
			thread_charge_num = ((int)(thread_charge_num / 4)) * 4;
			resource_set_integer("THREAD_CHARGE_NUM", thread_charge_num);
		}
	}
	printf("[system]: one thread is in charge of %d contexts\n",
		thread_charge_num);
	
	if (!resource_get_integer("THREAD_INIT_NUM", &thread_init_num)) {
		thread_init_num = 5;
		resource_set_integer("THREAD_INIT_NUM", thread_init_num);
	}
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

	str_val = resource_get_string("CONTEXT_AVERAGE_MEM");
	if (str_val == NULL) {
		context_aver_mem = 4;
		resource_set_string("CONTEXT_AVERAGE_MEM", "256K");
	} else {
		context_aver_mem = atobyte(str_val)/(64*1024);
		if (context_aver_mem <= 1) {
			context_aver_mem = 4;
			resource_set_string("CONTEXT_AVERAGE_MEM", "256K");
		}
	}
	bytetoa(context_aver_mem*64*1024, temp_buff);
	printf("[smtp]: context average memory is %s\n", temp_buff);
 
	str_val = resource_get_string("CONTEXT_MAX_MEM");
	if (str_val == NULL) {
		context_max_mem = 32; 
		resource_set_string("CONTEXT_MAX_MEM", "2M");
	} else {
		context_max_mem = atobyte(str_val)/(64*1024); 
	}
	if (context_max_mem < context_aver_mem) {
		context_max_mem = context_aver_mem;
		bytetoa(context_max_mem*64*1024, temp_buff);
		resource_set_string("CONTEXT_MAX_MEM", temp_buff);
	} 
	context_max_mem *= 64*1024;
	bytetoa(context_max_mem, temp_buff);
	printf("[smtp]: context maximum memory is %s\n", temp_buff);
 
	str_val = resource_get_string("DOMAIN_LIST_VALID");
	if (str_val == NULL) {
		resource_set_string("DOMAIN_LIST_VALID", "FALSE");
		domainlist_valid = FALSE;
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			domainlist_valid = FALSE;
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			domainlist_valid = TRUE;
		} else {
			resource_set_string("DOMAIN_LIST_VALID", "FALSE");
			domainlist_valid = FALSE;
		}
	}
	if (FALSE == domainlist_valid) {
		printf("[system]: domain list in system is invalid\n");
	} else {
		printf("[system]: domain list in system is valid\n");
	}
	
	str_val = resource_get_string("SMTP_CONN_TIMEOUT");
	if (str_val == NULL) {
		smtp_conn_timeout = 180;
		resource_set_string("SMTP_CONN_TIMEOUT", "3minutes");
	} else {
		smtp_conn_timeout = atoitvl(str_val);
		if (smtp_conn_timeout <= 0) {
			smtp_conn_timeout = 180;
			resource_set_string("SMTP_CONN_TIMEOUT", "3minutes");
		}
	}
	itvltoa(smtp_conn_timeout, temp_buff);
	printf("[smtp]: smtp socket read write time out is %s\n", temp_buff);
 
	str_val = resource_get_string("SMTP_SUPPORT_PIPELINE");
	if (str_val == NULL) {
		smtp_support_pipeline = true;
		resource_set_string("SMTP_SUPPORT_PIPELINE", "true");
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			smtp_support_pipeline = FALSE;
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			smtp_support_pipeline = TRUE;
		} else {
			smtp_support_pipeline = FALSE;
			resource_set_string("SMTP_SUPPORT_PIPELINE", "FALSE");
		}
	}
	if (FALSE == smtp_support_pipeline) {
		printf("[smtp]: smtp doesn't support esmtp pipeline mode\n");
	} else {
		printf("[smtp]: smtp supports esmtp pipeline mode\n");
	}

	str_val = resource_get_string("SMTP_SUPPORT_STARTTLS");
	if (str_val == NULL) {
		smtp_support_starttls = FALSE;
		resource_set_string("SMTP_SUPPORT_STARTTLS", "FALSE");
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			smtp_support_starttls = FALSE;
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			smtp_support_starttls = TRUE;
		} else {
			smtp_support_starttls = FALSE;
			resource_set_string("SMTP_SUPPORT_STARTTLS", "FALSE");
		}
	}
	certificate_path = resource_get_string("SMTP_CERTIFICATE_PATH");
	cb_passwd = resource_get_string("SMTP_CERTIFICATE_PASSWD");
	private_key_path = resource_get_string("SMTP_PRIVATE_KEY_PATH");
	if (TRUE == smtp_support_starttls) {
		if (NULL == certificate_path || NULL == private_key_path) {
			smtp_support_starttls = FALSE;
			printf("[smtp]: turn off TLS support because certificate or "
				"private key path is empty\n");
		} else {
			printf("[smtp]: smtp support esmtp TLS mode\n");
		}
	} else {
		printf("[smtp]: smtp doesn't support esmtp TLS mode\n");
	}

	str_val = resource_get_string("SMTP_FORCE_STARTTLS");
	if (str_val == NULL) {
		smtp_force_starttls = FALSE;
		resource_set_string("SMTP_FORCE_STARTTLS", "FALSE");
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			smtp_force_starttls = FALSE;
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			smtp_force_starttls = TRUE;
		} else {
			smtp_force_starttls = FALSE;
			resource_set_string("SMTP_FORCE_STARTTLS", "FALSE");
		}
	}
	
	if (TRUE == smtp_support_starttls && TRUE == smtp_force_starttls) {
		printf("[smtp]: smtp MUST running in TLS mode\n");
	}

	if (FALSE == smtp_support_starttls && listen_ssl_port > 0) {
		listen_ssl_port = 0;
	}

	if (listen_ssl_port > 0) {
		printf("[system]: system SSL listening port %d\n", listen_ssl_port);
	}

	str_val = resource_get_string("SMTP_NEED_AUTH");
	if (str_val == NULL) {
		smtp_need_auth = FALSE;
		resource_set_string("SMTP_NEED_AUTH", "FALSE");
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			smtp_need_auth = FALSE;
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			smtp_need_auth = TRUE;
		} else {
			smtp_need_auth = FALSE;
			resource_set_string("SMTP_NEED_AUTH", "FALSE");
		}
	}
	if (FALSE == smtp_need_auth) {
		printf("[smtp]: smtp doesn't force users to authentificate\n");
	} else {
		printf("[smtp]: smtp forces users to authentificate\n");
	}

	if (!resource_get_integer("SMTP_AUTH_TIMES", &smtp_auth_times)) {
		smtp_auth_times = 3; 
		resource_set_integer("SMTP_AUTH_TIMES", smtp_auth_times);
	} else {
		if (smtp_auth_times <= 0) {
			smtp_auth_times = 3;
			resource_set_integer("SMTP_AUTH_TIMES", smtp_auth_times);
		}
	}
	printf("[smtp]: maximum authentification failure times is %d\n", 
			smtp_auth_times);

	str_val = resource_get_string("BLOCK_INTERVAL_AUTHS");
	if (str_val == NULL) {
		block_interval_auth = 60;
		resource_set_string("BLOCK_INTERVAL_AUTHS", "1 minute");
	} else {
		block_interval_auth = atoitvl(str_val);
		if (block_interval_auth <= 0) {
			block_interval_auth = 60;
			resource_set_string("BLOCK_INTERVAL_AUTHS", "1 minute");
		}
	}
	itvltoa(block_interval_auth, temp_buff);
	printf("[smtp]: block client %s when authentification failure times "
			"is exceeded\n", temp_buff);

	str_val = resource_get_string("MAIL_MAX_LENGTH");
	if (str_val == NULL) {
		max_mail_len = 64*1024*1024; 
		resource_set_string("MAIL_MAX_LENGTH", "64M");
	} else {
		max_mail_len = atobyte(str_val);
		if (max_mail_len <= 0) {
			max_mail_len = 64*1024*1024; 
			resource_set_string("MAIL_MAX_LENGTH", "64M");
		}
	}
	bytetoa(max_mail_len, temp_buff);
	printf("[smtp]: maximum mail length is %s\n", temp_buff);

	if (!resource_get_integer("SMTP_MAX_MAIL_NUM", &smtp_max_mail_num)) {
		smtp_max_mail_num = 100;
		resource_set_integer("SMTP_MAX_MAIL_NUM", smtp_max_mail_num);
	}
	printf("[smtp]: maximum mails number for one session is %d\n",
		smtp_max_mail_num);
	 
	str_val = resource_get_string("BLOCK_INTERVAL_SESSIONS");
	if (str_val == NULL) {
		block_interval_sessions = 60;
		resource_set_string("BLOCK_INTERVAL_SESSIONS", "1minute");
	} else {
		block_interval_sessions = atoitvl(str_val);
		if (block_interval_sessions <= 0) {
			block_interval_sessions = 60;
			resource_set_string("BLOCK_INTERVAL_SESSIONS", "1minute");
		}
	}
	itvltoa(block_interval_sessions, temp_buff);
	printf("[smtp]: block remote side %s when mails number is exceed for one "
			"session\n", temp_buff);
	
	service_plugin_path = resource_get_string("SERVICE_PLUGIN_PATH");
	if (service_plugin_path == NULL) {
		service_plugin_path = PKGLIBDIR;
		resource_set_string("SERVICE_PLUGIN_PATH", service_plugin_path);
	}
	printf("[service]: service plugins path is %s\n", service_plugin_path);
	const char *str_value = resource_get_string("SERVICE_PLUGIN_LIST");
	const char *const *service_plugin_list = NULL;
	if (str_value != NULL) {
		service_plugin_list = const_cast<const char * const *>(read_file_by_line(str_value));
		if (service_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			return EXIT_FAILURE;
		}
	}
	str_value = resource_get_string("SERVICE_PLUGIN_IGNORE_ERRORS");
	bool svcplug_ignerr = parse_bool(str_value);
	resource_set_string("SERVICE_PLUGIN_IGNORE_ERRORS", svcplug_ignerr ? "true" : "false");

	flusher_plugin_path = resource_get_string("FLUSHER_PLUGIN_PATH");
	if (flusher_plugin_path == NULL) {
		flusher_plugin_path = PKGLIBDIR "/libgxf_message_enqueue.so";
		resource_set_string("FLUSHER_PLUGIN_PATH", flusher_plugin_path);
	}
	printf("[flusher]: flusher plugin path %s\n", flusher_plugin_path);

	const char *config_dir = str_val = resource_get_string("CONFIG_FILE_PATH");
	if (str_val == NULL) {
		config_dir = str_val = PKGSYSCONFDIR "/smtp:" PKGSYSCONFDIR;
		resource_set_string("CONFIG_FILE_PATH", str_val);
	}
	printf("[system]: config files path is %s\n", str_val);
	
	const char *data_dir = str_val = resource_get_string("DATA_FILE_PATH");
	if (str_val == NULL) {
		data_dir = str_val = PKGDATADIR "/smtp:" PKGDATADIR;
		resource_set_string("DATA_FILE_PATH", str_val);
	}
	printf("[system]: data files path is %s\n", str_val);
	
	const char *state_dir = str_val = resource_get_string("STATE_PATH");
	if (str_val == nullptr) {
		state_dir = PKGSTATEDIR;
		resource_set_string("STATE_PATH", state_dir);
	}
	printf("[system]: state path is %s\n", state_dir);

	console_server_ip = resource_get_string("CONSOLE_SERVER_IP");
	if (console_server_ip == NULL) {
		console_server_ip = "::1";
		resource_set_string("CONSOLE_SERVER_IP", console_server_ip);
	}
	if (!resource_get_integer("CONSOLE_SERVER_PORT", &console_server_port)) {
		console_server_port = 5566; 
		resource_set_integer("CONSOLE_SERVER_PORT", console_server_port);
	}
	printf("[console_server]: console server is address [%s]:%d\n",
	       *console_server_ip == '\0' ? "*" : console_server_ip, console_server_port);
	listener_init(listen_port, listen_ssl_port);
																			
	if (0 != listener_run()) {
		printf("[system]: fail to start listener\n");
		return EXIT_FAILURE;
	}
	auto cleanup_3 = make_scope_exit(listener_free);
	auto cleanup_4 = make_scope_exit(listener_stop);

	if (0 != getrlimit(RLIMIT_NOFILE, &rl)) {
		printf("[system]: fail to get file limitation\n");
		return EXIT_FAILURE;
	}
	if (rl.rlim_cur < context_num + 128 ||
		rl.rlim_max < context_num + 128) {
		rl.rlim_cur = context_num + 128;
		rl.rlim_max = context_num + 128;
		if (0 != setrlimit(RLIMIT_NOFILE, &rl)) {
			printf("[system]: fail to set file limitation\n");
		}
		printf("[system]: set file limitation to %d\n", context_num + 128);
	}
	if (*user_name != '\0') {
		puser_pass = getpwnam(user_name);
		if (NULL == puser_pass) {
			printf("[system]: no such user \"%s\"\n", user_name);
			return EXIT_FAILURE;
		}
		
		if (0 != setgid(puser_pass->pw_gid)) {
			printf("[system]: can not run group of \"%s\"\n", user_name);
			return EXIT_FAILURE;
		}
		if (0 != setuid(puser_pass->pw_uid)) {
			printf("[system]: can not run as \"%s\"\n", user_name);
			return EXIT_FAILURE;
		}
	}
	service_init({service_plugin_path, config_dir, data_dir, state_dir,
		service_plugin_list != NULL ? service_plugin_list : g_dfl_svc_plugins,
		svcplug_ignerr, context_num});
	printf("--------------------------- service plugins begin"
		   "---------------------------\n");
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

	files_allocator_init(context_num * 128);  
	if (0 != files_allocator_run()) { 
		printf("[system]: can not run file allocator\n"); 
		return EXIT_FAILURE;
	}
	auto cleanup_9 = make_scope_exit(files_allocator_free);
	auto cleanup_10 = make_scope_exit(files_allocator_stop);

	blocks_allocator_init(context_num * context_aver_mem);	   
 
	if (0 != blocks_allocator_run()) { 
		printf("[system]: can not run blocks allocator\n"); 
		return EXIT_FAILURE;
	}
	auto cleanup_11 = make_scope_exit(blocks_allocator_free);
	auto cleanup_12 = make_scope_exit(blocks_allocator_stop);
 
	if (0 == smtp_need_auth) {
		 smtp_auth_needed	 = FALSE;
	} else {
		smtp_auth_needed	 = TRUE;
	}
	
	threads_max_num	   = (0 == (context_num % thread_charge_num)) ? 
		(context_num / thread_charge_num) : 
		(context_num / thread_charge_num + 1);
							
	smtp_parser_init(context_num, threads_max_num, 
		domainlist_valid, smtp_auth_needed, max_mail_len,
		smtp_max_mail_num, block_interval_sessions, 
		context_max_mem, smtp_conn_timeout, smtp_auth_times,
		block_interval_auth, smtp_support_pipeline, smtp_support_starttls,
		smtp_force_starttls, certificate_path, cb_passwd, private_key_path);  
 
	if (0 != smtp_parser_run()) { 
		printf("[system]: failed to run smtp parser\n");
		return EXIT_FAILURE;
	}
	auto cleanup_15 = make_scope_exit(smtp_parser_free);
	auto cleanup_16 = make_scope_exit(smtp_parser_stop);
	
	contexts_pool_init(smtp_parser_get_contexts_list(),	 
		context_num, sizeof(SMTP_CONTEXT),
		reinterpret_cast<int (*)(void *)>(smtp_parser_get_context_socket),
		reinterpret_cast<timeval (*)(void *)>(smtp_parser_get_context_timestamp),
		thread_charge_num, smtp_conn_timeout); 
 
	if (0 != contexts_pool_run()) { 
		printf("[system]: failed to run contexts pool\n");
		return EXIT_FAILURE;
	}
	auto cleanup_17 = make_scope_exit(contexts_pool_free);
	auto cleanup_18 = make_scope_exit(contexts_pool_stop);

	flusher_init(flusher_plugin_path, context_num);
																			
	if (0 != flusher_run()) {
		printf("[system]: failed to run flusher\n");
		return EXIT_FAILURE;
	}
	auto cleanup_19 = make_scope_exit(flusher_free);
	auto cleanup_20 = make_scope_exit(flusher_stop);

	console_server_init(console_server_ip, console_server_port);
	console_server_register_command("return-code", cmd_handler_smtp_error_code_control);
	console_server_register_command("smtp", cmd_handler_smtp_control);
	console_server_register_command("system", cmd_handler_system_control);
	console_server_register_command("help", cmd_handler_help);
	console_server_register_command(nullptr, cmd_handler_service_plugins);

	if (0 != console_server_run()) {
		printf("[system]: failed to run console server\n");
		return EXIT_FAILURE;
	}
	auto cleanup_21 = make_scope_exit(console_server_free);
	auto cleanup_22 = make_scope_exit(console_server_stop);

	threads_pool_init(thread_init_num, reinterpret_cast<int (*)(SCHEDULE_CONTEXT *)>(smtp_parser_process));
	threads_pool_register_event_proc(smtp_parser_threads_event_proc);
	if (0 != threads_pool_run()) {
		printf("[system]: failed to run threads pool\n");
		return EXIT_FAILURE;
	}
	auto cleanup_25 = make_scope_exit(threads_pool_free);
	auto cleanup_26 = make_scope_exit(threads_pool_stop);

	/* accept the connection */
	if (0 != listerner_trigger_accept()) {
		printf("[system]: fail trigger accept\n");
		return EXIT_FAILURE;
	}
	
	retcode = EXIT_SUCCESS;
	printf("[system]: SMTP DAEMON is now running\n");
	while (FALSE == g_notify_stop) {
		sleep(3);
	}
	listener_stop_accept();
	return retcode;
} 

static void term_handler(int signo)
{
	console_server_notify_main_stop();
}


 
