#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <libHX/defs.h>
#include <libHX/option.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include "config_file.h"
#include "listener.h" 
#include "resource.h" 
#include "pop3_parser.h" 
#include "units_allocator.h" 
#include "blocks_allocator.h" 
#include "threads_pool.h" 
#include "console_server.h" 
#include "contexts_pool.h" 
#include "service.h" 
#include "system_services.h"
#include "util.h"
#include "vstack.h"
#include "lib_buffer.h"
#include <pwd.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

BOOL g_notify_stop = FALSE;
static char *opt_config_file;

static struct HXoption g_options_table[] = {
	{.sh = 'c', .type = HXTYPE_STRING, .ptr = &opt_config_file, .help = "Config file to read", .htyp = "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static const char *const g_dfl_svc_plugins[] = {
	"libmrasvc_event_proxy.so",
	"libmrasvc_ip_container.so",
	"libmrasvc_ip_filter.so",
	"libmrasvc_log_plugin.so",
	"libmrasvc_midb_agent.so",
	"libmrasvc_mysql_adaptor.so",
	"libmrasvc_user_filter.so",
	NULL,
};

typedef void (*STOP_FUNC)();

static void term_handler(int signo);

int main(int argc, const char **argv)
{ 
	int context_num, context_aver_units;
	size_t context_max_mem;
	size_t context_aver_mem;
	int listen_port, listen_ssl_port;
	int pop3_auth_times, pop3_conn_timeout;
	int thread_init_num, thread_charge_num; 
	int pop3_support_stls, pop3_force_stls;
	const char *service_plugin_path, *cdn_cache_path; 
	const char *console_server_ip, *user_name;
	const char *certificate_path, *cb_passwd, *private_key_path;
	int block_interval_auth;
	int console_server_port; 
	struct rlimit rl;
	struct passwd *puser_pass;
	const char *str_val;
	char temp_buff[256];
	LIB_BUFFER *allocator;
	VSTACK stop_stack;
	STOP_FUNC *stop, func_ptr;

	allocator = vstack_allocator_init(sizeof(STOP_FUNC), 50, FALSE);    
	vstack_init(&stop_stack, allocator, sizeof(STOP_FUNC), 50);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, term_handler);
	resource_init(opt_config_file, config_default_path("pop3.cfg"));
	if (0 != resource_run()) { 
		printf("[system]: fail to load resource\n"); 
		goto EXIT_PROGRAM; 
	}
	func_ptr    = (STOP_FUNC)resource_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)resource_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	
	if (!resource_get_integer("LISTEN_PORT", &listen_port)) {
		listen_port = 110; 
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
	if (user_name == nullptr)
		user_name = "gromox";
	if (*user_name == '\0')
		printf("[system]: running identity will not be changed\n");
	else
		printf("[system]: running identity of process will be %s\n", user_name);

	if (!resource_get_integer("CONTEXT_NUM", &context_num)) {
		context_num = 200;
		resource_set_integer("CONTEXT_NUM", context_num);
	}
	printf("[system]: total contexts number is %d\n", context_num);

	if (!resource_get_integer("THREAD_CHARGE_NUM", &thread_charge_num)) {
		thread_charge_num = 40; 
		resource_set_integer("THREAD_CHARGE_NUM", thread_charge_num);
	} else {
		if (thread_charge_num < 4) {
			thread_charge_num = 40;	
			resource_set_integer("THREAD_CHARGE_NUM", thread_charge_num);
		} else if (thread_charge_num % 4 != 0) {
			thread_charge_num = ((int)(thread_charge_num / 4)) * 4;
			resource_set_integer("THREAD_CHARGE_NUM", thread_charge_num);
		}
	}
	printf("[system]: one thread is in charge of %d contexts\n",
		thread_charge_num);
	
	if (!resource_get_integer("THREAD_INIT_NUM", &thread_init_num)) {
		thread_init_num = 1; 
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
	printf("[pop3]: context average memory is %s\n", temp_buff);
 
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
	printf("[pop3]: context maximum memory is %s\n", temp_buff);

	if (!resource_get_integer("CONTEXT_AVERAGE_UNITS", &context_aver_units)) {
		context_aver_units = 1024;
		resource_set_integer("CONTEXT_AVERAGE_UNITS", context_aver_units);
	} else {
		if (context_aver_units < 256) {
			context_aver_units = 256;
			resource_set_integer("CONTEXT_AVERAGE_UNITS", context_aver_units);
		}
	}
	printf("[pop3]: context average units number is %d\n", context_aver_units);
	
	str_val = resource_get_string("POP3_CONN_TIMEOUT");
	if (str_val == NULL) {
		pop3_conn_timeout = 180;
		resource_set_string("POP3_CONN_TIMEOUT", "3minutes");
	} else {
		pop3_conn_timeout = atoitvl(str_val);
		if (pop3_conn_timeout <= 0) {
			pop3_conn_timeout = 180;
			resource_set_string("POP3_CONN_TIMEOUT", "3minutes");
		}
	}
	itvltoa(pop3_conn_timeout, temp_buff);
	printf("[pop3]: pop3 socket read write time out is %s\n", temp_buff);
 
	if (!resource_get_integer("POP3_AUTH_TIMES", &pop3_auth_times)) {
		pop3_auth_times = 3; 
		resource_set_integer("POP3_AUTH_TIMES", pop3_auth_times);
	} else {
		if (pop3_auth_times <= 0) {
			pop3_auth_times = 3;
			resource_set_integer("POP3_AUTH_TIMES", pop3_auth_times);
		}
	}
	printf("[pop3]: maximum authentification failure times is %d\n", 
			pop3_auth_times);

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
	printf("[pop3]: block client %s when authentification failure times "
			"is exceeded\n", temp_buff);

	str_val = resource_get_string("POP3_SUPPORT_STLS");
	if (str_val == NULL) {
		pop3_support_stls = FALSE;
		resource_set_string("POP3_SUPPORT_STLS", "FALSE");
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			pop3_support_stls = FALSE;
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			pop3_support_stls = TRUE;
		} else {
			pop3_support_stls = FALSE;
			resource_set_string("POP3_SUPPORT_STLS", "FALSE");
		}
	}
	certificate_path = resource_get_string("POP3_CERTIFICATE_PATH");
	cb_passwd = resource_get_string("POP3_CERTIFICATE_PASSWD");
	private_key_path = resource_get_string("POP3_PRIVATE_KEY_PATH");
	if (TRUE == pop3_support_stls) {
		if (NULL == certificate_path || NULL == private_key_path) {
			pop3_support_stls = FALSE;
			printf("[pop3]: turn off TLS support because certificate or "
				"private key path is empty\n");
		} else {
			printf("[pop3]: pop3 support TLS mode\n");
		}
	} else {
		printf("[pop3]: pop3 doesn't support TLS mode\n");
	}
	
	str_val = resource_get_string("POP3_FORCE_STLS");
	if (str_val == NULL) {
		pop3_force_stls = FALSE;
		resource_set_string("POP3_FORCE_STLS", "FALSE");
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			pop3_force_stls = FALSE;
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			pop3_force_stls = TRUE;
		} else {
			pop3_force_stls = FALSE;
			resource_set_string("POP3_FORCE_STLS", "FALSE");
		}
	}
	
	if (TRUE == pop3_support_stls && TRUE == pop3_force_stls) {
		printf("[pop3]: pop3 MUST running in TLS mode\n");
	}

	if (FALSE == pop3_support_stls && listen_ssl_port > 0) {
		listen_ssl_port = 0;
	}

	if (listen_ssl_port > 0) {
		printf("[system]: system SSL listening port %d\n", listen_ssl_port);
	}

	cdn_cache_path = resource_get_string("CDN_CACHE_PATH");
	if (cdn_cache_path == NULL) {
		cdn_cache_path = "/cdn";
		resource_set_string("CDN_CACHE_PATH", cdn_cache_path);
	}
	printf("[system]: cdn cache path is %s\n", cdn_cache_path);

	service_plugin_path = resource_get_string("SERVICE_PLUGIN_PATH");
	if (service_plugin_path == NULL) {
		service_plugin_path = PKGLIBDIR;
		resource_set_string("SERVICE_PLUGIN_PATH", service_plugin_path);
	}
	printf("[service]: service plugins path is %s\n", service_plugin_path);
	const char *str_value = resource_get_string("SERVICE_PLUGIN_LIST");
	const char *const *service_plugin_list = NULL;
	if (str_value != NULL) {
		service_plugin_list = const_cast(const char *const *, read_file_by_line(str_value));
		if (service_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			goto EXIT_PROGRAM;
		}
	}
	str_value = resource_get_string("SERVICE_PLUGIN_IGNORE_ERRORS");
	bool svcplug_ignerr = parse_bool(str_value);
	resource_set_string("SERVICE_PLUGIN_IGNORE_ERRORS", svcplug_ignerr ? "true" : "false");

	str_val = resource_get_string("CONFIG_FILE_PATH");
	if (str_val == NULL) {
		str_val = PKGSYSCONFPOP3DIR;
		resource_set_string("CONFIG_FILE_PATH", str_val);
	}
	printf("[system]: config files path is %s\n", str_val);
	
	str_val = resource_get_string("DATA_FILE_PATH");
	if (str_val == NULL) {
		str_val = PKGDATAPOP3DIR;
		resource_set_string("DATA_FILE_PATH", str_val);
	}
	printf("[system]: data files path is %s\n", str_val);
	
	console_server_ip = resource_get_string("CONSOLE_SERVER_IP");
	if (console_server_ip == NULL) {
		console_server_ip = "127.0.0.1"; 
		resource_set_string("CONSOLE_SERVER_IP", console_server_ip);
	}
	printf("[console_server]: console server ipaddr %s\n", console_server_ip);
 
	if (!resource_get_integer("CONSOLE_SERVER_PORT", &console_server_port)) {
		console_server_port = 7788; 
		resource_set_integer("CONSOLE_SERVER_PORT", console_server_port);
	}
	printf("[console_server]: console server is port %d\n",
		console_server_port);
	listener_init(listen_port, listen_ssl_port);
																			
	if (0 != listener_run()) {
		printf("[system]: fail to start listener\n");
		goto EXIT_PROGRAM;
	} else {
		printf("[system]: listener start OK\n");
	}

	func_ptr    = (STOP_FUNC)listener_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)listener_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	if (0 != getrlimit(RLIMIT_NOFILE, &rl)) {
		printf("[system]: fail to get file limitation\n");
		goto EXIT_PROGRAM;
	}
	if (rl.rlim_cur < 2*context_num + 128 ||
		rl.rlim_max < 2*context_num + 128) {
		rl.rlim_cur = 2*context_num + 128;
		rl.rlim_max = 2*context_num + 128;
		if (0 != setrlimit(RLIMIT_NOFILE, &rl)) {
			printf("[system]: fail to set file limitation\n");
			goto EXIT_PROGRAM;
		}
		printf("[system]: set file limitation to %d\n", 2*context_num + 128);
	}
	if (*user_name != '\0') {
		puser_pass = getpwnam(user_name);
		if (NULL == puser_pass) {
			printf("[system]: no such user \"%s\"\n", user_name);
			goto EXIT_PROGRAM;
		}
		
		if (0 != setgid(puser_pass->pw_gid)) {
			printf("[system]: can not run group of \"%s\"\n", user_name);
			goto EXIT_PROGRAM;
		}
		if (0 != setuid(puser_pass->pw_uid)) {
			printf("[system]: can not run as \"%s\"\n", user_name);
			goto EXIT_PROGRAM;
		}
	}
	service_init(context_num, service_plugin_path,
		service_plugin_list != NULL ? service_plugin_list : g_dfl_svc_plugins,
		svcplug_ignerr);
	printf("--------------------------- service plugins begin"
		   "---------------------------\n");
	if (0 != service_run()) { 
		printf("---------------------------- service plugins end"
		   "----------------------------\n");
		printf("[system]: fail to run service\n"); 
		goto EXIT_PROGRAM; 
	} else {
		printf("---------------------------- service plugins end"
		   "----------------------------\n");
		printf("[system]: run service OK\n");
	}

	func_ptr    = (STOP_FUNC)service_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)service_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	
	system_services_init();
	if (0 != system_services_run()) { 
		printf("[system]: fail to run system service\n"); 
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run system service OK\n");
	}

	func_ptr    = (STOP_FUNC)system_services_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)system_services_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	units_allocator_init(context_num * context_aver_units);
	if (0 != units_allocator_run()) { 
		printf("[system]: can not run units allocator\n"); 
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run units allocator OK\n");
	}

	func_ptr    = (STOP_FUNC)units_allocator_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)units_allocator_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	blocks_allocator_init(context_num * context_aver_mem);     
 
	if (0 != blocks_allocator_run()) { 
		printf("[system]: can not run blocks allocator\n"); 
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run blocks allocator OK\n");
	}

	func_ptr    = (STOP_FUNC)blocks_allocator_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)blocks_allocator_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	pop3_parser_init(context_num, context_max_mem, pop3_conn_timeout,
		pop3_auth_times, block_interval_auth, pop3_support_stls,
		pop3_force_stls, certificate_path, cb_passwd,
		private_key_path, cdn_cache_path);  
 
	if (0 != pop3_parser_run()) { 
		printf("[system]: fail to run pop3 parser\n"); 
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run pop3 parser OK\n");
	}
																	  
	func_ptr    = (STOP_FUNC)pop3_parser_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)pop3_parser_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	
	contexts_pool_init(pop3_parser_get_contexts_list(),  
		context_num, sizeof(POP3_CONTEXT),
		(void*)pop3_parser_get_context_socket,
		(void*)pop3_parser_get_context_timestamp,
		thread_charge_num, pop3_conn_timeout); 
 
	if (0 != contexts_pool_run()) { 
		printf("[system]: fail to run contexts pool\n"); 
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run contexts pool OK\n");
	}
	func_ptr    = (STOP_FUNC)contexts_pool_free; 
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)contexts_pool_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
 

	console_server_init(console_server_ip, console_server_port);

	if (0 != console_server_run()) {
		printf("[system]: fail to run console server\n");
		goto EXIT_PROGRAM;
	} else {
		printf("[system]: run console server OK\n");
	}

	func_ptr    = (STOP_FUNC)console_server_free;
	vstack_push(&stop_stack, (void*)&func_ptr);

	func_ptr    = (STOP_FUNC)console_server_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	
	threads_pool_init(thread_init_num, (void*)pop3_parser_process);

	threads_pool_register_event_proc(pop3_parser_threads_event_proc);
	if (0 != threads_pool_run()) {
		printf("[system]: fail to run threads pool\n");
		goto EXIT_PROGRAM;
	} else {
		printf("[system]: run threads pool OK\n");
	}
	func_ptr    = (STOP_FUNC)threads_pool_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)threads_pool_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	/* accept the connection */
	if (0 != listerner_trigger_accept()) {
		printf("[system]: fail trigger accept\n");
		goto EXIT_PROGRAM;
	}
	
	printf("[system]: POP3 DAEMON is now running\n");
	while (FALSE == g_notify_stop) {
		sleep(3);
	}
	listener_stop_accept();
	
EXIT_PROGRAM:

	while (FALSE == vstack_is_empty(&stop_stack)) {
		stop = vstack_get_top(&stop_stack);
		(*stop)();
		vstack_pop(&stop_stack);
	}

	vstack_free(&stop_stack);
	vstack_allocator_free(allocator);
	return 0;
} 

static void term_handler(int signo)
{
	console_server_notify_main_stop();
}


 
