#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <libHX/defs.h>
#include <libHX/option.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include "config_file.h"
#include "util.h"
#include "vstack.h"
#include "service.h"
#include "listener.h"
#include "resource.h"
#include "mod_cache.h"
#include "lib_buffer.h"
#include "mod_rewrite.h"
#include "mod_fastcgi.h"
#include "http_parser.h"
#include "threads_pool.h"
#include "hpm_processor.h"
#include "pdu_processor.h"
#include "contexts_pool.h"
#include "console_server.h"
#include "system_services.h"
#include "blocks_allocator.h"
#include <pwd.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#define PDU_PROCESSOR_RATIO			10

BOOL g_notify_stop = FALSE;
static char *opt_config_file;

static struct HXoption g_options_table[] = {
	{.sh = 'c', .type = HXTYPE_STRING, .ptr = &opt_config_file, .help = "Config file to read", .htyp = "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static const char *const g_dfl_hpm_plugins[] = {
	"libexhpm_proxy.so",
	NULL,
};

static const char *const g_dfl_proc_plugins[] = {
	"libexproc_exchange_emsmdb.so",
	"libexproc_exchange_nsp.so",
	"libexproc_exchange_rfr.so",
	NULL,
};

static const char *const g_dfl_svc_plugins[] = {
	"libexsvc_codepage_lang.so",
	"libexsvc_exmdb_provider.so",
	"libexsvc_ip_container.so",
	"libexsvc_ip_filter.so",
	"libexsvc_lang_charset.so",
	"libexsvc_log_plugin.so",
	"libexsvc_mime_extension.so",
	"libexsvc_ms_locale.so",
	"libexsvc_mysql_adaptor.so",
	"libexsvc_timer_agent.so",
	"libexsvc_user_filter.so",
	NULL,
};

typedef void (*STOP_FUNC)();

static void term_handler(int signo);

int main(int argc, const char **argv)
{
	struct rlimit rl;
	VSTACK stop_stack;
	const char *str_val;
	char temp_buff[256];
	LIB_BUFFER *allocator;
	uint64_t hpm_max_size;
	size_t max_request_mem;
	int retcode = EXIT_FAILURE, block_interval_auth;
	int console_server_port;
	uint64_t hpm_cache_size;
	int fastcgi_exec_timeout;
	uint64_t fastcgi_max_size;
	STOP_FUNC *stop, func_ptr;
	struct passwd *puser_pass;
	char cache_list_path[256];
	char rewrite_list_path[256];
	char fastcgi_list_path[256];
	uint64_t fastcgi_cache_size;
	const char *hpm_plugin_path;
	char host_name[256], *ptoken;
	const char *proc_plugin_path;
	const char *service_plugin_path;
	int context_num, context_aver_mem;
	int http_auth_times, http_conn_timeout;
	const char *console_server_ip, *user_name;
	int listen_port, listen_ssl_port, mss_size;
	const char *dns_name, *dns_domain, *netbios_name;
	int thread_init_num, thread_charge_num, http_support_ssl;
	const char *certificate_path, *cb_passwd, *private_key_path;
	
	

	allocator = vstack_allocator_init(sizeof(STOP_FUNC), 50, FALSE);    
	vstack_init(&stop_stack, allocator, sizeof(STOP_FUNC), 50);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, term_handler);
	resource_init(opt_config_file, config_default_path("http.cfg"));
 
	if (0 != resource_run()) { 
		printf("[system]: fail to load resource\n"); 
		goto EXIT_PROGRAM; 
	}
	func_ptr    = (STOP_FUNC)resource_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)resource_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	
	if (!resource_get_integer("LISTEN_PORT", &listen_port)) {
		listen_port = 80; 
		resource_set_integer("LISTEN_PORT", listen_port);
	}
	printf("[system]: system listening port %d\n", listen_port);

	if (!resource_get_integer("LISTEN_SSL_PORT", &listen_ssl_port))
		listen_ssl_port = 0;
	
	if (!resource_get_integer("TCP_MAX_SEGMENT", &mss_size)) {
		mss_size = 0;
	} else {
		printf("[system]: maximum TCP segment size is %d\n", mss_size);
	}

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
	strncpy(host_name, str_val, 256);
	dns_name = str_val;
	
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

	ptoken = strchr(host_name, '.');
	netbios_name = host_name;
	if (NULL == ptoken) {
		dns_domain = str_val; 
	} else {
		*ptoken = '\0';
		dns_domain = ptoken + 1;
	}
	
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
		if (context_aver_mem <= 2) {
			context_aver_mem = 4;
			resource_set_string("CONTEXT_AVERAGE_MEM", "256K");
		}
	}
	bytetoa(context_aver_mem*64*1024, temp_buff);
	printf("[http]: context average memory is %s\n", temp_buff);
	
	str_val = resource_get_string("HTTP_CONN_TIMEOUT");
	if (str_val == NULL) {
		http_conn_timeout = 180;
		resource_set_string("HTTP_CONN_TIMEOUT", "3minutes");
	} else {
		http_conn_timeout = atoitvl(str_val);
		if (http_conn_timeout < 30) {
			http_conn_timeout = 180;
			resource_set_string("HTTP_CONN_TIMEOUT", "3minutes");
		}
	}
	itvltoa(http_conn_timeout, temp_buff);
	printf("[http]: http socket read write time out is %s\n", temp_buff);
 
	if (!resource_get_integer("HTTP_AUTH_TIMES", &http_auth_times)) {
		http_auth_times = 10;
		resource_set_integer("HTTP_AUTH_TIMES", http_auth_times);
	} else {
		if (http_auth_times <= 0) {
			http_auth_times = 3;
			resource_set_integer("HTTP_AUTH_TIMES", http_auth_times);
		}
	}
	printf("[http]: maximum authentification failure times is %d\n", 
			http_auth_times);

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
	printf("[http]: block client %s when authentification failure times "
			"is exceeded\n", temp_buff);
	
	str_val = resource_get_string("HTTP_SUPPORT_SSL");
	if (str_val == NULL) {
		http_support_ssl = FALSE;
		resource_set_string("HTTP_SUPPORT_SSL", "FALSE");
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			http_support_ssl = FALSE;
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			http_support_ssl = TRUE;
		} else {
			http_support_ssl = FALSE;
			resource_set_string("HTTP_SUPPORT_SSL", "FALSE");
		}
	}
	certificate_path = resource_get_string("HTTP_CERTIFICATE_PATH");
	cb_passwd = resource_get_string("HTTP_CERTIFICATE_PASSWD");
	private_key_path = resource_get_string("HTTP_PRIVATE_KEY_PATH");
	if (TRUE == http_support_ssl) {
		if (NULL == certificate_path || NULL == private_key_path) {
			http_support_ssl = FALSE;
			printf("[http]: turn off TLS support because certificate or "
				"private key path is empty\n");
		} else {
			printf("[http]: http support TLS mode\n");
		}
	} else {
		printf("[http]: http doesn't support TLS mode\n");
	}

	if (FALSE == http_support_ssl && listen_ssl_port > 0) {
		listen_ssl_port = 0;
	}

	if (listen_ssl_port > 0) {
		printf("[system]: system SSL listening port %d\n", listen_ssl_port);
	}
	
	str_val = resource_get_string("REQUEST_MAX_MEM");
	if (str_val == NULL) {
		max_request_mem = 4 << 20;
		resource_set_string("REQUEST_MAX_MEM", "4M");
	} else {
		max_request_mem = atobyte(str_val);
		if (max_request_mem < 1024*1024) {
			max_request_mem = 1024*1024;
			resource_set_string("REQUEST_MAX_MEM", "1M");
		}
	}
	bytetoa(max_request_mem, temp_buff);
	printf("[pdu_processor]: maximum request memory is %s\n", temp_buff);

	proc_plugin_path = resource_get_string("PROC_PLUGIN_PATH");
	if (proc_plugin_path == NULL) {
		proc_plugin_path = PKGLIBDIR;
		resource_set_string("PROC_PLUGIN_PATH", proc_plugin_path);
	}
	const char *str_value = resource_get_string("PROC_PLUGIN_IGNORE_ERRORS");
	bool procplug_ignerr = parse_bool(str_value);
	resource_set_string("PROC_PLUGIN_IGNORE_ERRORS", procplug_ignerr ? "true" : "false");

	printf("[pdu_processor]: proc plugins path is %s\n", proc_plugin_path);
	str_value = resource_get_string("SERVICE_PLUGIN_LIST");
	const char *const *proc_plugin_list = NULL;
	if (str_value != NULL) {
		proc_plugin_list = const_cast(const char * const *, read_file_by_line(str_value));
		if (proc_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			goto EXIT_PROGRAM;
		}
	}
	str_value = resource_get_string("SERVICE_PLUGIN_IGNORE_ERRORS");
	bool svcplug_ignerr = parse_bool(str_value);
	resource_set_string("SERVICE_PLUGIN_IGNORE_ERRORS", svcplug_ignerr ? "true" : "false");
	
	hpm_plugin_path = resource_get_string("HPM_PLUGIN_PATH");
	if (hpm_plugin_path == NULL) {
		hpm_plugin_path = PKGLIBDIR;
		resource_set_string("HPM_PLUGIN_PATH", hpm_plugin_path);
	}
	printf("[hpm_processor]: hpm plugins path is %s\n", hpm_plugin_path);
	str_value = resource_get_string("HPM_PLUGIN_LIST");
	const char *const *hpm_plugin_list = NULL;
	if (str_value != NULL) {
		hpm_plugin_list = const_cast(const char * const *, read_file_by_line(str_value));
		if (hpm_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			goto EXIT_PROGRAM;
		}
	}
	str_value = resource_get_string("HPM_PLUGIN_IGNORE_ERRORS");
	bool hpmplug_ignerr = parse_bool(str_value);
	resource_set_string("HPM_PLUGIN_IGNORE_ERRORS", hpmplug_ignerr ? "true" : "false");
	
	str_val = resource_get_string("HPM_CACHE_SIZE");
	if (str_val == NULL) {
		hpm_cache_size = 512 << 10;
		resource_set_string("HPM_CACHE_SIZE", "512K");
	} else {
		hpm_cache_size = atobyte(str_val);
		if (hpm_cache_size < 64*1024) {
			hpm_cache_size = 256*1024;
			resource_set_string("HPM_CACHE_SIZE", "256K");
		}
	}
	bytetoa(hpm_cache_size, temp_buff);
	printf("[hpm_processor]: fastcgi cache size is %s\n", temp_buff);
	
	str_val = resource_get_string("HPM_MAX_SIZE");
	if (str_val == NULL) {
		hpm_max_size = 4 << 20;
		resource_set_string("HPM_MAX_SIZE", "4M");
	} else {
		hpm_max_size = atobyte(str_val);
		if (hpm_max_size < 64*1024) {
			hpm_max_size = 1024*1024;
			resource_set_string("HPM_MAX_SIZE", "1M");
		}
	}
	bytetoa(hpm_max_size, temp_buff);
	printf("[hpm_processor]: hpm maximum size is %s\n", temp_buff);

	service_plugin_path = resource_get_string("SERVICE_PLUGIN_PATH");
	if (service_plugin_path == NULL) {
		service_plugin_path = PKGLIBDIR;
		resource_set_string("SERVICE_PLUGIN_PATH", service_plugin_path);
	}
	printf("[service]: service plugins path is %s\n", service_plugin_path);
	str_value = resource_get_string("SERVICE_PLUGIN_LIST");
	const char *const *service_plugin_list = NULL;
	if (str_value != NULL) {
		service_plugin_list = const_cast(const char * const *, read_file_by_line(str_value));
		if (service_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			goto EXIT_PROGRAM;
		}
	}

	str_val = resource_get_string("CONFIG_FILE_PATH");
	if (str_val == NULL) {
		str_val = PKGSYSCONFHTTPDIR;
		resource_set_string("CONFIG_FILE_PATH", str_val);
	}
	printf("[system]: config files path is %s\n", str_val);
	
	str_val = resource_get_string("DATA_FILE_PATH");
	if (str_val == NULL) {
		str_val = PKGDATAHTTPDIR;
		resource_set_string("DATA_FILE_PATH", str_val);
	}
	sprintf(fastcgi_list_path, "%s/fastcgi.txt", str_val);
	sprintf(cache_list_path, "%s/cache.txt", str_val);
	sprintf(rewrite_list_path, "%s/rewrite.txt", str_val);
	printf("[system]: data files path is %s\n", str_val);
	
	console_server_ip = resource_get_string("CONSOLE_SERVER_IP");
	if (console_server_ip == NULL) {
		console_server_ip = "127.0.0.1"; 
		resource_set_string("CONSOLE_SERVER_IP", console_server_ip);
	}
	printf("[console_server]: console server ipaddr %s\n", console_server_ip);
 
	if (!resource_get_integer("CONSOLE_SERVER_PORT", &console_server_port)) {
		console_server_port = 8899; 
		resource_set_integer("CONSOLE_SERVER_PORT", console_server_port);
	}
	printf("[console_server]: console server is port %d\n",
		console_server_port);
	
	str_val = resource_get_string("FASTCGI_CACHE_SIZE");
	if (str_val == NULL) {
		fastcgi_cache_size = 256*1024;
		resource_set_string("FASTCGI_CACHE_SIZE", "256K");
	} else {
		fastcgi_cache_size = atobyte(str_val);
		if (fastcgi_cache_size < 64*1024) {
			fastcgi_cache_size = 256*1024;
			resource_set_string("FASTCGI_CACHE_SIZE", "256K");
		}
	}
	bytetoa(fastcgi_cache_size, temp_buff);
	printf("[mod_fastcgi]: fastcgi cache size is %s\n", temp_buff);
	
	str_val = resource_get_string("FASTCGI_MAX_SIZE");
	if (str_val == NULL) {
		fastcgi_max_size = 4 << 20;
		resource_set_string("FASTCGI_MAX_SIZE", "4M");
	} else {
		fastcgi_max_size = atobyte(str_val);
		if (fastcgi_max_size < 64*1024) {
			fastcgi_max_size = 1024*1024;
			resource_set_string("FASTCGI_MAX_SIZE", "1M");
		}
	}
	bytetoa(fastcgi_max_size, temp_buff);
	printf("[mod_fastcgi]: fastcgi maximum size is %s\n", temp_buff);
	
	str_val = resource_get_string("FASTCGI_EXEC_TIMEOUT");
	if (str_val == NULL) {
		fastcgi_exec_timeout = 600;
		resource_set_string("FASTCGI_EXEC_TIMEOUT", "10minutes");
	} else {
		fastcgi_exec_timeout = atoitvl(str_val);
		if (fastcgi_exec_timeout < 60) {
			fastcgi_exec_timeout = 600;
			resource_set_string("FASTCGI_EXEC_TIMEOUT", "10minutes");
		}
	}
	itvltoa(fastcgi_exec_timeout, temp_buff);
	printf("[http]: fastcgi excution time out is %s\n", temp_buff);
	listener_init(listen_port, listen_ssl_port, mss_size);
																			
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
	if (rl.rlim_cur < 5*context_num + 256 ||
		rl.rlim_max < 5*context_num + 256) {
		rl.rlim_cur = 5*context_num + 256;
		rl.rlim_max = 5*context_num + 256;
		if (0 != setrlimit(RLIMIT_NOFILE, &rl)) {
			printf("[system]: fail to set file limitation\n");
			goto EXIT_PROGRAM;
		}
		printf("[system]: set file limitation to %d\n", 5*context_num + 256);
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
		printf("[system]: failed to run service\n");
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
		printf("[system]: failed to run system service\n");
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run system service OK\n");
	}

	func_ptr    = (STOP_FUNC)system_services_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)system_services_stop;
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

	pdu_processor_init(context_num, PDU_PROCESSOR_RATIO, netbios_name,
		dns_name, dns_domain, TRUE, max_request_mem, proc_plugin_path,
		proc_plugin_list != NULL ? proc_plugin_list : g_dfl_proc_plugins,
		procplug_ignerr);
	printf("---------------------------- proc plugins begin "
		   "----------------------------\n");
	if (0 != pdu_processor_run()) {
		printf("----------------------------- proc plugins end "
		   "-----------------------------\n");
		printf("[system]: can not run pdu processor\n");
		goto EXIT_PROGRAM;
	} else {
		printf("----------------------------- proc plugins end "
		   "-----------------------------\n");
		printf("[system run pdu processor OK\n");
	}
	
	func_ptr	= (STOP_FUNC)pdu_processor_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)pdu_processor_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	
	hpm_processor_init(context_num, hpm_plugin_path,
		hpm_plugin_list != NULL ? hpm_plugin_list : g_dfl_hpm_plugins,
		hpm_cache_size, hpm_max_size, hpmplug_ignerr);
	printf("---------------------------- hpm plugins begin "
		   "----------------------------\n");
	if (0 != hpm_processor_run()) {
		printf("----------------------------- hpm plugins end "
		   "-----------------------------\n");
		printf("[system]: can not run hpm processor\n");
		goto EXIT_PROGRAM;
	} else {
		printf("----------------------------- hpm plugins end "
		   "-----------------------------\n");
		printf("[system run hpm processor OK\n");
	}
	
	func_ptr	= (STOP_FUNC)hpm_processor_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)hpm_processor_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	
	mod_rewrite_init(rewrite_list_path);
	
	if (0 != mod_rewrite_run()) {
		printf("[system]: failed to run mod rewrite\n");
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run mod rewrite OK\n");
	}
	
	func_ptr    = (STOP_FUNC)mod_rewrite_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)mod_rewrite_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	
	mod_fastcgi_init(context_num,
		fastcgi_list_path, fastcgi_cache_size,
		fastcgi_max_size, fastcgi_exec_timeout); 
 
	if (0 != mod_fastcgi_run()) { 
		printf("[system]: failed to run mod fastcgi\n");
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run mod fastcgi OK\n");
	}
																	  
	func_ptr    = (STOP_FUNC)mod_fastcgi_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)mod_fastcgi_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	
	mod_cache_init(context_num, cache_list_path);
	
	if (0 != mod_cache_run()) {
		printf("[system]: failed to run mod cache\n");
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run mod cache OK\n");
	}
	
	func_ptr    = (STOP_FUNC)mod_cache_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)mod_cache_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	http_parser_init(context_num, http_conn_timeout,
		http_auth_times, block_interval_auth, http_support_ssl,
		certificate_path, cb_passwd, private_key_path);  
 
	if (0 != http_parser_run()) { 
		printf("[system]: failed to run http parser\n");
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run http parser OK\n");
	}
																	  
	func_ptr    = (STOP_FUNC)http_parser_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)http_parser_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	
	contexts_pool_init(http_parser_get_contexts_list(),
		context_num, sizeof(HTTP_CONTEXT),
		(void*)http_parser_get_context_socket,
		(void*)http_parser_get_context_timestamp,
		thread_charge_num, http_conn_timeout); 
 
	if (0 != contexts_pool_run()) { 
		printf("[system]: failed to run contexts pool\n");
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
		printf("[system]: failed to run console server\n");
		goto EXIT_PROGRAM;
	} else {
		printf("[system]: run console server OK\n");
	}

	func_ptr    = (STOP_FUNC)console_server_free;
	vstack_push(&stop_stack, (void*)&func_ptr);

	func_ptr    = (STOP_FUNC)console_server_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	
	threads_pool_init(thread_init_num, (void*)http_parser_process);

	threads_pool_register_event_proc(http_parser_threads_event_proc);
	if (0 != threads_pool_run()) {
		printf("[system]: failed to run threads pool\n");
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
	
	retcode = EXIT_SUCCESS;
	printf("[system]: HTTP DAEMON is now running\n");
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
	return retcode;
} 

static void term_handler(int signo)
{
	http_parser_shutdown_async();
	console_server_notify_main_stop();
}

