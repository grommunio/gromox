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
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

#define PDU_PROCESSOR_RATIO			10

/* the only global variable in system to indicate the program to exit */
BOOL g_notify_stop = FALSE;

typedef void (*STOP_FUNC)();

static void term_handler(int signo);

int main(int argc, char* argv[]) 
{
	struct rlimit rl;
	VSTACK stop_stack;
	const char *str_val;
	char temp_buff[256];
	LIB_BUFFER *allocator;
	uint64_t hpm_max_size;
	size_t max_request_mem;
	int block_interval_auth;
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
	if (argc != 2) { 
		printf("%s <cfg file>\n", argv[0]); 
		exit(1); 
	} 
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, term_handler);
	resource_init(argv[1]); 
 
	if (0 != resource_run()) { 
		printf("[system]: fail to load resource\n"); 
		goto EXIT_PROGRAM; 
	}
	func_ptr    = (STOP_FUNC)resource_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr    = (STOP_FUNC)resource_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	

	if (FALSE == resource_get_integer(RES_LISTEN_PORT, &listen_port)) { 
		listen_port = 80; 
		resource_set_integer(RES_LISTEN_PORT, 80);
	}
	printf("[system]: system listening port %d\n", listen_port);

	if (FALSE == resource_get_integer(RES_LISTEN_SSL_PORT, &listen_ssl_port)) {
		listen_ssl_port = 0;
	}
	
	if (FALSE == resource_get_integer(RES_TCP_MAX_SEGMENT, &mss_size)) {
		mss_size = 0;
	} else {
		printf("[system]: maximum TCP segment size is %d\n", mss_size);
	}

	if (NULL == (str_val = resource_get_string(RES_HOST_ID))) { 
		memset(temp_buff, 0, 256);
		gethostname(temp_buff, 256);
		resource_set_string(RES_HOST_ID, temp_buff);
		str_val = temp_buff;
		printf("[system]: warning! cannot find host ID, OS host name will be "
			"used as host ID\n");
	}
	printf("[system]: host ID is %s\n", str_val);
	strncpy(host_name, str_val, 256);
	dns_name = str_val;
	
	if (NULL == (str_val = resource_get_string(RES_DEFAULT_DOMAIN))) {
		memset(temp_buff, 0, 256);
		getdomainname(temp_buff, 256);
		resource_set_string(RES_DEFAULT_DOMAIN, temp_buff);
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
	
	
	if (NULL == (user_name = resource_get_string(RES_RUNNING_IDENTITY))) {
		printf("[system]: running identity will not be changed\n");
	} else {
		printf("[system]: running identity of process will be %s\n", user_name);
	}

	if (FALSE == resource_get_integer(RES_CONTEXT_NUM, &context_num)) { 
		context_num = 200;
		resource_set_integer(RES_CONTEXT_NUM, 200);
	}
	printf("[system]: total contexts number is %d\n", context_num);

	if (FALSE == resource_get_integer(RES_THREAD_CHARGE_NUM, 
		&thread_charge_num)) { 
		thread_charge_num = 40; 
		resource_set_integer(RES_THREAD_CHARGE_NUM, 40);
	} else {
		if (thread_charge_num < 4) {
			thread_charge_num = 40;
			resource_set_integer(RES_THREAD_CHARGE_NUM, 40);
		} else if (thread_charge_num % 4 != 0) {
			thread_charge_num = ((int)(thread_charge_num / 4)) * 4;
			resource_set_integer(RES_THREAD_CHARGE_NUM, thread_charge_num);
		}
	}
	printf("[system]: one thread is in charge of %d contexts\n",
		thread_charge_num);
	
	if (FALSE == resource_get_integer(RES_THREAD_INIT_NUM, 
		&thread_init_num)) { 
		thread_init_num = 1; 
		resource_set_integer(RES_THREAD_INIT_NUM, 1);
	}
	if (thread_init_num * thread_charge_num > context_num) {
		thread_init_num = context_num / thread_charge_num;
		if (0 == thread_init_num) {
			thread_init_num = 1;
			context_num = thread_charge_num;
			resource_set_integer(RES_CONTEXT_NUM, context_num);
			printf("[system]: rectify contexts number %d\n", context_num);
		}
		resource_set_integer(RES_THREAD_INIT_NUM, thread_init_num);
	}
	printf("[system]: threads pool initial threads number is %d\n",
		thread_init_num);

	if (NULL == (str_val = resource_get_string(RES_CONTEXT_AVERAGE_MEM))) { 
		context_aver_mem = 4;
		resource_set_string(RES_CONTEXT_AVERAGE_MEM, "256K");
	} else {
		context_aver_mem = atobyte(str_val)/(64*1024);
		if (context_aver_mem <= 2) {
			context_aver_mem = 4;
			resource_set_string(RES_CONTEXT_AVERAGE_MEM, "256K");
		}
	}
	bytetoa(context_aver_mem*64*1024, temp_buff);
	printf("[http]: context average memory is %s\n", temp_buff);
	
	if (NULL == (str_val = resource_get_string(RES_HTTP_CONN_TIMEOUT))) {
		http_conn_timeout = 180;
		resource_set_string(RES_HTTP_CONN_TIMEOUT, "3minutes");
	} else {
		http_conn_timeout = atoitvl(str_val);
		if (http_conn_timeout < 30) {
			http_conn_timeout = 180;
			resource_set_string(RES_HTTP_CONN_TIMEOUT, "3minutes");
		}
	}
	itvltoa(http_conn_timeout, temp_buff);
	printf("[http]: http socket read write time out is %s\n", temp_buff);
 
 
	if (FALSE == resource_get_integer(RES_HTTP_AUTH_TIMES, 
		&http_auth_times)) { 
		http_auth_times = 3; 
		resource_set_integer(RES_HTTP_AUTH_TIMES, 3);
	} else {
		if (http_auth_times <= 0) {
			http_auth_times = 3;
			resource_set_integer(RES_HTTP_AUTH_TIMES, 3);
		}
	}
	printf("[http]: maximum authentification failure times is %d\n", 
			http_auth_times);

	if (NULL == (str_val = resource_get_string(RES_BLOCK_INTERVAL_AUTHS))) { 
		block_interval_auth = 60;
		resource_set_string(RES_BLOCK_INTERVAL_AUTHS, "1 minute");
	} else {
		block_interval_auth = atoitvl(str_val);
		if (block_interval_auth <= 0) {
			block_interval_auth = 60;
			resource_set_string(RES_BLOCK_INTERVAL_AUTHS, "1 minute");
		}
	}
	itvltoa(block_interval_auth, temp_buff);
	printf("[http]: block client %s when authentification failure times "
			"is exceeded\n", temp_buff);
	
	if (NULL == (str_val = resource_get_string(RES_HTTP_SUPPORT_SSL))) {
		http_support_ssl = FALSE;
		resource_set_string(RES_HTTP_SUPPORT_SSL, "FALSE");
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			http_support_ssl = FALSE;
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			http_support_ssl = TRUE;
		} else {
			http_support_ssl = FALSE;
			resource_set_string(RES_HTTP_SUPPORT_SSL, "FALSE");
		}
	}
	certificate_path = resource_get_string(RES_HTTP_CERTIFICATE_PATH);
	cb_passwd = resource_get_string(RES_HTTP_CERTIFICATE_PASSWD);
	private_key_path = resource_get_string(RES_HTTP_PRIVATE_KEY_PATH);
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
	
	if (NULL == (str_val = resource_get_string(RES_REQUEST_MAX_MEM))) { 
		max_request_mem = 64*1024*1024;
		resource_set_string(RES_REQUEST_MAX_MEM, "64M");
	} else {
		max_request_mem = atobyte(str_val);
		if (max_request_mem < 1024*1024) {
			max_request_mem = 1024*1024;
			resource_set_string(RES_REQUEST_MAX_MEM, "1M");
		}
	}
	bytetoa(max_request_mem, temp_buff);
	printf("[pdu_processor]: maximum request memory is %s\n", temp_buff);

	if (NULL == (proc_plugin_path = resource_get_string(
		RES_PROC_PLUGIN_PATH))) {
		proc_plugin_path = "../proc_plugins";
		resource_set_string(RES_PROC_PLUGIN_PATH, "../proc_plugins");
	}
	printf("[pdu_processor]: proc plugins path is %s\n", proc_plugin_path);
	
	if (NULL == (hpm_plugin_path = resource_get_string(
		RES_HPM_PLUGIN_PATH))) {
		hpm_plugin_path = "../hpm_plugins";
		resource_set_string(RES_HPM_PLUGIN_PATH, "../hpm_plugins");
	}
	printf("[hpm_processor]: hpm plugins path is %s\n", hpm_plugin_path);
	
	if (NULL == (str_val = resource_get_string(RES_HPM_CACHE_SIZE))) { 
		hpm_cache_size = 256*1024;
		resource_set_string(RES_HPM_CACHE_SIZE, "256K");
	} else {
		hpm_cache_size = atobyte(str_val);
		if (hpm_cache_size < 64*1024) {
			hpm_cache_size = 256*1024;
			resource_set_string(RES_HPM_CACHE_SIZE, "256K");
		}
	}
	bytetoa(hpm_cache_size, temp_buff);
	printf("[hpm_processor]: fastcgi cache size is %s\n", temp_buff);
	
	if (NULL == (str_val = resource_get_string(RES_HPM_MAX_SIZE))) { 
		hpm_max_size = 1024*1024;
		resource_set_string(RES_HPM_MAX_SIZE, "1M");
	} else {
		hpm_max_size = atobyte(str_val);
		if (hpm_max_size < 64*1024) {
			hpm_max_size = 1024*1024;
			resource_set_string(RES_HPM_MAX_SIZE, "1M");
		}
	}
	bytetoa(hpm_max_size, temp_buff);
	printf("[hpm_processor]: hpm maximum size is %s\n", temp_buff);

	if (NULL == (service_plugin_path = resource_get_string(
		RES_SERVICE_PLUGIN_PATH))) {
		service_plugin_path = "../service_plugins/http";
		resource_set_string(RES_SERVICE_PLUGIN_PATH, "../service_plugins/http");
	}
	printf("[service]: service plugins path is %s\n", service_plugin_path);

	if (NULL == (str_val = resource_get_string(RES_CONFIG_FILE_PATH))) {
		str_val = "../config/http";
		resource_set_string(RES_CONFIG_FILE_PATH, "../config/http");
	}
	printf("[system]: config files path is %s\n", str_val);
	
	if (NULL == (str_val = resource_get_string(RES_DATA_FILE_PATH))) {
		str_val = "../data/http";
		resource_set_string(RES_DATA_FILE_PATH, "../data/http");
	}
	sprintf(fastcgi_list_path, "%s/fastcgi.txt", str_val);
	sprintf(cache_list_path, "%s/cache.txt", str_val);
	sprintf(rewrite_list_path, "%s/rewrite.txt", str_val);
	printf("[system]: data files path is %s\n", str_val);
	
	if (NULL == (console_server_ip = resource_get_string(
		RES_CONSOLE_SERVER_IP))) { 
		console_server_ip = "127.0.0.1"; 
		resource_set_string(RES_CONSOLE_SERVER_IP, "127.0.0.1");
	}
	printf("[console_server]: console server ip %s\n", console_server_ip);
 
	if (FALSE == (resource_get_integer(RES_CONSOLE_SERVER_PORT, 
		&console_server_port))) { 
		console_server_port = 8899; 
		resource_set_integer(RES_CONSOLE_SERVER_PORT, 8899);
	}
	printf("[console_server]: console server is port %d\n",
		console_server_port);
	
	if (NULL == (str_val = resource_get_string(RES_FASTCGI_CACHE_SIZE))) { 
		fastcgi_cache_size = 256*1024;
		resource_set_string(RES_FASTCGI_CACHE_SIZE, "256K");
	} else {
		fastcgi_cache_size = atobyte(str_val);
		if (fastcgi_cache_size < 64*1024) {
			fastcgi_cache_size = 256*1024;
			resource_set_string(RES_FASTCGI_CACHE_SIZE, "256K");
		}
	}
	bytetoa(fastcgi_cache_size, temp_buff);
	printf("[mod_fastcgi]: fastcgi cache size is %s\n", temp_buff);
	
	if (NULL == (str_val = resource_get_string(RES_FASTCGI_MAX_SIZE))) { 
		fastcgi_max_size = 1024*1024;
		resource_set_string(RES_FASTCGI_MAX_SIZE, "1M");
	} else {
		fastcgi_max_size = atobyte(str_val);
		if (fastcgi_max_size < 64*1024) {
			fastcgi_max_size = 1024*1024;
			resource_set_string(RES_FASTCGI_MAX_SIZE, "1M");
		}
	}
	bytetoa(fastcgi_max_size, temp_buff);
	printf("[mod_fastcgi]: fastcgi maximum size is %s\n", temp_buff);
	
	if (NULL == (str_val = resource_get_string(RES_FASTCGI_EXEC_TIMEOUT))) {
		fastcgi_exec_timeout = 600;
		resource_set_string(RES_FASTCGI_EXEC_TIMEOUT, "10minutes");
	} else {
		fastcgi_exec_timeout = atoitvl(str_val);
		if (fastcgi_exec_timeout < 60) {
			fastcgi_exec_timeout = 600;
			resource_set_string(RES_FASTCGI_EXEC_TIMEOUT, "10minutes");
		}
	}
	itvltoa(fastcgi_exec_timeout, temp_buff);
	printf("[http]: fastcgi excution time out is %s\n", temp_buff);
	
	if (FALSE == resource_save()) {
		printf("[system]: fail to write configuration back to file\n");
		goto EXIT_PROGRAM;
	}

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
	if (NULL != user_name) {
		puser_pass = getpwnam(user_name);
		if (NULL == puser_pass) {
			printf("[system]: no such user %s\n", user_name);
			goto EXIT_PROGRAM;
		}
		
		if (0 != setgid(puser_pass->pw_gid)) {
			printf("[system]: can not run group of %s\n", user_name);
			goto EXIT_PROGRAM;
		}
		if (0 != setuid(puser_pass->pw_uid)) {
			printf("[system]: can not run as %s\n", user_name);
			goto EXIT_PROGRAM;
		}
	}
	service_init(context_num, service_plugin_path);
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
		dns_name, dns_domain, TRUE, max_request_mem, proc_plugin_path);
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
		hpm_cache_size, hpm_max_size);
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
		printf("[system]: fail to run mod rewrite\n"); 
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
		printf("[system]: fail to run mod fastcgi\n"); 
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
		printf("[system]: fail to run mod cache\n"); 
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
		printf("[system]: fail to run http parser\n"); 
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

	
	threads_pool_init(thread_init_num, (void*)http_parser_process);

	threads_pool_register_event_proc(http_parser_threads_event_proc);
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
	return 0;
} 

static void term_handler(int signo)
{
	http_parser_shutdown_async();
	console_server_notify_main_stop();
}

