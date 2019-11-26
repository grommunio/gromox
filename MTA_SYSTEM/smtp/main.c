#include "listener.h" 
#include "resource.h" 
#include "flusher.h" 
#include "smtp_parser.h" 
#include "bndstack_allocator.h" 
#include "files_allocator.h" 
#include "blocks_allocator.h" 
#include "threads_pool.h" 
#include "console_server.h" 
#include "contexts_pool.h" 
#include "anti_spamming.h"
#include "service.h" 
#include "system_services.h"
#include "vstack.h"
#include "lib_buffer.h"
#include <pwd.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

/* the only global variable in system to indicate the program to exit */
BOOL g_notify_stop = FALSE;

typedef void (*STOP_FUNC)();

static void term_handler(int signo);

int main(int argc, char* argv[]) 
{ 
 
	int listen_port, listen_ssl_port;
	int context_num, smtp_running_mode; 
	size_t max_mail_len;
	size_t context_aver_mem, context_max_mem;
	int smtp_max_mail_num;
	int smtp_auth_times, smtp_conn_timeout;
	BOOL smtp_need_auth, smtp_support_pipeline,
		smtp_support_starttls, smtp_force_starttls;
	int thread_init_num, thread_charge_num, threads_max_num; 
	const char *certificate_path, *cb_passwd, *private_key_path;
	const char *anti_spam_path, *service_plugin_path; 
	const char *console_server_ip, *flusher_plugin_path, *user_name;
	int block_interval_auth, block_interval_sessions;
	int console_server_port; 
	struct rlimit rl;
	struct passwd *puser_pass;
	const char *str_val;
	char temp_buff[256];
	BOOL smtp_auth_needed;
	BOOL domainlist_valid;
	LIB_BUFFER *allocator;
	VSTACK stop_stack;
	STOP_FUNC *stop, func_ptr;

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
	func_ptr	= (STOP_FUNC)resource_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)resource_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	

	if (FALSE == resource_get_integer(RES_LISTEN_PORT, &listen_port)) { 
		listen_port = 25; 
		resource_set_integer(RES_LISTEN_PORT, 25);
	}
	printf("[system]: system listening port %d\n", listen_port);

	if (FALSE == resource_get_integer(RES_LISTEN_SSL_PORT, &listen_ssl_port)) {
		listen_ssl_port = 0;
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
	
	if (NULL == (str_val = resource_get_string(RES_DEFAULT_DOMAIN))) {
		memset(temp_buff, 0, 256);
		getdomainname(temp_buff, 256);
		resource_set_string(RES_DEFAULT_DOMAIN, temp_buff);
		str_val = temp_buff;
		printf("[system]: warning! cannot find default domain, OS domain name "
			"will be used as default domain\n");
	}
	printf("[system]: default domain is %s\n", str_val);
	
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
		if (context_aver_mem <= 1) {
			context_aver_mem = 4;
			resource_set_string(RES_CONTEXT_AVERAGE_MEM, "256K");
		}
	}
	bytetoa(context_aver_mem*64*1024, temp_buff);
	printf("[smtp]: context average memory is %s\n", temp_buff);
 
	if (NULL == (str_val = resource_get_string(RES_CONTEXT_MAX_MEM))) {
		context_max_mem = 32; 
		resource_set_string(RES_CONTEXT_MAX_MEM, "2M");
	} else {
		context_max_mem = atobyte(str_val)/(64*1024); 
	}
	if (context_max_mem < context_aver_mem) {
		context_max_mem = context_aver_mem;
		bytetoa(context_max_mem*64*1024, temp_buff);
		resource_set_string(RES_CONTEXT_MAX_MEM, temp_buff);
	} 
	context_max_mem *= 64*1024;
	bytetoa(context_max_mem, temp_buff);
	printf("[smtp]: context maximum memory is %s\n", temp_buff);
 
	if (FALSE == resource_get_integer(RES_SMTP_RUNNING_MODE, 
		&smtp_running_mode)) { 
		smtp_running_mode = SMTP_MODE_MIXTURE; 
		resource_set_integer(RES_SMTP_RUNNING_MODE, 2);
	} else if (smtp_running_mode < SMTP_MODE_OUTBOUND || 
		smtp_running_mode >	 SMTP_MODE_MIXTURE) { 
		smtp_running_mode = SMTP_MODE_MIXTURE; 
		resource_set_integer(RES_SMTP_RUNNING_MODE, 2);
	}
	switch(smtp_running_mode) {
	case SMTP_MODE_OUTBOUND:
		printf("[smtp]: running mode is out-bound\n");
		break;
	case SMTP_MODE_INBOUND:
		printf("[smtp]: running mode is in-bound\n");
		break;
	case SMTP_MODE_MIXTURE:
		printf("[smtp]: running mode is mixture\n");
		break;
	}

	if (NULL == (str_val = resource_get_string(RES_DOMAIN_LIST_VALID))) {
		if (SMTP_MODE_MIXTURE == smtp_running_mode) {
			resource_set_string(RES_DOMAIN_LIST_VALID, "TRUE");
			domainlist_valid = TRUE;
		} else {
			resource_set_string(RES_DOMAIN_LIST_VALID, "FALSE");
			domainlist_valid = FALSE;
		}
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			if (SMTP_MODE_MIXTURE == smtp_running_mode) {
				resource_set_string(RES_DOMAIN_LIST_VALID, "TRUE");
				domainlist_valid = TRUE;
			} else {
				domainlist_valid = FALSE;
			}
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			domainlist_valid = TRUE;
		} else {
			if (SMTP_MODE_MIXTURE == smtp_running_mode) {
				resource_set_string(RES_DOMAIN_LIST_VALID, "TRUE");
				domainlist_valid = TRUE;
			} else {
				resource_set_string(RES_DOMAIN_LIST_VALID, "FALSE");
				domainlist_valid = FALSE;
			}
		}
	}
	if (FALSE == domainlist_valid) {
		printf("[system]: domain list in system is invalid\n");
	} else {
		printf("[system]: domain list in system is valid\n");
	}
	
	if (NULL == (str_val = resource_get_string(RES_SMTP_CONN_TIMEOUT))) {
		smtp_conn_timeout = 180;
		resource_set_string(RES_SMTP_CONN_TIMEOUT, "3minutes");
	} else {
		smtp_conn_timeout = atoitvl(str_val);
		if (smtp_conn_timeout <= 0) {
			smtp_conn_timeout = 180;
			resource_set_string(RES_SMTP_CONN_TIMEOUT, "3minutes");
		}
	}
	itvltoa(smtp_conn_timeout, temp_buff);
	printf("[smtp]: smtp socket read write time out is %s\n", temp_buff);
 
	if (NULL == (str_val = resource_get_string(RES_SMTP_SUPPORT_PIPELINE))) {
		smtp_support_pipeline = FALSE;
		resource_set_string(RES_SMTP_SUPPORT_PIPELINE, "FALSE");
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			smtp_support_pipeline = FALSE;
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			smtp_support_pipeline = TRUE;
		} else {
			smtp_support_pipeline = FALSE;
			resource_set_string(RES_SMTP_SUPPORT_PIPELINE, "FALSE");
		}
	}
	if (FALSE == smtp_support_pipeline) {
		printf("[smtp]: smtp doesn't support esmtp pipeline mode\n");
	} else {
		printf("[smtp]: smtp supports esmtp pipeline mode\n");
	}

	if (NULL == (str_val = resource_get_string(RES_SMTP_SUPPORT_STARTTLS))) {
		smtp_support_starttls = FALSE;
		resource_set_string(RES_SMTP_SUPPORT_STARTTLS, "FALSE");
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			smtp_support_starttls = FALSE;
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			smtp_support_starttls = TRUE;
		} else {
			smtp_support_starttls = FALSE;
			resource_set_string(RES_SMTP_SUPPORT_STARTTLS, "FALSE");
		}
	}
	certificate_path = resource_get_string(RES_SMTP_CERTIFICATE_PATH);
	cb_passwd = resource_get_string(RES_SMTP_CERTIFICATE_PASSWD);
	private_key_path = resource_get_string(RES_SMTP_PRIVATE_KEY_PATH);
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

	if (NULL == (str_val = resource_get_string(RES_SMTP_FORCE_STARTTLS))) {
		smtp_force_starttls = FALSE;
		resource_set_string(RES_SMTP_FORCE_STARTTLS, "FALSE");
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			smtp_force_starttls = FALSE;
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			smtp_force_starttls = TRUE;
		} else {
			smtp_force_starttls = FALSE;
			resource_set_string(RES_SMTP_FORCE_STARTTLS, "FALSE");
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

 
	if (NULL == (str_val = resource_get_string(RES_SMTP_NEED_AUTH))) {
		smtp_need_auth = FALSE;
		resource_set_string(RES_SMTP_NEED_AUTH, "FALSE");
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			smtp_need_auth = FALSE;
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			smtp_need_auth = TRUE;
		} else {
			smtp_need_auth = FALSE;
			resource_set_string(RES_SMTP_NEED_AUTH, "FALSE");
		}
	}
	if (FALSE == smtp_need_auth) {
		printf("[smtp]: smtp doesn't force users to authentificate\n");
	} else {
		printf("[smtp]: smtp forces users to authentificate\n");
	}

	if (FALSE == resource_get_integer(RES_SMTP_AUTH_TIMES, 
		&smtp_auth_times)) { 
		smtp_auth_times = 3; 
		resource_set_integer(RES_SMTP_AUTH_TIMES, 3);
	} else {
		if (smtp_auth_times <= 0) {
			smtp_auth_times = 3;
			resource_set_integer(RES_SMTP_AUTH_TIMES, 3);
		}
	}
	printf("[smtp]: maximum authentification failure times is %d\n", 
			smtp_auth_times);

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
	printf("[smtp]: block client %s when authentification failure times "
			"is exceeded\n", temp_buff);

	if (NULL == (str_val = resource_get_string(RES_MAIL_MAX_LENGTH))) {
		max_mail_len = 64*1024*1024; 
		resource_set_string(RES_MAIL_MAX_LENGTH, "64M");
	} else {
		max_mail_len = atobyte(str_val);
		if (max_mail_len <= 0) {
			max_mail_len = 64*1024*1024; 
			resource_set_string(RES_MAIL_MAX_LENGTH, "64M");
		}
	}
	bytetoa(max_mail_len, temp_buff);
	printf("[smtp]: maximum mail length is %s\n", temp_buff);

	if (FALSE == resource_get_integer(RES_SMTP_MAX_MAIL_NUM, 
		&smtp_max_mail_num)) { 
		smtp_max_mail_num = 10; 
		resource_set_integer(RES_SMTP_MAX_MAIL_NUM, 10);
	}
	printf("[smtp]: maximum mails number for one session is %d\n",
		smtp_max_mail_num);
	 
	if (NULL == (str_val = resource_get_string(RES_BLOCK_INTERVAL_SESSIONS))) {
		block_interval_sessions = 60;
		resource_set_string(RES_BLOCK_INTERVAL_SESSIONS, "1minute");
	} else {
		block_interval_sessions = atoitvl(str_val);
		if (block_interval_sessions <= 0) {
			block_interval_sessions = 60;
			resource_set_string(RES_BLOCK_INTERVAL_SESSIONS, "1minute");
		}
	}
	itvltoa(block_interval_sessions, temp_buff);
	printf("[smtp]: block remote side %s when mails number is exceed for one "
			"session\n", temp_buff);
	
	if (NULL == (anti_spam_path = resource_get_string(
		RES_ANTI_SPAMMING_INIT_PATH))) { 
		anti_spam_path = "../as_plugins";
		resource_set_string(RES_ANTI_SPAMMING_INIT_PATH, "../as_plugins");
	}
	printf("[anti_spamming]: anti-spamming plugin path %s\n", anti_spam_path);
 
	if (NULL == (service_plugin_path = resource_get_string(
		RES_SERVICE_PLUGIN_PATH))) {
		service_plugin_path = "../service_plugins/smtp";
		resource_set_string(RES_SERVICE_PLUGIN_PATH, "../service_plugins/smtp");
	}
	printf("[service]: service plugins path is %s\n", service_plugin_path);

	if (NULL == (flusher_plugin_path = resource_get_string(
		RES_FLUSHER_PLUGIN_PATH))) {
		flusher_plugin_path = "../flusher_plugins/message_enqueue.flh";
		resource_set_string(RES_FLUSHER_PLUGIN_PATH, 
			"../flusher_plugins/message_enqueue.flh");
	}
	printf("[flusher]: flusher plugin path %s\n", flusher_plugin_path);

	if (NULL == (str_val = resource_get_string(RES_CONFIG_FILE_PATH))) {
		str_val = "../config/smtp";
		resource_set_string(RES_CONFIG_FILE_PATH, "../config/smtp");
	}
	printf("[system]: config files path is %s\n", str_val);
	
	if (NULL == (str_val = resource_get_string(RES_DATA_FILE_PATH))) {
		str_val = "../data/smtp";
		resource_set_string(RES_DATA_FILE_PATH, "../data/smtp");
	}
	printf("[system]: data files path is %s\n", str_val);
	
	if (NULL == (console_server_ip = resource_get_string(
		RES_CONSOLE_SERVER_IP))) { 
		console_server_ip = "127.0.0.1"; 
		resource_set_string(RES_CONSOLE_SERVER_IP, "127.0.0.1");
	}
	printf("[console_server]: console server ip %s\n", console_server_ip);
 
	if (FALSE == (resource_get_integer(RES_CONSOLE_SERVER_PORT, 
		&console_server_port))) { 
		console_server_port = 5566; 
		resource_set_integer(RES_CONSOLE_SERVER_PORT, 5566);
	}
	printf("[console_server]: console server is port %d\n",
		console_server_port);

	if (FALSE == resource_save()) {
		printf("[system]: fail to write configuration back to file\n");
		goto EXIT_PROGRAM;
	}

	listener_init(listen_port, listen_ssl_port);
																			
	if (0 != listener_run()) {
		printf("[system]: fail to start listener\n");
		goto EXIT_PROGRAM;
	} else {
		printf("[system]: listener start OK\n");
	}

	func_ptr	= (STOP_FUNC)listener_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)listener_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	if (0 != getrlimit(RLIMIT_NOFILE, &rl)) {
		printf("[system]: fail to get file limitation\n");
		goto EXIT_PROGRAM;
	}
	if (rl.rlim_cur < context_num + 128 ||
		rl.rlim_max < context_num + 128) {
		rl.rlim_cur = context_num + 128;
		rl.rlim_max = context_num + 128;
		if (0 != setrlimit(RLIMIT_NOFILE, &rl)) {
			printf("[system]: fail to set file limitation\n");
			goto EXIT_PROGRAM;
		}
		printf("[system]: set file limitation to %d\n", context_num + 128);
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

	func_ptr	= (STOP_FUNC)service_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)service_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	
	system_services_init();
	if (0 != system_services_run()) { 
		printf("[system]: fail to run system service\n"); 
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run system service OK\n");
	}

	func_ptr	= (STOP_FUNC)system_services_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)system_services_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	files_allocator_init(context_num * 128);  
	if (0 != files_allocator_run()) { 
		printf("[system]: can not run file allocator\n"); 
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run file allocator OK\n");
	}

	func_ptr	= (STOP_FUNC)files_allocator_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)files_allocator_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	blocks_allocator_init(context_num * context_aver_mem);	   
 
	if (0 != blocks_allocator_run()) { 
		printf("[system]: can not run blocks allocator\n"); 
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run blocks allocator OK\n");
	}

	func_ptr	= (STOP_FUNC)blocks_allocator_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)blocks_allocator_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
 
	bndstack_allocator_init(context_num * 3); 
 
	if (0 != bndstack_allocator_run()) { 
		printf("[system]: can not run bndstack allocator\n"); 
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run bndstack allocator OK\n");
	}

	func_ptr	= (STOP_FUNC)bndstack_allocator_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)bndstack_allocator_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	 
	if (0 == smtp_need_auth) {
		 smtp_auth_needed	 = FALSE;
	} else {
		smtp_auth_needed	 = TRUE;
	}
	
	threads_max_num	   = (0 == (context_num % thread_charge_num)) ? 
		(context_num / thread_charge_num) : 
		(context_num / thread_charge_num + 1);
							
	smtp_parser_init(context_num, threads_max_num, 
		smtp_running_mode, domainlist_valid, smtp_auth_needed, max_mail_len, 
		smtp_max_mail_num, block_interval_sessions, 
		context_max_mem, smtp_conn_timeout, smtp_auth_times,
		block_interval_auth, smtp_support_pipeline, smtp_support_starttls,
		smtp_force_starttls, certificate_path, cb_passwd, private_key_path);  
 
	if (0 != smtp_parser_run()) { 
		printf("[system]: fail to run smtp parser\n"); 
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run smtp parser OK\n");
	}
																	  
	func_ptr	= (STOP_FUNC)smtp_parser_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)smtp_parser_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	
	contexts_pool_init(smtp_parser_get_contexts_list(),	 
		context_num, sizeof(SMTP_CONTEXT),
		(void*)smtp_parser_get_context_socket,
		(void*)smtp_parser_get_context_timestamp,
		thread_charge_num, smtp_conn_timeout); 
 
	if (0 != contexts_pool_run()) { 
		printf("[system]: fail to run contexts pool\n"); 
		goto EXIT_PROGRAM; 
	} else {
		printf("[system]: run contexts pool OK\n");
	}
	func_ptr	= (STOP_FUNC)contexts_pool_free; 
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)contexts_pool_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
 

	flusher_init(flusher_plugin_path, context_num);
																			
	if (0 != flusher_run()) {
		printf("[system]: fail to run flusher\n");
		goto EXIT_PROGRAM;
	} else {
		printf("[system]: run flusher OK\n");
	}

	func_ptr	= (STOP_FUNC)flusher_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)flusher_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	console_server_init(console_server_ip, console_server_port);

	if (0 != console_server_run()) {
		printf("[system]: fail to run console server\n");
		goto EXIT_PROGRAM;
	} else {
		printf("[system]: run console server OK\n");
	}

	func_ptr	= (STOP_FUNC)console_server_free;
	vstack_push(&stop_stack, (void*)&func_ptr);

	func_ptr	= (STOP_FUNC)console_server_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	anti_spamming_init(anti_spam_path); 

	printf("------------------------ anti-spamming plugins begin"
		   "------------------------\n");
	if (0 != anti_spamming_run()) { 
		printf("------------------------- anti-spamming plugins end"
		   "-------------------------\n");
		printf("[system]: fail to run anti-spamming \n"); 
		goto EXIT_PROGRAM; 
	} else {
		printf("------------------------- anti-spamming plugins end"
		   "-------------------------\n");
		printf("[system]: run anti-spamming OK\n");
	}

	func_ptr	= (STOP_FUNC)anti_spamming_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)anti_spamming_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	threads_pool_init(thread_init_num, (void*)smtp_parser_process);

	threads_pool_register_event_proc(smtp_parser_threads_event_proc);
	if (0 != threads_pool_run()) {
		printf("[system]: fail to run threads pool\n");
		goto EXIT_PROGRAM;
	} else {
		printf("[system]: run threads pool OK\n");
	}
	func_ptr	= (STOP_FUNC)threads_pool_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)threads_pool_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);

	/* accept the connection */
	if (0 != listerner_trigger_accept()) {
		printf("[system]: fail trigger accept\n");
		goto EXIT_PROGRAM;
	}
	
	printf("[system]: SMTP DAEMON is now running\n");
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


 
