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

static const char *const g_dfl_as_plugins[] = {
	"libmtapas_address_checker.so",
	"libmtapas_anti_enum.so",
	"libmtapas_attach_filter.so",
	"libmtapas_attach_wildcard.so",
	"libmtapas_auth_whitelist.so",
	"libmtapas_base64_encoding.so",
	"libmtapas_boundary_filter.so",
	"libmtapas_ddns_filter.so",
	"libmtapas_dns_rbl.so",
	"libmtapas_domain_filter.so",
	"libmtapas_domain_keyword.so",
	"libmtapas_domain_limit.so",
	"libmtapas_from_auditor.so",
	"libmtapas_from_filter.so",
	"libmtapas_from_validator.so",
	"libmtapas_header_filter.so",
	"libmtapas_headerfrom_filter.so",
	"libmtapas_hello_filter.so",
	"libmtapas_inmail_frequency.so",
	"libmtapas_keyword_filter.so",
	"libmtapas_multipart_check.so",
	"libmtapas_outmail_frequency.so",
	"libmtapas_precise_interception.so",
	"libmtapas_property_001.so",
	"libmtapas_property_002.so",
	"libmtapas_property_003.so",
	"libmtapas_property_004.so",
	"libmtapas_property_005.so",
	"libmtapas_property_006.so",
	"libmtapas_property_007.so",
	"libmtapas_property_008.so",
	"libmtapas_property_009.so",
	"libmtapas_property_010.so",
	"libmtapas_property_011.so",
	"libmtapas_property_012.so",
	"libmtapas_property_013.so",
	"libmtapas_property_014.so",
	"libmtapas_property_015.so",
	"libmtapas_property_016.so",
	"libmtapas_property_017.so",
	"libmtapas_property_018.so",
	"libmtapas_property_019.so",
	"libmtapas_property_020.so",
	"libmtapas_property_021.so",
	"libmtapas_property_022.so",
	"libmtapas_property_023.so",
	"libmtapas_property_024.so",
	"libmtapas_property_025.so",
	"libmtapas_property_026.so",
	"libmtapas_property_027.so",
	"libmtapas_property_028.so",
	"libmtapas_property_029.so",
	"libmtapas_property_030.so",
	"libmtapas_property_031.so",
	"libmtapas_property_032.so",
	"libmtapas_property_033.so",
	"libmtapas_property_034.so",
	"libmtapas_property_035.so",
	"libmtapas_property_036.so",
	"libmtapas_property_037.so",
	"libmtapas_property_038.so",
	"libmtapas_property_039.so",
	"libmtapas_property_040.so",
	"libmtapas_property_041.so",
	"libmtapas_property_042.so",
	"libmtapas_property_043.so",
	"libmtapas_property_044.so",
	"libmtapas_property_045.so",
	"libmtapas_property_046.so",
	"libmtapas_property_047.so",
	"libmtapas_property_048.so",
	"libmtapas_property_049.so",
	"libmtapas_property_050.so",
	"libmtapas_property_051.so",
	"libmtapas_property_052.so",
	"libmtapas_property_053.so",
	"libmtapas_property_054.so",
	"libmtapas_property_055.so",
	"libmtapas_property_056.so",
	"libmtapas_property_057.so",
	"libmtapas_property_058.so",
	"libmtapas_property_059.so",
	"libmtapas_rbl_check.so",
	"libmtapas_rcpt_filter.so",
	"libmtapas_rcpt_limit.so",
	"libmtapas_scamming_filter.so",
	"libmtapas_site_protection.so",
	"libmtapas_special_protection.so",
	"libmtapas_spf_filter.so",
	"libmtapas_subject_auditor.so",
	"libmtapas_subject_dots.so",
	"libmtapas_trojan_detector.so",
	"libmtapas_xmailer_filter.so",
	NULL,
};

static const char *const g_dfl_svc_plugins[] = {
	"libmtasvc_boundary_list.so",
	"libmtasvc_domain_list.so",
	"libmtasvc_domain_whitelist.so",
	"libmtasvc_forbidden_domain.so",
	"libmtasvc_forbidden_from.so",
	"libmtasvc_forbidden_rcpt.so",
	"libmtasvc_inmail_frequency_audit.so",
	"libmtasvc_ip_container.so",
	"libmtasvc_ip_filter.so",
	"libmtasvc_ip_whitelist.so",
	"libmtasvc_log_plugin.so",
	"libmtasvc_mail_from_audit.so",
	"libmtasvc_mail_subject_audit.so",
	"libmtasvc_midb_agent.so",
	"libmtasvc_mysql_adaptor.so",
	"libmtasvc_outmail_frequency_audit.so",
	"libmtasvc_outmail_limitation_audit.so",
	"libmtasvc_protection_ip_audit.so",
	"libmtasvc_relay_list.so",
	"libmtasvc_retrying_table.so",
	"libmtasvc_spam_statistic.so",
	"libmtasvc_special_protection_audit.so",
	"libmtasvc_tagging_table.so",
	"libmtasvc_user_filter.so",
	NULL,
};

typedef void (*STOP_FUNC)();

static void term_handler(int signo);

int main(int argc, const char **argv)
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
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, term_handler);
	resource_init(opt_config_file, config_default_path("smtp.cfg"));
	if (0 != resource_run()) { 
		printf("[system]: fail to load resource\n"); 
		goto EXIT_PROGRAM; 
	}
	func_ptr	= (STOP_FUNC)resource_free;
	vstack_push(&stop_stack, (void*)&func_ptr);
	func_ptr	= (STOP_FUNC)resource_stop;
	vstack_push(&stop_stack, (void*)&func_ptr);
	
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
 
	if (!resource_get_integer("SMTP_RUNNING_MODE", &smtp_running_mode)) {
		smtp_running_mode = SMTP_MODE_MIXTURE; 
		resource_set_integer("SMTP_RUNNING_MODE", smtp_running_mode);
	} else if (smtp_running_mode < SMTP_MODE_OUTBOUND || 
		smtp_running_mode >	 SMTP_MODE_MIXTURE) { 
		smtp_running_mode = SMTP_MODE_MIXTURE; 
		resource_set_integer("SMTP_RUNNING_MODE", smtp_running_mode);
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

	str_val = resource_get_string("DOMAIN_LIST_VALID");
	if (str_val == NULL) {
		if (SMTP_MODE_MIXTURE == smtp_running_mode) {
			resource_set_string("DOMAIN_LIST_VALID", "TRUE");
			domainlist_valid = TRUE;
		} else {
			resource_set_string("DOMAIN_LIST_VALID", "FALSE");
			domainlist_valid = FALSE;
		}
	} else {
		if (0 == strcasecmp(str_val, "FALSE")) {
			if (SMTP_MODE_MIXTURE == smtp_running_mode) {
				resource_set_string("DOMAIN_LIST_VALID", "TRUE");
				domainlist_valid = TRUE;
			} else {
				domainlist_valid = FALSE;
			}
		} else if (0 == strcasecmp(str_val, "TRUE")) {
			domainlist_valid = TRUE;
		} else {
			if (SMTP_MODE_MIXTURE == smtp_running_mode) {
				resource_set_string("DOMAIN_LIST_VALID", "TRUE");
				domainlist_valid = TRUE;
			} else {
				resource_set_string("DOMAIN_LIST_VALID", "FALSE");
				domainlist_valid = FALSE;
			}
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
		smtp_support_pipeline = FALSE;
		resource_set_string("SMTP_SUPPORT_PIPELINE", "FALSE");
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
		smtp_max_mail_num = 10; 
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
	
	anti_spam_path = resource_get_string("ANTI_SPAMMING_INIT_PATH");
	if (anti_spam_path == NULL) {
		anti_spam_path = PKGLIBDIR;
		resource_set_string("ANTI_SPAMMING_INIT_PATH", anti_spam_path);
	}
	printf("[anti_spamming]: anti-spamming plugin path %s\n", anti_spam_path);
	const char *str_value = resource_get_string("ANTI_SPAMMING_PLUGIN_LIST");
	const char *const *as_plugin_list = NULL;
	if (str_value != NULL) {
		as_plugin_list = const_cast(const char * const *, read_file_by_line(str_value));
		if (as_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			goto EXIT_PROGRAM;
		}
	}
	str_value = resource_get_string("ANTI_SPAMMING_IGNORE_ERRORS");
	bool as_ignerr = parse_bool(str_value);
	resource_set_string("ANTI_SPAMMING_IGNORE_ERRORS", as_ignerr ? "true" : "false");
 
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
	str_value = resource_get_string("SERVICE_PLUGIN_IGNORE_ERRORS");
	bool svcplug_ignerr = parse_bool(str_value);
	resource_set_string("SERVICE_PLUGIN_IGNORE_ERRORS", svcplug_ignerr ? "true" : "false");

	flusher_plugin_path = resource_get_string("FLUSHER_PLUGIN_PATH");
	if (flusher_plugin_path == NULL) {
		flusher_plugin_path = "libmtaflh_message_enqueue.so";
		resource_set_string("FLUSHER_PLUGIN_PATH", flusher_plugin_path);
	}
	printf("[flusher]: flusher plugin path %s\n", flusher_plugin_path);

	str_val = resource_get_string("CONFIG_FILE_PATH");
	if (str_val == NULL) {
		str_val = PKGSYSCONFSMTPDIR;
		resource_set_string("CONFIG_FILE_PATH", str_val);
	}
	printf("[system]: config files path is %s\n", str_val);
	
	str_val = resource_get_string("DATA_FILE_PATH");
	if (str_val == NULL) {
		str_val = PKGDATASMTPDIR;
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
		console_server_port = 5566; 
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

	anti_spamming_init(anti_spam_path, as_plugin_list != NULL ?
		as_plugin_list : g_dfl_as_plugins, as_ignerr);

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


 
