#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <libHX/defs.h>
#include <libHX/option.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include "config_file.h"
#include "message_dequeue.h" 
#include "console_server.h" 
#include "system_services.h"
#include "transporter.h" 
#include "lib_buffer.h"
#include "resource.h" 
#include "service.h" 
#include "vstack.h"
#include "util.h"
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <pwd.h>

BOOL g_notify_stop = FALSE;
static char *opt_config_file;
static struct HXoption g_options_table[] = {
	{.sh = 'c', .type = HXTYPE_STRING, .ptr = &opt_config_file, .help = "Config file to read", .htyp = "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static const char *const g_dfl_mpc_plugins[] = {
	"libmtahook_alias_translator.so",
	"libmtahook_anonymous_keyword.so",
	"libmtahook_antivirus_processor.so",
	"libmtahook_archive_agent.so",
	"libmtahook_domain_keyword.so",
	"libmtahook_domain_mailbox.so",
	"libmtahook_domain_monitor.so",
	"libmtahook_domain_sign.so",
	"libmtahook_domain_subsystem.so",
	"libmtahook_exmdb_local.so",
	"libmtahook_from_replace.so",
	"libmtahook_group_monitor.so",
	"libmtahook_mail_approving.so",
	"libmtahook_mailbox_collector.so",
	"libmtahook_mail_forwarder.so",
	"libmtahook_message_insulation.so",
	"libmtahook_mlist_expand.so",
	"libmtahook_os_inspection.so",
	"libmtahook_relay_agent.so",
	"libmtahook_remote_postman.so",
	"libmtahook_report_forms.so",
	"libmtahook_self_monitor.so",
	"libmtahook_spam_complain.so",
	"libmtahook_spam_tagging.so",
	"libmtahook_status_forms.so",
	"libmtahook_system_sign.so",
	"libmtahook_system_updater.so",
	"libmtahook_user_forwarder.so",
	NULL,
};

static const char *const g_dfl_svc_plugins[] = {
	"libmtasvc_backup_list.so",
	"libmtasvc_delivery_console_control.so",
	"libmtasvc_dns_adaptor.so",
	"libmtasvc_domain_list.so",
	"libmtasvc_lang_charset.so",
	"libmtasvc_log_plugin.so",
	"libmtasvc_mime_extension.so",
	"libmtasvc_monitor_domains.so",
	"libmtasvc_ms_locale.so",
	"libmtasvc_mysql_adaptor.so",
	"libmtasvc_relay_domains.so",
	"libmtasvc_remote_delivery_audit.so",
	"libmtasvc_remote_delivery_forbidden.so",
	"libmtasvc_remote_mx_hello.so",
	"libmtasvc_single_rcpt.so",
	"libmtasvc_smtp_console_control.so",
	"libmtasvc_spam_statistic.so",
	"libmtasvc_sssp_agent.so",
	NULL,
};

typedef void (*STOP_FUNC)();

static void term_handler(int signo);

int main(int argc, const char **argv)
{ 
    size_t tape_size, max_mem; 
    int threads_min, threads_max;
	int free_contexts, mime_ratio;
    const char *dequeue_path, *mpc_plugin_path, *service_plugin_path; 
    const char *console_server_ip, *user_name, *str_val, *admin_mb;
	char temp_buff[256];
    int console_server_port; 
    struct passwd *puser_pass;
	BOOL domainlist_valid;
    LIB_BUFFER *allocator;
    VSTACK stop_stack;
    STOP_FUNC *stop, func_ptr;

    allocator    = vstack_allocator_init(sizeof(STOP_FUNC), 50, FALSE);    
    vstack_init(&stop_stack, allocator, sizeof(STOP_FUNC), 50);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, term_handler);
	resource_init(opt_config_file, config_default_path("delivery.cfg"));
    if (0 != resource_run()) { 
        printf("[system]: fail to load resource\n"); 
        goto EXIT_PROGRAM; 
    }
    func_ptr    = (STOP_FUNC)resource_free;
    vstack_push(&stop_stack, (void*)&func_ptr);
    func_ptr    = (STOP_FUNC)resource_stop;
    vstack_push(&stop_stack, (void*)&func_ptr);

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
	
	admin_mb = resource_get_string("ADMIN_MAILBOX");
	if (admin_mb == NULL) {
		admin_mb = "admin@gridware-info.com";
		resource_set_string("ADMIN_MAILBOX", "admin@gridware-info.com");
	}
	printf("[system]: administrator mailbox is %s\n", admin_mb);

	str_val = resource_get_string("DOMAIN_LIST_VALID");
	if (str_val == NULL) {
		resource_set_string("DOMAIN_LIST_VALID", "true");
		domainlist_valid = true;
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

	if (!resource_get_integer("WORK_THREADS_MIN", &threads_min)) {
		threads_min = 16;
		resource_set_integer("WORK_THREADS_MIN", threads_min);
    } else {
		if (threads_min <= 0) {
			threads_min = 16;
			resource_set_integer("WORK_THREADS_MIN", threads_min);
		}
	}
    printf("[system]: minimum working threads number is %d\n", threads_min);

	if (!resource_get_integer("WORK_THREADS_MAX", &threads_max)) {
        threads_max = threads_min * 2; 
		resource_set_integer("WORK_THREADS_MAX", threads_max);
    } else {
		if (threads_max <= threads_min) {
			threads_max = threads_min + 1;
			resource_set_integer("WORK_THREADS_MAX", threads_max);
		}
    }
    printf("[system]: maximum working threads number is %d\n", threads_max);

	if (!resource_get_integer("FREE_CONTEXT_NUM", &free_contexts)) {
        free_contexts = threads_max; 
		resource_set_integer("FREE_CONTEXT_NUM", free_contexts);
    } else {
		if (free_contexts < threads_max) {
			free_contexts = threads_max; 
			resource_set_integer("FREE_CONTEXT_NUM", free_contexts);
		}
	}
    printf("[system]: free contexts number is %d\n", free_contexts);
    
	if (!resource_get_integer("CONTEXT_AVERAGE_MIME", &mime_ratio)) {
        mime_ratio = 8; 
		resource_set_integer("CONTEXT_AVERAGE_MIME", mime_ratio);
    } else {
		if (mime_ratio <= 0) {
			mime_ratio = 8; 
			resource_set_integer("CONTEXT_AVERAGE_MIME", mime_ratio);
		}
    }
	printf("[system]: average mimes number for one context is %d\n",
		mime_ratio);
	
	dequeue_path = resource_get_string("DEQUEUE_PATH");
	if (dequeue_path == NULL) {
		dequeue_path = PKGSTATEQUEUEDIR;
		resource_set_string("DEQUEUE_PATH", dequeue_path);
    }
    printf("[message_dequeue]: dequeue path %s\n", dequeue_path);
	
	str_val = resource_get_string("DEQUEUE_TAPE_SIZE");
	if (str_val == NULL) {
		tape_size = 0; 
		resource_set_string("DEQUEUE_TAPE_SIZE", "0");
    } else { 
		tape_size = atobyte(str_val)/(64*1024*2);
		if (tape_size < 0) {
			tape_size = 0;
			resource_set_string("DEQUEUE_TAPE_SIZE", "0");
		}
    } 
	bytetoa(tape_size*64*1024*2, temp_buff);
	printf("[message_dequeue]: dequeue tape size is %s\n", temp_buff);
 
	str_val = resource_get_string("DEQUEUE_MAXIMUM_MEM");
	if (str_val == NULL) {
		max_mem = 1UL << 30;
		resource_set_string("DEQUEUE_MAXIMUM_MEM", "1024M");
    } else {
		max_mem = atobyte(str_val);
		if (max_mem <= 0) {
			max_mem = 128*1024*1024; 
			resource_set_string("DEQUEUE_MAXIMUM_MEM", "128M");
		}
	}
	bytetoa(max_mem, temp_buff);
    printf("[message_dequeue]: maximum allocated memory is %s\n", temp_buff);
    
	mpc_plugin_path = resource_get_string("MPC_PLUGIN_PATH");
	if (mpc_plugin_path == NULL) {
		mpc_plugin_path = PKGLIBDIR;
		resource_set_string("MPC_PLUGIN_PATH", mpc_plugin_path);
    }
    printf("[mpc]: mpc plugins path is %s\n", mpc_plugin_path);
	const char *str_value = resource_get_string("MPC_PLUGIN_LIST");
	const char *const *mpc_plugin_list = NULL;
	if (str_value != NULL) {
		mpc_plugin_list = const_cast(const char * const *, read_file_by_line(str_value));
		if (mpc_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			goto EXIT_PROGRAM;
		}
	}
	str_value = resource_get_string("MPC_PLUGIN_IGNORE_ERRORS");
	bool mpcplug_ignerr = parse_bool(str_value);
	resource_set_string("MPC_PLUGIN_IGNORE_ERRORS", mpcplug_ignerr ? "true" : "false");
 
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

	str_val = resource_get_string("CONFIG_FILE_PATH");
	if (str_val == NULL) {
		str_val = PKGSYSCONFDELIVERYDIR;
		resource_set_string("CONFIG_FILE_PATH", str_val);
	}
	printf("[system]: config files path is %s\n", str_val);

	str_val = resource_get_string("DATA_FILE_PATH");
	if (str_val == NULL) {
		str_val = PKGDATADELIVERYDIR;
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
        console_server_port = 6677; 
		resource_set_integer("CONSOLE_SERVER_PORT", console_server_port);
    }
    printf("[console_server]: console server port is %d\n",
		console_server_port);
	
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

	service_init(threads_max + free_contexts, service_plugin_path,
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

                            
    message_dequeue_init(dequeue_path, tape_size, max_mem);
 
    if (0 != message_dequeue_run()) { 
        printf("[system]: fail to run message dequeue\n"); 
        goto EXIT_PROGRAM; 
    } else {
        printf("[system]: run message dequeue OK\n");
    }
                                                                      
    func_ptr    = (STOP_FUNC)message_dequeue_free;
    vstack_push(&stop_stack, (void*)&func_ptr);
    func_ptr    = (STOP_FUNC)message_dequeue_stop;
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

    transporter_init(mpc_plugin_path, mpc_plugin_list != NULL ?
		mpc_plugin_list : g_dfl_mpc_plugins, threads_min, threads_max,
		free_contexts, mime_ratio, domainlist_valid, mpcplug_ignerr);

	printf("--------------------------- mpc plugins begin"
		"---------------------------\n");
    if (0 != transporter_run()) { 
		printf(" ---------------------------- mpc plugins end"
			"-----------------------------\n");
        printf("[system]: fail to run transporter\n"); 
        goto EXIT_PROGRAM; 
    } else {
		printf("----------------------------- mpc plugins end"
			"-----------------------------\n");
        printf("[system]: run transporter OK\n");
    }

    func_ptr    = (STOP_FUNC)transporter_free;
    vstack_push(&stop_stack, (void*)&func_ptr);
    func_ptr    = (STOP_FUNC)transporter_stop;
    vstack_push(&stop_stack, (void*)&func_ptr);

    
    printf("[system]: DELIVERY APP is now running\n");
    while (FALSE == g_notify_stop) {
        sleep(3);
    }
    
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


 
