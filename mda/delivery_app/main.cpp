// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <libHX/option.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/config_file.hpp>
#include "message_dequeue.h" 
#include "console_cmd_handler.h"
#include <gromox/console_server.hpp>
#include "system_services.h"
#include "transporter.h" 
#include <gromox/lib_buffer.hpp>
#include "resource.h" 
#include "service.h" 
#include <gromox/util.hpp>
#include <sys/types.h>
#include <csignal>
#include <unistd.h>
#include <cstdio>
#include <pwd.h>

using namespace gromox;

std::atomic<bool> g_notify_stop{false};
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static std::atomic<bool> g_hup_signalled{false};
static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static const char *const g_dfl_mpc_plugins[] = {
	"libgxm_alias_translator.so",
	"libgxm_exmdb_local.so",
	"libgxm_mlist_expand.so",
	NULL,
};

static const char *const g_dfl_svc_plugins[] = {
	"libgxs_domain_list.so",
	"libgxs_logthru.so",
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_textmaps.so",
	"libgxs_authmgr.so",
	NULL,
};

typedef void (*STOP_FUNC)();

static void term_handler(int signo);

int main(int argc, const char **argv)
{ 
	size_t max_mem;
	int retcode = EXIT_FAILURE;
	unsigned int threads_min, threads_max;
	unsigned int free_contexts, mime_ratio;
    const char *dequeue_path, *mpc_plugin_path, *service_plugin_path; 
    const char *console_server_ip, *user_name, *str_val, *admin_mb;
	char temp_buff[256];
    int console_server_port; 
    struct passwd *puser_pass;
	BOOL domainlist_valid;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	struct sigaction sact{};
	sigemptyset(&sact.sa_mask);
	sact.sa_handler = [](int) {};
	sigaction(SIGALRM, &sact, nullptr);
	sact.sa_handler = [](int) { g_hup_signalled = true; };
	sigaction(SIGHUP, &sact, nullptr);
	sact.sa_handler = SIG_IGN;
	sact.sa_flags   = SA_RESTART;
	sigaction(SIGPIPE, &sact, nullptr);
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESETHAND;
	sigaction(SIGINT, &sact, nullptr);
	sigaction(SIGTERM, &sact, nullptr);
	g_config_file = config_file_prg(opt_config_file, "delivery.cfg");
	if (opt_config_file != nullptr && g_config_file == nullptr)
		printf("[resource]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (g_config_file == nullptr)
		return EXIT_FAILURE;

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
		admin_mb = "root@localhost";
		resource_set_string("ADMIN_MAILBOX", admin_mb);
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

	if (!resource_get_uint("WORK_THREADS_MIN", &threads_min)) {
		threads_min = 16;
		resource_set_integer("WORK_THREADS_MIN", threads_min);
    } else {
		if (threads_min <= 0) {
			threads_min = 16;
			resource_set_integer("WORK_THREADS_MIN", threads_min);
		}
	}
    printf("[system]: minimum working threads number is %d\n", threads_min);

	if (!resource_get_uint("WORK_THREADS_MAX", &threads_max)) {
        threads_max = threads_min * 2; 
		resource_set_integer("WORK_THREADS_MAX", threads_max);
    } else {
		if (threads_max <= threads_min) {
			threads_max = threads_min + 1;
			resource_set_integer("WORK_THREADS_MAX", threads_max);
		}
    }
    printf("[system]: maximum working threads number is %d\n", threads_max);

	if (!resource_get_uint("FREE_CONTEXT_NUM", &free_contexts)) {
        free_contexts = threads_max; 
		resource_set_integer("FREE_CONTEXT_NUM", free_contexts);
    } else {
		if (free_contexts < threads_max) {
			free_contexts = threads_max; 
			resource_set_integer("FREE_CONTEXT_NUM", free_contexts);
		}
	}
    printf("[system]: free contexts number is %d\n", free_contexts);
    
	if (!resource_get_uint("CONTEXT_AVERAGE_MIME", &mime_ratio)) {
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
		mpc_plugin_list = const_cast<const char * const *>(read_file_by_line(str_value));
		if (mpc_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			return EXIT_FAILURE;
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
		service_plugin_list = const_cast<const char * const *>(read_file_by_line(str_value));
		if (service_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			return EXIT_FAILURE;
		}
	}
	str_value = resource_get_string("SERVICE_PLUGIN_IGNORE_ERRORS");
	bool svcplug_ignerr = parse_bool(str_value);
	resource_set_string("SERVICE_PLUGIN_IGNORE_ERRORS", svcplug_ignerr ? "true" : "false");

	const char *config_dir = str_val = resource_get_string("CONFIG_FILE_PATH");
	if (str_val == NULL) {
		config_dir = str_val = PKGSYSCONFDIR "/delivery:" PKGSYSCONFDIR;
		resource_set_string("CONFIG_FILE_PATH", str_val);
	}
	printf("[system]: config files path is %s\n", str_val);

	const char *data_dir = str_val = resource_get_string("DATA_FILE_PATH");
	if (str_val == NULL) {
		data_dir = str_val = PKGDATADIR "/delivery:" PKGDATADIR;
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
        console_server_port = 6677; 
		resource_set_integer("CONSOLE_SERVER_PORT", console_server_port);
    }
	printf("[console_server]: console server address is [%s]:%d\n",
	       *console_server_ip == '\0' ? "*" : console_server_ip, console_server_port);
	
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
		svcplug_ignerr, threads_max + free_contexts});
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
	auto cleanup_4 = make_scope_exit(service_stop);

    if (0 != system_services_run()) { 
		printf("[system]: failed to run system service\n");
		return EXIT_FAILURE;
    }
	auto cleanup_6 = make_scope_exit(system_services_stop);

	message_dequeue_init(dequeue_path, max_mem);
    if (0 != message_dequeue_run()) { 
		printf("[system]: failed to run message dequeue\n");
		return EXIT_FAILURE;
    }
	auto cleanup_7 = make_scope_exit(message_dequeue_free);
	auto cleanup_8 = make_scope_exit(message_dequeue_stop);

    console_server_init(console_server_ip, console_server_port);
	console_server_register_command("system", cmd_handler_system_control);
	console_server_register_command("help", cmd_handler_help);
	console_server_register_command(nullptr, cmd_handler_mpc_plugins);
	console_server_register_command(nullptr, cmd_handler_service_plugins);

    if (0 != console_server_run()) {
		printf("[system]: failed to run console server\n");
		return EXIT_FAILURE;
    }
	auto cleanup_9 = make_scope_exit(console_server_free);
	auto cleanup_10 = make_scope_exit(console_server_stop);

    transporter_init(mpc_plugin_path, mpc_plugin_list != NULL ?
		mpc_plugin_list : g_dfl_mpc_plugins, threads_min, threads_max,
		free_contexts, mime_ratio, domainlist_valid, mpcplug_ignerr);

	printf("--------------------------- mpc plugins begin"
		"---------------------------\n");
    if (0 != transporter_run()) { 
		printf(" ---------------------------- mpc plugins end"
			"-----------------------------\n");
		printf("[system]: failed to run transporter\n");
		return EXIT_FAILURE;
    } else {
		printf("----------------------------- mpc plugins end"
			"-----------------------------\n");
    }
	auto cleanup_11 = make_scope_exit(transporter_free);
	auto cleanup_12 = make_scope_exit(transporter_stop);

	retcode = EXIT_SUCCESS;
    printf("[system]: DELIVERY APP is now running\n");
	while (!g_notify_stop) {
        sleep(3);
		if (g_hup_signalled.exchange(false))
			service_reload_all();
    }
	return retcode;
} 

static void term_handler(int signo)
{
	console_server_notify_main_stop();
}


 
