#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <gromox/hook_common.h>
#include "config_file.h"
#include "relay_agent.h"
#include "relay_bridge.h"
#include "ip_range.h"
#include "util.h"
#include "vstack.h"
#include <pthread.h>
#include <stdio.h>

typedef BOOL (*RELAY_DOMAINS_QUERY)(char*);
typedef BOOL (*DNS_QUERY)(char*, VSTACK*);
typedef BOOL (*CHECK_LOCAL)(const char*);

DECLARE_API;

static BOOL mail_hook(MESSAGE_CONTEXT *pcontext);

static void console_talk(int argc, char **argv, char *result, int length);

static RELAY_DOMAINS_QUERY relay_domains_query;

static DNS_QUERY dns_query_A;

static DNS_QUERY dns_query_MX;

static CHECK_LOCAL dns_check_local;

static LIB_BUFFER *g_stack_allocator;

static int g_max_thr;
static int g_concurrent_thr;
static char g_config_path[256];
static pthread_mutex_t g_concurrent_mutex;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	int interval;
	int listen_port;
	int channel_num;
	BOOL b_main;
	BOOL relay_switch;
	char temp_buff[64];
    char file_name[256];
	char tmp_path[256];
	char url_path[1024];
	char mess_path[256];
	char save_path[256];
	char token_path[256];
	char country[16];
    char *psearch;
	char *str_value;
	CONFIG_FILE *pfile;

	/* path contains the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		g_concurrent_thr = 0;

		if (get_threads_num() - 4 > 0) {
			g_max_thr = get_threads_num() - 4;
		} else {
			g_max_thr = get_threads_num();
		}
		
		pthread_mutex_init(&g_concurrent_mutex, NULL);
		
		relay_domains_query = (RELAY_DOMAINS_QUERY)query_service(
								"relay_domains_query");
		if (NULL == relay_domains_query) {
			printf("[relay_agent]: failed to get service \"relay_domains_query\"\n");
            return FALSE;
		}
		dns_query_A = (DNS_QUERY)query_service("dns_query_A");
		if (NULL == dns_query_A) {
			printf("[relay_agent]: failed to get service \"dns_query_A\"\n");
			return FALSE;
		}

		dns_query_MX = (DNS_QUERY)query_service("dns_query_MX");
		if (NULL == dns_query_MX) {
			printf("[relay_agent]: failed to get service \"dns_query_MX\"\n");
			return FALSE;
		}

		dns_check_local = (CHECK_LOCAL)query_service("dns_check_local");
		if (NULL == dns_check_local) {
			printf("[relay_agent]: failed to get service \"dns_check_local\"\n");
			return FALSE;
		}
		
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(g_config_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			printf("[relay_agent]: config_file_init %s: %s\n", g_config_path, strerror(errno));
			return FALSE;
		}

		str_value = config_file_get_value(pfile, "RELAY_SWITCH");
		if (NULL == str_value) {
			config_file_set_value(pfile, "RELAY_SWITCH", "OFF");
			relay_switch = FALSE;
		} else {
			if (0 == strcasecmp(str_value, "ON")) {
				relay_switch = TRUE;
			} else {
				relay_switch = FALSE;
			}
		}

		if (TRUE == relay_switch) {
			printf("[relay_agent]: relay switch is ON\n");
		} else {
			printf("[relay_agent]: relay switch is OFF\n");
		}
		
		str_value = config_file_get_value(pfile, "URL_PATH");
		if (NULL == str_value) {
			strcpy(url_path, "http://ftp.apnic.net/apnic/dbase/data/country-ipv4.lst");
			config_file_set_value(pfile, "URL_PATH", url_path);
		} else {
			strcpy(url_path, str_value);
		}
		printf("[relay_agent]: download url path is %s\n", url_path);
		
		str_value = config_file_get_value(pfile, "DOWNLOAD_INTERVAL");
		if (NULL == str_value) {
			config_file_set_value(pfile, "DOWNLOAD_INTERVAL", "12hours");
			interval = 12*60*60;
		} else {
			interval = atoitvl(str_value);
			if (interval <= 0) {
				interval = 12*60*60;
			}
		}
		itvltoa(interval, temp_buff);
		printf("[relay_agent]: download interval is %s\n", temp_buff);
		
		str_value = config_file_get_value(pfile, "COUNTRY");
		if (NULL == str_value) {
			config_file_set_value(pfile, "COUNTRY", "CN");
			strcpy(country, "CN");
		} else {
			strcpy(country, str_value);
		}
		printf("[relay_agent]: country code is %s\n", country);

		str_value = config_file_get_value(pfile, "TYPE");
		if (NULL == str_value) {
			config_file_set_value(pfile, "TYPE", "0");
			b_main = TRUE;
		} else {
			if (0 == strcmp(str_value, "0")) {
				b_main = TRUE;
			} else if (0 == strcmp(str_value, "1")) {
				b_main = FALSE;
			} else {
				b_main = TRUE;
				config_file_set_value(pfile, "TYPE", "0");
			}
		}
		if (FALSE == b_main) {
			printf("[relay_agent]: site type is main\n");
		} else {
			printf("[relay_agent]: site tyep is mirror\n");
		}

		str_value = config_file_get_value(pfile, "CHANNEL_NUM");
		if (NULL == str_value) {
			channel_num = 8;
			config_file_set_value(pfile, "CHANNEL_NUM", "8");
		} else {
			channel_num = atoi(str_value);
			if (channel_num <= 0) {
				channel_num = 8;
				config_file_set_value(pfile, "CHANNEL_NUM", "8");
			}
		}
		printf("[relay_agent]: channel number per host is %d\n", channel_num);

		str_value = config_file_get_value(pfile, "LISTEN_PORT");
		if (NULL == str_value) {
			listen_port = 8000;
			config_file_set_value(pfile, "LISTEN_PORT", "8000");
		} else {
			listen_port = atoi(str_value);
			if (listen_port <= 0) {
				listen_port = 8000;
				config_file_set_value(pfile, "LISTEN_PORT", "8000");
			}
		}
		printf("[relay_agent]: listen port is %d\n", listen_port);
		config_file_free(pfile);

		sprintf(mess_path, "%s/mess", get_queue_path());
		sprintf(save_path, "%s/save", get_queue_path());
		sprintf(token_path, "%s/token.ipc", get_queue_path());
        sprintf(tmp_path, "%s/%s.txt", get_data_path(), file_name);
		relay_agent_init(tmp_path, save_path, channel_num, relay_switch);
		sprintf(tmp_path, "%s/ip_range.txt", get_data_path());
		ip_range_init(tmp_path, url_path, interval, country, b_main);
		sprintf(tmp_path, "%s/relay_allow.txt", get_data_path());
		relay_bridge_init(listen_port, tmp_path, mess_path, save_path,
			token_path);
		g_stack_allocator = vstack_allocator_init(16, 1024*get_context_num(), TRUE);
		if (NULL == g_stack_allocator) {
			printf("[relay_agent]: Failed to init stack allocator\n");
			return FALSE;
		}
		if (0 != ip_range_run()) {
			printf("[relay_agent]: failed to run ip range module\n");
			return FALSE;
		}
		if (0 != relay_agent_run()) {
			printf("[relay_agent]: failed to run relay agent module\n");
			ip_range_stop();
			ip_range_free();
            return FALSE;
		}
		if (0 != relay_bridge_run()) {
			printf("[relay_agent]: failed to run relay bridge module\n");
			relay_agent_stop();
			relay_agent_free();
			ip_range_stop();
			ip_range_free();
			return FALSE;
		}
		register_talk(console_talk);
        if (FALSE == register_hook(mail_hook)) {
			printf("[relay_agent]: failed to register the hook function\n");
			relay_agent_stop();
			relay_agent_free();
			relay_bridge_stop();
			relay_bridge_free();
			ip_range_stop();
			ip_range_free();
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
		if (NULL != g_stack_allocator) {
			vstack_allocator_free(g_stack_allocator);
			g_stack_allocator = NULL;
		}
		relay_bridge_stop();
		relay_bridge_free();
		relay_agent_stop();
		relay_agent_free();
		ip_range_stop();
		ip_range_free();
		pthread_mutex_destroy(&g_concurrent_mutex);
        return TRUE;
    }
	return false;
}

static BOOL mail_hook(MESSAGE_CONTEXT *pcontext)
{
	MEM_FILE pass_file, tmp_file;
	char rcpt_to[256];
	char temp_buff[256];
	char *pdomain, *dest_ip;
	BOOL need_relay;
	BOOL relay_all;
	BOOL in_range;
	BOOL can_enter;
	BOOL process_result;
	VSTACK stack;
	MIME *pmime;

	if (FALSE == relay_agent_get_param(RELAY_SWITCH)) {
		return FALSE;
	}

	if (0 == strcasecmp(pcontext->pcontrol->from,
		"system-monitor@system.mail")) {
		return FALSE;
	}

	pmime = mail_get_head(pcontext->pmail);
	if (NULL == pmime) {
		return FALSE;
	}
	if (BOUND_IN != pcontext->pcontrol->bound_type &&
		TRUE == mime_get_field(pmime, "X-Penetrate-Bounce", temp_buff, 256)) {
		if (0 == strcasecmp(temp_buff, "No")) {
			pcontext->pcontrol->need_bounce = FALSE;
		}
		if (mime_get_field_num(pmime, "X-Penetrate-Bounce") >= 2) {
			return FALSE;
		}
	}

	pthread_mutex_lock(&g_concurrent_mutex);
	if (g_concurrent_thr >= g_max_thr) {
		can_enter = FALSE;
	} else {
		g_concurrent_thr ++;
		can_enter = TRUE;
	}
	pthread_mutex_unlock(&g_concurrent_mutex);

	if (FALSE == can_enter) {
		return FALSE;
	}
	
	mem_file_init(&tmp_file, pcontext->pcontrol->f_rcpt_to.allocator);
	mem_file_init(&pass_file, pcontext->pcontrol->f_rcpt_to.allocator);
	mem_file_copy(&pcontext->pcontrol->f_rcpt_to, &tmp_file);
	mem_file_clear(&pcontext->pcontrol->f_rcpt_to);
	need_relay = FALSE;
	relay_all = TRUE;
	while (MEM_END_OF_FILE != mem_file_readline(&tmp_file, rcpt_to, 256)) {
		pdomain = strchr(rcpt_to, '@');
		if (NULL == pdomain) {
			relay_all = FALSE;
			mem_file_writeline(&pass_file, rcpt_to);
			continue;
		}
		pdomain ++;
		if (TRUE == relay_domains_query(pdomain)) {
			relay_all = FALSE;
			mem_file_writeline(&pass_file, rcpt_to);
			continue;
		}
		if (TRUE == is_domainlist_valid()) {
			if (TRUE == check_domain(pdomain)) {
				if (TRUE == ip_range_get_param(SITE_TYPE)) {
					relay_all = FALSE;
					mem_file_writeline(&pass_file, rcpt_to);
				} else {
					need_relay = TRUE;
					mem_file_writeline(&pcontext->pcontrol->f_rcpt_to, rcpt_to);
				}
				continue;
			}
		} else {
			if (TRUE == dns_check_local(pdomain)) {
				if (TRUE == ip_range_get_param(SITE_TYPE)) {
					relay_all = FALSE;
					mem_file_writeline(&pass_file, rcpt_to);
				} else {
					need_relay = TRUE;
					mem_file_writeline(&pcontext->pcontrol->f_rcpt_to, rcpt_to);	
				}
				continue;
			}
		}
		
		vstack_init(&stack, g_stack_allocator, 16, 1024);
		if (FALSE == dns_query_MX(pdomain, &stack) &&
			FALSE == dns_query_A(pdomain, &stack)) {
			relay_all = FALSE;
			mem_file_writeline(&pass_file, rcpt_to);
			vstack_free(&stack);
			continue;
		}

		in_range = FALSE;
		while (FALSE == vstack_is_empty(&stack)) {
			dest_ip = vstack_get_top(&stack);
			if (TRUE == ip_range_check(dest_ip)) {
				in_range = TRUE;
				break;
			}
			vstack_pop(&stack);
		}
		vstack_free(&stack);
		
		if (TRUE == ip_range_get_param(SITE_TYPE)) {
			if (TRUE == in_range) {
				relay_all = FALSE;
				mem_file_writeline(&pass_file, rcpt_to);
			} else {
				need_relay = TRUE;
				mem_file_writeline(&pcontext->pcontrol->f_rcpt_to, rcpt_to);
			}
		} else {
			if (TRUE == in_range) {
				need_relay = TRUE;
				mem_file_writeline(&pcontext->pcontrol->f_rcpt_to, rcpt_to);
			} else {
				relay_all = FALSE;
				mem_file_writeline(&pass_file, rcpt_to);
			}
		}	
	}

	pthread_mutex_lock(&g_concurrent_mutex);
	g_concurrent_thr --;
	pthread_mutex_unlock(&g_concurrent_mutex);
	
	if (FALSE == need_relay) {
		mem_file_copy(&tmp_file, &pcontext->pcontrol->f_rcpt_to);
		mem_file_free(&tmp_file);
		mem_file_free(&pass_file);
		return FALSE;
	}
	process_result = relay_agent_process(pcontext);
	if (FALSE == process_result) {
		mem_file_copy(&tmp_file, &pcontext->pcontrol->f_rcpt_to);
	} else {
		mem_file_copy(&pass_file, &pcontext->pcontrol->f_rcpt_to);
	}
	mem_file_free(&tmp_file);
	mem_file_free(&pass_file);
	if (FALSE == process_result || FALSE == relay_all) {
		return FALSE;
	} else {
		return TRUE;
	}
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	int interval;
	CONFIG_FILE *pfile;
	char str_interval[32];
	char help_string[] = "250 relay agent help information:\r\n"
						 "\t%s info\r\n"
						 "\t    --print the module information\r\n"
						 "\t%s switch [ON|OFF]\r\n"
						 "\t    --turn the relay switch ON or OFF\r\n"
						 "\t%s set <download-interval>\r\n"
						 "\t    --set download interval of ip range list\r\n"
		                 "\t%s reload agent\r\n"
						 "\t    --reload the relay table from list file\r\n"
						 "\t%s reload allow\r\n"
						 "\t    --reload the allow table from list file";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0],
			argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}

	if (2 == argc && 0 == strcmp("info", argv[1])) {
		itvltoa(ip_range_get_param(DOWNLOAD_INTERVAL), str_interval); 
		snprintf(result, length,
				"250 relay agent module information:\r\n"
				"\tswitch                   %s\r\n"
				"\tcountry                  %s\r\n"
				"\tsite type                %s\r\n"
				"\tdownload url             %s\r\n"
				"\tdownload interval        %s\r\n",
				relay_agent_get_param(RELAY_SWITCH)?"ON" : "OFF",
				ip_range_country(),
				ip_range_get_param(SITE_TYPE)?"main" : "mirror",
				ip_range_url(),
				str_interval);
		result[length - 1] ='\0';
		return;		
	}

	if (3 == argc && 0 == strcmp("switch", argv[1])) {
		if (0 == strcasecmp(argv[2], "ON")) {
			pfile = config_file_init2(NULL, g_config_path);
			if (NULL == pfile) {
				strncpy(result, "550 Failed to open config file", length);
				return;
			}
			config_file_set_value(pfile, "RELAY_SWITCH", "ON");
			if (FALSE == config_file_save(pfile)) {
				strncpy(result, "550 fail to save config file", length);
				config_file_free(pfile);
				return;
			}
			config_file_free(pfile);
			relay_agent_set_param(RELAY_SWITCH, TRUE);
			strncpy(result, "250 relay switch is turned ON", length);
			return;
		} else if (0 == strcasecmp(argv[2], "OFF")) {
			pfile = config_file_init2(NULL, g_config_path);
			if (NULL == pfile) {
				strncpy(result, "550 Failed to open config file", length);
				return;
			}
			config_file_set_value(pfile, "RELAY_SWITCH", "OFF");
			if (FALSE == config_file_save(pfile)) {
				strncpy(result, "550 fail to save config file", length);
				config_file_free(pfile);
				return;
			}
			config_file_free(pfile);
			relay_agent_set_param(RELAY_SWITCH, FALSE);
			strncpy(result, "250 relay switch is turned OFF", length);
			return;
		}
		snprintf(result, length, "550 unkonwn parameter %s, can only be "
			"ON or OFF", argv[2]);
		return;
	}
	
	if (3 == argc && 0 == strcmp("set", argv[1])) {
		interval = atoitvl(argv[2]);
		if (interval <= 0) {
			snprintf(result, length, "550 illegal interval %s", argv[2]);
			return;
		}
		pfile = config_file_init2(NULL, g_config_path);
		if (NULL == pfile) {
			strncpy(result, "550 Failed to open config file", length);
			return;
		}
		config_file_set_value(pfile, "DOWNLOAD_INTERVAL", argv[2]);
		if (FALSE == config_file_save(pfile)) {
			strncpy(result, "550 fail to save config file", length);
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		ip_range_set_param(DOWNLOAD_INTERVAL, interval);
		strncpy(result, "250 set download interval OK", length);
		return;
	}
	
	if (3 == argc && 0 == strcmp("reload", argv[1])) {
		if (0 == strcmp("agent", argv[2])) {
			if (TRUE == relay_agent_refresh_table()) {
				strncpy(result, "250 relay table reload OK", length);
			} else {
				strncpy(result, "550 fail to reload relay table", length);
			}
		} else if (0 == strcmp("allow", argv[2])) {
			if (TRUE == relay_bridge_refresh_table()) {
				strncpy(result, "250 allow table reload OK", length);
			} else {
				strncpy(result, "550 fail to relay allow table", length);
			}
		} else {
			snprintf(result, length, "550 invalid argument %s", argv[2]);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

