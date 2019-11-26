#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "mail_func.h"
#include <stdio.h>

#define SPAM_STATISTIC_NEED_AUTH		6

typedef BOOL (*WHITELIST_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);
		
static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop, 
    CONNECTION *pconnection, char *reason, int length);

DECLARE_API;

static WHITELIST_QUERY ip_whitelist_query;
static SPAM_STATISTIC spam_statistic;

static char g_return_string[1024];

int AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
    
	switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);

		ip_whitelist_query = (WHITELIST_QUERY)query_service(
							"ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[auth_whitelist]: fail to get \"ip_whitelist_query\" "
					"service\n");
			return FALSE;

		}
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init2(NULL, temp_path);
		if (NULL == pconfig_file) {
			printf("[auth_whitelist]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "authentification needed");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[auth_whitelist]: return string is %s\n", g_return_string);
		config_file_free(pconfig_file);
        if (FALSE == register_judge(envelop_judge)) {
			printf("[auth_whitelist]: fail to register judge function!!!\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
	return TRUE;
}

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop,
    CONNECTION *pconnection, char *reason, int length)
{
    if (FALSE == penvelop->is_relay && TRUE == penvelop->is_outbound &&
		FALSE == penvelop->is_login) {
		if (0 == strcasecmp(penvelop->from, "system-monitor@system.mail") &&
			0 == strcmp(pconnection->client_ip, "127.0.0.1")) {
			return MESSAGE_ACCEPT;
		}
        if (FALSE == ip_whitelist_query(pconnection->client_ip)) { 
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_NEED_AUTH);
			}
            strncpy(reason, g_return_string, length);
            return MESSAGE_REJECT;
        }
		strcpy(penvelop->username, penvelop->from);
    }
    return MESSAGE_ACCEPT;
}

