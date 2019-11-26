#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "mail_func.h"
#include <stdio.h>

#define SPAM_STATISTIC_FROM_VALIDATOR			6

typedef BOOL (*WHITELIST_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECKING_USER)(char*, char*);

static WHITELIST_QUERY ip_whitelist_query;
static SPAM_STATISTIC spam_statistic;
static CHECKING_USER check_user;


DECLARE_API;

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop,
	CONNECTION *pconnection, char *reason, int length);

static char g_return_reason[1024];

BOOL AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		if (NULL == check_domain) {
			printf("[from_validator]: fail to get \"check_domain\" "
				"service\n");
			return FALSE;
		}
		check_user = (CHECKING_USER)query_service("check_user");
		if (NULL == check_user) {
			printf("[from_validator]: fail to get \"check_user\" "
				"service\n");
			return FALSE;
		}
		ip_whitelist_query = (WHITELIST_QUERY)query_service(
				            "ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[from_validator]: fail to get \"ip_whitelist_query\" "
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
			printf("[from_validator]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "authentification needed");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[from_validator]: return string is \"%s\"\n", g_return_reason);
		config_file_free(pconfig_file);
        /* invoke register_judge for registering judge of mail envelop */
        if (FALSE == register_judge(envelop_judge)) {
			printf("[from_validator]: failed to register judge function\n");
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
	char *pdomain;
	char tmp_buff[256];
	
	if (TRUE == penvelop->is_outbound || TRUE == penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == ip_whitelist_query(pconnection->client_ip)) {
		return MESSAGE_ACCEPT;
	}

	if (NULL == check_user) {
		return MESSAGE_ACCEPT;
	}

	pdomain = strchr(penvelop->from, '@');
	if (NULL == pdomain) {
		return MESSAGE_ACCEPT;
	}
	pdomain ++;

	if (FALSE == check_domain(pdomain)) {
		return MESSAGE_ACCEPT;
	}

	if (TRUE == check_user(penvelop->from, tmp_buff)) {
		mem_file_readline(&penvelop->f_rcpt_to, tmp_buff, 256);
		if (0 != strcasecmp(penvelop->from, tmp_buff)) {
			return MESSAGE_ACCEPT;
		}
	}
	
	strncpy(reason, g_return_reason, length);
	if (NULL != spam_statistic) {
		spam_statistic(SPAM_STATISTIC_FROM_VALIDATOR);
	}
	return MESSAGE_REJECT;
}

