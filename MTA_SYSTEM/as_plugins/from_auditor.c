#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "mail_func.h"
#include <stdio.h>

#define SPAM_STATISTIC_FROM_AUDITOR		13

typedef BOOL (*FROM_AUDIT)(char*);
typedef BOOL (*WHITELIST_QUERY)(char*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);
typedef void (*SPAM_STATISTIC)(int);

static FROM_AUDIT from_audit;
static WHITELIST_QUERY ip_whitelist_query;
static CHECK_TAGGING check_tagging;
static SPAM_STATISTIC spam_statistic;

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
		from_audit = (FROM_AUDIT)query_service("from_audit");
		if (NULL == from_audit) {
			printf("[from_auditor]: fail to get \"from_audit\" service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[from_auditor]: fail to get \"check_tagging\" service\n");
			return FALSE;
		}
		ip_whitelist_query = (WHITELIST_QUERY)query_service(
								"ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[from_auditor]: fail to get \"ip_whitelist_query\" "
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
		pconfig_file = config_file_init(temp_path);
		if (NULL == pconfig_file) {
			printf("[from_auditor]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000013 empty from address is forbidden");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[from_auditor]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
        /* invoke register_judge for registering judge of mail envelop */
        if (FALSE == register_judge(envelop_judge)) {
			printf("[from_auditor]: fail to register judge function!!!\n");
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
	char rcpt_address[256];
	
	if (TRUE == penvelop->is_outbound || TRUE == penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	
	if (0 != strcmp(penvelop->from, "none@none")) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == ip_whitelist_query(pconnection->client_ip)) {
		return MESSAGE_ACCEPT;
	}
	mem_file_readline(&penvelop->f_rcpt_to, rcpt_address, 256);
	pdomain = strchr(rcpt_address, '@');
	pdomain ++;
	if (FALSE == from_audit(pdomain)) {
		if (TRUE == check_tagging(penvelop->from, &penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_FROM_AUDITOR);
			}
			strncpy(reason, g_return_reason, length);
			return MESSAGE_REJECT;
		}
	}
	return MESSAGE_ACCEPT;
}

