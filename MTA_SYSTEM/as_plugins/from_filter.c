#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "mail_func.h"

#define SPAM_STATISTIC_FROM_FILTER		35

typedef BOOL (*FROM_FILTER_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);

static FROM_FILTER_QUERY from_filter_query;
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
		from_filter_query = (FROM_FILTER_QUERY)query_service(
							  "from_filter_query");
		if (NULL == from_filter_query) {
			printf("[from_filter]: failed to get service \"from_filter_query\"\n");
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
			printf("[from_filter]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000035 from address <%s> is forbidden");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[from_filter]: return string is \"%s\"\n", g_return_reason);
		config_file_free(pconfig_file);
        /* invoke register_judge for registering judge of mail envelop */
        if (FALSE == register_judge(envelop_judge)) {
			printf("[from_filter]: failed to register judge function\n");
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
	if (TRUE == penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}

	if (TRUE == penvelop->is_outbound) {
		if (TRUE ==  from_filter_query(penvelop->username)) {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_FROM_FILTER);
			}
			snprintf(reason, length, g_return_reason, penvelop->from);
			return MESSAGE_REJECT;
		}
	}
	
	if (TRUE == from_filter_query(penvelop->from)) {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_FROM_FILTER);
		}
		snprintf(reason, length, g_return_reason, penvelop->from);
		return MESSAGE_REJECT;
	}

	return MESSAGE_ACCEPT;
}

