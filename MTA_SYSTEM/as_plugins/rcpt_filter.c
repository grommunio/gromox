#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include <stdio.h>

#define SPAM_STATISTIC_RCPT_FILTER			10

typedef BOOL (*FORBIDDEN_RCPT_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);

static FORBIDDEN_RCPT_QUERY forbidden_rcpt_query;
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
		forbidden_rcpt_query = (FORBIDDEN_RCPT_QUERY)query_service(
			"forbidden_rcpt_query");
		if (NULL == forbidden_rcpt_query) {
			printf("[rcpt_filter]: fail to get \"forbidden_rcpt_query\" "
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
			printf("[rcpt_filter]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000010 remote mail address %s "
				"is forbidden");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[rcpt_filter]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
        /* invoke register_judge for registering judge of mail envelop */
        if (FALSE == register_judge(envelop_judge)) {
			printf("[rcpt_filter]: fail to register judge function!!!\n");
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
	char mem_line[256];
	
	if (TRUE == penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	while (MEM_END_OF_FILE != mem_file_readline(
		&penvelop->f_rcpt_to, mem_line, 256)) {
		if (TRUE == forbidden_rcpt_query(mem_line)) {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_RCPT_FILTER);
			}
			snprintf(reason, length, g_return_reason, mem_line);
			return MESSAGE_REJECT;
		}
	}
	return MESSAGE_ACCEPT;
}

