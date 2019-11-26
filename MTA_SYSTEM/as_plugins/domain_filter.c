#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "mail_func.h"
#include <stdio.h>

#define SPAM_STATISTIC_DOMAIN_FILTER		18

typedef BOOL (*DOMAIN_FILTER_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);

static DOMAIN_FILTER_QUERY domain_filter_query;
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
		domain_filter_query = (DOMAIN_FILTER_QUERY)query_service(
							  "domain_filter_query");
		if (NULL == domain_filter_query) {
			printf("[domain_filter]: fail to get \"domain_filter_query\" "
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
			printf("[domain_filter]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000018 domain %s is forbidden");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[domain_filter]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
        /* invoke register_judge for registering judge of mail envelop */
        if (FALSE == register_judge(envelop_judge)) {
			printf("[domain_filter]: fail to register judge function!!!\n");
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
	EMAIL_ADDR email_address;
	char mem_line[256];
	
	if (TRUE == penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	parse_email_addr(&email_address, penvelop->from);
	if (TRUE == domain_filter_query(email_address.domain)) {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_DOMAIN_FILTER);
		}
		snprintf(reason, length, g_return_reason, email_address.domain);
		return MESSAGE_REJECT;
	}

	while (MEM_END_OF_FILE != mem_file_readline(
		&penvelop->f_rcpt_to, mem_line, 256)) {
		parse_email_addr(&email_address, mem_line);
		if (TRUE == domain_filter_query(email_address.domain)) {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_DOMAIN_FILTER);
			}
			snprintf(reason, length, g_return_reason, email_address.domain);
			return MESSAGE_REJECT;
		}
	}
	return MESSAGE_ACCEPT;
}

