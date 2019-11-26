#include "config_file.h"
#include "mail_func.h"
#include "as_common.h"
#include "mem_file.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_SCAMMING_FILTER          20

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*WHITELIST_QUERY)(char*);

static SPAM_STATISTIC spam_statistic;
static WHITELIST_QUERY domain_whitelist_query;

DECLARE_API;

static char g_return_reason[1024];

static int scamming_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);

int AS_LibMain(int reason, void **ppdata)
{	
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		domain_whitelist_query = (WHITELIST_QUERY)query_service(
									"domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[scamming_filter]: fail to get "
				"\"domain_whitelist_query\" service\n");
			return FALSE;
		}
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init(temp_path);
		if (NULL == pconfig_file) {
			printf("[scamming_filter]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, 
				"000020 please don't send scamming email!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[scamming_filter]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		if (FALSE == register_auditor(scamming_filter)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}

static int scamming_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	char *pdomain;
	size_t tmp_len;
	char tmp_buff[1024];
	EMAIL_ADDR email_addr;
	EMAIL_ADDR email_addr1;
	
	if (TRUE == pmail->penvelop->is_relay ||
		TRUE == pmail->penvelop->is_outbound) {
		return MESSAGE_ACCEPT;
	}
	pdomain = strchr(pmail->penvelop->from, '@');
	pdomain ++;
	if (TRUE == domain_whitelist_query(pdomain)) {
		return MESSAGE_ACCEPT;
	}
	tmp_len = mem_file_get_total_length(&pmail->phead->f_mime_from);
	if (tmp_len > 1024 || 0 == tmp_len) {
		return MESSAGE_ACCEPT;
	}
	mem_file_read(&pmail->phead->f_mime_from, tmp_buff, 1024);
	parse_email_addr(&email_addr, tmp_buff);
	if (NULL == strchr(email_addr.display_name, '@')
		|| '\0' == email_addr.local_part[0]
		|| '\0' == email_addr.domain[0]) {
		return MESSAGE_ACCEPT;
	}
	parse_email_addr(&email_addr1, email_addr.display_name);
	if ('\0' == email_addr1.local_part[0] ||
		'\0' == email_addr1.domain[0] ||
		NULL == strchr(email_addr1.domain, '.') ||
		NULL != strchr(email_addr1.domain, ')')) {
		return MESSAGE_ACCEPT;	
	}
	if (0 == strcasecmp(email_addr.domain, email_addr1.domain)) {
		return MESSAGE_ACCEPT;	
	}
	if (NULL != spam_statistic) {
		spam_statistic(SPAM_STATISTIC_SCAMMING_FILTER);
	}
	strncpy(reason, g_return_reason, length);
	return MESSAGE_REJECT;
}
