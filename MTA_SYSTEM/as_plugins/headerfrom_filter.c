#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "mem_file.h"
#include "config_file.h"
#include "mail_func.h"
#include <stdio.h>

#define SPAM_STATISTIC_HEADERFROM_FILTER          19

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*WHITELIST_QUERY)(char*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static WHITELIST_QUERY domain_whitelist_query;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int headerfrom_filter(int context_ID, MAIL_ENTITY* pmail, 
	CONNECTION *pconnection, char* reason, int length);

int AS_LibMain(int reason, void **ppdata)
{	
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		domain_whitelist_query = (WHITELIST_QUERY)query_service(
										"domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[headerfrom_filter]: fail to get "
				"\"domain_whitelist_query\" service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[headerfrom_filter]: fail to "
				"get \"check_tagging\" service\n");
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
			printf("[headerfrom_filter]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason,
				"000019 header from in your mail is illegal");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[headerfrom_filter]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		/* invoke register_filter for registering all type of mime paragraph*/
		if (FALSE == register_auditor(headerfrom_filter)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}

static int headerfrom_filter(int context_ID, MAIL_ENTITY* pmail, 
	CONNECTION *pconnection, char* reason, int length)
{
	int buff_len;
	char *pdomain;
	char buff[1024];
	char rcpt_to[256];
	char tmp_address[256];
	EMAIL_ADDR email_addr;

	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (MULTI_PARTS_MAIL == pmail->phead->mail_part) {
		return MESSAGE_ACCEPT;
	}
	pdomain = strchr(pmail->penvelop->from, '@') + 1;
	if (TRUE == domain_whitelist_query(pdomain)) {
		return MESSAGE_ACCEPT;
	}
	mem_file_readline(&pmail->penvelop->f_rcpt_to, rcpt_to, 256);
	buff_len = mem_file_read(&pmail->phead->f_mime_from, buff, 1024);
	if (MEM_END_OF_FILE == buff_len || buff_len >= 1024) {
		return MESSAGE_ACCEPT;
	}
	buff[buff_len] = '\0';
	parse_email_addr(&email_addr, buff);
	snprintf(tmp_address, 256, "%s@%s", email_addr.local_part, email_addr.domain);
	if (0 == strcasecmp(tmp_address, rcpt_to)) {
		if (TRUE == check_tagging(pmail->penvelop->from,
			&pmail->penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_HEADERFROM_FILTER);
			}
			strncpy(reason, g_return_reason, length);
			return MESSAGE_REJECT;
		}
	}
	return MESSAGE_ACCEPT;
}
