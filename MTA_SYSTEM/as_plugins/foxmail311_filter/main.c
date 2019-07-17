#include "as_common.h"
#include "mem_file.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_FOXMAIL311_FILTER          9

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int xmailer_filter(int context_ID, MAIL_ENTITY* pmail, 
	CONNECTION *pconnection, char* reason, int length);

int AS_LibMain(int reason, void **ppdata)
{	
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[foxmail311_filter]: fail to get \"check_tagging\" service\n");
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
			printf("[foxmail311_filter]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			    strcpy(g_return_reason, "00009 您的邮件是使用foxmail3.11[cn]编写的，"
						"请使用高版本的foxmail");
		} else {
			    strcpy(g_return_reason, str_value);
		}
		printf("[foxmail311_filter]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		/* invoke register_filter for registering all type of mime paragraph*/
		if (FALSE == register_auditor(xmailer_filter)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}

static int xmailer_filter(int context_ID, MAIL_ENTITY* pmail, 
	CONNECTION *pconnection, char* reason, int length)
{
	char buff[1024];

	if (MULTI_PARTS_MAIL == pmail->phead->mail_part) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	memset(buff, 0 , 1024);
	if (MEM_END_OF_FILE == mem_file_read(&pmail->phead->f_xmailer, buff, 1024)){
		return MESSAGE_ACCEPT;
	}
	if (0 != strncmp(buff, "FoxMail 3.11 Release [cn]", 25) &&
		0 != strncmp(buff, "FoxMail 3.11 [cn]", 17)) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else { 
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_FOXMAIL311_FILTER);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}
}

