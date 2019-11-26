#include "util.h"
#include "as_common.h"
#include "config_file.h"
#include <pthread.h>
#include <stdio.h>

#define SPAM_STATISTIC_TROJAN_DETECTOR		9

typedef void (*SPAM_STATISTIC)(int);
typedef void (*DISABLE_SMTP)(const char*);

static SPAM_STATISTIC spam_statistic;
static DISABLE_SMTP disable_smtp;

DECLARE_API;

static char g_return_string[1024];

static int xmailer_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);

int AS_LibMain(int reason, void **ppdata)
{
	char *psearch;
	char *str_value;
	char file_name[256];
	char temp_path[256];
	CONFIG_FILE *pconfig_file;

	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		disable_smtp = (DISABLE_SMTP)query_service("disable_smtp");
		if (NULL == disable_smtp) {
			printf("[trojan_detector]: fail to "
				"get \"disable_smtp\" service");
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
			printf("[trojan_detector]: fail to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000009 this account will be disabled!");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[trojan_detector]: return string is %s\n", g_return_string);
		config_file_free(pconfig_file);
		/* invoke register_auditor for registering auditor of mime head */
		if (FALSE == register_auditor(xmailer_filter)) {
			printf("[trojan_detector]: fail to register auditor function!!!\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}

static int xmailer_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	int tmp_len;
	char tmp_buff[1024];
	
	if (FALSE == pmail->penvelop->is_outbound) {
		return MESSAGE_ACCEPT;
	}
	tmp_len = mem_file_read(&pmail->phead->f_xmailer,
					tmp_buff, sizeof(tmp_buff) - 1);
	if (MEM_END_OF_FILE == tmp_len) {
		return MESSAGE_ACCEPT;
	}
	tmp_buff[tmp_len] = '\0';
	if (0 != strcasecmp(tmp_buff, "Outlook")) {
		return MESSAGE_ACCEPT;
	}
	disable_smtp(pmail->penvelop->username);
	if (NULL != spam_statistic) {
		spam_statistic(SPAM_STATISTIC_TROJAN_DETECTOR);
	}
	strncpy(reason, g_return_string, length);
	return MESSAGE_REJECT;
}
