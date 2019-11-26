#include <errno.h>
#include <stdbool.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include <string.h>
#include <time.h>
#include <stdio.h>


#define SPAM_STATISTIC_PROPERTY_026		63


typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);

BOOL AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_026]: fail to get \"check_tagging\" service\n");
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
			printf("[property_026]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000063 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_026]: return string is \"%s\"\n", g_return_reason);
		config_file_free(pconfig_file);
		if (FALSE == register_auditor(head_filter)) {
			return FALSE;
		}
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    case SYS_THREAD_CREATE:
        return TRUE;
        /* a pool thread is created */
    case SYS_THREAD_DESTROY:
        return TRUE;
    }
	return false;
}

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	int out_len;
	char buff[1024];
	char rcpt_to[256];
	
	if (TRUE == pmail->penvelop->is_relay ||
		TRUE == pmail->penvelop->is_outbound) {
		return MESSAGE_ACCEPT;
	}
	out_len = mem_file_read(&pmail->phead->f_mime_from, buff, 1024);
	if (MEM_END_OF_FILE == out_len) {
		return MESSAGE_ACCEPT;
	}
	buff[out_len] = '\0';
	if ('<' == buff[0] && '>' == buff[out_len - 1]) {
		memmove(buff, buff + 1, out_len - 2);
		buff[out_len - 2] = '\0';
	}
	if (MEM_END_OF_FILE == mem_file_readline(
		&pmail->penvelop->f_rcpt_to, rcpt_to,
		256) || 0 != strcasecmp(rcpt_to, buff)) {
		return MESSAGE_ACCEPT;	
	}
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_026);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}
}

