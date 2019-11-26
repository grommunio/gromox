#include "as_common.h"
#include "config_file.h"
#include "util.h"
#include <ctype.h>
#include <string.h>
#include <stdio.h>


#define SPAM_STATISTIC_PROPERTY_029		66


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
			printf("[property_029]: fail to get \"check_tagging\" service\n");
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
			printf("[property_029]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000066 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_029]: return string is %s\n", g_return_reason);
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
}

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	int i, len;
	int out_len;
	char *pcharset;
	char buff[1024];
	

	if (TRUE == pmail->penvelop->is_relay ||
		SINGLE_PART_MAIL != pmail->phead->mail_part) {
		return MESSAGE_ACCEPT;
	}
	
	out_len = mem_file_read(&pmail->phead->f_xmailer, buff, 1024);
    if (MEM_END_OF_FILE == out_len) {
        return MESSAGE_ACCEPT;
    }
	buff[out_len] = '\0';
	if (0 != strncasecmp(buff, "Microsoft Outlook Express", 25)) {
		return MESSAGE_ACCEPT;
	}
	out_len = mem_file_read(&pmail->phead->f_subject, buff, 1024);
	if (MEM_END_OF_FILE == out_len) {
		return MESSAGE_ACCEPT;
	}
	buff[out_len] = '\0';
	pcharset = search_string(buff, "=?GB2312?B?", out_len);
	if (NULL == pcharset) {
		pcharset = search_string(buff, "=?ISO-2022-JP?B?", out_len);
		if (NULL == pcharset) {
			return MESSAGE_ACCEPT;
		}
	}
	len = pcharset - buff;
	if (len < 1 || len > 20) {
		return MESSAGE_ACCEPT;
	}
	for (i=0; i<len; i++) {
		if (buff[i] != '@' && buff[i] != '#' && buff[i] != '$' &&
			buff[i] != '%' && buff[i] != '^' && buff[i] != '&' &&
			buff[i] != '*' && buff[i] != '~' && buff[i] != ' ') {
			return MESSAGE_ACCEPT;
		}
	}
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_029);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}
}

