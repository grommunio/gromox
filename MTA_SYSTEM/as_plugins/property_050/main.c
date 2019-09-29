#include "as_common.h"
#include "config_file.h"
#include "util.h"
#include <time.h>
#include <string.h>
#include <stdio.h>


#define SPAM_STATISTIC_PROPERTY_050		87


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
			printf("[property_050]: fail to get \"check_tagging\" service\n");
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
			printf("[property_050]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000087 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_050]: return string is %s\n", g_return_reason);
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
	int i;
	int up_num;
	int low_num;
	int tmp_len;
	char *ptoken;
	char buff[1024];

	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	tmp_len = mem_file_read(&pmail->phead->f_xmailer, buff, 1024);
	if (tmp_len < 7 && tmp_len > 12) {
		return MESSAGE_ACCEPT;
	}
	buff[tmp_len] = '\0';
	ptoken = strrchr(buff, ' ');
	if (NULL == ptoken) {
		return MESSAGE_ACCEPT;
	}
	*ptoken = '\0';
	ptoken ++;
	tmp_len = strlen(ptoken);
	if (1 != tmp_len && 2 != tmp_len) {
		return MESSAGE_ACCEPT;
	}
	for (i=0; i<tmp_len; i++) {
		if (0 == isdigit(ptoken[i])) {
			return MESSAGE_ACCEPT;
		}
	}
	up_num = 0;
	low_num = 0;
	ptoken = buff;
	while ('\0' != *ptoken) {
		if (islower(*ptoken)) {
			low_num ++;
		} else if (isupper(*ptoken)) {
			up_num ++;
		} else {
			return MESSAGE_ACCEPT;
		}
		ptoken ++;
	}
	if (low_num < 2 || 1 == up_num) {
		return MESSAGE_ACCEPT;
	}
	if (NULL != spam_statistic) {
		spam_statistic(SPAM_STATISTIC_PROPERTY_050);
	}
	strncpy(reason, g_return_reason, length);
	return MESSAGE_REJECT;
}
