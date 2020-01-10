#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "util.h"
#include "config_file.h"
#include <stdio.h>
#define SPAM_STATISTIC_PROPERTY_041		78

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop,
	CONNECTION *pconnection, char *reason, int length)
{
	char *ptoken;
	
	if (TRUE == penvelop->is_relay ||
		TRUE == penvelop->is_outbound) {
		return MESSAGE_ACCEPT;
	}
	ptoken = strchr(penvelop->from, '@');
	if (NULL == ptoken) {
		return MESSAGE_ACCEPT;
	}
	ptoken ++;
	if (0 != strncasecmp(ptoken, "mail.", 5)) {
		return MESSAGE_ACCEPT;
	}
	ptoken += 5;
	ptoken = strchr(ptoken, '.');
	if (NULL == ptoken) {
		return MESSAGE_ACCEPT;
	}
	if (0 != strcasecmp(ptoken, ".bid") &&
		0 != strcasecmp(ptoken, ".icu")) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == check_tagging(penvelop->from, &penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_041);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}
	return MESSAGE_ACCEPT;
}

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
			printf("[property_041]: failed to get service \"check_tagging\"\n");
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
			printf("[property_041]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000078 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_041]: return string is \"%s\"\n", g_return_reason);
		config_file_free(pconfig_file);
		if (FALSE== register_judge(envelop_judge)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}
