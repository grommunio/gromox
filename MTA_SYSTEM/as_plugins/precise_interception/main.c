#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "util.h"
#include "mem_file.h"
#include "config_file.h"
#include "precise_interception.h"
#include <stdio.h>

#define SPAM_STATISTIC_PRECISE_INTERCEPTION          38


typedef void (*SPAM_STATISTIC)(int);

static SPAM_STATISTIC spam_statistic;

DECLARE_API;

static char g_return_reason[1024];

static int interception_filter(int action, int context_ID, MAIL_BLOCK* mail_blk,
	char* reason, int length);

int AS_LibMain(int reason, void **ppdata)
{	
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init2(NULL, temp_path);
		if (NULL == pconfig_file) {
			printf("[precise_interception]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000038 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[precise_interception]: return string is %s\n",
			g_return_reason);
		config_file_free(pconfig_file);
		sprintf(temp_path, "%s/%s", get_data_path(), file_name);
		precise_interception_init(temp_path);
		if (0 != precise_interception_run()) {
			printf("[precise_interception]: fail to run precise "
				"interception\n");
			return FALSE;
		}
		/* invoke register_filter for registering all type of mime paragraph*/
		if (FALSE == register_filter(NULL, interception_filter)) {
			printf("[precise_interception]: fail to register the filter "
				"function\n");
			return FALSE;
		}
		register_talk(precise_interception_console_talk);
		return TRUE;
	case PLUGIN_FREE:
		precise_interception_stop();
		precise_interception_free();
		return TRUE;
	}
	return TRUE;
}

static int interception_filter(int action, int context_ID, MAIL_BLOCK* mail_blk,
	char* reason, int length)
{
	int size;
	const char *ptr;
	MAIL_ENTITY mail_entity;

	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		mail_entity = get_mail_entity(context_ID);
		if (TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}
		if (TRUE == mail_blk->is_parsed) {
			ptr = mail_blk->parsed_buff;
			size = mail_blk->parsed_length;
		} else {
			ptr = mail_blk->original_buff;
			size = mail_blk->original_length;
		}
		if (TRUE == precise_interception_judge(ptr, size)) {
			return MESSAGE_ACCEPT;
		} else {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_PRECISE_INTERCEPTION);
			}
			strncpy(reason, g_return_reason, length);
			return MESSAGE_REJECT;
		}
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}


