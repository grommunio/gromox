#include "as_common.h"
#include "util.h"
#include "mem_file.h"
#include "config_file.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_017          46

typedef void (*SPAM_STATISTIC)(int);

static SPAM_STATISTIC spam_statistic;

DECLARE_API;

static char g_return_reason[1024];

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
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
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init(temp_path);
		if (NULL == pconfig_file) {
			printf("[property_017]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000046 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_017]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		if (FALSE == register_auditor(head_filter)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	int out_len;
	int tag_len;
	int val_len;
	char buff[1024];

	if (TRUE == pmail->penvelop->is_outbound ||
			TRUE == pmail->penvelop->is_relay) {
			return MESSAGE_ACCEPT;
	}
	if (SINGLE_PART_MAIL != pmail->phead->mail_part) {
		return MESSAGE_ACCEPT;
	}
	out_len = mem_file_read(&pmail->phead->f_xmailer, buff, 1024);
	if (MEM_END_OF_FILE == out_len) {
		return MESSAGE_ACCEPT;
	}
	if (0 != strncasecmp(buff, "Foxmail 6", 9) &&
		0 != strncasecmp(buff, "Foxmail 7", 9)) {
		return MESSAGE_ACCEPT;
	}
	while (MEM_END_OF_FILE != mem_file_read(
		&pmail->phead->f_others, &tag_len, sizeof(int))) {
		if (25 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp(buff, "Content-Transfer-Encoding", 25)) {
				mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
				if (4 != val_len) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others, buff, 4);
				if (0 != strncasecmp(buff, "8bit", 4)) {
					return MESSAGE_ACCEPT;
				}
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_PROPERTY_017);
				}
				strncpy(reason, g_return_reason, length);
				return MESSAGE_REJECT;
			}
		} else {
			mem_file_seek(&pmail->phead->f_others,
				MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others,
			MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
	}
	return MESSAGE_ACCEPT;
}
