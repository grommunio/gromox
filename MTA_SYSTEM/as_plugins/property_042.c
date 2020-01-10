#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "mail_func.h"
#include "util.h"
#include <stdio.h>
#define SPAM_STATISTIC_PROPERTY_042          79

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

DECLARE_API;


static char g_return_reason[1024];

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);


int AS_LibMain(int reason, void **ppdata)
{	
	char file_name[256];
	char temp_path[256];
	char *str_value, *psearch;
	CONFIG_FILE *pconfig_file;
	
	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_042]: failed to get service \"check_tagging\"\n");
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
			printf("[property_042]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000079 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_042]: return string is \"%s\"\n", g_return_reason);
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
	int tmp_len;
	char *ptr1, *ptr2;
	char tmp_buff[1024];
	char file_name[1024];

	if (TRUE == pmail->penvelop->is_relay ||
		TRUE == pmail->penvelop->is_outbound) {
		return MESSAGE_ACCEPT;
	}
	
	if (SINGLE_PART_MAIL != pmail->phead->mail_part) {
		return MESSAGE_ACCEPT;
	}
	
	if (0 != mem_file_get_total_length(&pmail->phead->f_xmailer)) {
		return MESSAGE_ACCEPT;
	}

	tmp_len = mem_file_read(&pmail->phead->f_subject, tmp_buff, 1024);
	if (MEM_END_OF_FILE == tmp_len) {
		return MESSAGE_ACCEPT;
	}

	tmp_buff[tmp_len] = '\0';
	if (NULL == strstr(tmp_buff, "=?GB2312?B?")) {
		return MESSAGE_ACCEPT;
	}

	tmp_len = mem_file_read(&pmail->phead->f_content_type, tmp_buff, 1024);
	if (MEM_END_OF_FILE == tmp_len) {
		return MESSAGE_ACCEPT;
	}
	if (0 != strncasecmp(tmp_buff, "application/octet-stream", 24)) {
		return MESSAGE_ACCEPT;
	}

	
	tmp_len = strlen(tmp_buff);
	ptr1 = search_string(tmp_buff, "name=\"", tmp_len);
	if (NULL == ptr1) {
		return MESSAGE_ACCEPT;
	}
	ptr1 += 6;
	ptr2 = strchr(ptr1, '\"');
	if (NULL == ptr2) {
		return MESSAGE_ACCEPT;
	}
	memcpy(file_name, ptr1, ptr2 - ptr1);
	tmp_len = decode_mime_string(file_name, ptr2 - ptr1, tmp_buff, 1024);
	if (0 != strcasecmp(tmp_buff + tmp_len - 4, ".xls") &&
		0 != strcasecmp(tmp_buff + tmp_len - 4, ".doc")) {
		return MESSAGE_ACCEPT;
	}
	

	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_042);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}
}



