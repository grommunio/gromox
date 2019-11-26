#include <gromox/as_common.h>
#include "util.h"
#include "config_file.h"
#include <stdio.h>
#define SPAM_STATISTIC_PROPERTY_055		92

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
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
	switch (reason) {
	case PLUGIN_INIT:

		LINK_API(ppdata);

		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_055]: fail to get \"check_tagging\" service\n");
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
			printf("[property_055]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000092 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_055]: return string is %s\n", g_return_reason);
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
	int tag_len;
	int val_len;
	char buff[1024];
	char rcpt_to[256];

	
	if (TRUE == pmail->penvelop->is_relay ||
		TRUE == pmail->penvelop->is_outbound) {
		return MESSAGE_ACCEPT;
	}

	if (0 == strncmp(pmail->penvelop->from, "prvs=", 5)) {
		return MESSAGE_ACCEPT;
	}

	if ('\0' != pmail->phead->x_original_ip[0]) {
		return MESSAGE_ACCEPT;
	}

	if (MEM_END_OF_FILE == mem_file_readline(&pmail->penvelop->f_rcpt_to,
		rcpt_to, 256)) {
		return MESSAGE_ACCEPT;
	}


	if (mem_file_get_total_length(&pmail->phead->f_xmailer) > 0) {
		return MESSAGE_ACCEPT;
	}

	tmp_len = mem_file_readline(&pmail->phead->f_mime_to, buff, 1024);
	if (MEM_END_OF_FILE != tmp_len) {
		ltrim_string(buff);
		rtrim_string(buff);
		if ('<' != buff[0] && '\0' != buff[0] &&
			0 != strcasecmp(buff, rcpt_to)) {
			return MESSAGE_ACCEPT;
		}
	}

	tmp_len = mem_file_read(&pmail->phead->f_content_type, buff, 1024);
	if (MEM_END_OF_FILE == tmp_len) {
		return MESSAGE_ACCEPT;
	}

	if (0 != strncasecmp(buff, "text/plain", 10) &&
		0 != strncasecmp(buff, "text/html", 9) &&
		0 != strncasecmp(buff, "multipart/alternative", 21)) {
		return MESSAGE_ACCEPT;
	}

	if (NULL != search_string(buff, "ISO-2022-JP", tmp_len)) {
		return MESSAGE_ACCEPT;
	}


	while (MEM_END_OF_FILE != mem_file_read(&pmail->phead->f_others,
		&tag_len, sizeof(int))) {
		if (8 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("Received", buff, 8)) {
				return MESSAGE_ACCEPT;
			}
		} else if (9 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("X-MimeOLE", buff, 9)) {
				return MESSAGE_ACCEPT;
			}
		} else if (14 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("DKIM-Signature", buff, 14)) {
				return MESSAGE_ACCEPT;
			}
		} else {
			mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR,
				tag_len, MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR, val_len,
			MEM_FILE_SEEK_CUR);
	}
	
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_055);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}

	return MESSAGE_ACCEPT;
	
}

