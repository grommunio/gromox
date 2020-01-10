#include <errno.h>
#include <string.h>
#include <libHX/ctype_helper.h>
#include <gromox/as_common.h>
#include "mem_file.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_007          31


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
			printf("[property_007]: failed to get service \"check_tagging\"\n");
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
			printf("[property_007]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000031 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_007]: return string is \"%s\"\n", g_return_reason);
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
	int i;
	int tmp_len;
	int val_len;
	int tag_len;
	char tmp_buff[1024];
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	tmp_len = mem_file_read(&pmail->phead->f_xmailer, tmp_buff, 1024);
	if (tmp_len < 7 || tmp_len > 12) {
		return MESSAGE_ACCEPT;
	}
	if (!HX_isupper(tmp_buff[0]) || tmp_buff[tmp_len-2] != ' ' ||
	    !HX_isdigit(tmp_buff[tmp_len-1]))
		return MESSAGE_ACCEPT;	
	for (i=1; i<tmp_len-2; i++) {
		if (!HX_islower(tmp_buff[i]))
			return MESSAGE_ACCEPT;
	}
	while (MEM_END_OF_FILE != mem_file_read(
		&pmail->phead->f_others, &tag_len, sizeof(int))) {
		if (8 == tag_len) {
			mem_file_read(&pmail->phead->f_others, tmp_buff, tag_len);
			if (0 == strncasecmp("Received", tmp_buff, 8)) {
				return MESSAGE_ACCEPT;
			}
		} else if (10 == tag_len) {
			mem_file_read(&pmail->phead->f_others, tmp_buff, tag_len);
			if (0 == strncasecmp("Message-ID", tmp_buff, 10)) {
				mem_file_read(&pmail->phead->f_others,
								&val_len, sizeof(int));
				if (val_len > 50 || val_len < 35) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others,
									tmp_buff, val_len);
				if ('<' != tmp_buff[0] || '@' != tmp_buff[33]
					|| '>' != tmp_buff[val_len - 1]) {
					return MESSAGE_ACCEPT;
				}
				for (i=1; i<33; i++) {
					if (('0' <= tmp_buff[i] && tmp_buff[i] <= '9') ||
						('A' <= tmp_buff[i] && tmp_buff[i] <= 'F')) {
						continue;
					}
					return MESSAGE_ACCEPT;
				}
				if (TRUE == check_tagging(pmail->penvelop->from,
					&pmail->penvelop->f_rcpt_to)) {
					mark_context_spam(context_ID);
					return MESSAGE_ACCEPT;
				} else {
					if (NULL != spam_statistic) {
						spam_statistic(SPAM_STATISTIC_PROPERTY_007);
					}
					strncpy(reason, g_return_reason, length);
					return MESSAGE_REJECT;
				}
				return MESSAGE_ACCEPT;
			}
		} else {
			mem_file_seek(&pmail->phead->f_others,
				MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others,
					&val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others,
			MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
	}
	return MESSAGE_ACCEPT;
}
