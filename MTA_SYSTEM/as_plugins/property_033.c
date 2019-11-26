#include <errno.h>
#include <stdbool.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include <string.h>
#include <stdio.h>


#define SPAM_STATISTIC_PROPERTY_033		70


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
			printf("[property_033]: fail to get \"check_tagging\" service\n");
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
			printf("[property_033]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000070 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_033]: return string is %s\n", g_return_reason);
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
	char temp_num[9];
	char buff[1024];
	char *ptr, *pbackup;
	int out_len;
	int tag_len;
	int val_len;
	int bnd_num;
	int msg_num;
	int sub_num;
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}

	if (MULTI_PARTS_MAIL != pmail->phead->mail_part) {
		return MESSAGE_ACCEPT;
	}
	
	if (MEM_END_OF_FILE == mem_file_read(&pmail->phead->f_xmailer,
		buff, 1024)) {
		return MESSAGE_ACCEPT;
	}
	if (0 != strncasecmp(buff, "Microsoft Outlook Express", 25)) {
		return MESSAGE_ACCEPT;
	}

	if (MEM_END_OF_FILE == mem_file_read(&pmail->phead->f_subject,
		buff, 1024)) {
		return MESSAGE_ACCEPT;
	}
	/*
	if (0 != strncasecmp(buff, "=?koi8-r?", 9)) {
		size = strlen(pmail->phead->compose_time);
		if (0 != strncmp(pmail->phead->compose_time + size - 6,
			" +0000", 6)) {
			return MESSAGE_ACCEPT;
		}
	}
	*/
	out_len = mem_file_read(&pmail->phead->f_content_type, buff, 1024);
    if (MEM_END_OF_FILE == out_len) {   /* no content type */
        return MESSAGE_ACCEPT;
    }
	if (NULL == (ptr = search_string(buff, "boundary", out_len))) {
		return MESSAGE_ACCEPT;
	}
	ptr += 8;
	if (NULL == (ptr = strchr(ptr, '"'))) {
		return MESSAGE_ACCEPT;
	}
	ptr++;
	pbackup = ptr;
	if (NULL == (ptr = strchr(ptr, '"'))) {
		return MESSAGE_ACCEPT;
	}
	out_len = (int)(ptr - pbackup);
	if (41 != out_len) {
		return MESSAGE_ACCEPT;
	}
	if (0 != strncmp(pbackup, "----=_NextPart_", 15)) {
		return MESSAGE_ACCEPT;
	}
	memcpy(temp_num, pbackup + 24, 8);
	temp_num[8] = '\0';
	bnd_num = strtol(temp_num, NULL, 16);
		
	while (MEM_END_OF_FILE != mem_file_read(&pmail->phead->f_others, &tag_len,
		sizeof(int))) {
		if (8 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("Received", buff, 8)) {
				return MESSAGE_ACCEPT;
			}
		} else if (10 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("Message-ID", buff, 10)) {
				mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
				if (val_len > 1024 || val_len < 32) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others, buff, val_len);
				if ('$' != buff[13] || '$' != buff[22] || '@' != buff[31]) {
					return MESSAGE_ACCEPT;
				}
				memcpy(temp_num, buff + 5, 8);
				temp_num[8] = '\0';
				msg_num = strtol(temp_num, NULL, 16);
				sub_num = bnd_num - msg_num;
				if (sub_num > -8 * 13 && sub_num < 8 * 14) {
					return MESSAGE_ACCEPT;
				} else {
					if (TRUE == check_tagging(pmail->penvelop->from,
						&pmail->penvelop->f_rcpt_to)) {
						mark_context_spam(context_ID);
						return MESSAGE_ACCEPT;
					} else {
						if (NULL != spam_statistic) {
							spam_statistic(SPAM_STATISTIC_PROPERTY_033);
						}
						strncpy(reason, g_return_reason, length);
						return MESSAGE_REJECT;
					}
				}
			}
		} else {
			mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR,
				tag_len, MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR, val_len,
		    MEM_FILE_SEEK_CUR);
	}
	return MESSAGE_ACCEPT;
}

