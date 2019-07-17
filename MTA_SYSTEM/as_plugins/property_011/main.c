#include "as_common.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_011        40

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int paragraph_filter(int action, int context_ID,
	MAIL_BLOCK* mail_blk, char* reason, int length);

DECLARE_API;

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

static char g_return_string[1024];

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
			printf("[property_011]: fail to get \"check_tagging\" service\n");
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
			printf("[property_011]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000040 you ares now sending spam mail!");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[property_011]: return string is %s\n", g_return_string);
		config_file_free(pconfig_file);
        if (FALSE == register_filter("application/vnd.ms-excel",
			paragraph_filter) || FALSE == register_filter(
			"application/msword", paragraph_filter)) {
			return FALSE;
		}
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
    return TRUE;
}

static int paragraph_filter(int action, int context_ID,
	MAIL_BLOCK* mail_blk, char* reason, int length)
{
	int tag_len;
	int val_len;
	int tmp_len;
	char tmp_buff[1024];
	MAIL_ENTITY mail_entity;
	
	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		mail_entity	= get_mail_entity(context_ID);
		if (MULTI_PARTS_MAIL != mail_entity.phead->mail_part) {
			return MESSAGE_ACCEPT;
		}
		if (TRUE == mail_entity.penvelop->is_outbound ||
			TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}
		if (0 != mem_file_get_total_length(
			&mail_entity.phead->f_xmailer)) {
			return MESSAGE_ACCEPT;
		}
		while (MEM_END_OF_FILE != mem_file_read(
			&mail_entity.phead->f_others, &tag_len,
			sizeof(int))) {
			if (8 == tag_len) {
				mem_file_read(&mail_entity.phead->f_others,
										tmp_buff, tag_len);
				if (0 == strncasecmp("Received", tmp_buff, 8)) {
					return MESSAGE_ACCEPT;
				}
			} else {
				mem_file_seek(&mail_entity.phead->f_others,
					MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			}
			mem_file_read(&mail_entity.phead->f_others,
				&val_len, sizeof(int));
			mem_file_seek(&mail_entity.phead->f_others,
				MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
		}
		tmp_len = mem_file_read(&mail_entity.phead->f_content_type,
													tmp_buff, 1024);
		if (MEM_END_OF_FILE == tmp_len || NULL == search_string(
			tmp_buff, "boundary=\"----=_NextPart_000_", tmp_len)) {
			return MESSAGE_ACCEPT;
		}
		if (TRUE == check_tagging(mail_entity.penvelop->from,
			&mail_entity.penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_PROPERTY_011);
			}
			strncpy(reason, g_return_string, length);
			return MESSAGE_REJECT;
		}
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;	
}
