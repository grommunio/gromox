#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "mail_func.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_037        74

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int mime_auditor(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);

static int xmailer_filter(int action, int context_ID, MAIL_BLOCK* mail_blk, 
	char* reason, int length);

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
			printf("[property_037]: fail to get \"check_tagging\" service\n");
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
			printf("[property_037]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000074 you are now sending spam mail!");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[property_037]: return string is %s\n", g_return_string);
		config_file_free(pconfig_file);
		if (FALSE == register_auditor(mime_auditor)) {
			return FALSE;
		}
		if (FALSE == register_filter("text/plain", xmailer_filter)) {
			return FALSE;
		}
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
    return TRUE;
}

static int mime_auditor(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	int out_len;
	char buff[1024];

	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}

	if (MULTI_PARTS_MAIL == pmail->phead->mail_part) {
		return MESSAGE_ACCEPT;
	}

	if (0 != strcasecmp(pmail->penvelop->from, "none@none")) {
		return MESSAGE_ACCEPT;
	}
	
	out_len = mem_file_read(&pmail->phead->f_xmailer, buff, 1024);
		
	if (MEM_END_OF_FILE == out_len) {
		return MESSAGE_ACCEPT;
	}
		
	if (0 != strncasecmp(buff, "Microsoft Outlook Express", 25) &&
		0 != strncasecmp(buff, "Thunderbird ", 12)) {
		return MESSAGE_ACCEPT;
	}
		
	out_len = mem_file_read(&pmail->phead->f_content_type, buff, 1024);
		
	if (MEM_END_OF_FILE == out_len) {
		return MESSAGE_ACCEPT;
	}
	if (0 != strncmp(buff, "text/plain;", 11)) {
		return MESSAGE_ACCEPT;
	}
	if (NULL == search_string(buff, "format=flowed", out_len)) {
		return MESSAGE_ACCEPT;
	}
	
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_037);
		}
		strncpy(reason, g_return_string, length);
		return MESSAGE_REJECT;
	}
}

static int xmailer_filter(int action, int context_ID, MAIL_BLOCK* mail_blk, 
	char* reason, int length)
{
	int out_len;
	char *purl;
	char buff[1024];
	MAIL_ENTITY mail_entity;

	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		mail_entity	= get_mail_entity(context_ID);
		if (MULTI_PARTS_MAIL == mail_entity.phead->mail_part) {
			return MESSAGE_ACCEPT;
		}
		if (TRUE == mail_entity.penvelop->is_outbound ||
			TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}
		out_len = mem_file_read(&mail_entity.phead->f_xmailer, buff, 1024);
		
		if (MEM_END_OF_FILE == out_len) {
			return MESSAGE_ACCEPT;
		}
		
		if (0 != strncasecmp(buff, "Microsoft Outlook Express", 25) &&
			0 != strncasecmp(buff, "Thunderbird ", 12)) {
			return MESSAGE_ACCEPT;
		}
		
		out_len = mem_file_read(&mail_entity.phead->f_content_type, buff, 1024);
		
		if (MEM_END_OF_FILE == out_len) {
			return MESSAGE_ACCEPT;
		}
		if (0 != strncmp(buff, "text/plain;", 11)) {
			return MESSAGE_ACCEPT;
		}
		if (NULL == search_string(buff, "format=flowed", out_len)) {
			return MESSAGE_ACCEPT;
		}
		
		if (mail_blk->original_length > 140) {
			return MESSAGE_ACCEPT;
		}
		
		if (NULL == search_string(mail_blk->original_buff, "http://",
			mail_blk->original_length)) {
			return MESSAGE_ACCEPT;
		}
		purl = find_url((char*)mail_blk->original_buff,
				mail_blk->original_length, &out_len);
		if (NULL == purl) {
			return MESSAGE_ACCEPT;
		}
		if (TRUE == check_tagging(mail_entity.penvelop->from,
			&mail_entity.penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_PROPERTY_037);
			}
			strncpy(reason, g_return_string, length);
			return MESSAGE_REJECT;
		}
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}

