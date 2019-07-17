#include "as_common.h"
#include "util.h"
#include "mem_file.h"
#include "config_file.h"
#include "mail_func.h"
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_017          46

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);


static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int plain_filter(int action, int context_ID, MAIL_BLOCK* mail_blk, 
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
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_017]: fail to get \"check_tagging\" service\n");
			return FALSE;
		}
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
		/* invoke register_filter for registering all type of mime paragraph*/
		if (FALSE == register_filter("text/plain" , plain_filter)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}

static int plain_filter(int action, int context_ID, MAIL_BLOCK* mail_blk, 
	char* reason, int length)
{
	int score;
	int out_len;
	char buff[1024];
	MAIL_ENTITY mail_entity;

	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		mail_entity	= get_mail_entity(context_ID);
		if (TRUE == mail_entity.penvelop->is_outbound ||
			TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}

		if (SINGLE_PART_MAIL != mail_entity.phead->mail_part) {
			return MESSAGE_ACCEPT;
		}

		out_len = mem_file_read(&mail_entity.phead->f_xmailer, buff, 1024);
		if (MEM_END_OF_FILE == out_len) {
			return MESSAGE_ACCEPT;
		}

		if (0 != strncasecmp(buff, "Microsoft Outlook Express 6", 27)) {
			return MESSAGE_ACCEPT;
		}
		
		if (TRUE == mail_blk->is_parsed || mail_blk->original_length > 400) {
			return MESSAGE_ACCEPT;
		}
		
		score = 0;

		if (NULL != search_string(mail_blk->original_buff, "target:",
			mail_blk->original_length)) {
			score ++;
		}

		if (NULL != search_string(mail_blk->original_buff, "price:",
			mail_blk->original_length)) {
			score ++;
		}

		if (NULL != search_string(mail_blk->original_buff, "Target Price:",
			mail_blk->original_length)) {
			score ++;
		}

		if (NULL != search_string(mail_blk->original_buff, "sym:",
			mail_blk->original_length)) {
			score ++;
		}

		if (NULL != search_string(mail_blk->original_buff, "symbol:",
			mail_blk->original_length)) {
			score ++;
		}

		if (NULL != search_string(mail_blk->original_buff, "company:",
			mail_blk->original_length)) {
			score ++;
		}

		if (NULL != search_string(mail_blk->original_buff, "date:",
			mail_blk->original_length)) {
			score ++;
		}

		if (NULL != search_string(mail_blk->original_buff, "trade:",
			mail_blk->original_length)) {
			score ++;
		}

		if (NULL != search_string(mail_blk->original_buff, "traded:",
			mail_blk->original_length)) {
			score ++;
		}

		if (NULL != search_string(mail_blk->original_buff, "ticker:",
			mail_blk->original_length)) {
			score ++;
		}

		if (score < 3) {
			return MESSAGE_ACCEPT;
		}

		if (TRUE == check_tagging(mail_entity.penvelop->from,
			&mail_entity.penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_PROPERTY_017);
			}
			strncpy(reason, g_return_reason, length);
			return MESSAGE_REJECT;
		}
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}

