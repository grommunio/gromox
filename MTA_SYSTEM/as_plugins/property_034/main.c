#include "util.h"
#include "mem_file.h"
#include "as_common.h"
#include "mail_func.h"
#include "config_file.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_034          71

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int xmailer_filter(int action, int context_ID,
	MAIL_BLOCK* mail_blk,  char* reason, int length);

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
			printf("[property_034]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000071 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_034]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		if (FALSE == register_filter("text/plain" , xmailer_filter)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}

static int xmailer_filter(int action, int context_ID,
	MAIL_BLOCK* mail_blk, char* reason, int length)
{
	int out_len;
	char tmp_buff[1024];
	char tmp_buff1[1024];
	MAIL_ENTITY mail_entity;
	EMAIL_ADDR email_address;
	ENCODE_STRING encode_string;

	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		mail_entity	= get_mail_entity(context_ID);
		if (TRUE == mail_entity.penvelop->is_outbound ||
			TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}
		if (MULTI_PARTS_MAIL != mail_entity.phead->mail_part) {
			return MESSAGE_ACCEPT;
		}
		out_len = mem_file_read(&mail_entity.phead->f_mime_from,
									tmp_buff, sizeof(tmp_buff));
		if (MEM_END_OF_FILE == out_len) {
			return MESSAGE_ACCEPT;
		}
		parse_mime_encode_string(tmp_buff, out_len, &encode_string);
		if (0 != strcasecmp(encode_string.charset, "utf-8")) {
			return MESSAGE_ACCEPT;
		}
		decode_mime_string(tmp_buff, out_len, tmp_buff1, sizeof(tmp_buff1));
		parse_email_addr(&email_address, tmp_buff1);
		if (0 != strcasecmp(email_address.domain, "outlook.com")) {
			return MESSAGE_ACCEPT;
		}
		out_len = strlen(email_address.display_name);
		if (7 != out_len && 10 != out_len) {
			return MESSAGE_ACCEPT;
		}
		if (' ' != email_address.display_name[3] ||
			FALSE == utf8_len(email_address.display_name,
			&out_len) || (3 != out_len && 4 != out_len)) {
			return MESSAGE_ACCEPT;	
		}
		if (0 != strncmp(mail_blk->parsed_buff, "[cid:000", 8)
			&& NULL == memmem(mail_blk->parsed_buff,
			mail_blk->parsed_length, "\r\n\r\n[cid:000", 12)) {
			return MESSAGE_ACCEPT;	
		}
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_034);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
		
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}
