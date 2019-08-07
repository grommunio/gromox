#include "as_common.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#include <string.h>

#define SPAM_STATISTIC_PROPERTY_018          49

typedef void (*SPAM_STATISTIC)(int);

static SPAM_STATISTIC spam_statistic;

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
			printf("[property_018]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000049 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_018]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		/* invoke register_filter for registering all type of mime paragraph*/
		if (FALSE == register_filter("text/plain" , xmailer_filter) ||
			FALSE == register_filter("text/html" , xmailer_filter)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}

static int xmailer_filter(int action, int context_ID,
	MAIL_BLOCK* mail_blk,  char* reason, int length)
{
	char *ptr, *ptr1;
	int i, count, len;
	BOOL b_alph, b_num;
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
		if (mail_blk->parsed_length > 4096) {
			return MESSAGE_ACCEPT;
		}
		if (NULL == search_string(mail_blk->parsed_buff,
				"Bitcoin", mail_blk->parsed_length) &&
			NULL == search_string(mail_blk->parsed_buff,
				"BTC ", mail_blk->parsed_length) &&
			NULL == search_string(mail_blk->parsed_buff,
				" BTC", mail_blk->parsed_length) &&
			NULL == search_string(mail_blk->parsed_buff,
				"\r\n[", mail_blk->parsed_length)) {
			return MESSAGE_ACCEPT;
		}
		ptr = mail_blk->parsed_buff;
		len = mail_blk->parsed_length;
		while (ptr1 = memmem(ptr, len, "\r\n", 2)) {
			ptr1 += 2;
			len -= ptr1 - ptr;
			ptr = ptr1;
			if (0 != strncmp(ptr + 34, "\r\n", 2)) {
				continue;
			}
			b_num = FALSE;
			b_alph = FALSE;
			for (i=0; i<34; i++) {
				if (0 != isalpha(ptr[i])) {
					b_alph = TRUE;
				} else if (0 != isdigit(ptr[i])) {
					b_num = TRUE;
				} else {
					break;
				}
			}
			if (34 == i && TRUE == b_alph && TRUE == b_num) {
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_PROPERTY_018);
				}
				strncpy(reason, g_return_reason, length);
				return MESSAGE_REJECT;
			}
		}
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}
