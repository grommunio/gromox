#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "util.h"
#include "mem_file.h"
#include "config_file.h"
#include "mail_func.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_058          95

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int xmailer_filter(int action, int context_ID, MAIL_BLOCK* mail_blk, 
	char* reason, int length);

int AS_LibMain(int reason, void **ppdata)
{	
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[property_058]: fail to get \"check_retrying\" service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_058]: fail to get \"check_tagging\" service\n");
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
			printf("[property_058]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000095 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_058]: return string is %s\n", g_return_reason);
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

static int xmailer_filter(int action, int context_ID, MAIL_BLOCK* mail_blk, 
	char* reason, int length)
{
	int len;
	char buff[1024];
	int tag_len, val_len;
	MAIL_ENTITY mail_entity;
	CONNECTION *pconnection;

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
		memset(buff, 0, 1024);
		if (MEM_END_OF_FILE == mem_file_read(&mail_entity.phead->f_xmailer,
			buff, 1024)) {
			return MESSAGE_ACCEPT;
		}
		if (NULL == search_string(buff, "Mozilla", 1024)) {
			return MESSAGE_ACCEPT;
		}

		while (MEM_END_OF_FILE != mem_file_read(mail_blk->fp_mime_info,
			&tag_len, sizeof(int))) {
			if (8 == tag_len) {
				mem_file_read(mail_blk->fp_mime_info, buff, tag_len);
				if (0 == strncasecmp("Received", buff, 8)) {
					return MESSAGE_ACCEPT;
				}
			} else {
				mem_file_seek(mail_blk->fp_mime_info, MEM_FILE_READ_PTR,
					tag_len, MEM_FILE_SEEK_CUR);
			}
			mem_file_read(mail_blk->fp_mime_info, &val_len, sizeof(int));
			mem_file_seek(mail_blk->fp_mime_info, MEM_FILE_READ_PTR, val_len,
				MEM_FILE_SEEK_CUR);
		}

		if (NULL == find_url((char*)mail_blk->original_buff,
			mail_blk->original_length, &len)) {
			return MESSAGE_ACCEPT;
		}


		if (TRUE == check_tagging(mail_entity.penvelop->from,
			&mail_entity.penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			pconnection = get_connection(context_ID);
			if (FALSE == check_retrying(pconnection->client_ip,
				mail_entity.penvelop->from,
				&mail_entity.penvelop->f_rcpt_to)) {
				strncpy(reason, g_return_reason, length);
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_PROPERTY_058);
				}
				return MESSAGE_RETRYING;
			}
		}
		return MESSAGE_REJECT;
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}

