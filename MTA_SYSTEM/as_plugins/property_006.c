#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "util.h"
#include "mem_file.h"
#include "config_file.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_006          30

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int xmailer_filter(int action, int context_ID,
	MAIL_BLOCK* mail_blk, char* reason, int length);

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
			printf("[property_006]: fail to get \"check_tagging\" service\n");
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
			printf("[property_006]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000030 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_006]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		/* invoke register_filter for registering all type of mime paragraph*/
		if (FALSE == register_filter("text/html" , xmailer_filter)) {
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
	int tag_len;
	int val_len;
	BOOL b_messid;
	BOOL b_mimeole;
	int i;
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
		if (TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}
		b_messid = FALSE;
		b_mimeole = FALSE;
		while (MEM_END_OF_FILE != mem_file_read(
			&mail_entity.phead->f_others, &tag_len, sizeof(int))) {
			if (9 == tag_len) {
				mem_file_read(&mail_entity.phead->f_others, buff, tag_len);
				if (0 == strncasecmp("X-MimeOLE", buff, 9)) {
					mem_file_read(&mail_entity.phead->f_others,
										&val_len, sizeof(int));
					if (45 != val_len) {
						return MESSAGE_ACCEPT;
					}
					mem_file_read(&mail_entity.phead->f_others, buff, val_len);
					if (0 != strncmp(buff,
						"Produced By Microsoft MimeOLE V6.00.2900.5512", 45)) {
						return MESSAGE_ACCEPT;
					}
					b_mimeole = TRUE;
					continue;
				}
			} else if (10 == tag_len) {
				mem_file_read(&mail_entity.phead->f_others, buff, tag_len);
				if (0 == strncasecmp("Message-ID", buff, 10)) {
					mem_file_read(&mail_entity.phead->f_others,
										&val_len, sizeof(int));
					if (36 > val_len || val_len > 128) {
						return MESSAGE_ACCEPT;
					}
					mem_file_read(&mail_entity.phead->f_others, buff, val_len);
					if (buff[0] != '<' || (buff[33] != '@' && buff[val_len-1] != '>'))
						return MESSAGE_ACCEPT;
					for (i=1; i<=32; i++) {
						if (('0' <= buff[i] && buff[i] <= '9') ||
							('A' <= buff[i] && buff[i] <= 'F')) {
							continue;	
						}
						return MESSAGE_ACCEPT;
					}
					b_messid = TRUE;
					continue;
				}
			} else {
				mem_file_seek(&mail_entity.phead->f_others,
					MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
			}
			mem_file_read(&mail_entity.phead->f_others, &val_len, sizeof(int));
			mem_file_seek(&mail_entity.phead->f_others,
				MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
		}
		if (FALSE == b_messid || FALSE == b_mimeole) {
			return MESSAGE_ACCEPT;
		}
		if (FALSE == mail_blk->is_parsed) {
			return MESSAGE_ACCEPT;
		}
		if (NULL != search_string(mail_blk->parsed_buff,
			"href=\"http://", mail_blk->parsed_length)){
			if (TRUE == check_tagging(mail_entity.penvelop->from,
				&mail_entity.penvelop->f_rcpt_to)) {
				mark_context_spam(context_ID);
				return MESSAGE_ACCEPT;
			} else {
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_PROPERTY_006);
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
