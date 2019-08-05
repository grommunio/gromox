#include "as_common.h"
#include "mem_file.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>

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
	int tag_len;
	int val_len;
	char buff[1024];
	MEM_FILE *fp_mime_field;
	MAIL_ENTITY mail_entity;

	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		mail_entity	= get_mail_entity(context_ID);
		if (MULTI_PARTS_MAIL == mail_entity.phead->mail_part) {
			return MESSAGE_ACCEPT;
		}
		if (0 != mem_file_get_total_length(&mail_entity.phead->f_xmailer)) {
			return MESSAGE_ACCEPT;
		}
		if (TRUE == mail_entity.penvelop->is_outbound ||
			TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}
		if (mail_blk->original_length > 4096) {
			return MESSAGE_ACCEPT;
		}
		fp_mime_field = mail_blk->fp_mime_info;
		while (MEM_END_OF_FILE != mem_file_read(
			fp_mime_field, &tag_len, sizeof(int))) {
			if (25 == tag_len) {
				mem_file_read(fp_mime_field, buff, tag_len);
				if (0 == strncasecmp(buff, "Content-Transfer-Encoding", 25)) {
					mem_file_read(fp_mime_field, &val_len, sizeof(int));
					if (4 != val_len) {
						return MESSAGE_ACCEPT;
					}
					mem_file_read(fp_mime_field, buff, 4);
					if (0 != strncasecmp(buff, "8bit", 4) &&
						0 != strncasecmp(buff, "quoted-printable", 16)) {
						return MESSAGE_ACCEPT;
					}
					
					if (NULL == search_string((char*)mail_blk->original_buff,
							"Bitcoin", mail_blk->original_length) &&
						NULL == search_string((char*)mail_blk->original_buff,
							"BTC ", mail_blk->original_length) &&
						NULL == search_string((char*)mail_blk->original_buff,
							" BTC", mail_blk->original_length)) {
						return MESSAGE_ACCEPT;
					}
					if (NULL != spam_statistic) {
						spam_statistic(SPAM_STATISTIC_PROPERTY_018);
					}
					strncpy(reason, g_return_reason, length);
					return MESSAGE_REJECT;
				}
			} else {
				mem_file_seek(fp_mime_field, MEM_FILE_READ_PTR,
									tag_len, MEM_FILE_SEEK_CUR);
			}
			mem_file_read(fp_mime_field, &val_len, sizeof(int));
			mem_file_seek(fp_mime_field, MEM_FILE_READ_PTR,
								val_len, MEM_FILE_SEEK_CUR);
		}
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}
