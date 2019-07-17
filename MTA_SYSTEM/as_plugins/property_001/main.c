#include "as_common.h"
#include "mem_file.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_001          14

enum{
	IGNORE_FOUND,
	NONE_FOUND
};

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int check_other_filed(MEM_FILE *pfile);

static int check_subject(MEM_FILE *pfile);

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
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_001]: fail to get \"check_tagging\" service\n");
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
			printf("[property_001]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000014 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_001]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		/* invoke register_filter for registering all type of mime paragraph*/
		if (FALSE == register_filter("text/plain" , xmailer_filter)) {
			return FALSE;
		}
		if (FALSE == register_filter("text/html" , xmailer_filter)) {
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
	BOOL b_outlook;
	BOOL b_xmime;
	int read_length;
	int count, i, size;
	char buff[1024], *ptr;
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
		if (TRUE == mail_entity.penvelop->is_outbound ||
			TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}
		mem_file_seek(&mail_entity.phead->f_xmailer, MEM_FILE_READ_PTR, 0,
			MEM_FILE_SEEK_BEGIN);
		if (MEM_END_OF_FILE == mem_file_read(&mail_entity.phead->f_xmailer, 
			buff, 1024)) {
			return MESSAGE_ACCEPT;
		}
		if (0 == strncasecmp(buff, "Microsoft Outlook Express", 25)) {
			b_outlook = TRUE;
		} else if (0 == strncasecmp(buff, "Foxmail", 7)) {
			b_outlook = FALSE;
		} else {
			return MESSAGE_ACCEPT;
		}
		if (IGNORE_FOUND == check_subject(&mail_entity.phead->f_subject) ||
			IGNORE_FOUND == check_other_filed(&mail_entity.phead->f_mime_from)||
			IGNORE_FOUND == check_other_filed(&mail_entity.phead->f_mime_to) ||
			IGNORE_FOUND == check_other_filed(&mail_entity.phead->f_mime_cc)) {
			return MESSAGE_ACCEPT;
		}
		b_xmime = FALSE;
		fp_mime_field = mail_blk->fp_mime_info;
		while (MEM_END_OF_FILE != mem_file_read(fp_mime_field, &read_length,
			sizeof(int))) {
			mem_file_read(fp_mime_field, buff, read_length);
			buff[read_length] = '\0';
			mem_file_read(fp_mime_field, &size, sizeof(int));
			if (25 == read_length && 0 == strncasecmp(buff, 
				"Content-Transfer-Encoding", 25)) {
				if (size > 1023) {
					return MESSAGE_REJECT;
				}
				mem_file_read(fp_mime_field, buff, size);
				buff[size] = '\0';
				if (0 != strncasecmp(buff, "8bit", 4) &&
					0 != strncasecmp(buff, "7bit", 4)) {
					return MESSAGE_ACCEPT;
				}
			} else if (12 == read_length && 0 == strncasecmp(buff,
				"Content-Type", 12)) {
				if (size > 1023) {
					return MESSAGE_REJECT;
				}
				mem_file_read(fp_mime_field, buff, size);
				if (NULL == search_string(buff, "gb2312", size)) {
					return MESSAGE_ACCEPT;
				}
			} else {
				if (9 == read_length &&
					0 == strncasecmp(buff, "X-MimeOLE", 9)) {
					b_xmime = TRUE;
				}
				mem_file_seek(fp_mime_field, MEM_FILE_READ_PTR,
				size, MEM_FILE_SEEK_CUR);
			}
		}
		if (TRUE == b_outlook && TRUE == b_xmime) {
			return MESSAGE_ACCEPT;
		}
		/* 
		 * some version of outlook express does not encode the message,
		 * so when these MUAs reply the messages containing some chinese
		 * characters, the content will contain gb2312 characters without
		 * base64 or quote-printable encoding
		 */
		if (NULL != search_string((char*)mail_blk->original_buff,
				"Original Message", mail_blk->original_length)) {
			return MESSAGE_ACCEPT;
		}
		for (i=0, count=0, ptr=(char*)mail_blk->original_buff; 
			i<mail_blk->original_length; i++, ptr++) {
			if ( ((char)*ptr) & ((char)0x80) ) {
				count ++;
			}
		}
		if (count >= 20) {
			if (TRUE == check_tagging(mail_entity.penvelop->from,
				&mail_entity.penvelop->f_rcpt_to)) {
				mark_context_spam(context_ID);
				return MESSAGE_ACCEPT;
			} else {
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_PROPERTY_001);
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

static int check_other_filed(MEM_FILE *pfile)
{
	char str_buf[4096];
	int size;

	size = mem_file_read(pfile, str_buf, 4096);
	if (MEM_END_OF_FILE == size) {
		return NONE_FOUND;
	}
	if (size >= 4095) {
		str_buf[4095] = '\0';
		size = 4095;
	} else {
		str_buf[size] = '\0';
	}

	if (NULL != search_string(str_buf, "=?big5?", size) ||
		NULL != search_string(str_buf, "=?gb2312?q?", size)) {
		return IGNORE_FOUND;
	}
	return NONE_FOUND;
}

static int check_subject(MEM_FILE *pfile)
{
	char str_buf[4096];
	int size;

	size = mem_file_read(pfile, str_buf, 4096);
	if (MEM_END_OF_FILE == size) {
		return NONE_FOUND;
	}
	if (size >= 4095) {
		str_buf[4095] = '\0';
		size = 4095;
	} else {
		str_buf[size] = '\0';
	}

	if (NULL != search_string(str_buf, "=?big5?", size) ||
		NULL != search_string(str_buf, "=?gb2312?q?", size) ||
		NULL != strstr(str_buf, "Re: Re: ") ||
		NULL != strstr(str_buf, "UmU6IFJl") ||
		NULL != strstr(str_buf, "Fw: Fw: ") ||
		NULL != strstr(str_buf, "Rnc6IEZ3") ||
		NULL != strstr(str_buf, "Fw: Re: ") ||
		NULL != strstr(str_buf, "Re: Fw: ") ||
		NULL != strstr(str_buf, "Rnc6IFJl") ||
		NULL != strstr(str_buf, "UmU6IEZ3")) {
		return IGNORE_FOUND;
	}
	return NONE_FOUND;
}

