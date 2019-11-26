#include <stdbool.h>
#include "as_common.h"
#include "config_file.h"
#include "util.h"
#include "mail_func.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>


#define SPAM_STATISTIC_PROPERTY_056		93


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
			printf("[property_056]: fail to get \"check_tagging\" service\n");
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
			printf("[property_056]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000093 请在邮件主题的末尾加上--not spam，"
				"并再次发送此邮件以规避反垃圾过滤，导致邮件被反垃圾网关"
				"过滤的原因是您使用的Outlook Express(版本6.00.2900.5512)"
				"存在重大安全隐患，可以升级您的Outlook Express或者改用其它"
				"客户端发送邮件，谢谢!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_056]: return string is %s\n", g_return_reason);
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
	int count;
	int i, len;
	int out_len;
	int tag_len;
	int val_len;
	BOOL b_from;
	char rcpt[256];
	char buff[1024];
	char subject_buff[1024];
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}

	out_len = mem_file_read(&pmail->phead->f_xmailer, buff, 1024);
	if (40 != out_len) {
        	return MESSAGE_ACCEPT;
	}
	if (0 != strncasecmp(buff, "Microsoft Outlook Express 6.00.2900.5512", 40)) {
		return MESSAGE_ACCEPT;
	}

	b_from = FALSE;
	out_len = mem_file_read(&pmail->phead->f_mime_from, buff, 1024);
	if (MEM_END_OF_FILE != out_len && (0 == strncmp(buff, "=?gb2312?B?", 11) ||
		0 == strncmp(buff, "=?utf-8?B?", 10))) {
		b_from = TRUE;
	}

	out_len = mem_file_read(&pmail->phead->f_subject, buff, 1024);
	if (MEM_END_OF_FILE != out_len) {
		if (FALSE == b_from && (0 != strncmp(buff, "=?gb2312?B?", 11) &&
			0 != strncmp(buff, "=?utf-8?B?", 10) && 
			!(8 == out_len && islower(buff[0]) && '-' == buff[1]))) {
			return MESSAGE_ACCEPT;
		}
	
	
		len = decode_mime_string(buff, out_len, subject_buff, 1024);

		if (NULL != search_string(subject_buff, "not spam", len)) {
			return MESSAGE_ACCEPT;
		}
	}

	count = 0;
	while (MEM_END_OF_FILE != mem_file_readline(&pmail->penvelop->f_rcpt_to,
		rcpt, 256)) {
		count ++;
	}

	if (count > 1) {
		return MESSAGE_ACCEPT;
	}
	
	if (mem_file_get_total_length(&pmail->phead->f_mime_cc) > 0) {
		return MESSAGE_ACCEPT;
	}


	while (MEM_END_OF_FILE != mem_file_read(&pmail->phead->f_others,
		&tag_len, sizeof(int))) {
		if (10 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("References", buff, 10)) {
				return MESSAGE_ACCEPT;
			}
		} else if (9 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("X-MimeOLE", buff, 9)) {
				mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
				if (val_len != 45) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others, buff, 45);
				if (0 != strncmp(buff, "Produced By Microsoft MimeOLE "
					"V6.00.2900.5512", 45) &&
					0 != strncmp(buff, "Produced By Microsoft MimeOLE "
					"V6.00.2900.5579", 45) &&
					0 != strncmp(buff, "Produced By Microsoft MimeOLE "
					"V6.00.2900.5594", 45) &&
					0 != strncmp(buff, "Produced By Microsoft MimeOLE "
					"V6.00.2900.5994", 45) &&
					0 != strncmp(buff, "Produced By Microsoft MimeOLE "
					"V6.00.2900.6090", 45) &&
					0 != strncmp(buff, "Produced By Microsoft MimeOLE "
					"V6.00.2900.6157", 45) &&
					0 != strncmp(buff, "Produced By Microsoft MimeOLE "
					"V6.1.7601.17609", 45)) {
					return MESSAGE_ACCEPT;
				}
				continue;
			}
		} else {
			mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR,
				tag_len, MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR, val_len,
			MEM_FILE_SEEK_CUR);
	}
	
	if (TRUE == check_tagging(pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_056);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}
}

