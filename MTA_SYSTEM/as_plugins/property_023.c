#include <errno.h>
#include <stdbool.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#include <string.h>


#define SPAM_STATISTIC_PROPERTY_023		60


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
			printf("[property_023]: failed to get service \"check_tagging\"\n");
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
			printf("[property_023]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000060 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_023]: return string is \"%s\"\n", g_return_reason);
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
	int num;
	int out_len;
	int tag_len;
	int val_len;
	char buff[1024];
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}

	if (SINGLE_PART_MAIL != pmail->phead->mail_part) {
		return MESSAGE_ACCEPT;
	}

	if (0 != mem_file_get_total_length(&pmail->phead->f_xmailer)) {
		return MESSAGE_ACCEPT;
	}

	out_len = mem_file_read(&pmail->phead->f_content_type, buff, 1024);
	if (MEM_END_OF_FILE == out_len) {
		return MESSAGE_ACCEPT;
	}
	buff[out_len] = '\0';

	if (0 != strcasecmp(buff, "text/plain") &&
		0 != strcasecmp(buff, "text/html")) {
		return MESSAGE_ACCEPT;
	}

	num = 0;
	while (MEM_END_OF_FILE != mem_file_read(&pmail->phead->f_others, &tag_len,
		sizeof(int))) {
		if (tag_len >= 1024) {
			return MESSAGE_ACCEPT;
		}
		mem_file_read(&pmail->phead->f_others, buff, tag_len);
		buff[tag_len] = 0;
		if (0 == strcasecmp(buff, "Received")) {
			return MESSAGE_ACCEPT;
		} else if (0 == strcasecmp(buff, "Reply-To") ||
			0 == strcasecmp(buff, "From") ||
			0 == strcasecmp(buff, "Sender") ||
			0 == strcasecmp(buff, "To") ||
			0 == strcasecmp(buff, "Subject") ||
			0 == strcasecmp(buff, "Date") ||
			0 == strcasecmp(buff, "User-Agent") ||
			0 == strcasecmp(buff, "Organization") ||
			0 == strcasecmp(buff, "Message-ID") ||
			0 == strcasecmp(buff, "MIME-Version") ||
			0 == strcasecmp(buff, "Thread-Index") ||
			0 == strncasecmp(buff, "Content", 7) ||
			0 == strncasecmp(buff, "DNS", 3) ||
			0 == strncasecmp(buff, "X-", 2)) {
			/* do nothing */
		} else {
			num ++;
		}


		mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR, val_len,
			MEM_FILE_SEEK_CUR);
	}

	if (0 == num) {
		return MESSAGE_ACCEPT;
	}
	
	if (TRUE == check_tagging(pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_023);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}
				
}

