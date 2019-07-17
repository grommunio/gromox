#include "as_common.h"
#include "config_file.h"
#include "util.h"
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <stdio.h>


#define SPAM_STATISTIC_PROPERTY_034		71


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
			printf("[property_034]: fail to get \"check_tagging\" service\n");
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
}

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	int tag_len;
	int val_len;
	int i, out_len;
	char buff[1024];
	char *ptr, *ptr_at;
	struct tm tmp_tm;
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}

	if (0 != strncasecmp(pmail->penvelop->hello_domain, "mx", 2)) {
		return MESSAGE_ACCEPT;	
	}

	ptr = strchr(pmail->penvelop->hello_domain, '.');
	if (NULL == ptr || (3 != ptr - pmail->penvelop->hello_domain &&
		4 != ptr - pmail->penvelop->hello_domain)) {
		return MESSAGE_ACCEPT;
	}
	for (i=2; i<ptr-pmail->penvelop->hello_domain; i++) {
		if (0 == isdigit(pmail->penvelop->hello_domain[i])) {
			return MESSAGE_ACCEPT;
		}
	}
	
	ptr_at = strchr(pmail->penvelop->from, '@');
	if (NULL == ptr_at || 0 != strcmp(ptr_at + 1, ptr + 1)) {
		return MESSAGE_ACCEPT;
	}
	
	out_len = mem_file_read(&pmail->phead->f_subject, buff, 1024);
    if (MEM_END_OF_FILE == out_len) {
        return MESSAGE_ACCEPT; 
	}

	buff[out_len] = '\0';
	if (NULL != strstr(buff, "=?")) {
		return MESSAGE_ACCEPT;
	}

	for (i=0; i<out_len; i++) {
		if (buff[i] > 126 || buff[i] < 32) {
			return MESSAGE_ACCEPT;
		}
	}

	out_len = mem_file_read(&pmail->phead->f_mime_to, buff, 1024);
	if (MEM_END_OF_FILE == out_len) {
		return MESSAGE_ACCEPT;
	}

	if ('<' != buff[0] || '>' != buff[out_len - 1]) {
		return MESSAGE_ACCEPT;
	}
	
	while (MEM_END_OF_FILE != mem_file_read(&pmail->phead->f_others, &tag_len,
		sizeof(int))) {
		if (10 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("Message-ID", buff, 10)) {
				mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
				if (val_len > 1024 || val_len < 33) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others, buff, val_len);
				buff[val_len] = '\0';
				if ('<' != buff[0] || '>' != buff[val_len - 1]) {
					return MESSAGE_ACCEPT;
				}
				buff[val_len - 1] = '\0';
				
				ptr_at = strrchr(buff, '@');
				if (NULL == ptr_at || 0 != strcmp(ptr_at + 1,
					pmail->penvelop->hello_domain)) {
					return MESSAGE_ACCEPT;
				}
				
				
				if (NULL != strptime(buff, "%Y%m%d%H%M%S.", &tmp_tm)) {
					return MESSAGE_ACCEPT;
				}

				ptr = strchr(buff, '.') + 1;
				if (ptr_at - ptr < 6) {
					return MESSAGE_ACCEPT;
				}
				for (;ptr<ptr_at; ptr++) {
					if (0 == islower(*ptr)) {
						return MESSAGE_ACCEPT;
					}
				}
				
				if (TRUE == check_tagging(pmail->penvelop->from,
					&pmail->penvelop->f_rcpt_to)) {
					mark_context_spam(context_ID);
					return MESSAGE_ACCEPT;
				} else {
					if (NULL != spam_statistic) {
						spam_statistic(SPAM_STATISTIC_PROPERTY_034);
					}
					strncpy(reason, g_return_reason, length);
					return MESSAGE_REJECT;
				}
			}
		} else {
			mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR, tag_len,
				MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR, val_len,
			MEM_FILE_SEEK_CUR);
	}
	return MESSAGE_ACCEPT;
	
}

