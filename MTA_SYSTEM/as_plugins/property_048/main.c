#include "as_common.h"
#include "config_file.h"
#include "util.h"
#include "mail_func.h"
#include <ctype.h>
#include <string.h>
#include <stdio.h>


#define SPAM_STATISTIC_PROPERTY_048		85


typedef void (*SPAM_STATISTIC)(int);

static SPAM_STATISTIC spam_statistic;

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
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init(temp_path);
		if (NULL == pconfig_file) {
			printf("[property_048]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000085 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_048]: return string is %s\n", g_return_reason);
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
	int i;
	int count;
	int tmp_len;
	int tag_len;
	int val_len;
	char *ptoken;
	char buff[1024];
	char *ptr1, *ptr2;
	char boundary_string[256];
	char messageid_string[256];
	
	if (TRUE == pmail->penvelop->is_relay ||
		TRUE == pmail->penvelop->is_outbound) {
		return MESSAGE_ACCEPT;
	}
	if (0 != mem_file_get_total_length(&pmail->phead->f_xmailer)){
		return MESSAGE_ACCEPT;
	}
	tmp_len = mem_file_read(&pmail->phead->f_content_type, buff, 1024);
    if (MEM_END_OF_FILE == tmp_len) {   /* no content type */
        return MESSAGE_ACCEPT;
    }
	if (NULL == (ptr1 = search_string(buff, "boundary", tmp_len))) {
		return MESSAGE_ACCEPT;
	}
	ptr1 += 8;
	if (NULL == (ptr1 = strchr(ptr1, '"'))) {
		return MESSAGE_ACCEPT;
	}
	ptr1 ++;
	ptr2 = ptr1;
	if (NULL == (ptr1 = strchr(ptr1, '"'))) {
		return MESSAGE_ACCEPT;
	}
	memcpy(boundary_string, ptr2, ptr1 - ptr2);
	boundary_string[ptr1 - ptr2] = '\0';
	messageid_string[0] = '\0';
	while (MEM_END_OF_FILE != mem_file_read(
		&pmail->phead->f_others, &tag_len, sizeof(int))) {
		if (10 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("Message-ID", buff, 10)) {
				mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
				if (val_len >= 1024) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others, buff, val_len);
				if ('<' == buff[0] && '>' == buff[val_len - 1]) {
					memcpy(messageid_string, buff + 1, val_len - 2);
					messageid_string[val_len - 2] = '\0';
				} else {
					memcpy(messageid_string, buff, val_len);
					messageid_string[val_len] = '\0';
				}
				break;
			}
		} else {
			mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR,
				tag_len, MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR, val_len,
			MEM_FILE_SEEK_CUR);
	}
	ptoken = strrchr(messageid_string, '@');
	if (NULL == ptoken) {
		return MESSAGE_ACCEPT;
	}
	*ptoken = '\0';
	count = 0;
	tmp_len = strlen(messageid_string);
	for (i=0; i<tmp_len; i++) {
		if ('-' == messageid_string[i]) {
			messageid_string[i] = '\0';
			count ++;
			if (2 == count) {
				ptr1 = messageid_string + i + 1;
			} else if (3 == count) {
				ptr2 = messageid_string + i + 1;
			}
		}
	}
	if (3 != count) {
		return MESSAGE_ACCEPT;
	}
	ptoken = strrchr(boundary_string, '_');
	if (NULL == ptoken) {
		return MESSAGE_ACCEPT;
	}
	*ptoken = '\0';
	ptoken ++;
	if (0 != strcmp(ptr2, ptoken)) {
		return MESSAGE_ACCEPT;
	}
	ptoken = strrchr(boundary_string, '_');
	if (NULL == ptoken) {
		return MESSAGE_ACCEPT;
	}
	*ptoken = '\0';
	ptoken ++;
	if (0 != strcmp(ptr1, ptoken)) {
		return MESSAGE_ACCEPT;
	}
	if (NULL != spam_statistic) {
		spam_statistic(SPAM_STATISTIC_PROPERTY_048);
	}
	strncpy(reason, g_return_reason, length);
	return MESSAGE_REJECT;
}

