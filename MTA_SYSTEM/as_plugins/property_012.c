#include "as_common.h"
#include "config_file.h"
#include "util.h"
#include <ctype.h>
#include <string.h>
#include <stdio.h>


#define SPAM_STATISTIC_PROPERTY_012		41


typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
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
			printf("[property_012]: fail to get \"check_tagging\" service\n");
			return FALSE;
		}
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[property_012]: fail to get \"check_retrying\" service\n");
			return FALSE;
		}
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init(temp_path);
		if (NULL == pconfig_file) {
			printf("[property_012]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000041 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_012]: return string is %s\n", g_return_reason);
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
	char *ptr;
	int tmp_len;
	int val_len;
	int tag_len;
	char tmp_buff[1024];
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (NULL != pconnection->ssl) {
		return MESSAGE_ACCEPT;
	}
	tmp_len = mem_file_read(&pmail->phead->f_xmailer, tmp_buff, 1024);
	if (MEM_END_OF_FILE != tmp_len) {
		if (0 != strncmp(tmp_buff, "NetEase ", 8) &&
			0 != strncmp(tmp_buff, "Foxmail ", 8) &&
			0 != strncmp(tmp_buff, "Microsoft ", 10)) {
			return MESSAGE_ACCEPT;
		}
	}
	while (MEM_END_OF_FILE != mem_file_read(
		&pmail->phead->f_others, &tag_len,
		sizeof(int))) {
		if (8 == tag_len) {
			mem_file_read(&pmail->phead->f_others,
									tmp_buff, tag_len);
			if (0 == strncasecmp("Received", tmp_buff, 8)) {
				mem_file_read(&pmail->phead->f_others,
								&val_len, sizeof(int));
				if (val_len >= 1024) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others,
									tmp_buff, val_len);
				ptr = search_string(tmp_buff,
					" with SMTP id ", val_len);
				if (NULL == ptr) {
					return MESSAGE_ACCEPT;
				}
				ptr += 14;
				if ('.' != ptr[16] || '1' != ptr[17]) {
					return MESSAGE_ACCEPT;
				}
				break;
			}
		} else {
			mem_file_seek(&pmail->phead->f_others,
				MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others,
					&val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others,
			MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
	}
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		pconnection = get_connection(context_ID);
		if (FALSE == check_retrying(pconnection->client_ip,
			pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_PROPERTY_012);
			}
			strncpy(reason, g_return_reason, length);
			return MESSAGE_RETRYING;
		}
	}
	return MESSAGE_ACCEPT;
}
