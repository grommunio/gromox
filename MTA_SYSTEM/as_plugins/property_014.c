#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "mail_func.h"
#include "util.h"
#include <stdio.h>
#define SPAM_STATISTIC_PROPERTY_014		43

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
	
	switch (reason) {
	case PLUGIN_INIT:

		LINK_API(ppdata);

		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_014]: failed to get service \"check_tagging\"\n");
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
			printf("[property_014]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000043 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_014]: return string is \"%s\"\n", g_return_reason);
		config_file_free(pconfig_file);
		if (FALSE == register_auditor(head_filter)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}


static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	char *ptr;
	int out_len;
	int tag_len;
	int val_len;
	int tmp_len;
	char buff[1024];
	EMAIL_ADDR email_addr;

	
	if (TRUE == pmail->penvelop->is_relay ||
		TRUE == pmail->penvelop->is_outbound) {
		return MESSAGE_ACCEPT;
	}

	if (NULL == (ptr = strchr(pmail->penvelop->hello_domain, '.'))) {
		return MESSAGE_ACCEPT;
	}
	
	ptr ++;

	if (NULL == strchr(ptr, '.')) {
		return MESSAGE_ACCEPT;
	}

	out_len = mem_file_read(&pmail->phead->f_mime_from, buff, 1024);
	if (MEM_END_OF_FILE == out_len) {
		return MESSAGE_ACCEPT;
	}

	buff[out_len] = '\0';
	parse_email_addr(&email_addr, buff);
	if (0 != strcmp(ptr, email_addr.domain) &&
		'\0' == email_addr.domain[0]) {
		return MESSAGE_ACCEPT;
	}


	if (0 != mem_file_get_total_length(&pmail->phead->f_xmailer)) {
		return MESSAGE_ACCEPT;
	}


	while (MEM_END_OF_FILE != mem_file_read(&pmail->phead->f_others,
		&tag_len, sizeof(int))) {
		if (8 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("Received", buff, 8)) {
				mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
				if (val_len > 256) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others, buff, val_len);
				if (NULL == (ptr = search_string(buff, " (envelope-from <", val_len))) {
					return MESSAGE_ACCEPT;
				}
				ptr += 17;
				tmp_len = strlen(pmail->penvelop->from);
				if (0 != strncmp(pmail->penvelop->from, ptr, tmp_len)) {
					return MESSAGE_ACCEPT;
				}
				if (NULL == (ptr = strchr(ptr, '@'))) {
					return MESSAGE_ACCEPT;
				}
				ptr ++;
				tmp_len = strlen(pmail->penvelop->hello_domain);
				if (0 != strncmp(ptr, pmail->penvelop->hello_domain, tmp_len) ||
					ptr[tmp_len] != '>' || ptr[tmp_len + 1] != ')') {
					return MESSAGE_ACCEPT;
				}

				if (TRUE == check_tagging(pmail->penvelop->from,
					&pmail->penvelop->f_rcpt_to)) {
					mark_context_spam(context_ID);
					return MESSAGE_ACCEPT;
				} else {
					if (NULL != spam_statistic) {
						spam_statistic(SPAM_STATISTIC_PROPERTY_014);
					}
					strncpy(reason, g_return_reason, length);
					return MESSAGE_REJECT;
				}
			}
		} else {
			mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR,
				tag_len, MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR, val_len,
			MEM_FILE_SEEK_CUR);
	}
	
	
	return MESSAGE_ACCEPT;
	
}

