#include <errno.h>
#include <stdbool.h>
#include <libHX/ctype_helper.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include <string.h>
#include <stdio.h>


#define SPAM_STATISTIC_PROPERTY_030		67


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
	
	/* path contains the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_030]: failed to get service \"check_tagging\"\n");
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
			printf("[property_030]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000067 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_030]: return string is \"%s\"\n", g_return_reason);
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
	int i;
	int out_len;
	int tag_len;
	int val_len;
	char buff[1024];
	
	if (TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	out_len = mem_file_read(&pmail->phead->f_xmailer, buff, 1024);
    if (MEM_END_OF_FILE == out_len) {
        return MESSAGE_ACCEPT;
    }
	buff[out_len] = '\0';
	if (0 != strncasecmp(buff, "Microsoft Outlook Express", 25)) {
		return MESSAGE_ACCEPT;
	}
	while (MEM_END_OF_FILE != mem_file_read(&pmail->phead->f_others, &tag_len,
		sizeof(int))) {
		if (10 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("Message-ID", buff, 10)) {
				mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
				if (val_len > 1024 || val_len < 30) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others, buff, val_len);
				if ('<' == buff[0] && '>' == buff[val_len - 1] &&
					'$' == buff[13] && '$' == buff[22] && '@' == buff[31]) {
					for (i=1; i<13; i++) {
						if (!HX_isdigit(buff[i]))
							return MESSAGE_ACCEPT;
					}
					for (i=14; i<22; i++) {
						if (!HX_isdigit(buff[i]))
							return MESSAGE_ACCEPT;
					}
					for (i=23; i<31; i++) {
						if (!HX_isdigit(buff[i]))
							return MESSAGE_ACCEPT;
					}
					if (TRUE == check_tagging(pmail->penvelop->from,
						&pmail->penvelop->f_rcpt_to)) {
						mark_context_spam(context_ID);
						return MESSAGE_ACCEPT;
					} else {
						if (NULL != spam_statistic) {
							spam_statistic(SPAM_STATISTIC_PROPERTY_030);
						}
						strncpy(reason, g_return_reason, length);
						return MESSAGE_REJECT;
					}
				} else if ('<' == buff[0] && '>' == buff[val_len - 1] &&
					'$' == buff[11] && '$' == buff[20] && '@' == buff[29]) {
					for (i=1; i<11; i++) {
						if (!HX_isdigit(buff[i]))
							return MESSAGE_ACCEPT;
					}
					for (i=12; i<20; i++) {
						if (!HX_isdigit(buff[i]))
							return MESSAGE_ACCEPT;
					}
					for (i=21; i<29; i++) {
						if (!HX_isdigit(buff[i]))
							return MESSAGE_ACCEPT;
					}
					if (TRUE == check_tagging(pmail->penvelop->from,
						&pmail->penvelop->f_rcpt_to)) {
						mark_context_spam(context_ID);
						return MESSAGE_ACCEPT;
					} else {
						if (NULL != spam_statistic) {
							spam_statistic(SPAM_STATISTIC_PROPERTY_030);
						}
						strncpy(reason, g_return_reason, length);
						return MESSAGE_REJECT;
					}
				} else {
					return MESSAGE_ACCEPT;
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

