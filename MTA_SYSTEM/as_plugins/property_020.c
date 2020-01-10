#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_020		51

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);

DECLARE_API;

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

static char g_return_string[1024];

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
			printf("[property_020]: failed to get service \"check_tagging\"\n");
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
			printf("[property_020]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000051 you are now sending spam mail!");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[property_020]: return string is \"%s\"\n", g_return_string);
		config_file_free(pconfig_file);

        /* invoke register_auditor for registering auditor of mime head */
        if (FALSE == register_auditor(head_filter)) {
			printf("[property_020]: failed to register auditor function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
    return TRUE;
}

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection,  char *reason, int length)
{
	int tag_len;
	int val_len;
    int out_len;
	BOOL b_sender;
    char buf[1024];

	if (TRUE == pmail->penvelop->is_relay ||
		TRUE == pmail->penvelop->is_outbound) {
		return MESSAGE_ACCEPT;
	}
	if (mem_file_get_total_length(&pmail->phead->f_xmailer) > 0) {
		return MESSAGE_ACCEPT;
	}
	out_len = mem_file_read(&pmail->phead->f_subject, buf, 1024);
	if (MEM_END_OF_FILE == out_len) {
		return MESSAGE_ACCEPT;
	}
	if (0 != strncasecmp(buf, "=?utf-8?B?", 10)) {
		return MESSAGE_ACCEPT;
	}
	
	b_sender = FALSE;
	
	while (MEM_END_OF_FILE != mem_file_read(&pmail->phead->f_others, &tag_len,
		sizeof(int))) {
		if (6 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buf, tag_len);
			if (0 == strncasecmp("Sender", buf, 6)) {
				b_sender = TRUE;
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
	
	if (FALSE == b_sender) {
		return MESSAGE_ACCEPT;
	}
	
    out_len = mem_file_read(&pmail->phead->f_content_type, buf, 1024);
    if (MEM_END_OF_FILE == out_len) {   /* no content type */
        return MESSAGE_ACCEPT;
    }

    if (NULL == search_string(buf, "boundary=--boundary_", out_len)) {
        return MESSAGE_ACCEPT;
    }
	
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
	    strncpy(reason, g_return_string, length);
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_020);
		}
		return MESSAGE_REJECT;
	}
}

