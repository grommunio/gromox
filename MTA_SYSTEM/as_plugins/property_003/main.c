#include "as_common.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#include <ctype.h>

#define SPAM_STATISTIC_PROPERTY_003		16

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int boundary_filter(int context_ID, MAIL_ENTITY *pmail,
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
			printf("[property_003]: fail to get \"check_tagging\" service\n");
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
			printf("[property_003]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000016 you are now sending spam mail!");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[property_003]: return string is %s\n", g_return_string);
		config_file_free(pconfig_file);

        /* invoke register_auditor for registering auditor of mime head */
        if (FALSE == register_auditor(boundary_filter)) {
			printf("[property_003]: fail to register auditor function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
    return TRUE;
}

static int boundary_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection,  char *reason, int length)
{
    int  i, out_len;
    char buf[1024], *ptr, *pbackup;

	if (TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
    out_len = mem_file_read(&pmail->phead->f_content_type, buf, 1024);
    if (MEM_END_OF_FILE == out_len) {   /* no content type */
        return MESSAGE_ACCEPT;
    }
    if (NULL == (ptr = search_string(buf, "boundary", out_len))) {
        return MESSAGE_ACCEPT;
    }
    ptr += 8;
    if (NULL == (ptr = strchr(ptr, '"'))) {
        return MESSAGE_ACCEPT;
    }
    ptr++;
    pbackup = ptr;
    if (NULL == (ptr = strchr(ptr, '"'))) {
        return MESSAGE_ACCEPT;
    }
    out_len = (int)(ptr - pbackup);
    if (out_len <= 0 || out_len > 255) {
        return MESSAGE_ACCEPT;
    }
    memmove(buf, pbackup, out_len);
    buf[out_len] = '\0';

	/*------------------------------------------------------------------*/
FIRST_CHECK:
	if (8 == out_len || 7 == out_len) {
		if (0 != mem_file_get_total_length(&pmail->phead->f_xmailer)) {
			goto SECOND_CHECK;
		}
		for (i=0; i<out_len; i++) {
			if (!isdigit(buf[i])) {
				goto SECOND_CHECK;
			}
		}
		goto SPAM_FOUND;
	}

SECOND_CHECK:
	if (20 == out_len) {
		if (0 != mem_file_get_total_length(&pmail->phead->f_xmailer)) {
			goto THIRD_CHECK;
		}
		for (i=0; i<20; i++) {
			if (!isupper(buf[i])) {
				goto THIRD_CHECK;
			}
		}
		goto SPAM_FOUND;
	}

THIRD_CHECK:
	return MESSAGE_ACCEPT;

SPAM_FOUND:

	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		strncpy(reason, g_return_string, length);
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_003);
		}
		return MESSAGE_REJECT;
	}
    return MESSAGE_ACCEPT;
}

