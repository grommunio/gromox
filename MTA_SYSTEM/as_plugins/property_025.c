#include <errno.h>
#include <stdbool.h>
#include <libHX/ctype_helper.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include <libHX/ctype_helper.h>
#include "util.h"
#include <string.h>
#include <stdio.h>


#define SPAM_STATISTIC_PROPERTY_025		62


typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static CHECK_TAGGING check_tagging;
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
	
	/* path contains the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_025]: failed to get service \"check_tagging\"\n");
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
			printf("[property_025]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000062 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_025]: return string is \"%s\"\n", g_return_reason);
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
	char buff[1024];
	char *ptr, *pbackup;
	int out_len, i;
	
	if (TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	out_len = mem_file_read(&pmail->phead->f_content_type, buff, 1024);
    if (MEM_END_OF_FILE == out_len) {   /* no content type */
        return MESSAGE_ACCEPT;
    }
	if (NULL == (ptr = search_string(buff, "boundary", out_len))) {
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
	
	if (41 == out_len && 0 == strncmp(pbackup, "----=_NextPart_000_", 19) &&
		'_' == pbackup[23] && '.' == pbackup[32]) {
		for (i=19; i<23; i++) {
			if ((pbackup[i] >= 'A' && pbackup[i] <= 'F') ||
				(pbackup[i] >= '0' && pbackup[i] <= '9')) {
				continue;
			} else {
				return MESSAGE_ACCEPT;
			}	
		}
		for (i=24; i<32; i++) {
			if ((pbackup[i] >= 'A' && pbackup[i] <= 'F') ||
				(pbackup[i] >= '0' && pbackup[i] <= '9')) {
				continue;
			} else {
				return MESSAGE_ACCEPT;
			}	
		}
		for (i=33; i<41; i++) {
			if ((pbackup[i] >= 'A' && pbackup[i] <= 'F') ||
				(pbackup[i] >= '0' && pbackup[i] <= '9')) {
				continue;
			} else {
				return MESSAGE_ACCEPT;
			}	
		}
		out_len = mem_file_read(&pmail->phead->f_xmailer, buff, 1024);
		if (MEM_END_OF_FILE == out_len || out_len < 4 || out_len > 14) {
			return MESSAGE_ACCEPT;
		}
		if (out_len < 4 || !HX_isupper(buff[0]) ||
			' ' != buff[out_len - 2] ||
		    !HX_isdigit(buff[out_len-1]))
			return MESSAGE_ACCEPT;
		for (i=1; i<out_len-2; i++) {
			if (!HX_islower(buff[i]))
				return MESSAGE_ACCEPT;
		}
	} else if (28 == out_len && 0 == strncmp(pbackup, "----=_0", 7) &&
		'_' == pbackup[10]  && '.' == pbackup[19]) {
		for (i=6; i<10; i++) {
			if ((pbackup[i] >= 'A' && pbackup[i] <= 'F') ||
				(pbackup[i] >= '0' && pbackup[i] <= '9')) {
				continue;
			} else {
				return MESSAGE_ACCEPT;
			}
		}
		for (i=11; i<19; i++) {
			if ((pbackup[i] >= 'A' && pbackup[i] <= 'F') ||
				(pbackup[i] >= '0' && pbackup[i] <= '9')) {
				continue;
			} else {
				return MESSAGE_ACCEPT;
			}
		}
		for (i=20; i<28; i++) {
			if ((pbackup[i] >= 'A' && pbackup[i] <= 'F') ||
				(pbackup[i] >= '0' && pbackup[i] <= '9')) {
				continue;
			} else {
				return MESSAGE_ACCEPT;
			}
		}
	} else if (32 == out_len && 0 == strncmp(pbackup, "----=_001_", 10) &&
		0 == strncmp(pbackup + 26, "_=----", 6)) {
		for (i=10; i<26; i++) {
			if ((pbackup[i]  >= '0' && pbackup[i] <= '9') ||
				(pbackup[i] >= 'a' && pbackup[i] <= 'f')) {
				continue;
			} else {
				return MESSAGE_ACCEPT;
			}
		}
	} else {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_025);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}
}

