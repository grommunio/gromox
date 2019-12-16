#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include "mail_func.h"
#include <stdio.h>

#define SPAM_STATISTIC_SUBJECT_DOTS		25

typedef BOOL (*WHITELIST_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int subject_dots(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);

DECLARE_API;

static WHITELIST_QUERY domain_whitelist_query;
static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

static int g_pattern_len;
static char g_pattern_string[128];
static char g_return_string[1024];

int AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	const char *str_value;
	char *psearch;

    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
        domain_whitelist_query = (WHITELIST_QUERY)query_service(
                                 "domain_whitelist_query");
        if (NULL == domain_whitelist_query) {
            printf("[subject_dots]: fail to get \"domain_whitelist_query\" "
                    "service\n");
            return FALSE;
        }
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[subject_dots]: fail to get \"check_tagging\" service\n");
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
			printf("[subject_dots]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "PATTERN_STRING");
		if (str_value == NULL) {
			str_value = "~@$%^&*-_+=?,./\\";
			config_file_set_value(pconfig_file, "PATTERN_STRING", str_value);
		}
		g_pattern_len = strlen(str_value);
		if (0 == g_pattern_len) {
			printf("[subject_dots]: there's no character in pattern string\n");
			config_file_free(pconfig_file);
			return FALSE;
		}
		if (g_pattern_len > 127) {
			printf("[subject_dots]: pattern string too long\n");
			config_file_free(pconfig_file);
			return FALSE;
		}
		memcpy(g_pattern_string, str_value, g_pattern_len);
		g_pattern_string[g_pattern_len] = '\0';
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000025 请不要在主题中使用过多的\"%c\"");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[subject_dots]: return string is \"%s\"\n", g_return_string);
		config_file_free(pconfig_file);

        /* invoke register_auditor for registering auditor of mime head */
        if (FALSE == register_auditor(subject_dots)) {
			printf("[subject_dots]: failed to register auditor function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
    return TRUE;
}

static int subject_dots(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection,  char *reason, int length)
{
    int i, j;
	char *pdomain;
	size_t tmp_len;
    char tmp_buff[1024];
	ENCODE_STRING subject;
	int prev_pos, dots_num;

	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	pdomain = strchr(pmail->penvelop->from, '@');
	if (NULL == pdomain) {
		return MESSAGE_ACCEPT;
	}
    pdomain ++;
    if (TRUE == domain_whitelist_query(pdomain)) {
        return MESSAGE_ACCEPT;
    }
	tmp_len = mem_file_get_total_length(&pmail->phead->f_subject);
	if (tmp_len > 1024 || 0 == tmp_len) {
		return MESSAGE_ACCEPT;
	}
	mem_file_read(&pmail->phead->f_subject, tmp_buff, 1024);
	parse_mime_encode_string(tmp_buff, tmp_len, &subject);
	if (0 != strcasecmp(subject.charset, "gb2312")) {
		return MESSAGE_ACCEPT;
	}
	if (0 != decode64(subject.title, strlen(subject.title), tmp_buff,
		&tmp_len)) {
		return MESSAGE_ACCEPT;
	}
	for (j=0; j<g_pattern_len; j++) {
		prev_pos = -1;
		dots_num = 0;
		for (i=0; i<tmp_len; i++) {
			if (g_pattern_string[j] == tmp_buff[i]) {
				if (-1 != prev_pos && i - prev_pos != 3) {
					continue;
				}
				prev_pos = i;
				dots_num ++;
			}
		}
		if (dots_num >= 5) {
			if (TRUE == check_tagging(pmail->penvelop->from,
				&pmail->penvelop->f_rcpt_to)) {
				mark_context_spam(context_ID);
				return MESSAGE_ACCEPT;
			} else {
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_SUBJECT_DOTS);
				}
				snprintf(reason, length, g_return_string, g_pattern_string[j]);
				return MESSAGE_REJECT;
			}
		}
	}
    return MESSAGE_ACCEPT;
}

