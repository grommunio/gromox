#include <errno.h>
#include <string.h>
#include <libHX/ctype_helper.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include "mail_func.h"
#include <stdio.h>

#define SPAM_STATISTIC_SUBJECT_AUDITOR		11

typedef BOOL (*SUBJECT_AUDIT)(char*);
typedef BOOL (*WHITELIST_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int subject_auditor(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);

DECLARE_API;

static SUBJECT_AUDIT subject_audit;
static WHITELIST_QUERY ip_whitelist_query;
static WHITELIST_QUERY domain_whitelist_query;
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
		subject_audit = (SUBJECT_AUDIT)query_service("subject_audit");
		if (NULL == subject_audit) {
			printf("[subject_auditor]: fail to get \"subject_audit\" "
					"service\n");
			return FALSE;
		}
		ip_whitelist_query = (WHITELIST_QUERY)query_service(
                             "ip_whitelist_query");
        if (NULL == ip_whitelist_query) {
            printf("[subject_auditor]: fail to get \"ip_whitelist_query\" "
                    "service\n");
            return FALSE;
        }
        domain_whitelist_query = (WHITELIST_QUERY)query_service(
                                 "domain_whitelist_query");
        if (NULL == domain_whitelist_query) {
            printf("[subject_auditor]: fail to get \"domain_whitelist_query\" "
                    "service\n");
            return FALSE;
        }
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[subject_auditor]: fail to get \"check_tagging\" service\n");
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
			printf("[subject_auditor]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000011 subject %s is audited by server");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[subject_auditor]: return string is \"%s\"\n", g_return_string);
		config_file_free(pconfig_file);

        /* invoke register_auditor for registering auditor of mime head */
        if (FALSE == register_auditor(subject_auditor)) {
			printf("[subject_auditor]: fail to register auditor function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
    return TRUE;
}

static int subject_auditor(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection,  char *reason, int length)
{
    char tmp_buff[256], subject[256];
	char rcpt_to[256];
    int tmp_len, local_len;
	int i, len, rest_len;
	char *pdomain;
	char *pbegin, *pbackup;

	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == ip_whitelist_query(pconnection->client_ip)) {
        return MESSAGE_ACCEPT;
    }
	pdomain = strchr(pmail->penvelop->from, '@');
    pdomain ++;
    if (TRUE == domain_whitelist_query(pdomain)) {
        return MESSAGE_ACCEPT;
    }
	mem_file_readline(&pmail->penvelop->f_rcpt_to, rcpt_to, 256);
	pdomain = strchr(rcpt_to, '@');
	*pdomain = '\0';
	tmp_len = mem_file_get_total_length(&pmail->phead->f_subject);
	if (tmp_len > 255 || 0 == tmp_len) {
		return MESSAGE_ACCEPT;
	}
	mem_file_read(&pmail->phead->f_subject, tmp_buff, 256);
	pbegin = search_string(tmp_buff, rcpt_to, tmp_len);
	if (NULL == pbegin) {
		if (MULTI_PARTS_MAIL != pmail->phead->mail_part) {
			return MESSAGE_ACCEPT;
		}
		if (mem_file_get_total_length(&pmail->phead->f_xmailer) != 0) {
			return MESSAGE_ACCEPT;
		}
		/* check subject string if there's none-asc character inside */
		for (i=0; i<tmp_len; i++) {
			if (tmp_buff[i] & ((char)0x80)) {
				break;
			}
		}
		if (i == tmp_len) {
			return MESSAGE_ACCEPT;
		}
		memcpy(subject, tmp_buff, tmp_len);
		subject[tmp_len] = '\0';
		tmp_len = mem_file_read(&pmail->phead->f_content_type, tmp_buff, 256);
		if (MEM_END_OF_FILE == tmp_len) {
			return MESSAGE_ACCEPT;
		}
		/* get boundary string */
		if (NULL == (pbegin = search_string(tmp_buff, "boundary", tmp_len))) {
			return MESSAGE_ACCEPT;
		}
		pbegin += 8;
		if (NULL == (pbegin = strchr(pbegin, '"'))) {
			return MESSAGE_ACCEPT;
		}
		pbegin ++;
		pbackup = pbegin;
		if (NULL == (pbegin = strchr(pbegin, '"'))) {
			return MESSAGE_ACCEPT;
		}
		len = (int)(pbegin - pbackup);
		/* ----=_NextPart_000_0009_01C5BED7.D0481C40 */
		if (41 != len) {
			return MESSAGE_ACCEPT;
		}
		if (0 != strncmp(pbackup, "----=_NextPart_", 15)) {
			return MESSAGE_ACCEPT;
		}
		if (pbackup[18] != '_' || pbackup[23] != '_' || pbackup[32] != '.') {
			return MESSAGE_ACCEPT;
		}
		for (i=15; i<18; i++) {
			if ('0' > pbackup[i] || '9' < pbackup[i]) {
				return MESSAGE_ACCEPT;
			}
		}
		for (i=19; i<23; i++) {
			if ('0' > pbackup[i] || '9' < pbackup[i]) {
				return MESSAGE_ACCEPT;
			}
		}
		for (i=24; i<32; i++) {
			if (!HX_isdigit(pbackup[i]) && !HX_isalpha(pbackup[i]))
				return MESSAGE_ACCEPT;
		}
		for (i=33; i<41; i++) {
			if (!HX_isdigit(pbackup[i]) && !HX_isalpha(pbackup[i]))
				return MESSAGE_ACCEPT;
		}
	} else {
		local_len = strlen(rcpt_to);
		len = pbegin - tmp_buff;
		if (len > 255) {
			return MESSAGE_ACCEPT;
		}
		memcpy(subject, tmp_buff, len);
		rest_len = tmp_len - len - local_len;
		if (rest_len < 0 || rest_len > 255 - len) {
			return MESSAGE_ACCEPT;
		}
		memcpy(subject + len, pbegin + local_len, tmp_len - len - local_len);
		subject[tmp_len - local_len] = '\0';
	}
	if (FALSE == subject_audit(subject)) {
		if (TRUE == check_tagging(pmail->penvelop->from,
			&pmail->penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_SUBJECT_AUDITOR);
			}
			snprintf(reason, length, g_return_string, subject);
			return MESSAGE_REJECT;
		}
	}
    return MESSAGE_ACCEPT;
}

