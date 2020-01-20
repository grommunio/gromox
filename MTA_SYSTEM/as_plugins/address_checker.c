#include <errno.h>
#include <string.h>
#include <libHX/ctype_helper.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include "mail_func.h"
#include <stdlib.h>
#include <stdio.h>

#define SPAM_STATISTIC_ADDRESS_CHECKER		24
#define MAX_DIGIT_LOCAL_LEN		5
#define MAX_DIGIT_DOMAIN_LEN	4
#define CELL_NUM_LEN			11

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*WHITELIST_QUERY)(char*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static WHITELIST_QUERY ip_whitelist_query;
static WHITELIST_QUERY domain_whitelist_query;
static CHECK_TAGGING check_tagging;

static char g_return_string[1024];

DECLARE_API;

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop,
	CONNECTION *pconnection, char *reason, int length);

BOOL AS_LibMain(int reason, void **ppdata)
{
    CONFIG_FILE *pconfig_file;
    char file_name[256], temp_path[256];
    char *str_value, *psearch;

    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);

		domain_whitelist_query = (WHITELIST_QUERY)query_service(
				                "domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[address_checker]: failed to get service \"domain_whitelist_query\"\n");
			return FALSE;
		}
		ip_whitelist_query = (WHITELIST_QUERY)query_service(
				            "ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[address_checker]: failed to get service \"ip_whitelist_query\"\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[address_checker]: failed to get service \"check_tagging\"\n");
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
			printf("[address_checker]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
        str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string,"000024 it seems your address \"%s\" is "
				"illegal");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[address_checker]: return string is \"%s\"\n", g_return_string);
        config_file_free(pconfig_file);
        /* invoke register_judge for registering judge of mail envelop */
        if (FALSE == register_judge(envelop_judge)) {
			printf("[address_checker]: failed to register judge function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
    return TRUE;
}

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop, 
    CONNECTION *pconnection, char *reason, int length)
{
	char *at_pos, *dot_pos, *hyphen_pos, *ptr;
	BOOL b_local_hint, b_domain_hint;
	int local_len, domain_len;
	int prefix_len, digit_num, upper_num;
	char temp_buff[16];
	
	if (TRUE == penvelop->is_outbound || TRUE == penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == ip_whitelist_query(pconnection->client_ip)) {
		return MESSAGE_ACCEPT;
	}
	if (0 == strcmp(penvelop->from, "none@none")) {
		return MESSAGE_ACCEPT;
	}
	at_pos = strchr(penvelop->from, '@');
	if (domain_whitelist_query(at_pos + 1) == TRUE) {
		return MESSAGE_ACCEPT;
	}
	if (NULL != strchr(at_pos + 1, '@') ||
		NULL != extract_ip(at_pos + 1, temp_buff)) {
		if (TRUE == check_tagging(penvelop->from, &penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			snprintf(reason, length, g_return_string, penvelop->from);
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_ADDRESS_CHECKER);
			}
			return MESSAGE_REJECT;
		}
	}
	ptr = penvelop->from;
	/* check if there exists none-ascii character */
	while (*ptr != '\0') {
		if (*ptr & ((char)0x80)) {
			if (TRUE == check_tagging(penvelop->from, &penvelop->f_rcpt_to)) {
				mark_context_spam(context_ID);
				return MESSAGE_ACCEPT;
			} else {
				snprintf(reason, length, g_return_string, penvelop->from);
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_ADDRESS_CHECKER);
				}
				return MESSAGE_REJECT;
			}
		}
		ptr ++;
	}
	/* check if there exists dot in domain name like format "@.net" */
	dot_pos = strchr(at_pos, '.');
	if (NULL == dot_pos || dot_pos == at_pos + 1) {
		if (TRUE == check_tagging(penvelop->from, &penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			snprintf(reason, length, g_return_string, penvelop->from);
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_ADDRESS_CHECKER);
			}
			return MESSAGE_REJECT;
		}
	}
	/* check if the local part of address is composed only by digits */
	b_local_hint = TRUE;
	local_len = 0;
	for (ptr=penvelop->from; ptr<at_pos; ptr++) {
		if (!HX_isdigit(*ptr)) {
			b_local_hint = FALSE;
			break;
		}
		local_len ++;
	}
	/* check if domain is composed only by digits */
	b_domain_hint = TRUE;
	domain_len = 0;
	for (ptr=at_pos+1; ptr<dot_pos; ptr++) {
		if (!HX_isdigit(*ptr)) {
			b_domain_hint = FALSE;
			break;
		}
		domain_len ++;
	}
	if (TRUE == b_domain_hint && TRUE == b_local_hint &&
		CELL_NUM_LEN != local_len && local_len > MAX_DIGIT_LOCAL_LEN && 
		domain_len > MAX_DIGIT_DOMAIN_LEN) {
		if (TRUE == check_tagging(penvelop->from, &penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			snprintf(reason, length, g_return_string, penvelop->from);
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_ADDRESS_CHECKER);
			}
			return MESSAGE_REJECT;
		}
	}
	local_len = at_pos - penvelop->from;
	if(local_len <= 3) {
		return MESSAGE_ACCEPT;
	}
	/* check address of format like 487745@OK-D13D078C4EBC.net */
	if ((local_len != 4 && local_len != 5 && local_len != 6) ||
		dot_pos - at_pos - 1 != 15) {
		return MESSAGE_ACCEPT;
	}
	if (0 != strcasecmp(dot_pos + 1, "net")) {
		return MESSAGE_ACCEPT;
	}
	for (ptr=penvelop->from; ptr<at_pos; ptr++) {
		if (!HX_isdigit(*ptr))
			return MESSAGE_ACCEPT;
	}
	hyphen_pos = strchr(at_pos, '-');
	digit_num = 0;
	upper_num = 0;
	if (NULL == hyphen_pos) {
		/* 721471@BE0D5C530AE843A.net */
		for (ptr=at_pos+1; ptr<dot_pos; ptr++) {
			if (HX_isupper(*ptr))
				upper_num ++;
			else if (HX_isdigit(*ptr))
				digit_num ++;
			else
				return MESSAGE_ACCEPT;
		}
		if (upper_num > 0 && digit_num > 3) {
			if (TRUE == check_tagging(penvelop->from, &penvelop->f_rcpt_to)) {
				mark_context_spam(context_ID);
				return MESSAGE_ACCEPT;
			} else {
				snprintf(reason, length, g_return_string, penvelop->from);
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_ADDRESS_CHECKER);
				}
				return MESSAGE_REJECT;
			}
		}
	} else {
		prefix_len = hyphen_pos - at_pos - 1;
		if (0 == prefix_len) {
			return MESSAGE_ACCEPT;
		}
		for (ptr=at_pos+1; ptr<hyphen_pos; ptr++) {
			if (!HX_isupper(*ptr) && !HX_isdigit(*ptr))
				return MESSAGE_ACCEPT;
		}
		for (ptr=hyphen_pos+1; ptr<dot_pos; ptr++) {
			if (HX_isupper(*ptr))
				upper_num ++;
			else if (HX_isdigit(*ptr))
				digit_num ++;
			else
				return MESSAGE_ACCEPT;
		}
		if (upper_num > 0 && digit_num > 3 &&
			14 == prefix_len + digit_num + upper_num) {
			if (TRUE == check_tagging(penvelop->from, &penvelop->f_rcpt_to)) {
				mark_context_spam(context_ID);
				return MESSAGE_ACCEPT;
			} else {
				snprintf(reason, length, g_return_string, penvelop->from);
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_ADDRESS_CHECKER);
				}
				return MESSAGE_REJECT;
			}
		}
	}
	
	return MESSAGE_ACCEPT;
}

