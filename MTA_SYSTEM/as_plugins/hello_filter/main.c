#include "as_common.h"
#include "config_file.h"
#include "mail_func.h"
#include <stdio.h>

#define SPAM_STATISTIC_HELLO_FILTER			22

typedef BOOL (*WHITELIST_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static WHITELIST_QUERY ip_whitelist_query;
static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop,
	CONNECTION *pconnection, char *reason, int length);

static char g_return_reason[1024];

BOOL AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[hello_filter]: fail to get \"check_retrying\" service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[hello_filter]: fail to get \"check_tagging\" service\n");
			return FALSE;
		}
		ip_whitelist_query = (WHITELIST_QUERY)query_service(
				            "ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[hello_filter]: fail to get \"ip_whitelist_query\" "
					"service\n");
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
			printf("[hello_filter]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000022 domain name %s after helo is "
				"illegal please contact your mail system administrator!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[hello_filter]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
        /* invoke register_judge for registering judge of mail envelop */
        if (FALSE == register_judge(envelop_judge)) {
			printf("[hello_filter]: fail to register judge function!!!\n");
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
	int i, num, len;
	char *pdomain;
	char temp_ip[16];
	char rcpt_to[256];
	char complain_address[256];
	char subject[1024];
	
	if (TRUE == penvelop->is_outbound || TRUE == penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (NULL != pconnection->ssl) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == ip_whitelist_query(pconnection->client_ip)) {
		return MESSAGE_ACCEPT;
	}
	if (extract_ip(penvelop->hello_domain, temp_ip) != NULL) {
		goto ILLEGAL_HELO;
	}

	len = strlen(penvelop->hello_domain);
	for (num=0,i=0; i<len; i++) {
		if ('.' == penvelop->hello_domain[i]) {
			num ++;
		}
	}

	if (num >= 3) {
		strcpy(temp_ip, pconnection->client_ip);
		len = strlen(temp_ip);
		for (i=0; i<len; i++) {
			if ('.' == temp_ip[i]) {
				temp_ip[i] = '-';
			}
		}

		if (NULL != strstr(penvelop->hello_domain, temp_ip)) {
			goto ILLEGAL_HELO;
		}
	}
	
	if (NULL == strchr(penvelop->hello_domain, '.')) {
		if (0 == strncasecmp(penvelop->hello_domain, "mx", 2) ||
			0 == strncasecmp(penvelop->hello_domain, "localhost", 9) ||
			0 == strncasecmp(penvelop->hello_domain, "www", 3) ||
			0 == strncasecmp(penvelop->hello_domain, "mail", 4) ||
			0 == strncasecmp(penvelop->hello_domain, "web", 3)) {
			return MESSAGE_ACCEPT;
		}
		goto ILLEGAL_HELO;
	}
	memset(rcpt_to, 0, 256);
	mem_file_readline(&penvelop->f_rcpt_to, rcpt_to, 256);
	pdomain = strchr(rcpt_to, '@') + 1;
	if (0 == strcasecmp(penvelop->hello_domain, pdomain)) {
		goto ILLEGAL_HELO;
	}
	return MESSAGE_ACCEPT;
ILLEGAL_HELO:
	len = strlen(penvelop->hello_domain);
	for (i=0; i<len; i++) {
		if (penvelop->hello_domain[i] & (char)0x80 ||
			(' ' == penvelop->hello_domain[i] && i != 0 && i != len - 1)) {
			if (TRUE == check_tagging(penvelop->from, &penvelop->f_rcpt_to)) {
				mark_context_spam(context_ID);
				return MESSAGE_ACCEPT;
			} else {
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_HELLO_FILTER);
				}
				snprintf(reason, length, g_return_reason,
					penvelop->hello_domain);
				return MESSAGE_REJECT;
			}
		}
	}
	if (TRUE == check_tagging(penvelop->from, &penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (FALSE == check_retrying(pconnection->client_ip, penvelop->from,
			&penvelop->f_rcpt_to)) {
			snprintf(reason, length, g_return_reason, penvelop->hello_domain);
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_HELLO_FILTER);
			}
			return MESSAGE_RETRYING;
		} else {
			return MESSAGE_ACCEPT;
		}
	}
}

