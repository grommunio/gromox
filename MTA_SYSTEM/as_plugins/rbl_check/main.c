#include "as_common.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_DNS_RBL         37

enum {
	RBL_CACHE_NORMAL,
	RBL_CACHE_BLACK,
	RBL_CACHE_NONE
};

typedef BOOL (*WHITELIST_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
	CONNECTION *pconnection, char *reason, int length);

static BOOL (*dns_rbl_judge)(const char*, char*, int);

static int (*rbl_cache_query)(const char*, char *, int);

static void (*rbl_cache_add)(const char*, int, char*);

DECLARE_API;

static WHITELIST_QUERY ip_whitelist_query;
static WHITELIST_QUERY domain_whitelist_query;
static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
static CHECK_TAGGING check_tagging;


static char g_return_string[1024];

BOOL AS_LibMain(int reason, void **ppdata)
{
	/* path conatins the config files directory */
	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[dns_rbl]: fail to get \"check_retrying\" service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[dns_rbl]: fail to get \"check_tagging\" service\n");
			return FALSE;
		}
		ip_whitelist_query = (WHITELIST_QUERY)query_service(
							"ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[dns_rbl]: fail to get "
				"\"ip_whitelist_query\" service\n");
			return FALSE;
		}
		domain_whitelist_query = (WHITELIST_QUERY)query_service(
				                "domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[dns_rbl]: fail to get "
				"\"domain_whitelist_query\" service\n");
			return FALSE;
		}
		dns_rbl_judge = query_service("dns_rbl_judge");
		if (NULL == dns_rbl_judge) {
			printf("[dns_rbl]: fail to get "
				"\"dns_rbl_judge\" service\n");
			return FALSE;
		}
		rbl_cache_query = query_service("rbl_cache_query");
		if (NULL == rbl_cache_query) {
			printf("[dns_rbl]: fail to get "
				"\"rbl_cache_query\" service\n");
			return FALSE;
		}
		rbl_cache_add = query_service("rbl_cache_add");
		if (NULL == rbl_cache_add) {
			printf("[dns_rbl]: fail to get "
				"\"rbl_cache_add\" service\n");
			return FALSE;
		}
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		/* invoke register_statistic for registering statistic of mail */
		if (FALSE == register_statistic(mail_statistic)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	char *pdomain;
	int result;
	
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
	/* ignore system messages */
	if (0 == strncasecmp(pmail->penvelop->from, "system-", 7) &&
		0 == strcasecmp(pdomain, "system.mail")) {
		return MESSAGE_ACCEPT;
	}
	result = rbl_cache_query(pconnection->client_ip, reason, length);
	if (RBL_CACHE_NORMAL == result) {
		return MESSAGE_ACCEPT;
	} else if (RBL_CACHE_BLACK == result) {
		if (TRUE == check_tagging(pmail->penvelop->from,
			&pmail->penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (FALSE == check_retrying(pconnection->client_ip,
				pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {
				if (NULL!= spam_statistic) {
					spam_statistic(SPAM_STATISTIC_DNS_RBL);
				}
				return MESSAGE_RETRYING;
			} else {
				return MESSAGE_ACCEPT;
			}
		}
	}
	if (FALSE == dns_rbl_judge(pconnection->client_ip, reason, length)) {
		rbl_cache_add(pconnection->client_ip, RBL_CACHE_BLACK, reason);
		if (TRUE == check_tagging(pmail->penvelop->from,
			&pmail->penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (FALSE == check_retrying(pconnection->client_ip,
				pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {	
				if (NULL!= spam_statistic) {
					spam_statistic(SPAM_STATISTIC_DNS_RBL);
				}
				return MESSAGE_RETRYING;
			} else {
				return MESSAGE_ACCEPT;
			}
		}
	}
	rbl_cache_add(pconnection->client_ip, RBL_CACHE_NORMAL, NULL);
	return MESSAGE_ACCEPT;
}
