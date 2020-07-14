#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "mail_func.h"
#include "site_protection.h"
#include <stdio.h>

#define SPAM_STATISTIC_SITE_PROTECTION			23

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*WHITELIST_QUERY)(char*);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);


static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
static CHECK_TAGGING check_tagging;
static WHITELIST_QUERY ip_whitelist_query;

DECLARE_API;

static int mime_auditor(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);
	
static char g_return_reason[1024];

BOOL AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
	/* path contains the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		ip_whitelist_query = (WHITELIST_QUERY)query_service(
								"ip_whitelist_query");
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[site_protection]: failed to get service \"check_retrying\"\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[site_protection]: failed to get service \"check_tagging\"\n");
			return FALSE;
		}
		if (NULL == ip_whitelist_query) {
			printf("[site_protection]: failed to get service \"ip_whitelist_query\"\n");
			return FALSE;
		}
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init2(NULL, temp_path);
		if (NULL == pconfig_file) {
			printf("[site_protection]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000023 it seems your IP address %s does not "
				"belong to domain %s, please send a mail to %s to complain "
				"this problem, thank you!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[site_protection]: return string is \"%s\"\n", g_return_reason);
		config_file_free(pconfig_file);
		sprintf(temp_path, "%s/%s.txt", get_data_path(), file_name);
		site_protection_init(temp_path);
		if (0 != site_protection_run()) {
			printf("[site_protection]: failed to run the site_protection\n");
			return FALSE;
		}
        /* invoke register_auditor for registering auditor of mail head */
        if (FALSE == register_auditor(mime_auditor)) {
			printf("[site_protection]: failed to register judge function\n");
            return FALSE;
        }
		if (FALSE == register_talk(site_protection_console_talk)) {
			printf("[site_protection]: failed to register console talk\n");
            return FALSE;
		}
        return TRUE;
    case PLUGIN_FREE:
		site_protection_stop();
		site_protection_free();
        return TRUE;
    }
	return TRUE;
}
	
static int mime_auditor(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	int result;
	int tag_len;
	int val_len;
	char *from_domain;
	char temp_ip[16];
	char rcpt_to[256];
	char temp_buff[1024];
	char complain_address[256];
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == ip_whitelist_query(pconnection->client_ip)) {
		return MESSAGE_ACCEPT;
	}
	from_domain = strchr(pmail->penvelop->from, '@') + 1;
	result = site_protection_verify(from_domain, pconnection->client_ip);
	if (SITE_PROTECTION_REJECT != result && SITE_PROTECTION_RETRY != result) {
		return MESSAGE_ACCEPT;
	}
	while (MEM_END_OF_FILE != mem_file_read(&pmail->phead->f_others, &tag_len,
		sizeof(int))) {
		if (8 == tag_len) {
			mem_file_read(&pmail->phead->f_others, temp_buff, tag_len);
			if (0 == strncasecmp("Received", temp_buff, 8)) {
				mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
				if (val_len > 1023) {
					return MESSAGE_REJECT;
				}
				mem_file_read(&pmail->phead->f_others, temp_buff, val_len);
				temp_buff[val_len] = '\0';
				if (NULL == extract_ip(temp_buff, temp_ip)) {
					continue;
				}
				if (SITE_PROTECTION_OK == site_protection_verify(from_domain,
					temp_ip)) {
					return MESSAGE_ACCEPT;
				} else {
					continue;
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

	memset(rcpt_to, 0, 256);
	mem_file_readline(&pmail->penvelop->f_rcpt_to, rcpt_to, 256);
	if (0 == strncasecmp(rcpt_to, "spam-", 5)) {
		return MESSAGE_ACCEPT;
	}

	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		snprintf(complain_address, 256, "spam-complain@%s",
			get_default_domain());
		snprintf(reason, length, g_return_reason, pconnection->client_ip,
			from_domain, complain_address);
		if (SITE_PROTECTION_RETRY == result) {
			if (FALSE == check_retrying(pconnection->client_ip,
				pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_SITE_PROTECTION);
				}
				return MESSAGE_RETRYING;
			} else {
				return MESSAGE_ACCEPT;
			}
		} else {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_SITE_PROTECTION);
			}
			return MESSAGE_REJECT;
		}
	}
}

