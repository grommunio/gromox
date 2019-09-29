#include "as_common.h"
#include "config_file.h"
#include "util.h"
#include <ctype.h>
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_009        33

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*WHITELIST_QUERY)(char*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);


static int mail_boundary(int context_ID, MAIL_ENTITY *pmail,
    CONNECTION *pconnection, char *reason, int length);

DECLARE_API;

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;
static WHITELIST_QUERY domain_whitelist_query;

static char g_return_string[1024];

BOOL AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_009]: fail to get \"check_tagging\" service\n");
			return FALSE;
		}
		domain_whitelist_query = (WHITELIST_QUERY)
			query_service("domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[property_009]: fail to get "
				"\"domain_whitelist_query\" service\n");
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
			printf("[property_009]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000033 you are now sending spam mail");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[property_009]: return string is %s\n", g_return_string);
		config_file_free(pconfig_file);
        /* invoke register_auditor for registering auditor of mail */
        if (FALSE == register_auditor(mail_boundary)) {
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
    return TRUE;
}


static int mail_boundary(int context_ID, MAIL_ENTITY *pmail,
    CONNECTION *pconnection, char *reason, int length)
{
	int i;
	char *ptr;
	int tmp_len;
	char *pdomain;
	char buff[1024];
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	pdomain = strchr(pmail->penvelop->from, '@');
	pdomain ++;
	if (TRUE == domain_whitelist_query(pdomain)) {
		return MESSAGE_ACCEPT;
	}
	tmp_len = mem_file_read(&pmail->phead->f_content_type, buff, 1024);
	if (MEM_END_OF_FILE == tmp_len) {   /* no content type */
		return MESSAGE_ACCEPT;
	}
	ptr = search_string(buff, "boundary=\"", tmp_len);
	if (NULL == ptr) {
		return MESSAGE_ACCEPT;
	}
	ptr += 10;
	if ('"' == ptr[32]) {
		tmp_len = 32;
	} else {
		return MESSAGE_ACCEPT;
	}
	for (i=0; i<tmp_len; i++) {
		if (('0' <= ptr[i] && ptr[i] <= '9') ||
			('a' <= ptr[i] && ptr[i] <= 'f')) {
			continue;
		}
		return MESSAGE_ACCEPT;
	}
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_009);
		}
		strncpy(reason, g_return_string, length);
		return MESSAGE_REJECT;
	}
}
