#include <errno.h>
#include <arpa/inet.h>
#include "config_file.h"
#include <gromox/as_common.h>
#include "mail_func.h"
#include "util.h"
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h> 

#define SPAM_STATISTIC_PROPERTY_011        40

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int mail_boundary(int context_ID, MAIL_ENTITY *pmail,
    CONNECTION *pconnection, char *reason, int length);

DECLARE_API;

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

static char g_return_string[1024];

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
			printf("[property_011]: failed to get service \"check_tagging\"\n");
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
			printf("[property_011]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000040 you ares now sending spam mail!");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[property_011]: return string is \"%s\"\n", g_return_string);
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
	int tmp_len;
	int h_errnop;
	in_addr_t addr;
	char buff[1024];
	struct hostent hostinfo, *phost;
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	tmp_len = mem_file_read(&pmail->phead->f_xmailer, buff, 1024);
    if (MEM_END_OF_FILE == tmp_len) {
        return MESSAGE_ACCEPT;
    }
	if (0 != strncasecmp(buff, "Foxmail 7, 0, 1, 91[cn]", 23)) {
		return MESSAGE_ACCEPT;
	}
	if (MULTI_PARTS_MAIL == pmail->phead->mail_part) {
		tmp_len = mem_file_read(&pmail->phead->f_content_type, buff, 1024);
		if (MEM_END_OF_FILE == tmp_len) {   /* no content type */
			return MESSAGE_ACCEPT;
		}
		if (NULL != search_string(buff,
			"boundary=\"----=_001_NextPart", tmp_len)) {
			return MESSAGE_ACCEPT;	
		}
		strncpy(reason, g_return_string, length);
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_011);
		}
		return MESSAGE_REJECT;
	}
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	}
	inet_pton(AF_INET, pconnection->client_ip, &addr);
	if (0 == gethostbyaddr_r((char*)&addr, sizeof(addr),
		AF_INET, &hostinfo, buff, sizeof(buff), &phost,
		&h_errnop) && NULL != phost && NULL == extract_ip(
		phost->h_name, buff)) {
		return MESSAGE_ACCEPT;
	}
	strncpy(reason, g_return_string, length);
	if (NULL != spam_statistic) {
		spam_statistic(SPAM_STATISTIC_PROPERTY_011);
	}
	return MESSAGE_REJECT;
}
