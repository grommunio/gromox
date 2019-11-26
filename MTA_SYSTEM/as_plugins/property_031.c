#include "as_common.h"
#include "config_file.h"
#include "util.h"
#include "mail_func.h"
#include <ctype.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h> 



#define SPAM_STATISTIC_PROPERTY_031        68

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);

static int text_filter(int action, int context_ID, MAIL_BLOCK *pblock,
    char *reason, int length);

static int html_filter(int action, int context_ID, MAIL_BLOCK *pblock,
    char *reason, int length);

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
			printf("[property_031]: fail to get \"check_tagging\" service\n");
			return FALSE;
		}
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[property_031]: fail to get"
				" \"check_retrying\" service\n");
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
			printf("[property_031]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000068 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_031]: return string is %s\n", g_return_reason);
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
}

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	int out_len;
	int h_errnop;
	in_addr_t addr;
	char buff[4096];
	struct hostent hostinfo, *phost;

	if (TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (NULL != pconnection->ssl) {
		return MESSAGE_ACCEPT;
	}
	out_len = mem_file_read(&pmail->phead->f_mime_to, buff, 1024);
	if (25 != out_len) {
		return MESSAGE_ACCEPT;
	}
	if (0 != strncasecmp(buff, "undisclosed-recipients:;", 24)) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	}
	if (FALSE == check_retrying(pconnection->client_ip,
		pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {
		strncpy(reason, g_return_reason, length);
		if (NULL!= spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_031);
		}
		return MESSAGE_RETRYING;
	}
	inet_pton(AF_INET, pconnection->client_ip, &addr);
	if (0 == gethostbyaddr_r((char*)&addr, sizeof(addr),
		AF_INET, &hostinfo, buff, sizeof(buff), &phost,
		&h_errnop) && NULL != phost && NULL == extract_ip(
		phost->h_name, buff)) {
		return MESSAGE_ACCEPT;
	}
	strncpy(reason, g_return_reason, length);
	if (NULL != spam_statistic) {
		spam_statistic(SPAM_STATISTIC_PROPERTY_031);
	}
	return MESSAGE_REJECT;
}
