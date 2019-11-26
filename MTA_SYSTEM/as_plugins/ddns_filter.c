#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "mail_func.h"
#include "list_file.h"
#include <pthread.h>

#define SPAM_STATISTIC_DDNS_FILTER			12

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*WHITELIST_QUERY)(char*);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static WHITELIST_QUERY ip_whitelist_query;
static WHITELIST_QUERY domain_whitelist_query;
static CHECK_RETRYING check_retrying;
static CHECK_TAGGING  check_tagging;

DECLARE_API;

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
	CONNECTION *pconnection, char *reason, int length);

static void console_talk(int argc, char **argv, char *result, int length);

static LIST_FILE *g_ddns_list;
static char g_listfile_name[256];
static char g_return_reason[1024];
static pthread_rwlock_t g_reload_lock;

BOOL AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		pthread_rwlock_init(&g_reload_lock, NULL);
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[ddns_filter]: fail to get \"check_retrying\" service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[ddns_filter]: fail to get \"check_tagging\" service\n");
			return FALSE;
		}
		domain_whitelist_query = (WHITELIST_QUERY)query_service(
									"domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[ddns_filter]: fail to get \"domain_whitelist_query\" "
				"service\n");
			return FALSE;
		}
		ip_whitelist_query = (WHITELIST_QUERY)query_service(
								"ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[ddns_filter]: fail to get \"ip_whitelist_query\" "
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
			printf("[ddns_filter]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000012 domain name %s is dynamic, please"
				"retry your mail in 10 minutes");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[ddns_filter]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		sprintf(g_listfile_name, "%s/%s.txt", get_data_path(), file_name);
		g_ddns_list = list_file_init(g_listfile_name, "%s:256");
		if (NULL == g_ddns_list) {
			printf("[ddns_filter]: fail to open list file!!!\n");
			return FALSE;
		}
        /* invoke register_statistic for registering static of mail envelop */
        if (FALSE == register_statistic(mail_statistic)) {
			printf("[ddns_filter]: fail to register judge function!!!\n");
            return FALSE;
        }
		register_talk(console_talk);
        return TRUE;
    case PLUGIN_FREE:
		if (NULL != g_ddns_list) {
			list_file_free(g_ddns_list);
		}
		pthread_rwlock_destroy(&g_reload_lock);
        return TRUE;
    }
	return TRUE;
}

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	BOOL b_hint;
	char *pdomain, *pitem;
	int i, len;
	int item_size;
	int domain_len;
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == ip_whitelist_query(pconnection->client_ip)) {
		return MESSAGE_ACCEPT;
	}
	pdomain = strchr(pmail->penvelop->from, '@') + 1;
	if (TRUE == domain_whitelist_query(pdomain)) {
		return MESSAGE_ACCEPT;
	}

	domain_len = strlen(pdomain);
	b_hint = FALSE;
	pthread_rwlock_rdlock(&g_reload_lock);
	item_size = list_file_get_item_num(g_ddns_list);
	pitem = (char*)list_file_get_list(g_ddns_list);
	for (i=0; i<item_size; i++) {
		len = strlen(pitem + 256*i);
		if ('.' != pdomain[domain_len - len - 1]) {
			continue;
		}
		if (0 == strcasecmp(pdomain + domain_len - len, pitem + 256*i)) {
			b_hint = TRUE;
			break;
		}
	}
	pthread_rwlock_unlock(&g_reload_lock);
	if (FALSE == b_hint) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (FALSE == check_retrying(pconnection->client_ip,
			pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {
			snprintf(reason, length, g_return_reason, pdomain);
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_DDNS_FILTER);
			}
			return MESSAGE_RETRYING;
		} else {
			return MESSAGE_ACCEPT;
		}
	}
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	LIST_FILE *plist, *plist_temp;
	char help_string[] = "250 ddns filter help information:\r\n"
				         "\t%s reload\r\n"
						 "\t    --reload the ddns list from file";
	
	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "reload")) {
		plist = list_file_init(g_listfile_name, "%s:256");
		if (NULL == plist) {
			strncpy(result, "550 ddns list file error", length);
			return;
		}
		pthread_rwlock_wrlock(&g_reload_lock);
		plist_temp = g_ddns_list;
		g_ddns_list = plist;
		pthread_rwlock_unlock(&g_reload_lock);
		list_file_free(plist_temp);
		strncpy(result, "250 ddns list reload OK", length);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

