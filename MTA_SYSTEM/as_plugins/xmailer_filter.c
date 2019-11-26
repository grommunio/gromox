#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "list_file.h"
#include "util.h"
#include <pthread.h>
#include <stdio.h>

#define SPAM_STATISTIC_XMAILER_FILTER		7

typedef struct _XMAILER_ITEM {
	char processing[16];
	char xmailer[256];
} XMAILER_ITEM;

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*WHITELIST_QUERY)(char*);
typedef BOOL (*OUTMAIL_LIMITATION_AUDIT)(char*);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);


static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
static CHECK_TAGGING check_tagging;
static WHITELIST_QUERY ip_whitelist_query;
static WHITELIST_QUERY domain_whitelist_query;
static OUTMAIL_LIMITATION_AUDIT outmail_limitation_audit;

DECLARE_API;

static LIST_FILE *g_xmailer_list;
static char g_listfile_name[256];
static char g_return_string[1024];
static pthread_rwlock_t g_reload_lock;

static int xmailer_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);

static void console_talk(int argc, char **argv, char *result, int length);

int AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;

    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		ip_whitelist_query = (WHITELIST_QUERY)query_service(
								"ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[xmailer_filter]: fail to get \"ip_whitelist_query\" "
				"service\n");
			return FALSE;
		}
		domain_whitelist_query = (WHITELIST_QUERY)query_service(
									"domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[xmailer_filter]: fail to get \"domain_whitelist_query\" "
					"service\n");
			return FALSE;
		}
		pthread_rwlock_init(&g_reload_lock, NULL);
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[xmailer_filter]: fail to get \"check_retrying\" "
					"service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[xmailer_filter]: fail to get \"check_tagging\" service\n");
			return FALSE;
		}
		outmail_limitation_audit = (OUTMAIL_LIMITATION_AUDIT)query_service(
				                    "outmail_limitation_audit");
		if (NULL == outmail_limitation_audit) {
			printf("[xmailer_filter]: fail to get "
					"\"outmail_limitation_audit\" service\n");
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
			printf("[xmailer_filter]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000007 please fill only \"email --not "
				"spam\" in your mail subject then try it again, thank you!");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[xmailer_filter]: return string is \"%s\"\n", g_return_string);
		config_file_free(pconfig_file);
		sprintf(g_listfile_name, "%s/%s.txt", get_data_path(), file_name);
		g_xmailer_list = list_file_init3(g_listfile_name, "%s:16%s:256", false);
        if (NULL == g_xmailer_list) {
			printf("[xmailer_filter]: list_file_init %s: %s\n",
				g_listfile_name, strerror(errno));
            return FALSE;
        }
        /* invoke register_auditor for registering auditor of mime head */
        if (FALSE == register_auditor(xmailer_filter)) {
			printf("[xmailer_filter]: failed to register auditor function\n");
            return FALSE;
        }
		register_talk(console_talk);
        return TRUE;
    case PLUGIN_FREE:
        if (NULL != g_xmailer_list) {
            list_file_free(g_xmailer_list);
        }
		pthread_rwlock_destroy(&g_reload_lock);
        return TRUE;
    }
    return TRUE;
}

static int xmailer_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
    int i, table_size;
	XMAILER_ITEM *items;
    char xmailer_buf[512];
	char buff[1024];
	char *pdomain;

	if (TRUE == pmail->penvelop->is_relay) {
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
	if (mem_file_get_total_length(&pmail->phead->f_xmailer) >
		sizeof(xmailer_buf) - 1) {
		return MESSAGE_ACCEPT;
	}
    if (MEM_END_OF_FILE == mem_file_read(&pmail->phead->f_xmailer,
        xmailer_buf, 512)) {
        return MESSAGE_ACCEPT;
    }
	pthread_rwlock_rdlock(&g_reload_lock);
	table_size = list_file_get_item_num(g_xmailer_list);
	items = (XMAILER_ITEM*)list_file_get_list(g_xmailer_list);
    for (i=0; i<table_size; i++) {
        if (NULL != strstr(xmailer_buf, items[i].xmailer)) {
			pthread_rwlock_unlock(&g_reload_lock);	
			memset(buff, 0, 1024);
			mem_file_read(&pmail->phead->f_subject, buff, 1023);
			if (NULL != search_string(buff, "not spam", 1024)) {
				return MESSAGE_ACCEPT;
			}
            strncpy(reason, g_return_string, length);
			if (0 == strcasecmp(items[i].processing, "M_RETRY")) {
				if (TRUE == pmail->penvelop->is_outbound) {
					if (FALSE == outmail_limitation_audit(pmail->penvelop->from)) {
						if (NULL != spam_statistic) {
							spam_statistic(SPAM_STATISTIC_XMAILER_FILTER);
						}
						return MESSAGE_REJECT;
					}
					return MESSAGE_ACCEPT;
				} else {
					if (TRUE == check_tagging(pmail->penvelop->from,
						&pmail->penvelop->f_rcpt_to)) {
						mark_context_spam(context_ID);
						return MESSAGE_ACCEPT;
					} else {
						if (FALSE == check_retrying(pconnection->client_ip,
							pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {
							if (NULL!= spam_statistic) {
								spam_statistic(SPAM_STATISTIC_XMAILER_FILTER);
							}
							return MESSAGE_RETRYING;
						} else {
							return MESSAGE_ACCEPT;
						}
					}
				}
			} else if (0 == strcasecmp(items[i].processing, "M_REJECT")) {
				if (TRUE == check_tagging(pmail->penvelop->from,
					&pmail->penvelop->f_rcpt_to)) {
					mark_context_spam(context_ID);
					return MESSAGE_ACCEPT;
				} else {
					if (NULL != spam_statistic) {
						spam_statistic(SPAM_STATISTIC_XMAILER_FILTER);
					}
					return MESSAGE_REJECT;
				}
			} else {
				return MESSAGE_ACCEPT;
			}
        }
    }
	pthread_rwlock_unlock(&g_reload_lock);	
    return MESSAGE_ACCEPT;
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	LIST_FILE *plist, *plist_temp;
	char help_string[] = "250 xmailer filter help information:\r\n"
			             "\t%s reload\r\n"
						 "\t    --reload the xmailer list from file";
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
		plist = list_file_init(g_listfile_name, "%s:16%s:256");
		if (NULL == plist) {
			strncpy(result, "550 xmailer list file error", length);
			return;
		}
		pthread_rwlock_wrlock(&g_reload_lock);
		plist_temp = g_xmailer_list;
		g_xmailer_list = plist;
		pthread_rwlock_unlock(&g_reload_lock);
		list_file_free(plist_temp);
		strncpy(result, "250 xmailer list reload OK", length);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

