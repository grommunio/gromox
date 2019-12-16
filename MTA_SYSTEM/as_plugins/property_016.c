#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#define OFFICE_XMAILER					1
#define WEBMAIL_XMAILER					2
#define SPAM_STATISTIC_PROPERTY_016		45

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*WHITELIST_QUERY)(char*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int head_auditor(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);

DECLARE_API;

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
		domain_whitelist_query = (WHITELIST_QUERY)query_service(
									"domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[property_016]: fail to get \"domain_whitelist_query\" "
					"service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_016]: fail to get \"check_tagging\" service\n");
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
			printf("[property_016]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000045 you are now sending spam mail!");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[property_016]: return string is \"%s\"\n", g_return_string);
		config_file_free(pconfig_file);

        /* invoke register_auditor for registering auditor of mime head */
        if (FALSE == register_auditor(head_auditor)) {
			printf("[property_016]: failed to register auditor function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
    return TRUE;
}

static int head_auditor(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection,  char *reason, int length)
{
	BOOL b_unlst;
	char *pdomain;
    char buff[1024];
	int tag_len, val_len;

	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	
	pdomain = strchr(pmail->penvelop->from, '@');
	pdomain ++;
	if (TRUE == domain_whitelist_query(pdomain)) {
		return MESSAGE_ACCEPT;
	}
	
	if (0 != mem_file_get_total_length(&pmail->phead->f_xmailer)) {
        return MESSAGE_ACCEPT;
    }

	b_unlst = FALSE;
	
	while (MEM_END_OF_FILE != mem_file_read(&pmail->phead->f_others,
		&tag_len, sizeof(int))) {
		if (16 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("List-Unsubscribe", buff, 16)) {
				mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
				if (val_len > 1024) {
					b_unlst = TRUE;
				} else {
					mem_file_read(&pmail->phead->f_others, buff, val_len);
					buff[val_len] = '\0';
					if (NULL == search_string(buff, "http", val_len)) {
						b_unlst = TRUE;
					} else {
						if (NULL != strstr(buff, "/U/")) {
							b_unlst = TRUE;
						}
					}
				}
				break;
			}
		} else {
			mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR,
				tag_len, MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR, val_len,
			MEM_FILE_SEEK_CUR);
	}

	if (FALSE == b_unlst) {
		return MESSAGE_ACCEPT;
	}

	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		strncpy(reason, g_return_string, length);
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_016);
		}
		return MESSAGE_REJECT;
	}

}

