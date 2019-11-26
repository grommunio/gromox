#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include "mail_func.h"
#include <ctype.h>
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_039        76

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
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
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_039]: fail to get \"check_tagging\" service\n");
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
			printf("[property_039]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000076 you are now sending spam mail!");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[property_039]: return string is %s\n", g_return_string);
		config_file_free(pconfig_file);
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
	int out_len;
	int type_len;
	size_t body_len;
	char buff[1024];
	char content_type[256];
	   
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}

	out_len = mem_file_read(&pmail->phead->f_xmailer, buff, 1024);
	if (MEM_END_OF_FILE == out_len) {   /* no content type */
		return MESSAGE_ACCEPT;
	}
	if (0 != strncasecmp(buff, "Microsoft Outlook, Build ", 25)) {
		return MESSAGE_ACCEPT;
	}

	
	if (MEM_END_OF_FILE == mem_file_read(&pmail->pbody->f_mail_parts,
		&type_len, sizeof(int))) {
		return MESSAGE_ACCEPT;
	}
	mem_file_read(&pmail->pbody->f_mail_parts, content_type, type_len);
	content_type[type_len] = '\0';
	mem_file_read(&pmail->pbody->f_mail_parts, &body_len, sizeof(size_t));
	if (0 != strncasecmp("text/plain", content_type, 10) || body_len > 8) {
		return MESSAGE_ACCEPT;
	}
	
	if (MEM_END_OF_FILE == mem_file_read(&pmail->pbody->f_mail_parts,
		&type_len, sizeof(int))) {
		return MESSAGE_ACCEPT;
	}
	mem_file_read(&pmail->pbody->f_mail_parts, content_type, type_len);
	content_type[type_len] = '\0';
	mem_file_read(&pmail->pbody->f_mail_parts, &body_len, sizeof(size_t));
	if (0 != strncasecmp("image/", content_type, 6)) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		strncpy(reason, g_return_string, length);
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_039);
		}
		return MESSAGE_REJECT;
	}
}

