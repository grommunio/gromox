#include <gromox/as_common.h>
#include "util.h"
#include "config_file.h"
#include <stdio.h>
#define SPAM_STATISTIC_PROPERTY_005		29

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);

int AS_LibMain(int reason, void **ppdata)
{	
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
	switch (reason) {
	case PLUGIN_INIT:

		LINK_API(ppdata);

		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_005]: fail to get \"check_tagging\" service\n");
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
			printf("[property_005]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000029 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_005]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		if (FALSE == register_auditor(head_filter)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}


static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	char *ptr;
	int out_len;
	int tag_len;
	int val_len;
	char buff[1024];
	char xmailer[1024];
	char messageid[1024];

	
	if (TRUE == pmail->penvelop->is_relay ||
		TRUE == pmail->penvelop->is_outbound) {
		return MESSAGE_ACCEPT;
	}

	out_len = mem_file_read(&pmail->phead->f_xmailer, xmailer, 1024);
	if (MEM_END_OF_FILE == out_len) {
		out_len = 0;
	}
	xmailer[out_len] = '\0';


	messageid[0] = '\0';
	while (MEM_END_OF_FILE != mem_file_read(&pmail->phead->f_others,
		&tag_len, sizeof(int))) {
		if (10 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("Message-ID", buff, 10)) {
				mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
				if (val_len >= 1024) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others, buff, val_len);
				if ('<' == buff[0] && '>' == buff[val_len - 1]) {
					memcpy(messageid, buff + 1, val_len - 2);
					messageid[val_len - 2] = '\0';
				} else {
					memcpy(messageid, buff, val_len);
					messageid[val_len] = '\0';
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

	if ('\0' == messageid[0]) {
		return MESSAGE_ACCEPT;
	}

	ptr = strrchr(messageid, '@');
	if (NULL != ptr && '0' == messageid[0] && '.' == messageid[1] &&
		'0' == messageid[2] && '.' == messageid[3]) {
		goto SPAM_FOUND;
	}

	/* Message-ID like 9175501272_5501272.5501272.yanfeng@suotex.com845v */
	if ('\0' == xmailer[0]) {
		out_len = mem_file_readline(&pmail->penvelop->f_rcpt_to, buff, 256);
		if (out_len != MEM_END_OF_FILE) {
			buff[out_len] = '\0';
			if (NULL != (ptr = strstr(messageid, buff)) &&
				messageid + strlen(messageid) - (ptr + out_len) >= 2) {
				goto SPAM_FOUND;
			}
		}
	}
	return MESSAGE_ACCEPT;

SPAM_FOUND:
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_005);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}
	
}

