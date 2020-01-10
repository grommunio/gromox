#include <errno.h>
#include <string.h>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#define SPAM_STATISTIC_PROPERTY_045          82

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
	char file_name[256];
	char temp_path[256];
	char *str_value, *psearch;
	CONFIG_FILE *pconfig_file;
	
	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_045]: failed to get service \"check_tagging\"\n");
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
			printf("[property_045]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000082 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_045]: return string is \"%s\"\n", g_return_reason);
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
	int i, tmp_len;
	char buff[1024];
	char buff1[1024];

	if (TRUE == pmail->penvelop->is_relay ||
		TRUE == pmail->penvelop->is_outbound) {
		return MESSAGE_ACCEPT;
	}

	if (0 != mem_file_get_total_length(&pmail->phead->f_xmailer)) {
		return MESSAGE_ACCEPT;
	}

	if (MEM_END_OF_FILE == mem_file_readline(&pmail->penvelop->f_rcpt_to,
		buff, 256)) {
		return MESSAGE_ACCEPT;
	}

	tmp_len = mem_file_read(&pmail->phead->f_mime_to, buff1, 1024);
	if (MEM_END_OF_FILE == tmp_len) {
		return MESSAGE_ACCEPT;
	}
	buff1[tmp_len] = '\0';
	HX_strrtrim(buff1);
	HX_strltrim(buff1);
	if (0 != strcmp(buff, buff1)) {
		return MESSAGE_ACCEPT;
	}

	tmp_len = mem_file_read(&pmail->phead->f_content_type, buff, 1024);
	if (MEM_END_OF_FILE == tmp_len) {
		return MESSAGE_ACCEPT;
	}

	if (NULL == (ptr = search_string(buff, "boundary=\"", tmp_len))) {
		return MESSAGE_ACCEPT;
	}

	ptr += 10;
	for (i=0; i<20; i++) {
		if ('=' != ptr[i]) {
			break;
		}
	}

	if (i < 12 || i > 16) {
		return MESSAGE_ACCEPT;
	}

	ptr += i;
	for (i=0; i<22; i++) {
		if (!HX_isdigit(ptr[i]))
			break;
	}
	
	if (i < 16 || i> 22) {
		return MESSAGE_ACCEPT;
	}

	if (0 != strncmp(ptr + i, "==\"", 3)) {
		return MESSAGE_ACCEPT;
	}

	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_045);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}

}

