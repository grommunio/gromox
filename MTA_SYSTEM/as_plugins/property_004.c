#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "util.h"
#include "mem_file.h"
#include "config_file.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_004          28

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int xmailer_filter(int action, int context_ID, MAIL_BLOCK* mail_blk, 
	char* reason, int length);

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
			printf("[property_004]: fail to get \"check_tagging\" service\n");
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
			printf("[property_004]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000028 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_004]: return string is \"%s\"\n", g_return_reason);
		config_file_free(pconfig_file);
		/* invoke register_filter for registering all type of mime paragraph*/
		if (FALSE == register_filter("text/plain" , xmailer_filter) ||
			FALSE == register_filter("text/html" , xmailer_filter)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}

static int xmailer_filter(int action, int context_ID, MAIL_BLOCK* mail_blk, 
	char* reason, int length)
{
	char *pbuff;
	MAIL_ENTITY mail_entity;

	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		mail_entity	= get_mail_entity(context_ID);
		
		if (TRUE == mail_entity.penvelop->is_outbound ||
			TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}
		
		if (MULTI_PARTS_MAIL == mail_entity.phead->mail_part) {
			return MESSAGE_ACCEPT;
		}

		pbuff = (char*)mail_blk->original_buff;
		if (0 != strncasecmp(pbuff, "RSET\r\n", 6) &&
			0 != strncasecmp(pbuff, "QUIT\r\n", 6) &&
			NULL == search_string(pbuff, "Received: ", 256) &&
			NULL == search_string(pbuff, "X-Mailer: ", 256) && 
			NULL == search_string(pbuff, "User-Agent: ", 256) &&
			NULL == search_string(pbuff, "Message-ID: ", 256) &&
			NULL == search_string(pbuff, "MIME-Version: ", 256) &&
			NULL == search_string(pbuff, "X-Priority: ", 256) &&
			NULL == search_string(pbuff, "Content-Type: ", 256) &&
			NULL == search_string(pbuff, "Content-Transfer-Encoding: ", 256)) {
			return MESSAGE_ACCEPT;
		}
		if (TRUE == check_tagging(mail_entity.penvelop->from,
			&mail_entity.penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_PROPERTY_004);
			}
			strncpy(reason, g_return_reason, length);
			return MESSAGE_REJECT;
		}
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}

