#include <errno.h>
#include <stdbool.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include "mail_func.h"
#include <string.h>
#include <stdio.h>


#define HTML_CONTENT	" name=GENERATOR></HEAD>\r\n<BODY></BODY></HTML>"


#define SPAM_STATISTIC_PROPERTY_035		72


typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

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
			printf("[property_035]: fail to get \"check_tagging\" service\n");
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
			printf("[property_035]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000072 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_035]: return string is \"%s\"\n", g_return_reason);
		config_file_free(pconfig_file);
		if (FALSE == register_filter("text/html", html_filter)) {
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
	return false;
}


static int html_filter(int action, int context_ID, MAIL_BLOCK *pblock,
    char *reason, int length)
{
	BOOL b_messid;
	int i, out_len;
	int tag_len, val_len;
	MAIL_ENTITY mail_entity;
	char *pat, buff[1024];
	
	switch (action) {
    case ACTION_BLOCK_NEW:
        return MESSAGE_ACCEPT;
    case ACTION_BLOCK_PROCESSING:
		mail_entity = get_mail_entity(context_ID);
		
		if (TRUE == mail_entity.penvelop->is_outbound ||
			TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}

		out_len = mem_file_read(&mail_entity.phead->f_xmailer, buff, 1024);
		if (MEM_END_OF_FILE == out_len) {
			return MESSAGE_ACCEPT;
		}

		if (0 != strncasecmp(buff, "Microsoft Outlook Express", 25)) {
			return MESSAGE_ACCEPT;
		}

		out_len = mem_file_read(&mail_entity.phead->f_content_type, buff, 1024);
		if (MEM_END_OF_FILE == out_len) {   /* no content type */
			return MESSAGE_ACCEPT;
		}
		if (0 != strncasecmp(buff, "multipart/mixed;", 16)) {
			return MESSAGE_ACCEPT;
		}

		b_messid = FALSE;

		while (MEM_END_OF_FILE != mem_file_read(&mail_entity.phead->f_others,
			&tag_len,  sizeof(int))) {
			if (10 == tag_len) {
				mem_file_read(&mail_entity.phead->f_others, buff, tag_len);
				if (0 == strncasecmp("Message-ID", buff, 10)) {
					mem_file_read(&mail_entity.phead->f_others, &val_len,
						sizeof(int));
					if (val_len > 50 || val_len < 35) {
						return MESSAGE_ACCEPT;
					}
					mem_file_read(&mail_entity.phead->f_others, buff, val_len);
					buff[val_len] = '\0';
					if ('<' != buff[0] || '>' != buff[val_len - 1]) {
						return MESSAGE_ACCEPT;
					}
					buff[val_len - 1] = '\0';
					pat = strrchr(buff, '@');
					if (NULL == pat || pat - buff != 33) {
						return MESSAGE_ACCEPT;
					}
					for (i=1; i<33; i++) {
						if (('0' <= buff[i] && buff[i] <= '9') ||
							('A' <= buff[i] && buff[i] <= 'F')) {
							continue;
						}
						return MESSAGE_ACCEPT;
					}

					b_messid = TRUE;
					break;
				}
			} else {
				mem_file_seek(&mail_entity.phead->f_others, MEM_FILE_READ_PTR,
					tag_len, MEM_FILE_SEEK_CUR);
			}
			mem_file_read(&mail_entity.phead->f_others, &val_len, sizeof(int));
			mem_file_seek(&mail_entity.phead->f_others, MEM_FILE_READ_PTR,
				val_len, MEM_FILE_SEEK_CUR);
		}


		if (FALSE == b_messid || FALSE == pblock->is_parsed) {
			return MESSAGE_ACCEPT;
		}
		
		if (pblock->parsed_length > 300 || pblock->parsed_length < 200) {
			return MESSAGE_ACCEPT;
		}
		
		if (NULL == strstr(pblock->parsed_buff, HTML_CONTENT)) {
			return MESSAGE_ACCEPT;
		}
		if (TRUE == check_tagging(mail_entity.penvelop->from,
			&mail_entity.penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_PROPERTY_035);
			}
			strncpy(reason, g_return_reason, length);
			return MESSAGE_REJECT;
		}
    case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
    }
	return MESSAGE_ACCEPT;
}

