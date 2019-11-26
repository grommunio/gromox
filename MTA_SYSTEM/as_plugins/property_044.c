#include <libHX/ctype_helper.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "mail_func.h"
#include "util.h"
#include <stdio.h>
#define SPAM_STATISTIC_PROPERTY_044        81


typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int xmailer_filter(int action, int context_ID, MAIL_BLOCK* mail_blk, 
	char* reason, int length);

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
			printf("[property_044]: fail to get \"check_tagging\" service\n");
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
			printf("[property_044]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000081 you are now sending spam mail!");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[property_044]: return string is %s\n", g_return_string);
		config_file_free(pconfig_file);
		if (FALSE == register_filter("text/html", xmailer_filter) ||
			FALSE == register_filter("text/plain", xmailer_filter)) {
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
	int out_len;
	int tag_len;
	int val_len;
	BOOL b_encoding;
	char buff[1024];
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

		if (0 != mem_file_get_total_length(&mail_entity.phead->f_xmailer)) {
			out_len = mem_file_read(&mail_entity.phead->f_xmailer, buff, 1024);
			if (out_len < 16 || ('_' != buff[6] && '_' != buff[7]) ||
			    !HX_isdigit(buff[0]) || !HX_isdigit(buff[1]) ||
			    !HX_isdigit(buff[2]) || !HX_isdigit(buff[3]) ||
			    !HX_isdigit(buff[4]) || !HX_isdigit(buff[5]))
				return MESSAGE_ACCEPT;
		}
		
		out_len = mem_file_read(&mail_entity.phead->f_content_type, buff, 1024);
		
		if (MEM_END_OF_FILE == out_len) {
			return MESSAGE_ACCEPT;
		}
		if (MULTI_PARTS_MAIL == mail_entity.phead->mail_part) {
			if (88 != out_len || '_' != buff[86] || 0 != strncmp(buff,
				"multipart/alternative; boundary=\"_NextPart_", 43)) {
				return MESSAGE_ACCEPT;		
			}
		} else {
			if (0 != strncmp(buff, "text/html; charset=us-ascii", 27) &&
				0 != strncmp(buff, "text/html; charset=\"us-ascii\"", 29) &&
				0 != strncmp(buff, "text/plain; charset=us-ascii", 28) &&
				0 != strncmp(buff, "text/plain; charset=\"us-ascii\"", 30) &&
				0 != strncmp(buff, "text/html; charset=utf-8", 24) &&
				0 != strncmp(buff, "text/html; charset=\"utf-8\"", 26) &&
				0 != strncmp(buff, "text/plain; charset=utf-8", 25) &&
				0 != strncmp(buff, "text/plain; charset=\"utf-8\"", 27)) {
				return MESSAGE_ACCEPT;
			}
		}

		b_encoding = FALSE;

		while (MEM_END_OF_FILE != mem_file_read(mail_blk->fp_mime_info,
			&tag_len, sizeof(int))) {
			if (25 == tag_len) {
				mem_file_read(mail_blk->fp_mime_info, buff, tag_len);
				if (0 == strncmp("Content-Transfer-Encoding", buff, 25)) {
					mem_file_read(mail_blk->fp_mime_info, &val_len,
						sizeof(int));
					if (val_len != 4) {
						return MESSAGE_ACCEPT;
					}
					mem_file_read(mail_blk->fp_mime_info, buff, 4);
					if (0 != strncmp(buff, "8bit", 4) &&
						0 != strncmp(buff, "7bit", 4)) {
						return MESSAGE_ACCEPT;
					}
					b_encoding = TRUE;
					continue;
				}
			} else if (8 == tag_len) {
				mem_file_read(mail_blk->fp_mime_info, buff, tag_len);
				if (0 == strncasecmp("Received", buff, 8)) {
					mem_file_read(mail_blk->fp_mime_info, &val_len,
						sizeof(int));
					if (val_len > 1024) {
						return MESSAGE_ACCEPT;
					}
					mem_file_read(mail_blk->fp_mime_info, buff, val_len);
					if (NULL == search_string(buff, "PowerMTA(TM)", val_len)) {
						return MESSAGE_ACCEPT;
					}
					continue;
				}
			} else {
				mem_file_seek(mail_blk->fp_mime_info, MEM_FILE_READ_PTR,
					tag_len, MEM_FILE_SEEK_CUR);
			}
			mem_file_read(mail_blk->fp_mime_info, &val_len, sizeof(int));
			mem_file_seek(mail_blk->fp_mime_info, MEM_FILE_READ_PTR, val_len,
				MEM_FILE_SEEK_CUR);
		}
		if (FALSE == b_encoding) {
			return MESSAGE_ACCEPT;
		}

		if (NULL == find_url((char*)mail_blk->original_buff,
						mail_blk->original_length, &out_len)) {
			return MESSAGE_ACCEPT;
		}

		
		if (TRUE == check_tagging(mail_entity.penvelop->from,
			&mail_entity.penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_PROPERTY_044);
			}
			strncpy(reason, g_return_string, length);
			return MESSAGE_REJECT;
		}
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}

