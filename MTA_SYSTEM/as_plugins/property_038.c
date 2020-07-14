#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include "mail_func.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_038        75


typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int text_filter(int action, int context_ID, MAIL_BLOCK* mail_blk,
	char* reason, int length);

DECLARE_API;

static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
static CHECK_TAGGING check_tagging;

static char g_return_string[1024];

BOOL AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
	/* path contains the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[property_038]: failed to get service \"check_retrying\"\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_038]: failed to get service \"check_tagging\"\n");
			return FALSE;
		}
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init2(NULL, temp_path);
		if (NULL == pconfig_file) {
			printf("[property_038]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000075 you are now sending spam mail!");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[property_038]: return string is \"%s\"\n", g_return_string);
		config_file_free(pconfig_file);

		if (FALSE == register_filter("text/plain", text_filter)) {
			return FALSE;
		}
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
    return TRUE;
}

static int text_filter(int action, int context_ID, MAIL_BLOCK* mail_blk,
	char* reason, int length)
{
	int read_length, size;
	BOOL charset_found;
	CONNECTION *pconnection;
	MAIL_ENTITY mail_entity;
	char buff[1024], *ptr, *ptr1;

	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		mail_entity = get_mail_entity(context_ID);
		if (TRUE == mail_entity.penvelop->is_outbound ||
			TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}

		charset_found = FALSE;
		while (MEM_END_OF_FILE != mem_file_read(mail_blk->fp_mime_info,
			&read_length, sizeof(int))) {
			mem_file_read(mail_blk->fp_mime_info, buff, read_length);
			buff[read_length] = '\0';
			mem_file_read(mail_blk->fp_mime_info, &size, sizeof(int));
			if (12 == read_length &&
				0 == strncasecmp(buff, "Content-Type", 12)) {
				if (size > 1023) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(mail_blk->fp_mime_info, buff, size);
				if (NULL != search_string(buff, "koi8-r", size) ||
					NULL != search_string(buff, "windows-1251", size)) {
					charset_found = TRUE;
					break;
				} else {
					return MESSAGE_ACCEPT;
				}
			} else {
				mem_file_seek(mail_blk->fp_mime_info, MEM_FILE_READ_PTR,
					size, MEM_FILE_SEEK_CUR);
			}
		}

		if (FALSE == charset_found) {
			return MESSAGE_ACCEPT;
		}
		
		if (TRUE == mail_blk->is_parsed) {
			ptr = (char*)mail_blk->parsed_buff;
			size = mail_blk->parsed_length;
		} else {
			ptr = (char*)mail_blk->original_buff;
			size = mail_blk->original_length;
		}

		if (size < 5000 && NULL != search_string(ptr, ".\xd2\xc6", size)) {
			if (TRUE == check_tagging(mail_entity.penvelop->from,
				&mail_entity.penvelop->f_rcpt_to)) {
				mark_context_spam(context_ID);
				return MESSAGE_ACCEPT;
			} else {
				pconnection = get_connection(context_ID);
				if (FALSE == check_retrying(pconnection->client_ip,
					mail_entity.penvelop->from,
					&mail_entity.penvelop->f_rcpt_to)) {
					if (NULL != spam_statistic) {
						spam_statistic(SPAM_STATISTIC_PROPERTY_038);
					}
					strncpy(reason, g_return_string, length);
					return MESSAGE_RETRYING;
				}
			}
		}
		
		ptr1 = ptr;
		if (NULL != (ptr = search_string(ptr1, "495", size)) ||
			NULL != (ptr = search_string(ptr1, "499", size))) {
			if (('(' == *(ptr - 1) && ')' == *(ptr + 3)) ||
				('/' == *(ptr - 1) && '/' == *(ptr + 3)) ||
				('[' == *(ptr - 1) && ']' == *(ptr + 3)) ||
				(('+' == *(ptr - 1) || '-' == *(ptr - 1) || '\n' == *(ptr - 1) ||
				'~' == *(ptr - 1) || '#' == *(ptr - 1) || ' ' == *(ptr - 1)) &&
				('+' == *(ptr + 3) || '-' == *(ptr + 3) || '~' == *(ptr + 3) ||
				'#' == *(ptr + 3) || ' ' == *(ptr + 3)))) {
				if (TRUE == check_tagging(mail_entity.penvelop->from,
					&mail_entity.penvelop->f_rcpt_to)) {
					mark_context_spam(context_ID);
					return MESSAGE_ACCEPT;
				} else {
					pconnection = get_connection(context_ID);
					if (FALSE == check_retrying(pconnection->client_ip,
						mail_entity.penvelop->from,
						&mail_entity.penvelop->f_rcpt_to)) {
						if (NULL != spam_statistic) {
							spam_statistic(SPAM_STATISTIC_PROPERTY_038);
						}
						strncpy(reason, g_return_string, length);
						return MESSAGE_RETRYING;
					}
				}
			}
		}
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}

