#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "mem_file.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_BASE64_ENCODING          47


typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int paragraph_filter(int action, int context_ID, MAIL_BLOCK* mail_blk, 
	char* reason, int length);

BOOL AS_LibMain(int reason, void **ppdata)
{	
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[base64_encoding]: failed to get service \"check_retrying\"\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[base64_encoding]: failed to get service \"check_tagging\"\n");
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
			printf("[base64_encoding]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000047 base64 encoding of mail content"
				"error, please try later!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[base64_encoding]: return string is \"%s\"\n", g_return_reason);
		config_file_free(pconfig_file);
		/* invoke register_filter for registering all type of mime paragraph*/
		if (FALSE == register_filter(NULL, paragraph_filter)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}

static int paragraph_filter(int action, int context_ID, MAIL_BLOCK* mail_blk, 
	char* reason, int length)
{
	BOOL b_base64;
	char buff[1024];
	int size, read_length;
	CONNECTION *pconnection;
	MEM_FILE *fp_mime_field;
	MAIL_ENTITY mail_entity;

	b_base64 = FALSE;
	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		if (TRUE == mail_blk->is_parsed) {
			return MESSAGE_ACCEPT;
		}
		mail_entity	= get_mail_entity(context_ID);
		if (TRUE == mail_entity.penvelop->is_outbound ||
			TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}
		fp_mime_field = mail_blk->fp_mime_info;
		while (MEM_END_OF_FILE != mem_file_read(fp_mime_field, &read_length,
			sizeof(int))) {
			mem_file_read(fp_mime_field, buff, read_length);
			buff[read_length] = '\0';
			mem_file_read(fp_mime_field, &size, sizeof(int));
			if (25 == read_length && 0 == strncasecmp(buff, 
				"Content-Transfer-Encoding", 25)) {
				if (size > 1023) {
					return MESSAGE_REJECT;
				}
				mem_file_read(fp_mime_field, buff, size);
				buff[size] = '\0';
				if (0 == strncasecmp(buff, "base64", 4)) {
					b_base64 = TRUE;
					break;
				} else {
					return MESSAGE_ACCEPT;
				}
			} else {
				mem_file_seek(fp_mime_field, MEM_FILE_READ_PTR,
				size, MEM_FILE_SEEK_CUR);
			}
		}
		if (FALSE == b_base64) {
			return MESSAGE_ACCEPT;
		}
		
		if (TRUE == check_tagging(mail_entity.penvelop->from,
			&mail_entity.penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			pconnection = get_connection(context_ID);
			if (FALSE == check_retrying(pconnection->client_ip,
				mail_entity.penvelop->from, &mail_entity.penvelop->f_rcpt_to)) {
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_BASE64_ENCODING);
				}
				strncpy(reason, g_return_reason, length);
				return MESSAGE_RETRYING;
			} else {
				return MESSAGE_ACCEPT;
			}
		}
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}

