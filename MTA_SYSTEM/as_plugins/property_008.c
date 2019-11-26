#include <errno.h>
#include <gromox/as_common.h>
#include "util.h"
#include "mem_file.h"
#include "config_file.h"
#include "mail_func.h"
#include <stdio.h>
#include <string.h>

#define SPAM_STATISTIC_PROPERTY_008          32

enum{
	XMAILER_NONE,
	XMAILER_OTHER,
	XMAILER_OUTLOOK_EXPRESS,
	XMAILER_NETSCAPE_CLASS,
	XMAILER_MICROSOFT_CLASS
};

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
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
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[property_008]: fail to get \"check_retrying\" service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_008]: fail to get \"check_tagging\" service\n");
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
			printf("[property_008]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000032 please append \"--not spam\" at "
				"the end of mail subject then try it again, thank you!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_008]: return string is \"%s\"\n", g_return_reason);
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
	char *purl;
	int i, len;
	int tag_len;
	int val_len;
	BOOL b_charset;
	BOOL b_caseID;
	BOOL b_netscape;
	BOOL b_microsoft;
	int xmailer_type;
	MAIL_ENTITY mail_entity;
	CONNECTION *pconnection;
	char tag_val[1024], buff[1024];

	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		mail_entity	= get_mail_entity(context_ID);
		if (MULTI_PARTS_MAIL == mail_entity.phead->mail_part) {
			return MESSAGE_ACCEPT;
		}
		if (TRUE == mail_entity.penvelop->is_outbound ||
			TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}
		
		memset(buff, 0, 1024);
		if (MEM_END_OF_FILE != mem_file_read(&mail_entity.phead->f_xmailer,
			buff, 1024)) {
			if (0 == strncasecmp(buff, "Microsoft Outlook Express", 25)) {
				xmailer_type = XMAILER_OUTLOOK_EXPRESS;
			} else if (0 == strncasecmp(buff, "Microsoft", 9)) {
				xmailer_type = XMAILER_MICROSOFT_CLASS;
			} else if (NULL != search_string(buff, "Netscape", 1024) ||
				NULL != search_string(buff, "Thunderbird", 1024) ||
				NULL != search_string(buff, "Mozilla", 1024)) {
				xmailer_type = XMAILER_NETSCAPE_CLASS;
			} else {
				xmailer_type = XMAILER_OTHER;
			}
		} else {
			xmailer_type = XMAILER_NONE;
		}
		b_charset = FALSE;
		b_caseID = FALSE;
		b_microsoft = FALSE;
		b_netscape = FALSE;
		while (MEM_END_OF_FILE != mem_file_read(mail_blk->fp_mime_info,
			&tag_len, sizeof(int))) {
			if (25 == tag_len) {
				mem_file_read(mail_blk->fp_mime_info, tag_val, tag_len);
				if (0 == strncasecmp("Content-Transfer-Encoding",
					tag_val, 25)) {
					mem_file_read(mail_blk->fp_mime_info, &val_len,sizeof(int));
					if (val_len > 1023) {
						return MESSAGE_REJECT;
					}
					mem_file_read(mail_blk->fp_mime_info, buff, val_len);
					if (0 != strncasecmp("7bit", buff, 4) &&
						0 != strncasecmp("8bit", buff, 4) &&
						(XMAILER_NONE == xmailer_type &&
						0 != strncasecmp("quoted-printable", buff, 16))) {
						return MESSAGE_ACCEPT;
					}
					continue;
				}
			} else if (12 == tag_len) {
				mem_file_read(mail_blk->fp_mime_info, tag_val, tag_len);
				if (0 == strncasecmp("Content-Type", tag_val, 12)) {
					mem_file_read(mail_blk->fp_mime_info ,&val_len,sizeof(int));
					if (val_len > 1023) {
						return MESSAGE_REJECT;
					}
					mem_file_read(mail_blk->fp_mime_info, buff, val_len);
					if (NULL != strstr(buff, "us-ascii") ||
						NULL != strcasestr(buff, "UTF-8") ||
						NULL != strcasestr(buff, "iso-8859-1") ||
						NULL != strcasestr(buff, "windows-125") ||
						NULL != strcasestr(buff, "koi8-r")) {
						b_charset = TRUE;
						continue;
					}else {
						return MESSAGE_ACCEPT;
					}
				}
			} else if (10 == tag_len) {
				mem_file_read(mail_blk->fp_mime_info, tag_val, tag_len);
				if (0 == strncasecmp("Message-ID", tag_val, 10)) {
					if (0 != strncmp("Message-ID", tag_val, 10)) {
						b_caseID = TRUE;
					}
					mem_file_read(mail_blk->fp_mime_info, &val_len,sizeof(int));
					if (val_len > 1023) {
						return MESSAGE_REJECT;
					}
					mem_file_read(mail_blk->fp_mime_info, buff, val_len);
					if (val_len > 20 && '.' == buff[9] && '@' == buff[17]) {
						for (i=1; i<9; i++) {
							if ((buff[i] >= '0' && buff[i] <= '9') ||
								(buff[i] >= 'A' && buff[i] <= 'F')) {
								continue;
							} else {
								goto FIELD_LOOP; 
							}
						}
						for (i=10; i<17; i++) {
							if ((buff[i] >= '0' && buff[i] <= '9') ||
								(buff[i] >= 'A' && buff[i] <= 'F')) {
								continue;
							} else {
								goto FIELD_LOOP; 
							}
						}
						b_netscape = TRUE;
					} else if (val_len > 34 && '$' == buff[13] &&
						'$' == buff[22] && '@' == buff[31]) {
						for (i=1; i<13; i++) {
							if ((buff[i] >= '0' && buff[i] <= '9') ||
								(buff[i] >= 'a' && buff[i] <= 'f')) {
								continue;
							} else {
								goto FIELD_LOOP;
							}
						}
						for (i=14; i<22; i++) {
							if ((buff[i] >= '0' && buff[i] <= '9') ||
								(buff[i] >= 'a' && buff[i] <= 'f')) {
								continue;
							} else {
								goto FIELD_LOOP;
							}
						}
						for (i=23; i<31; i++) {
							if ((buff[i] >= '0' && buff[i] <= '9') ||
								(buff[i] >= 'a' && buff[i] <= 'f')) {
								continue;
							} else {
								goto FIELD_LOOP;
							}
						}
						b_microsoft = TRUE;
					}
FIELD_LOOP:
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
		if (FALSE == b_charset) {
			return MESSAGE_ACCEPT;
		}
		purl = find_url((char*)mail_blk->original_buff,
				mail_blk->original_length, &len);
		if (NULL != purl) {
			if (NULL != search_string(purl, "w3.org", len) ||
				NULL != search_string(purl, "w3c.org", len) ||
				NULL != search_string(purl, "internet.email", len) ||
				NULL != search_string(purl, "yahoo.com", len) ||
				NULL != search_string(purl, "msn.com", len) ||
				NULL != search_string(purl, "aol.com", len) ||
				NULL != search_string(purl, "aim.com", len)) {
				return MESSAGE_ACCEPT;
			}
		} else {
			if (NULL == search_string(
				mail_blk->original_buff, ".ru",
				mail_blk->original_length)) {
				return MESSAGE_ACCEPT;
			}
		}
		memset(buff, 0, 1024);
		mem_file_read(&mail_entity.phead->f_subject, buff, 1023);
		if (NULL != search_string(buff, "not spam", 1024)) {
			return MESSAGE_ACCEPT;
		}
		switch (xmailer_type) {
		case XMAILER_NONE:
			goto SPAM_MAIL;
		case XMAILER_OTHER:
			if (TRUE == b_netscape || TRUE == b_microsoft) {
				goto SPAM_MAIL;
			} else {
				return MESSAGE_ACCEPT;
			}
		case XMAILER_OUTLOOK_EXPRESS:
			goto SPAM_MAIL;
		case XMAILER_MICROSOFT_CLASS:
			if (TRUE == b_caseID || FALSE == b_microsoft) {
				goto SPAM_MAIL;
			} else {
				return MESSAGE_ACCEPT;
			}
		case XMAILER_NETSCAPE_CLASS:
			if (TRUE == b_caseID || TRUE == b_microsoft) {
				goto SPAM_MAIL;
			} else {
				return MESSAGE_ACCEPT;
			}
		}
		return MESSAGE_ACCEPT;
		
SPAM_MAIL:
		if (TRUE == check_tagging(mail_entity.penvelop->from,
			&mail_entity.penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			pconnection = get_connection(context_ID);
			if (FALSE == check_retrying(pconnection->client_ip,
				mail_entity.penvelop->from, 
				&mail_entity.penvelop->f_rcpt_to)) {
				strncpy(reason, g_return_reason, length);
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_PROPERTY_008);
				}
				return MESSAGE_RETRYING;
			}
		}
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}

