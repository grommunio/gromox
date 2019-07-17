#include "as_common.h"
#include "util.h"
#include "mem_file.h"
#include "config_file.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_002          15

enum {
	GB2312_FOUND,
	IGNORE_FOUND,
	NONE_FOUND
};

enum {
	PROPERTY_NONE,
	PROPERTY_HEAD,
	PROPERTY_IGNORE
};

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*OUTMAIL_LIMITATION_AUDIT)(char*);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
static CHECK_TAGGING check_tagging;
static OUTMAIL_LIMITATION_AUDIT outmail_limitation_audit;

DECLARE_API;

static int *g_context_list;

static char g_return_reason[1024];

static int check_subject(MEM_FILE *pfile);

static BOOL check_8bit(MEM_FILE *pfile);

static int gb2312_filter(int action, int context_ID, MAIL_BLOCK *mail_blk, 
	char *reason, int length);

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop,
	CONNECTION *pconnection, char *reason, int length);

int AS_LibMain(int reason, void **ppdata)
{	
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;

	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[property_002]: fail to get \"check_retrying\" service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_002]: fail to get \"check_tagging\" service\n");
			return FALSE;
		}
		outmail_limitation_audit = (OUTMAIL_LIMITATION_AUDIT)query_service(
									"outmail_limitation_audit");
		if (NULL == outmail_limitation_audit) {
			printf("[property_002]: fail to get "
				"\"outmail_limitation_audit\" service\n");
			return FALSE;
		}
		g_context_list = malloc(get_context_num()*sizeof(int));
		if (NULL == g_context_list) {
			printf("[property_002]: fail to allocate context list memory\n");
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
			printf("[property_002]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000015 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_002]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		if (FALSE== register_judge(envelop_judge)) {
			return FALSE;
		}
		/* invoke register_filter for registering all type of mime paragraph*/
		if (FALSE == register_filter("text/plain", gb2312_filter)) {
			return FALSE;
		}
		if (FALSE == register_filter("text/html", gb2312_filter)) {
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		if (NULL != g_context_list) {
			free(g_context_list);
			g_context_list = NULL;
		}
		return TRUE;
	}
	return TRUE;
}

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop,
	CONNECTION *pconnection, char *reason, int length)
{
	if (TRUE == penvelop->is_relay) {
		g_context_list[context_ID] = PROPERTY_IGNORE;
	} else {
		g_context_list[context_ID] = PROPERTY_NONE;
	}
	return MESSAGE_ACCEPT;
}

static int gb2312_filter(int action, int context_ID, MAIL_BLOCK *mail_blk, 
	char *reason, int length)
{
	char *ptoken;
	int sub_result;
	size_t buff_size;
	int read_length, size;
	char *ptr, buff[1024];
	CONNECTION *pconnection;
	MAIL_ENTITY	mail_entity;
	BOOL should_check, gb2312_found;
	BOOL GB2312_found, base64_found;

	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		if (PROPERTY_IGNORE == g_context_list[context_ID]) {
			return MESSAGE_ACCEPT;
		}
		mail_entity = get_mail_entity(context_ID);
		if (MEM_END_OF_FILE == mem_file_read(&mail_entity.phead->f_xmailer, 
			buff, 1024)) {
			return MESSAGE_ACCEPT;
		}
		if (0 == strncasecmp(buff, "Microsoft Outlook Express", 25)) {
			should_check = TRUE;
		} else if (0 == strncasecmp(buff, "Foxmail 5.0 [cn]", 16) ||
			0 == strncasecmp(buff, "Foxmail 6, ", 11)) {
			should_check = FALSE;
		} else {
			return MESSAGE_ACCEPT;
		}
		if (PROPERTY_NONE == g_context_list[context_ID]) {
			sub_result = check_subject(&mail_entity.phead->f_subject);
			if (IGNORE_FOUND == sub_result) {
				g_context_list[context_ID] = PROPERTY_IGNORE;
				return MESSAGE_ACCEPT;
			}
		}
		if (FALSE == mail_blk->is_parsed) {
			ptr = (char*)mail_blk->original_buff;
			buff_size = mail_blk->original_length;
		} else {
			ptr = (char*)mail_blk->parsed_buff;
			buff_size = mail_blk->parsed_length;
		}
		if (NULL != search_string(ptr, "Original Message", buff_size)) {
			g_context_list[context_ID] = PROPERTY_IGNORE;
			return MESSAGE_ACCEPT;
		}
		if (PROPERTY_NONE == g_context_list[context_ID]) {
			if (TRUE == should_check && GB2312_FOUND == sub_result) {
				goto SPAM_RETRYING;
			}
			g_context_list[context_ID] = PROPERTY_HEAD;
		}
			
		GB2312_found = FALSE;
		gb2312_found = FALSE;
		base64_found = FALSE;
		while (MEM_END_OF_FILE != mem_file_read(mail_blk->fp_mime_info,
			&read_length, sizeof(int))) {
			mem_file_read(mail_blk->fp_mime_info, buff, read_length);
			buff[read_length] = '\0';
			mem_file_read(mail_blk->fp_mime_info, &size, sizeof(int));
			if (12 == read_length &&
				0 == strncasecmp(buff, "Content-Type", 12)) {
				if (size > 1023) {
					return MESSAGE_REJECT;
				}
				mem_file_read(mail_blk->fp_mime_info, buff, size);
				buff[size] = '\0';
				if (NULL != strstr(buff, "GB2312")) {
					GB2312_found = TRUE;
				}
				if (NULL != strstr(buff, "gb2312")) {
					gb2312_found = TRUE;
				}
			} else if (25 == read_length &&
				0 == strncasecmp(buff, "Content-Transfer-Encoding", 25)) {
				if (size > 1023) {
					return MESSAGE_REJECT;
				}
				mem_file_read(mail_blk->fp_mime_info, buff, size);
				buff[size] = '\0';
				if (NULL != strstr(buff, "base64")) {
					base64_found = TRUE;
				}	
			} else {
				mem_file_seek(mail_blk->fp_mime_info, MEM_FILE_READ_PTR,
					size, MEM_FILE_SEEK_CUR);
			}
		}
		if (TRUE == should_check && TRUE == gb2312_found &&
			FALSE == check_8bit(&mail_entity.phead->f_subject)) {
			goto SPAM_RETRYING;
		}
		if (TRUE == base64_found && TRUE == GB2312_found) {
			goto SPAM_RETRYING;
		}
		return MESSAGE_ACCEPT;
SPAM_RETRYING:
		if (TRUE == mail_entity.penvelop->is_outbound) {
			if (FALSE == outmail_limitation_audit(mail_entity.penvelop->from)) {
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_PROPERTY_002);
				}
				strncpy(reason, g_return_reason, length);
				return MESSAGE_REJECT;
			}
			g_context_list[context_ID] = PROPERTY_IGNORE;
			return MESSAGE_ACCEPT;
		} else {
			if (TRUE == check_tagging(mail_entity.penvelop->from,
				&mail_entity.penvelop->f_rcpt_to)) {
				mark_context_spam(context_ID);
				g_context_list[context_ID] = PROPERTY_IGNORE;
				return MESSAGE_ACCEPT;
			} else {
				ptoken = strstr(mail_entity.penvelop->from, "@a.");
				if (NULL != ptoken && isdigit(*(ptoken - 1))) {
					if (NULL != spam_statistic) {
						spam_statistic(SPAM_STATISTIC_PROPERTY_002);
					}
					strncpy(reason, g_return_reason, length);
					return MESSAGE_REJECT;
				}
				pconnection = get_connection(context_ID);
				if (FALSE == check_retrying(pconnection->client_ip,
					mail_entity.penvelop->from,
					&mail_entity.penvelop->f_rcpt_to)) {
					if (NULL != spam_statistic) {
						spam_statistic(SPAM_STATISTIC_PROPERTY_002);
					}
					strncpy(reason, g_return_reason, length);
					return MESSAGE_RETRYING;
				} else {
					return MESSAGE_ACCEPT;
				}
			}
		}
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
}

static int check_subject(MEM_FILE *pfile)
{
	char str_buf[4096];
	int size;

	size = mem_file_read(pfile, str_buf, 4096);
	if (MEM_END_OF_FILE == size) {
		return NONE_FOUND;
	}
	if (size >= 4095) {
		str_buf[4095] = '\0';
		size = 4095;
	} else {
		str_buf[size] = '\0';
	}
	
	if (NULL != search_string(str_buf, "=?big5?", size) ||
		NULL != search_string(str_buf, "=?gb2312?q?", size) ||
		NULL != strstr(str_buf, "Re: Re:") ||
		NULL != strstr(str_buf, "UmU6IFJl") ||
		NULL != strstr(str_buf, "Fw: Fw: ") ||
		NULL != strstr(str_buf, "Rnc6IEZ3") ||
		NULL != strstr(str_buf, "Fw: Re: ") ||
		NULL != strstr(str_buf, "Re: Fw: ") ||
		NULL != strstr(str_buf, "Rnc6IFJl") ||
		NULL != strstr(str_buf, "UmU6IEZ3")) {
		return IGNORE_FOUND;
	}
	if (NULL != strstr(str_buf, "=?GB2312?b?") ||
		NULL != strstr(str_buf, "=?GB2312?B?")) {
		return GB2312_FOUND;
	}
	return NONE_FOUND;
}

static BOOL check_8bit(MEM_FILE *pfile)
{
	char str_buf[4096], *ptr;
	int i, size;
	
	mem_file_seek(pfile, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	size = mem_file_read(pfile, str_buf, 4096);
	if (MEM_END_OF_FILE == size) {
		return TRUE;
	}
	
	for (i=0, ptr=str_buf; i<size; i++, ptr++) {
		if ( ((char)*ptr) & ((char)0x80) ) {
			return FALSE;
		}
	}		
	return TRUE;
}

