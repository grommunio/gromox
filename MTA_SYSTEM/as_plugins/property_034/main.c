#include "util.h"
#include "mem_file.h"
#include "as_common.h"
#include "mail_func.h"
#include "config_file.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_034          71

enum {
	RBL_CACHE_NORMAL,
	RBL_CACHE_BLACK,
	RBL_CACHE_NONE
};

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static BOOL (*dns_rbl_judge)(const char*, char*, int);

static int (*rbl_cache_query)(const char*, char *, int);

static void (*rbl_cache_add)(const char*, int, char*);


static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

DECLARE_API;

static char g_return_reason[1024];

static int xmailer_filter(int action, int context_ID,
	MAIL_BLOCK* mail_blk,  char* reason, int length);
	
static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
    CONNECTION *pconnection, char *reason, int length);

int AS_LibMain(int reason, void **ppdata)
{	
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		dns_rbl_judge = query_service("dns_rbl_judge");
		if (NULL == dns_rbl_judge) {
			printf("[property_034]: fail to get"
				" \"dns_rbl_judge\" service\n");
			return FALSE;
		}
		rbl_cache_query = query_service("rbl_cache_query");
		if (NULL == rbl_cache_query) {
			printf("[property_034]: fail to get"
				" \"rbl_cache_query\" service\n");
			return FALSE;
		}
		rbl_cache_add = query_service("rbl_cache_add");
		if (NULL == rbl_cache_add) {
			printf("[property_034]: fail to get"
				" \"rbl_cache_add\" service\n");
			return FALSE;
		}
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init(temp_path);
		if (NULL == pconfig_file) {
			printf("[property_034]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000071 you are now sending spam mail!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[property_034]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		if (FALSE == register_filter("text/plain" , xmailer_filter)) {
			return FALSE;
		}
        if (FALSE == register_statistic(mail_statistic)) {
            return FALSE;
        }
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
	return TRUE;
}

static int xmailer_filter(int action, int context_ID,
	MAIL_BLOCK* mail_blk, char* reason, int length)
{
	int out_len;
	char tmp_buff[1024];
	char tmp_buff1[1024];
	MAIL_ENTITY mail_entity;
	EMAIL_ADDR email_address;
	ENCODE_STRING encode_string;

	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		mail_entity	= get_mail_entity(context_ID);
		if (TRUE == mail_entity.penvelop->is_outbound ||
			TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}
		if (MULTI_PARTS_MAIL != mail_entity.phead->mail_part) {
			return MESSAGE_ACCEPT;
		}
		out_len = mem_file_read(&mail_entity.phead->f_mime_from,
									tmp_buff, sizeof(tmp_buff));
		if (MEM_END_OF_FILE == out_len) {
			return MESSAGE_ACCEPT;
		}
		parse_mime_encode_string(tmp_buff, out_len, &encode_string);
		if (0 == strcasecmp(encode_string.charset, "utf-8")) {
			decode_mime_string(tmp_buff, out_len,
					tmp_buff1, sizeof(tmp_buff1));
			parse_email_addr(&email_address, tmp_buff1);
			if (0 != strcasecmp(email_address.domain, "outlook.com")) {
				return MESSAGE_ACCEPT;
			}
			out_len = strlen(email_address.display_name);
			if (7 != out_len && 10 != out_len) {
				return MESSAGE_ACCEPT;
			}
			if (' ' != email_address.display_name[3] ||
				FALSE == utf8_len(email_address.display_name,
				&out_len) || (3 != out_len && 4 != out_len)) {
				return MESSAGE_ACCEPT;	
			}
		} else if (0 == strcasecmp(encode_string.charset, "gb2312")) {
			decode_mime_string(tmp_buff, out_len,
					tmp_buff1, sizeof(tmp_buff1));
			parse_email_addr(&email_address, tmp_buff1);
			if (0 != strcasecmp(email_address.domain, "outlook.com")) {
				return MESSAGE_ACCEPT;
			}
		} else {
			return MESSAGE_ACCEPT;
		}
		if (0 != strncmp(mail_blk->parsed_buff, "[cid:", 5)
			&& NULL == memmem(mail_blk->parsed_buff,
			mail_blk->parsed_length, "\r\n\r\n[cid:", 9)) {
			return MESSAGE_ACCEPT;	
		}
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_034);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
		
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
    CONNECTION *pconnection, char *reason, int length)
{
	int result;
	int tag_len;
	int val_len;
	int pic_num;
	int html_num;
	char *pdomain;
	char buff[1024];
	char content_type[128];
	char x_originating_ip[16];
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (pmail->pbody->parts_num < 2) {
		return MESSAGE_ACCEPT;
	}
	pdomain = strchr(pmail->penvelop->from, '@');
	if (NULL == pdomain) {
		return MESSAGE_ACCEPT;
	}
	pdomain ++;
	if (0 != strcasecmp(pdomain, "126.com") &&
		0 != strcasecmp(pdomain, "163.com")) {
		return MESSAGE_ACCEPT;	
	}
	pic_num = 0;
	html_num = 0;
	while (MEM_END_OF_FILE != mem_file_read(
		&pmail->pbody->f_mail_parts, &type_len,
		sizeof(int))) {
		if (type_len >= sizeof(content_type)) {
			return MESSAGE_ACCEPT;
		}
		mem_file_read(&pmail->pbody->f_mail_parts,
			content_type, type_len);
		content_type[type_len] = '\0';
		mem_file_read(&pmail->pbody->f_mail_parts,
			&body_len, sizeof(size_t));
		if (0 == strcasecmp("text/html", content_type)) {
			html_num ++;
		} else if (0 == strcasecmp("text/plain", content_type)) {
			return MESSAGE_ACCEPT;
		} else if (0 == strcasecmp("image/gif", content_type) ||
			0 == strcasecmp("image/jpeg", content_type) ||
			0 == strcasecmp("image/jpg", content_type) ||
			0 == strcasecmp("image/png", content_type)) {
			pic_num ++;
		}
	}
	if (1 != html_num || 1 != pic_num) {
		return MESSAGE_ACCEPT;
	}
	x_originating_ip[0] = '\0';
	while (MEM_END_OF_FILE != mem_file_read(
		&pmail->phead->f_others, &tag_len, sizeof(int))) {
		if (16 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("X-Originating-IP", buff, 16)) {
				mem_file_read(&pmail->phead->f_others,
					&val_len, sizeof(int));
				if (val_len >= 16) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others,
					x_originating_ip, val_len);
				x_originating_ip[val_len] = '\0';
				break;
			}
		} else {
			mem_file_seek(&pmail->phead->f_others,
				MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR,
			val_len, MEM_FILE_SEEK_CUR);
	}
	if ('\0' == x_originating_ip[0] ||
		NULL == extract_ip(x_originating_ip, buff)) {
		return MESSAGE_ACCEPT;
	}
	result = rbl_cache_query(buff, reason, length);
	if (RBL_CACHE_NORMAL == result) {
		return MESSAGE_ACCEPT;
	} else if (RBL_CACHE_BLACK == result) {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_034);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}
	if (FALSE == dns_rbl_judge(buff, reason, length)) {
		rbl_cache_add(buff, RBL_CACHE_BLACK, reason);
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_PROPERTY_034);
		}
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}
	return MESSAGE_ACCEPT;
}
