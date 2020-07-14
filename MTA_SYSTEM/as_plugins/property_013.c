#include <errno.h>
#include <string.h>
#include <libHX/ctype_helper.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include "mail_func.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_013        42

enum {
	PROPERTY_IGNORE,
	PROPERTY_FURTHER,
	PROPERTY_CHARSET,
	PROPERTY_BOUNDARY,
	PROPERTY_XMID,
	PROPERTY_RECEIVED
};

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
    CONNECTION *pconnection, char *reason, int length);

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);

static int html_filter(int action, int context_ID, MAIL_BLOCK* mail_blk,
	char* reason, int length);

static int alternative_filter(int action, int context_ID, MAIL_BLOCK* mail_blk,
	char* reason, int length);

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop,
	CONNECTION *pconnection, char *reason, int length);

DECLARE_API;

static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
static CHECK_TAGGING check_tagging;

static char g_return_string[1024];
static int *g_context_list;

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
			printf("[property_013]: failed to get service \"check_retrying\"\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_013]: failed to get service \"check_tagging\"\n");
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
			printf("[property_013]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000042 please append \"--not spam\" at "
				"the end of mail subject then try it again, thank you!");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[property_013]: return string is \"%s\"\n", g_return_string);
		config_file_free(pconfig_file);
		g_context_list = malloc(get_context_num()*sizeof(int));
		if (NULL == g_context_list) {
			printf("[property_013]: fail to allocate context list memory\n");
			return FALSE;
		}
		if (FALSE == register_judge(envelop_judge)) {
			return FALSE;
		}
		if (FALSE == register_auditor(head_filter)) {
			return FALSE;
		}
		if (FALSE == register_filter("text/html", html_filter)) {
			return FALSE;
		}
		if (FALSE == register_filter("multipart/alternative",
			alternative_filter)) {
			return FALSE;
		}
        /* invoke register_statistic for registering statistic of mail */
        if (FALSE == register_statistic(mail_statistic)) {
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
	if (TRUE == penvelop->is_outbound ||
		TRUE == penvelop->is_relay) {
		g_context_list[context_ID] = PROPERTY_IGNORE;
	} else {
		g_context_list[context_ID] = PROPERTY_FURTHER;
	}
	return MESSAGE_ACCEPT;
}

static int head_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	char *temp_ptr;
	char buff[1024];
	BOOL b_mismatch;
	BOOL ms_boundary;
	BOOL has_received;
	int i, tag_len, val_len;
	int subject_len, out_len;
	int upper_num, digit_num;
	
	if (PROPERTY_IGNORE == g_context_list[context_ID]) {
		return MESSAGE_ACCEPT;
	}
	if (MULTI_PARTS_MAIL != pmail->phead->mail_part) {
		g_context_list[context_ID] = PROPERTY_IGNORE;
		return MESSAGE_ACCEPT;
	}
	subject_len = mem_file_read(&pmail->phead->f_subject, buff, 1024);
	
	if (MEM_END_OF_FILE != subject_len && 
		NULL != search_string(buff, "not spam", subject_len)) {
		g_context_list[context_ID] = PROPERTY_IGNORE;
		return MESSAGE_ACCEPT;		
	}
	out_len = mem_file_read(&pmail->phead->f_content_type, buff, 1024);
	if (MEM_END_OF_FILE == out_len) {   /* no content type */
		g_context_list[context_ID] = PROPERTY_IGNORE;
		return MESSAGE_ACCEPT;
	}
	if (NULL != search_string(buff, "------------NextPartBnd", out_len) ||
		NULL != search_string(buff, "------------NextBound", out_len)) {
		g_context_list[context_ID] = PROPERTY_BOUNDARY;
		return MESSAGE_ACCEPT;
	}
	if (NULL != search_string(buff, "boundary=\"=====", out_len) &&
		NULL != search_string(buff, "_=====", out_len) &&
		NULL == search_string(buff, "Dragon", out_len)) {
		g_context_list[context_ID] = PROPERTY_BOUNDARY;
		return MESSAGE_ACCEPT;
	}
	
	temp_ptr = search_string(buff, "boundary=\"------------", out_len);
	if (NULL != temp_ptr) {
		temp_ptr += 22;

		/*
		for (i=0; i<24; i++) {
			if (!HX_isdigit(temp_ptr[i]))
				break;
		}
		if (24 == i && '"' == temp_ptr[24]) {
			g_context_list[context_ID] = PROPERTY_BOUNDARY;
			return MESSAGE_ACCEPT;
		}
		*/
		
		/* ------------9B16D306.4AD3355D */
		for (i=0; i<8; i++) {
			if (!HX_isdigit(temp_ptr[i]) && !HX_isupper(temp_ptr[i]))
				break;
		}
		if (8 == i && '.' == temp_ptr[8] && '"' == temp_ptr[17]) {
			for (i=9; i<17; i++) {
				if (!HX_isdigit(temp_ptr[i]) && !HX_isupper(temp_ptr[i]))
					break;
			}
			if (17 == i) {
				g_context_list[context_ID] = PROPERTY_BOUNDARY;
				return MESSAGE_ACCEPT;
			}
		}
	}
	temp_ptr = search_string(buff, "boundary=\"", out_len);
	if (NULL != temp_ptr) {
		temp_ptr += 10;
		b_mismatch = FALSE;
		upper_num = 0;
		digit_num = 0;
		for (i=0; i<out_len-(temp_ptr-buff); i++) {
			if ('"' == temp_ptr[i]) {
				break;
			}
			if (HX_isupper(temp_ptr[i])) {
				upper_num ++;
			} else if (HX_isdigit(temp_ptr[i])) {
				digit_num ++;
			} else {
				b_mismatch = TRUE;
				break;
			}
		}
		if (FALSE == b_mismatch && i >= 8 && i <= 24 && upper_num >= 1 &&
			digit_num >= 2) {
			g_context_list[context_ID] = PROPERTY_BOUNDARY;
			return MESSAGE_ACCEPT;
		}
	}
	/* ----=_NextPart_000_00CA_F181AEBA.5B6D0E38 */
	ms_boundary = FALSE;
	temp_ptr = search_string(buff, "boundary=\"----=_NextPart_", out_len);
	if (NULL != temp_ptr) {
		temp_ptr += 25;
		if ('_' != temp_ptr[3] || '_' != temp_ptr[8] ||
			'.' != temp_ptr[17] || '"' != temp_ptr[26]) {
			goto CHECK_MIME;
		}
		for (i=0; i<3; i++) {
			if (!HX_isdigit(temp_ptr[i]) && !HX_isupper(temp_ptr[i]))
				goto CHECK_MIME;
		}
		for (i=4; i<8; i++) {
			if (!HX_isdigit(temp_ptr[i]) && !HX_isupper(temp_ptr[i]))
				goto CHECK_MIME;
		}
		for (i=9; i<17; i++) {
			if (!HX_isdigit(temp_ptr[i]) && !HX_isupper(temp_ptr[i]))
				goto CHECK_MIME;
		}
		for (i=18; i<26; i++) {
			if (!HX_isdigit(temp_ptr[i]) && !HX_isupper(temp_ptr[i]))
				goto CHECK_MIME;
		}
		ms_boundary = TRUE;
	}
CHECK_MIME:
	has_received = FALSE;
	while (MEM_END_OF_FILE != mem_file_read(&pmail->phead->f_others, &tag_len,
		sizeof(int))) {
		if (5 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);		
			if (0 == strncasecmp("X-MID", buff, 5)) {
				g_context_list[context_ID] = PROPERTY_XMID;
				return MESSAGE_ACCEPT;
			}
		} else if (8 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("Received", buff, 8)) {
				has_received = TRUE;
			}	
		} else if (10 == tag_len && TRUE == ms_boundary) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("Message-ID", buff, 10)) {
				mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
				if (val_len > sizeof(buff)) {
					g_context_list[context_ID] = PROPERTY_IGNORE;
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others, buff, val_len);
				if (0 == strncmp(buff, "<01c70", 6)) {
					g_context_list[context_ID] = PROPERTY_XMID;
					return MESSAGE_ACCEPT;
				} else {
					continue;
				}
			}
		} else {
			mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR, tag_len,
				MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR, val_len,
			MEM_FILE_SEEK_CUR);
	}
	if (FALSE == has_received && TRUE == ms_boundary) {
		g_context_list[context_ID] = PROPERTY_RECEIVED;
		return MESSAGE_ACCEPT;
	}
	g_context_list[context_ID] = PROPERTY_IGNORE;
	return MESSAGE_ACCEPT;
}

static int html_filter(int action, int context_ID, MAIL_BLOCK* mail_blk,
	char* reason, int length)
{
	size_t blk_len;
	int read_length, size;
	char buff[1024], *ptr;
	BOOL qp_found;
	BOOL charset_found;

	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		if (PROPERTY_IGNORE == g_context_list[context_ID]) {
			return MESSAGE_ACCEPT;
		}
		if (PROPERTY_BOUNDARY == g_context_list[context_ID] ||
			PROPERTY_XMID == g_context_list[context_ID] ||
			PROPERTY_RECEIVED == g_context_list[context_ID]) {
			goto CHECK_CONTENTID;
		}
		qp_found = FALSE;
		charset_found = FALSE;
		while (MEM_END_OF_FILE != mem_file_read(mail_blk->fp_mime_info,
			&read_length, sizeof(int))) {
			mem_file_read(mail_blk->fp_mime_info, buff, read_length);
			buff[read_length] = '\0';
			mem_file_read(mail_blk->fp_mime_info, &size, sizeof(int));
			if (25 == read_length && 0 == strncasecmp(buff,
				"Content-Transfer-Encoding", 25)) {
				if (size > 1023) {
					g_context_list[context_ID] = PROPERTY_IGNORE;
					return MESSAGE_ACCEPT;
				}
				mem_file_read(mail_blk->fp_mime_info, buff, size);
				buff[size] = '\0';
				if (0 != strcmp(buff, "quoted-printable") &&
					0 != strcmp(buff, "7bit") &&
					0 != strcmp(buff, "8bit")) {
					g_context_list[context_ID] = PROPERTY_IGNORE;
					return MESSAGE_ACCEPT;
				} else {
					qp_found = TRUE;
				}
			} else if (12 == read_length && 0 == strncasecmp(buff,
				"Content-Type", 12)) {
				if (size > 1023) {
					g_context_list[context_ID] = PROPERTY_IGNORE;
					return MESSAGE_ACCEPT;
				}
				mem_file_read(mail_blk->fp_mime_info, buff, size);
				if (NULL != search_string(buff, "windows-125", size) ||
					NULL != search_string(buff, "koi8-r", size) ||
					NULL == search_string(buff, "charset=", size) ||
					NULL != search_string(buff, "us-ascii", size) ||
					NULL != search_string(buff, "iso-8859-2", size)) {
					charset_found = TRUE;
				} else {
					g_context_list[context_ID] = PROPERTY_IGNORE;
					return MESSAGE_ACCEPT;
				}
			}else {
				mem_file_seek(mail_blk->fp_mime_info, MEM_FILE_READ_PTR,
					size, MEM_FILE_SEEK_CUR);
			}
		}

		if (FALSE == charset_found || FALSE == qp_found) {
			g_context_list[context_ID] = PROPERTY_IGNORE;
			return MESSAGE_ACCEPT;
		}
		g_context_list[context_ID] = PROPERTY_CHARSET;
CHECK_CONTENTID:
		if (TRUE == mail_blk->is_parsed) {
			ptr = (char*)mail_blk->parsed_buff;
			blk_len = mail_blk->parsed_length;
		} else {
			ptr = (char*)mail_blk->original_buff;
			blk_len = mail_blk->original_length;
		}
		if (NULL == search_string(ptr, "src=\"cid:", blk_len)) {
			g_context_list[context_ID] = PROPERTY_IGNORE;
			return MESSAGE_ACCEPT;
		}
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}
	
static int alternative_filter(int action, int context_ID, MAIL_BLOCK* mail_blk,
	char* reason, int length)
{
	int size;
	int read_length;
	char buff[1024];
	MAIL_ENTITY mail_entity;
	MEM_FILE *fp_mime_field;
	
	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		if (PROPERTY_IGNORE == g_context_list[context_ID]) {
			return MESSAGE_ACCEPT;
		}
		fp_mime_field = mail_blk->fp_mime_info;
		while (MEM_END_OF_FILE != mem_file_read(fp_mime_field, &read_length,
			sizeof(int))) {
			mem_file_read(fp_mime_field, buff, read_length);
			buff[read_length] = '\0';
			mem_file_read(fp_mime_field, &size, sizeof(int));
			if (12 == read_length && 0 == strncasecmp(buff,
				"Content-Type", 12)) {
				if (size > 1023) {
					return MESSAGE_REJECT;
				}
				mem_file_read(fp_mime_field, buff, size);
				if (NULL == search_string(buff, "boundary= \"----=_NextPart_",
					size)) {
					return MESSAGE_ACCEPT;
				} else {
					mail_entity = get_mail_entity(context_ID);
					if (TRUE == check_tagging(mail_entity.penvelop->from,
						&mail_entity.penvelop->f_rcpt_to)) {
						mark_context_spam(context_ID);
						return MESSAGE_ACCEPT;
					} else {
						strncpy(reason, g_return_string, length);
						if (NULL != spam_statistic) {
							spam_statistic(SPAM_STATISTIC_PROPERTY_013);
						}
						return MESSAGE_REJECT;
					}
				}
			} else {
				mem_file_seek(fp_mime_field, MEM_FILE_READ_PTR, size,
					MEM_FILE_SEEK_CUR);
			}
		}
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
	return MESSAGE_ACCEPT;
}

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
    CONNECTION *pconnection, char *reason, int length)
{
	int type_len;
	size_t body_len;
	int html_num, gif_num, gif_len;
	char content_type[256];
	
	if (PROPERTY_IGNORE == g_context_list[context_ID]) {
		return MESSAGE_ACCEPT;
	}
	if (pmail->pbody->parts_num < 2) {
		return MESSAGE_ACCEPT;
	}
	html_num = 0;
	gif_num = 0;
	gif_len = 0;
	while (MEM_END_OF_FILE != mem_file_read(&pmail->pbody->f_mail_parts,
		&type_len, sizeof(int))) {
		mem_file_read(&pmail->pbody->f_mail_parts, content_type, type_len);
		content_type[type_len] = '\0';
		mem_file_read(&pmail->pbody->f_mail_parts, &body_len, sizeof(size_t));
		if (0 == strcasecmp("text/html", content_type)) {
			html_num ++;
		} else if (0 == strcasecmp("image/gif", content_type) ||
			0 == strcasecmp("image/jpeg", content_type) ||
			0 == strcasecmp("image/jpg", content_type) ||
			0 == strcasecmp("image/png", content_type)) {
			gif_num ++;
			gif_len += body_len;
		}
	}
	if (1 == html_num && gif_num > 0 && gif_len < 96*1024) {
		if (TRUE == check_tagging(pmail->penvelop->from,
			&pmail->penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			strncpy(reason, g_return_string, length);
			if (PROPERTY_CHARSET == g_context_list[context_ID] ||
				PROPERTY_XMID == g_context_list[context_ID] ||
				PROPERTY_RECEIVED == g_context_list[context_ID]) {
				if (FALSE == check_retrying(pconnection->client_ip,
					pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {
					if (NULL != spam_statistic) {
						spam_statistic(SPAM_STATISTIC_PROPERTY_013);
					}
					return MESSAGE_RETRYING;
				} else {
					return MESSAGE_ACCEPT;
				}
			} else {
				if (NULL != spam_statistic) {
					spam_statistic(SPAM_STATISTIC_PROPERTY_013);
				}
				return MESSAGE_REJECT;
			}
		}
	}
	return MESSAGE_ACCEPT;
}

