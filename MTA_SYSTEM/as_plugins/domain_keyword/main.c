#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "util.h"
#include "mail_func.h"
#include "config_file.h"
#include "domain_keyword.h"
#include <pthread.h>
#include <stdio.h>


DECLARE_API;

static char g_return_reason[1024];

static BOOL extract_attachment_name(MEM_FILE *pmem_file, char *file_name);

static int mime_auditor(int context_ID, MAIL_ENTITY *pmail, 
    CONNECTION *pconnection, char *reason, int length);

static int paragraph_filter(int action, int context_ID, MAIL_BLOCK *pblock,
    char *reason, int length);

static int text_filter(int action, int context_ID, MAIL_BLOCK *pblock,
    char *reason, int length);


BOOL AS_LibMain(int reason, void **ppdata)
{
	int growing_num;
	char file_name[256];
	char temp_path[256];
	char *str_value, *psearch;
	CONFIG_FILE *pconfig_file;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init(temp_path);
		if (NULL == pconfig_file) {
			printf("[domain_keyword]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "GROWING_NUM");
		if (NULL == str_value) {
			growing_num = 100;
			config_file_set_value(pconfig_file, "GROWING_NUM", "100");
		} else {
			growing_num = atoi(str_value);
			if (growing_num <= 0) {
				growing_num = 100;
				config_file_set_value(pconfig_file, "GROWING_NUM", "100");			
			}
		}
		printf("[domain_keyword]: growing num of hash table is %d\n", growing_num);
		
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "specified keyword of domain found in this"
				"mail, please contact the administrator!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[domain_keyword]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		
		sprintf(temp_path, "%s/%s", get_data_path(), file_name);
		domain_keyword_init(growing_num, temp_path);
		if (0 != domain_keyword_run()) {
			printf("[domain_keyword]: fail to domain limit module\n");
			return FALSE;
		}
		
        /* invoke register_auditor for registering auditor of mime head */
        if (FALSE == register_auditor(mime_auditor)) {
            return FALSE;
        }
		if (FALSE == register_filter("text/plain", text_filter)) {
			return FALSE;
		}
		if (FALSE == register_filter("text/html", text_filter)) {
			return FALSE;
		}
        /* invoke register_filter for registering text/plain of mime paragraph*/
        if (FALSE == register_filter(NULL, paragraph_filter)) {
            return FALSE;
        }

		register_talk(domain_keyword_console_talk);
        return TRUE;
    case PLUGIN_FREE:
		domain_keyword_stop();
		domain_keyword_free();
        return TRUE;
    }
	return TRUE;
}


static int mime_auditor(int context_ID, MAIL_ENTITY *pmail,
    CONNECTION *pconnection, char *reason, int length)
{
	int buff_len, out_len;
	char temp_buff[1024];
	char parsed_buff[1024];
	ENCODE_STRING encode_string;

	buff_len = mem_file_get_total_length(&pmail->phead->f_subject);
	if (buff_len > 0 && buff_len < 1024) {
		mem_file_read(&pmail->phead->f_subject, temp_buff, 1024);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		out_len = decode_mime_string(temp_buff, buff_len, parsed_buff, 1024);
		if (FALSE == domain_keyword_check(pmail->penvelop->from,
			&pmail->penvelop->f_rcpt_to, encode_string.charset,
			parsed_buff, out_len)) {
			sprintf(reason, g_return_reason);
			return MESSAGE_REJECT;
		}
	}
	buff_len = mem_file_get_total_length(&pmail->phead->f_mime_from);
	if (buff_len > 0 && buff_len < 1024) {
		mem_file_read(&pmail->phead->f_mime_from, temp_buff, 1024);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		out_len = decode_mime_string(temp_buff, buff_len, parsed_buff, 1024);
		if (FALSE == domain_keyword_check(pmail->penvelop->from,
			&pmail->penvelop->f_rcpt_to, encode_string.charset,
			parsed_buff, out_len)) {
			sprintf(reason, g_return_reason);
			return MESSAGE_REJECT;
		}
	}
	buff_len = mem_file_get_total_length(&pmail->phead->f_mime_to);
	if (buff_len > 0 && buff_len < 1024) {
		mem_file_read(&pmail->phead->f_mime_to, temp_buff, 1024);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		out_len = decode_mime_string(temp_buff, buff_len, parsed_buff, 1024);
		if (FALSE == domain_keyword_check(pmail->penvelop->from,
			&pmail->penvelop->f_rcpt_to, encode_string.charset,
			parsed_buff, out_len)) {
			sprintf(reason, g_return_reason);
			return MESSAGE_REJECT;
		}
	}
	buff_len = mem_file_get_total_length(&pmail->phead->f_mime_cc);
	if (buff_len > 0 && buff_len < 1024) {
		mem_file_read(&pmail->phead->f_mime_cc, temp_buff, 1024);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		out_len = decode_mime_string(temp_buff, buff_len, parsed_buff, 1024);
		if (FALSE == domain_keyword_check(pmail->penvelop->from,
			&pmail->penvelop->f_rcpt_to, encode_string.charset,
			parsed_buff, out_len)) {
			sprintf(reason, g_return_reason);
			return MESSAGE_REJECT;
		}
	}
	return MESSAGE_ACCEPT;
}

static int text_filter(int action, int context_ID, MAIL_BLOCK *pblock,
    char *reason, int length)
{
	
	char buff[1024];
	char charset[32];
	char *pbegine, *pend, *ptr;
	int read_length, size;
	MEM_FILE *fp_mime_field;
	MAIL_ENTITY mail_entity;
	
	switch (action) {
    case ACTION_BLOCK_NEW:
        return MESSAGE_ACCEPT;
    case ACTION_BLOCK_PROCESSING:
		mail_entity = get_mail_entity(context_ID);
		charset[0] = '\0';
		fp_mime_field = pblock->fp_mime_info;
		while (MEM_END_OF_FILE != mem_file_read(fp_mime_field, &read_length,
			sizeof(int))) {
			mem_file_read(fp_mime_field, buff, read_length);
			buff[read_length] = '\0';
			mem_file_read(fp_mime_field, &size, sizeof(int));
			if (12 == read_length && 0 == strncasecmp(buff,
				"Content-Type", 12)) {
				if (size > 1023) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(fp_mime_field, buff, size);
				buff[size] = '\0';
				if (NULL != (ptr = search_string(buff, "charset=", size))) {
					ptr += 8;
					while (' ' == *ptr || '\t' == *ptr) {
						ptr ++;
					}
					if ('"' == *ptr) {
						ptr ++;
					}
					pbegine = ptr;
					
					while (';' != *ptr && ' ' != *ptr && '\t' != *ptr &&
						'"' != *ptr && '\r' != *ptr && '\n' != *ptr &&
						'\0' != *ptr) {
						ptr ++;
					}
					pend = ptr;
					memcpy(charset, pbegine, pend - pbegine);
					charset[pend - pbegine] = '\0';
					break;
				}
			} else {
				mem_file_seek(fp_mime_field, MEM_FILE_READ_PTR, size,
					MEM_FILE_SEEK_CUR);
			}
		}

		if (TRUE == pblock->is_parsed) {
			if (FALSE == domain_keyword_check(mail_entity.penvelop->from,
				&mail_entity.penvelop->f_rcpt_to, charset, pblock->parsed_buff,
				pblock->parsed_length)) {
				sprintf(reason, g_return_reason);
				return MESSAGE_REJECT;
			}
		} else {
			if (FALSE == domain_keyword_check(mail_entity.penvelop->from,
				&mail_entity.penvelop->f_rcpt_to, charset,
				pblock->original_buff, pblock->original_length)) {
				sprintf(reason, g_return_reason);
				return MESSAGE_REJECT;
			}
		}
		return MESSAGE_ACCEPT;
    case ACTION_BLOCK_FREE:
        return MESSAGE_ACCEPT;
    }
	return MESSAGE_ACCEPT;
}

static int paragraph_filter(int action, int context_ID, MAIL_BLOCK *pblock,
    char *reason, int length)
{
	int out_len;
	int buff_len;
	char temp_buff[1024];
	char parsed_buff[1024];
	ENCODE_STRING encode_string;
	MAIL_ENTITY mail_entity;
	
    switch (action) {
    case ACTION_BLOCK_NEW:
        return MESSAGE_ACCEPT;
    case ACTION_BLOCK_PROCESSING:
		mail_entity = get_mail_entity(context_ID);
		if (FALSE == extract_attachment_name(pblock->fp_mime_info,
			temp_buff)) {
			return MESSAGE_ACCEPT;
		}
		buff_len = strlen(temp_buff);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		out_len = decode_mime_string(temp_buff, buff_len, parsed_buff, 1024);
		if (FALSE == domain_keyword_check(mail_entity.penvelop->from,
			&mail_entity.penvelop->f_rcpt_to, encode_string.charset,
			parsed_buff, out_len)) {
			strcpy(reason, g_return_reason);
			return MESSAGE_REJECT;
		}
		return MESSAGE_ACCEPT;
    case ACTION_BLOCK_FREE:
        return MESSAGE_ACCEPT;
    }
	return MESSAGE_ACCEPT;
}

static BOOL extract_attachment_name(MEM_FILE *pmem_file, char *file_name)
{
	int tag_len, value_len;
	char tag[256], value[1024];
	char *ptr1, *ptr2;
	
	while (MEM_END_OF_FILE != mem_file_read(pmem_file, &tag_len, sizeof(int))) {
		if (tag_len > 255) {
			mem_file_seek(pmem_file, MEM_FILE_READ_PTR, tag_len,
				MEM_FILE_SEEK_CUR);
		} else {
			mem_file_read(pmem_file, tag, tag_len);
			tag[tag_len] = '\0';
		}
		mem_file_read(pmem_file, &value_len, sizeof(int));
		if (value_len > 1023) {
			mem_file_seek(pmem_file, MEM_FILE_READ_PTR, value_len,
				MEM_FILE_SEEK_CUR);
		} else {
			mem_file_read(pmem_file, value, value_len);
			value[value_len] = '\0';
		}
		if (tag_len <= 255 && value_len <= 1023) {
			if (0 == strcasecmp(tag, "Content-Type")) {
				ptr1 = search_string(value, "name=\"", value_len);
				if (NULL == ptr1) {
					continue;
				}
				ptr1 += 6;
				ptr2 = strchr(ptr1, '\"');
				if (NULL == ptr2) {
					continue;
				}
				memcpy(file_name, ptr1, ptr2 - ptr1);
				return TRUE;
			}
			if (0 == strcasecmp(tag, "Content-Disposition")) {
				ptr1 = search_string(value, "filename=\"", value_len);
				if (NULL == ptr1) {
					continue;
				}
				ptr1 += 10;
				ptr2 = strchr(ptr1, '\"');
				if (NULL == ptr2) {
					continue;
				}
				memcpy(file_name, ptr1, ptr2 - ptr1);
				return TRUE;
			}
		}
	}
	return FALSE;
}


