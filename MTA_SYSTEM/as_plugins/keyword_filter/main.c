#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <gromox/as_common.h>
#include "util.h"
#include "mail_func.h"
#include "config_file.h"
#include "keyword_engine.h"
#include <pthread.h>
#include <stdio.h>

#define SPAM_STATISTIC_SUBJECT_KEYWORD			52
#define SPAM_STATISTIC_FROM_KEYWORD				53
#define SPAM_STATISTIC_TO_KEYWORD				54
#define SPAM_STATISTIC_CC_KEYWORD				55
#define SPAM_STATISTIC_CONTENT_KEYWORD			56
#define SPAM_STATISTIC_ATTACHMENT_KEYWORD		57

typedef void (*SPAM_STATISTIC)(int);

static SPAM_STATISTIC spam_statistic;

DECLARE_API;

static KEYWORD_ENGINE *g_subject_engine;
static KEYWORD_ENGINE *g_from_engine;
static KEYWORD_ENGINE *g_to_engine;
static KEYWORD_ENGINE *g_cc_engine;
static KEYWORD_ENGINE *g_content_engine;
static KEYWORD_ENGINE *g_attachment_engine;

static pthread_rwlock_t g_subject_lock;
static pthread_rwlock_t g_from_lock;
static pthread_rwlock_t g_to_lock;
static pthread_rwlock_t g_cc_lock;
static pthread_rwlock_t g_content_lock;
static pthread_rwlock_t g_attachment_lock;

static char g_subject_return[1024];
static char g_from_return[1024];
static char g_to_return[1024];
static char g_cc_return[1024];
static char g_content_return[1024];
static char g_attachment_return[1024];

static char g_charset_path[256];
static char g_subject_path[256];
static char g_from_path[256];
static char g_to_path[256];
static char g_cc_path[256];
static char g_content_path[256];
static char g_attachment_path[256];

static BOOL extract_attachment_name(MEM_FILE *pmem_file, char *file_name);

static int mime_auditor(int context_ID, MAIL_ENTITY *pmail, 
    CONNECTION *pconnection, char *reason, int length);

static int paragraph_filter(int action, int context_ID, MAIL_BLOCK *pblock,
    char *reason, int length);

static int text_filter(int action, int context_ID, MAIL_BLOCK *pblock,
    char *reason, int length);

static void console_talk(int argc, char **argv, char *result, int length);

BOOL AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256];
	char temp_path[256];
	char charset_path[256];
	char *str_value, *psearch;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);	

		pthread_rwlock_init(&g_subject_lock, NULL);
		pthread_rwlock_init(&g_from_lock, NULL);
		pthread_rwlock_init(&g_to_lock, NULL);
		pthread_rwlock_init(&g_cc_lock, NULL);
		pthread_rwlock_init(&g_content_lock, NULL);
		pthread_rwlock_init(&g_attachment_lock, NULL);
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init2(NULL, temp_path);
		if (NULL == pconfig_file) {
			printf("[keyword_filter]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file,
						"SUBJECT_RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_subject_return, "000052 mail subject contains illegal "
				"keyword [%s]");
		} else {
			strcpy(g_subject_return, str_value);
		}
		printf("[keyword_filter]: subject return string is %s\n",
			g_subject_return);
		str_value = config_file_get_value(pconfig_file, "FROM_RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_from_return, "000053 mail head \"From\" contains illegal "
				"keyword [%s]");
		} else {
			strcpy(g_from_return, str_value);
		}
		printf("[keyword_filter]: from return string is %s\n", g_from_return);
		str_value = config_file_get_value(pconfig_file, "TO_RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_to_return, "000054 mail head \"To\" contains illegal "
				"keyword [%s]");
		} else {
			strcpy(g_to_return, str_value);
		}
		printf("[keyword_filter]: to return string is %s\n", g_to_return);
		str_value = config_file_get_value(pconfig_file, "CC_RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_cc_return, "000055 mail head \"Cc\" contains illegal "
				"keyword [%s]");
		} else {
			strcpy(g_cc_return, str_value);
		}
		str_value = config_file_get_value(pconfig_file,
					"CONTENT_RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_content_return, "000056 mail content contains illegal "
				"keyword [%s]");
		} else {
			strcpy(g_content_return, str_value);
		}
		printf("[keyword_filter]: content return string is %s\n",
				g_content_return);
		str_value = config_file_get_value(pconfig_file,
			"ATTACHMENT_RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_attachment_return, "000057 attachment file name contains "
				"illegal keyword [%s]");
		} else {
			strcpy(g_attachment_return, str_value);
		}
		printf("[keyword_filter]: attachment return string is %s\n",
				g_attachment_return);
		config_file_free(pconfig_file);
		
		g_subject_engine = NULL;
		g_from_engine = NULL;
		g_to_engine = NULL;
		g_cc_engine = NULL;
		g_content_engine = NULL;
		g_attachment_engine = NULL;
		sprintf(charset_path, "%s/%s/charset.txt", get_data_path(), file_name);
		strcpy(g_charset_path, charset_path);
		
		sprintf(temp_path, "%s/%s/subject.txt", get_data_path(), file_name);
		strcpy(g_subject_path, temp_path);
		g_subject_engine = keyword_engine_init(charset_path, temp_path);
		if (NULL == g_subject_engine) {
			printf("[keyword_filter]: fail to init subject keyword engine\n");
			return FALSE;
		}
		sprintf(temp_path, "%s/%s/from.txt", get_data_path(), file_name);
		strcpy(g_from_path, temp_path);
		g_from_engine = keyword_engine_init(charset_path, temp_path);
		if (NULL == g_from_engine) {
			printf("[keyword_filter]: fail to init from keyword engine\n");
			return FALSE;
		}
		sprintf(temp_path, "%s/%s/to.txt", get_data_path(), file_name);
		strcpy(g_to_path, temp_path);
		g_to_engine = keyword_engine_init(charset_path, temp_path);
		if (NULL == g_to_engine) {
			printf("[keyword_filter]: fail to init to keyword engine\n");
			return FALSE;
		}
		sprintf(temp_path, "%s/%s/cc.txt", get_data_path(), file_name);
		strcpy(g_cc_path, temp_path);
		g_cc_engine = keyword_engine_init(charset_path, temp_path);
		if (NULL == g_cc_engine) {
			printf("[keyword_filter]: fail to init cc keyword engine\n");
			return FALSE;
		}
		sprintf(temp_path, "%s/%s/content.txt", get_data_path(), file_name);
		strcpy(g_content_path, temp_path);
		g_content_engine = keyword_engine_init(charset_path, temp_path);
		if (NULL == g_content_engine) {
			printf("[keyword_filter]: fail to init content keyword engine\n");
			return FALSE;
		}
		sprintf(temp_path, "%s/%s/attachment.txt", get_data_path(), file_name);
		strcpy(g_attachment_path, temp_path);
		g_attachment_engine = keyword_engine_init(charset_path, temp_path);
		if (NULL == g_attachment_engine) {
			printf("[keyword_filter]: fail to init attachment keyword engine\n");
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
        if (FALSE == register_talk(console_talk)) {
			printf("[keyword_filter]: fail to register talk function\n");
        }
        return TRUE;
    case PLUGIN_FREE:
		pthread_rwlock_destroy(&g_subject_lock);
		pthread_rwlock_destroy(&g_from_lock);
		pthread_rwlock_destroy(&g_to_lock);
		pthread_rwlock_destroy(&g_cc_lock);
		pthread_rwlock_destroy(&g_content_lock);
		pthread_rwlock_destroy(&g_attachment_lock);
		if (NULL != g_subject_engine) {
			keyword_engine_free(g_subject_engine);
			g_subject_engine = NULL;
		}
		if (NULL != g_from_engine) {
			keyword_engine_free(g_from_engine);
			g_from_engine = NULL;
		}
		if (NULL != g_to_engine) {
			keyword_engine_free(g_to_engine);
			g_to_engine = NULL;
		}
		if (NULL != g_cc_engine) {
			keyword_engine_free(g_cc_engine);
			g_cc_engine = NULL;
		}
		if (NULL != g_content_engine) {
			keyword_engine_free(g_content_engine);
			g_content_engine = NULL;
		}
		if (NULL != g_attachment_engine) {
			keyword_engine_free(g_attachment_engine);
			g_attachment_engine = NULL;
		}
        return TRUE;
    case SYS_THREAD_CREATE:
        return TRUE;
        /* a pool thread is created */
    case SYS_THREAD_DESTROY:
        return TRUE;
    }
	return false;
}

static int mime_auditor(int context_ID, MAIL_ENTITY *pmail,
    CONNECTION *pconnection, char *reason, int length)
{
	int buff_len, out_len;
	char temp_buff[1024];
	char parsed_buff[1024];
	const char *presult;
	ENCODE_STRING encode_string;

	if (TRUE == pmail->penvelop->is_relay ||
		TRUE == pmail->penvelop->is_outbound) {
		return MESSAGE_ACCEPT;
	}
	buff_len = mem_file_get_total_length(&pmail->phead->f_subject);
	if (buff_len > 0 && buff_len < 1024) {
		mem_file_read(&pmail->phead->f_subject, temp_buff, 1024);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		out_len = decode_mime_string(temp_buff, buff_len, parsed_buff, 1024);
		pthread_rwlock_rdlock(&g_subject_lock);
		presult = keyword_engine_match(g_subject_engine, encode_string.charset,
					parsed_buff, out_len);
		if (NULL != presult) {
			sprintf(reason, g_subject_return, presult);
			pthread_rwlock_unlock(&g_subject_lock);
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_SUBJECT_KEYWORD);
			}
			return MESSAGE_REJECT;
		}
		pthread_rwlock_unlock(&g_subject_lock);
	}
	buff_len = mem_file_get_total_length(&pmail->phead->f_mime_from);
	if (buff_len > 0 && buff_len < 1024) {
		mem_file_read(&pmail->phead->f_mime_from, temp_buff, 1024);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		out_len = decode_mime_string(temp_buff, buff_len, parsed_buff, 1024);
		pthread_rwlock_rdlock(&g_from_lock);
		presult = keyword_engine_match(g_from_engine, encode_string.charset,
					parsed_buff, out_len);
		if (NULL != presult) {
			sprintf(reason, g_from_return, presult);
			pthread_rwlock_unlock(&g_from_lock);
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_FROM_KEYWORD);
			}
			return MESSAGE_REJECT;
		}
		pthread_rwlock_unlock(&g_from_lock);
	}
	buff_len = mem_file_get_total_length(&pmail->phead->f_mime_to);
	if (buff_len > 0 && buff_len < 1024) {
		mem_file_read(&pmail->phead->f_mime_to, temp_buff, 1024);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		out_len = decode_mime_string(temp_buff, buff_len, parsed_buff, 1024);
		pthread_rwlock_rdlock(&g_to_lock);
		presult = keyword_engine_match(g_to_engine, encode_string.charset,
					parsed_buff, out_len);
		if (NULL != presult) {
			sprintf(reason, g_to_return, presult);
			pthread_rwlock_unlock(&g_to_lock);
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_TO_KEYWORD);
			}
			return MESSAGE_REJECT;
		}
		pthread_rwlock_unlock(&g_to_lock);
	}
	buff_len = mem_file_get_total_length(&pmail->phead->f_mime_cc);
	if (buff_len > 0 && buff_len < 1024) {
		mem_file_read(&pmail->phead->f_mime_cc, temp_buff, 1024);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		out_len = decode_mime_string(temp_buff, buff_len, parsed_buff, 1024);
		pthread_rwlock_rdlock(&g_cc_lock);
		presult = keyword_engine_match(g_cc_engine, encode_string.charset,
					parsed_buff, out_len);
		if (NULL != presult) {
			sprintf(reason, g_cc_return, presult);
			pthread_rwlock_unlock(&g_cc_lock);
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_CC_KEYWORD);
			}
			return MESSAGE_REJECT;
		}
		pthread_rwlock_unlock(&g_cc_lock);
	}
	return MESSAGE_ACCEPT;
}

static int text_filter(int action, int context_ID, MAIL_BLOCK *pblock,
    char *reason, int length)
{
	
	char buff[1024];
	char charset[32];
	const char *presult;
	char *pbegine, *pend, *ptr;
	int read_length, size;
	MEM_FILE *fp_mime_field;
	MAIL_ENTITY mail_entity;
	
	switch (action) {
    case ACTION_BLOCK_NEW:
        return MESSAGE_ACCEPT;
    case ACTION_BLOCK_PROCESSING:
		mail_entity = get_mail_entity(context_ID);
		if (TRUE == mail_entity.penvelop->is_relay ||
			TRUE == mail_entity.penvelop->is_outbound) {
			return MESSAGE_ACCEPT;
		}
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
		pthread_rwlock_rdlock(&g_content_lock);
		if (TRUE == pblock->is_parsed) {
			presult = keyword_engine_match(g_content_engine, charset,
						pblock->parsed_buff, pblock->parsed_length);
		} else {
			presult = keyword_engine_match(g_content_engine, charset,
						pblock->original_buff, pblock->original_length);
		}
		if (NULL != presult) {
			sprintf(reason, g_content_return, presult);
			pthread_rwlock_unlock(&g_content_lock);
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_CONTENT_KEYWORD);
			}
			return MESSAGE_REJECT;
		}
		pthread_rwlock_unlock(&g_content_lock);
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
	const char *presult;
	char temp_buff[1024];
	char parsed_buff[1024];
	ENCODE_STRING encode_string;
	MAIL_ENTITY mail_entity;
	
    switch (action) {
    case ACTION_BLOCK_NEW:
        return MESSAGE_ACCEPT;
    case ACTION_BLOCK_PROCESSING:
		mail_entity = get_mail_entity(context_ID);
		if (TRUE == mail_entity.penvelop->is_relay ||
			TRUE == mail_entity.penvelop->is_outbound) {
			return MESSAGE_ACCEPT;
		}
		if (FALSE == extract_attachment_name(pblock->fp_mime_info,
			temp_buff)) {
			return MESSAGE_ACCEPT;
		}
		buff_len = strlen(temp_buff);
		parse_mime_encode_string(temp_buff, buff_len, &encode_string);
		out_len = decode_mime_string(temp_buff, buff_len, parsed_buff, 1024);
		pthread_rwlock_rdlock(&g_attachment_lock);
		presult = keyword_engine_match(g_attachment_engine, encode_string.charset,
					parsed_buff, out_len);
		if (NULL != presult) {
			sprintf(reason, g_attachment_return, presult);
			pthread_rwlock_unlock(&g_attachment_lock);
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_ATTACHMENT_KEYWORD);
			}
			return MESSAGE_REJECT;
		}
		pthread_rwlock_unlock(&g_attachment_lock);
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

static void console_talk(int argc, char **argv, char *result, int length)
{
	KEYWORD_ENGINE *pengine;
	
	 char help_string[] = "250 keyword filter help information:\r\n"
						  "\t%s charset reload\r\n"
						  "\t    --reload charset list from file\r\n"
						  "\t%s subject reload\r\n"
						  "\t    --reload subject keywords from file\r\n"
						  "\t%s from reload\r\n"
						  "\t    --reload from keywords from file\r\n"
						  "\t%s to reload\r\n"
						  "\t    --reload to keywords from file\r\n"
						  "\t%s cc reload\r\n"
						  "\t    --reload cc keywords from file\r\n"
						  "\t%s content reload\r\n"
						  "\t    --reload content keywords from file\r\n"
						  "\t%s attachment reload\r\n"
						  "\t    --reload attachment keywords from file\r\n";
						  
	 
	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0],
			argv[0], argv[0], argv[0], argv[0]);
			result[length - 1] ='\0';
			return;
	}
	if (3 == argc && 0 == strcmp("reload", argv[2])) {
		if (0 == strcmp("charset", argv[1])) {
			pengine = keyword_engine_init(g_charset_path, g_subject_path);
			if (NULL == pengine) {
				strncpy(result, "550 fail to init subject keyword engine",
					length);
				return;
			}
			pthread_rwlock_wrlock(&g_subject_lock);
			keyword_engine_free(g_subject_engine);
			g_subject_engine = pengine;
			pthread_rwlock_unlock(&g_subject_lock);
			pengine = keyword_engine_init(g_charset_path, g_from_path);
			if (NULL == pengine) {
				strncpy(result, "550 fail to init from keyword engine",
					length);
				return;
			}
			pthread_rwlock_wrlock(&g_from_lock);
			keyword_engine_free(g_from_engine);
			g_from_engine = pengine;
			pthread_rwlock_unlock(&g_from_lock);
			pengine = keyword_engine_init(g_charset_path, g_to_path);
			if (NULL == pengine) {
				strncpy(result, "550 fail to init to keyword engine",
					length);
				return;
			}
			pthread_rwlock_wrlock(&g_to_lock);
			keyword_engine_free(g_to_engine);
			g_to_engine = pengine;
			pthread_rwlock_unlock(&g_to_lock);
			pengine = keyword_engine_init(g_charset_path, g_cc_path);
			if (NULL == pengine) {
				strncpy(result, "550 fail to init cc keyword engine",
					length);
				return;
			}
			pthread_rwlock_wrlock(&g_cc_lock);
			keyword_engine_free(g_cc_engine);
			g_cc_engine = pengine;
			pthread_rwlock_unlock(&g_cc_lock);
			pengine = keyword_engine_init(g_charset_path, g_content_path);
			if (NULL == pengine) {
				strncpy(result, "550 fail to init content keyword engine",
					length);
				return;
			}
			pthread_rwlock_wrlock(&g_content_lock);
			keyword_engine_free(g_content_engine);
			g_content_engine = pengine;
			pthread_rwlock_unlock(&g_content_lock);
			pengine = keyword_engine_init(g_charset_path, g_attachment_path);
			if (NULL == pengine) {
				strncpy(result, "550 fail to init attachment keyword engine",
					length);
				return;
			}
			pthread_rwlock_wrlock(&g_attachment_lock);
			keyword_engine_free(g_attachment_engine);
			g_attachment_engine = pengine;
			pthread_rwlock_unlock(&g_attachment_lock);
			strncpy(result, "250 reload charset list OK", length);
			return;
		}
		if (0 == strcmp("subject", argv[1])) {
			pengine = keyword_engine_init(g_charset_path, g_subject_path);
			if (NULL == pengine) {
				strncpy(result, "550 fail to init subject keyword engine",
					length);
				return;
			}
			pthread_rwlock_wrlock(&g_subject_lock);
			keyword_engine_free(g_subject_engine);
			g_subject_engine = pengine;
			pthread_rwlock_unlock(&g_subject_lock);
			strncpy(result, "250 reload subject keywords OK", length);
			return;
		}
		if (0 == strcmp("from", argv[1])) {
			pengine = keyword_engine_init(g_charset_path, g_from_path);
			if (NULL == pengine) {
				strncpy(result, "550 fail to init from keyword engine",
					length);
				return;
			}
			pthread_rwlock_wrlock(&g_from_lock);
			keyword_engine_free(g_from_engine);
			g_from_engine = pengine;
			pthread_rwlock_unlock(&g_from_lock);
			strncpy(result, "250 reload from keywords OK", length);
			return;
		}
		if (0 == strcmp("to", argv[1])) {
			pengine = keyword_engine_init(g_charset_path, g_to_path);
			if (NULL == pengine) {
				strncpy(result, "550 fail to init to keyword engine",
					length);
				return;
			}
			pthread_rwlock_wrlock(&g_to_lock);
			keyword_engine_free(g_to_engine);
			g_to_engine = pengine;
			pthread_rwlock_unlock(&g_to_lock);
			strncpy(result, "250 reload to keywords OK", length);
			return;
		}
		if (0 == strcmp("cc", argv[1])) {
			pengine = keyword_engine_init(g_charset_path, g_cc_path);
			if (NULL == pengine) {
				strncpy(result, "550 fail to init cc keyword engine",
					length);
				return;
			}
			pthread_rwlock_wrlock(&g_cc_lock);
			keyword_engine_free(g_cc_engine);
			g_cc_engine = pengine;
			pthread_rwlock_unlock(&g_cc_lock);
			strncpy(result, "250 reload cc keywords OK", length);
			return;
		}
		if (0 == strcmp("content", argv[1])) {
			pengine = keyword_engine_init(g_charset_path, g_content_path);
			if (NULL == pengine) {
				strncpy(result, "550 fail to init content keyword engine",
					length);
				return;
			}
			pthread_rwlock_wrlock(&g_content_lock);
			keyword_engine_free(g_content_engine);
			g_content_engine = pengine;
			pthread_rwlock_unlock(&g_content_lock);
			strncpy(result, "250 reload content keywords OK", length);
			return;
		}
		if (0 == strcmp("attachment", argv[1])) {
			pengine = keyword_engine_init(g_charset_path, g_attachment_path);
			if (NULL == pengine) {
				strncpy(result, "550 fail to init attachment keyword engine",
					length);
				return;
			}
			pthread_rwlock_wrlock(&g_attachment_lock);
			keyword_engine_free(g_attachment_engine);
			g_attachment_engine = pengine;
			pthread_rwlock_unlock(&g_attachment_lock);
			strncpy(result, "250 reload attachment keywords OK", length);
			return;
		}
		snprintf(result, length, "550 unkown parameter %s", argv[1]);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


