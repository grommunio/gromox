#include "util.h"
#include "as_common.h"
#include "mail_func.h"
#include "config_file.h"
#include <stdio.h>
#include <archive.h>
#include <archive_entry.h>

#define SPAM_STATISTIC_ATTACH_FILTER		17

#define CENTRALFILEHEADERSIGNATURE			0x02014b50

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*WHITELIST_QUERY)(char*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC    spam_statistic;
static WHITELIST_QUERY   ip_whitelist_query;
static CHECK_TAGGING     check_tagging;

DECLARE_API;

static int  attach_name_filter(int action, int context_ID, MAIL_BLOCK* mail_blk, 
    char* reason, int length);

static BOOL extract_attachment_name(MEM_FILE *pmem_file, char *file_name);

static char g_return_reason[1024];

static BOOL *g_context_list;


static char *g_attachment_list[] ={
	"exe", "com", "bat", "ps1", "scr", "cab",
	"js", "jse", "vbs", "vbe", "wsf", "jar"};

int AS_LibMain(int reason, void **ppdata, char *path)
{
	char file_name[256];
	char temp_path[256];
	char *str_value, *psearch;
	CONFIG_FILE *pconfig_file;
	
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
        ip_whitelist_query = (WHITELIST_QUERY)query_service(
				             "ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[attach_filter]: fail to get "
					"\"ip_whitelist_query\" service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[attach_filter]: fail to get \"check_tagging\" service\n");
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
			printf("[attach_filter]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason,
				"000017 %s file is not allowed as attachment");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[attach_filter]: return string is %s\n", g_return_reason);
		config_file_free(pconfig_file);
		g_context_list = malloc(get_context_num()*sizeof(BOOL));
		if (NULL == g_context_list) {
			printf("[attach_filter]: fail to allocate context list memory\n");
			return FALSE;	
		}
        /* invoke register_filter for registering all type of mime paragraph*/
        if (FALSE == register_filter(NULL , attach_name_filter)) {
			free(g_context_list);
			g_context_list = NULL;
			printf("[attach_filter]: fail to register filter function\n");
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


static int attach_name_filter(int action, int context_ID, MAIL_BLOCK* mail_blk, 
    char* reason, int length)
{
	char *pdot;
	int i, j, result;
	struct archive *a;
	const char *pstring;
	char file_name[1024];
	CONNECTION *pconnection;
	MAIL_ENTITY mail_entity;
	unsigned short name_length;
    char attachment_name[1024];
	struct archive_entry *entry;
	

    switch (action) {
    case ACTION_BLOCK_NEW:
		g_context_list[context_ID] = FALSE;
        return MESSAGE_ACCEPT;
    case ACTION_BLOCK_PROCESSING:
		if (TRUE == g_context_list[context_ID]) {
        	return MESSAGE_ACCEPT;
		}
		mail_entity = get_mail_entity(context_ID);
		if (TRUE == mail_entity.penvelop->is_relay) {
			return MESSAGE_ACCEPT;
		}
		pconnection = get_connection(context_ID);
		if (TRUE == ip_whitelist_query(pconnection->client_ip)) {
			g_context_list[context_ID] = TRUE;
			return MESSAGE_ACCEPT;
		}
        if (FALSE == extract_attachment_name(mail_blk->fp_mime_info,
			attachment_name)) {
			g_context_list[context_ID] = TRUE;
			return MESSAGE_ACCEPT;
		}
		decode_mime_string(attachment_name,
			strlen(attachment_name),
			file_name, sizeof(file_name));
		pdot = strrchr(file_name, '.');
		if (NULL == pdot) {
			g_context_list[context_ID] = TRUE;
			return MESSAGE_ACCEPT;
		}
		
		for (i=0; i<sizeof(g_attachment_list)/sizeof(char*); i++) {
			if (0 == strcasecmp(pdot + 1, g_attachment_list[i])) {
				if (TRUE == check_tagging(mail_entity.penvelop->from,
					&mail_entity.penvelop->f_rcpt_to)) {
					mark_context_spam(context_ID);
					g_context_list[context_ID] = TRUE;
					return MESSAGE_ACCEPT;
				} else {
					if (NULL!= spam_statistic) {
						spam_statistic(SPAM_STATISTIC_ATTACH_FILTER);
					}
					snprintf(reason, length, g_return_reason, g_attachment_list[i]);
					return MESSAGE_REJECT;
				}
			}
		}
		if (0 == strcasecmp(pdot + 1, "zip")) {
			if (FALSE == mail_blk->is_parsed) {
				g_context_list[context_ID] = TRUE;
				return MESSAGE_ACCEPT;
			}
			for (j=0; j<mail_blk->parsed_length; j++) {
				if (*(int*)(mail_blk->parsed_buff + j) == CENTRALFILEHEADERSIGNATURE) {
					name_length = *(unsigned short*)(mail_blk->parsed_buff + j + 28);
					if (name_length > 255) {
						name_length = 255;
					}
					memcpy(file_name, mail_blk->parsed_buff + j + 46, name_length);
					file_name[name_length] = '\0';
					pdot = strrchr(file_name, '.');
					if (NULL != pdot) {
						for (i=0; i<sizeof(g_attachment_list)/sizeof(char*); i++) {
							if (0 == strcasecmp(pdot + 1, g_attachment_list[i])) {
								if (TRUE == check_tagging(
									mail_entity.penvelop->from, &mail_entity.penvelop->f_rcpt_to)) {
									mark_context_spam(context_ID);
									g_context_list[context_ID] = TRUE;
									return MESSAGE_ACCEPT;
								} else {
									if (NULL!= spam_statistic) {
										spam_statistic(SPAM_STATISTIC_ATTACH_FILTER);
									}
									snprintf(reason, length, g_return_reason, g_attachment_list[i]);
									return MESSAGE_REJECT;
								}
							}
						}
					}
				}
			}
		} else if (0 == strcasecmp(pdot + 1, "gz") ||
			0 == strcasecmp(pdot + 1, "bz2") ||
			0 == strcasecmp(pdot + 1, "tar") ||
			0 == strcasecmp(pdot + 1, "tgz") ||
			0 == strcasecmp(pdot + 1, "tbz2") ||
			0 == strcasecmp(pdot + 1, "rar") ||
			0 == strcasecmp(pdot + 1, "7z") ||
			0 == strcasecmp(pdot + 1, "cab") ||
			0 == strcasecmp(pdot + 1, "xar") ||
			0 == strcasecmp(pdot + 1, "pax") ||
			0 == strcasecmp(pdot + 1, "cpio") ||
			0 == strcasecmp(pdot + 1, "iso") ||
			0 == strcasecmp(pdot + 1, "ar") ||
			0 == strcasecmp(pdot + 1, "lha") ||
			0 == strcasecmp(pdot + 1, "lzh")) {
			if (FALSE == mail_blk->is_parsed) {
				g_context_list[context_ID] = TRUE;
				return MESSAGE_ACCEPT;
			}
			a = archive_read_new();
			if (NULL == a) {
				g_context_list[context_ID] = TRUE;
				return MESSAGE_ACCEPT;
			}
			archive_read_support_filter_all(a);
			archive_read_support_format_all(a);
			result = archive_read_open_memory(
					a, mail_blk->parsed_buff,
					mail_blk->parsed_length);
			if (ARCHIVE_OK != result) {
				archive_read_free(a);
				g_context_list[context_ID] = TRUE;
				return MESSAGE_ACCEPT;
			}
			while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
				pstring = archive_entry_pathname(entry);
				if (NULL == pstring) {
					archive_read_data_skip(a);
					continue;
				}
				pdot = strrchr(pstring, '.');
				if (NULL == pdot) {
					archive_read_data_skip(a);
					continue;
				}
				for (i=0; i<sizeof(g_attachment_list)/sizeof(char*); i++) {
					if (0 == strcasecmp(pdot + 1,
						g_attachment_list[i])) {
						archive_read_free(a);
						if (TRUE == check_tagging(
							mail_entity.penvelop->from,
								&mail_entity.penvelop->f_rcpt_to)) {
							mark_context_spam(context_ID);
							g_context_list[context_ID] = TRUE;
							return MESSAGE_ACCEPT;
						} else {
							if (NULL!= spam_statistic) {
								spam_statistic(SPAM_STATISTIC_ATTACH_FILTER);
							}
							snprintf(reason, length, g_return_reason,
												g_attachment_list[i]);
							return MESSAGE_REJECT;
						}
					}
				}
				archive_read_data_skip(a);
			}
			archive_read_free(a);
		}
		g_context_list[context_ID] = TRUE;
		return MESSAGE_ACCEPT;
    case ACTION_BLOCK_FREE:
		g_context_list[context_ID] = FALSE;
        return MESSAGE_ACCEPT;
    }
    return MESSAGE_ACCEPT;
}

static BOOL extract_attachment_name(MEM_FILE *pmem_file, char *file_name)
{
	int temp_len;
	int tag_len, value_len;
	char tag[256], value[1024];
	char *ptr1, *ptr2;

	while (MEM_END_OF_FILE != mem_file_read(pmem_file, &tag_len,
			sizeof(int))) {
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
				ptr1 = search_string(value, "name=", value_len);
				if (NULL == ptr1) {
					continue;
				}
				ptr1 += 5;
				ptr2 = strchr(ptr1, ';');
				if (NULL == ptr2) {
					ptr2 = value + value_len;
				}
				temp_len = ptr2 - ptr1;
				memcpy(file_name, ptr1, temp_len);
				file_name[temp_len] = '\0';
				if ('"' == file_name[0]) {
					temp_len --;
					memcpy(file_name, file_name + 1, temp_len);
					file_name[temp_len] = '\0';
				}
				if ('"' == file_name[temp_len - 1]) {
					temp_len --;
					file_name[temp_len] = '\0';
				}
				ltrim_string(file_name);
				rtrim_string(file_name);
				temp_len = strlen(file_name);
				if (0 == strncasecmp(value, "application/zip", 15) &&
					0 != strcasecmp(file_name + temp_len - 4, ".zip")) {
					strcat(file_name, ".zip");
				}
				return TRUE;
				
			}
			if (0 == strcasecmp(tag, "Content-Disposition")) {
				ptr1 = search_string(value, "filename=", value_len);
				if (NULL == ptr1) {
					continue;
				}
				ptr1 += 9;
				ptr2 = strchr(ptr1, ';');
				if (NULL == ptr2) {
					ptr2 = value + value_len;
				}
				temp_len = ptr2 - ptr1;
				memcpy(file_name, ptr1, temp_len);
				file_name[temp_len] = '\0';
				if ('"' == file_name[0]) {
					temp_len --;
					memcpy(file_name, file_name + 1, temp_len);
					file_name[temp_len] = '\0';
				}
				if ('"' == file_name[temp_len - 1]) {
					temp_len --;
					file_name[temp_len] = '\0';
				}
				return TRUE;
			}
		}
    }
	return FALSE;
}
