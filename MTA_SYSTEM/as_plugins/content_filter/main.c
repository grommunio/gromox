#include "util.h"
#include "uri_rbl.h"
#include "mail_func.h"
#include "uri_cache.h"
#include "as_common.h"
#include "config_file.h"
#include <string.h>
#include <stdio.h>

#define SPAM_STATISTIC_DOMAIN_FILTER		18
#define SPAM_STATISTIC_URI_RBL				26
#define SPAM_STATISTIC_FROM_FILTER			35


enum {
	CONTEXT_URI_NONE,
	CONTEXT_URI_HAS,
	CONTEXT_URI_IGNORE
};

typedef struct _URI_INFORMATION {
	int type;
	char uri[256];
} URI_INFORMATION;

typedef BOOL (*WHITELIST_QUERY)(char*);
typedef BOOL (*STRING_FILTER_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop,
	CONNECTION *pconnection, char *reason, int length);

static int head_auditor(int context_ID, MAIL_ENTITY *pmail,
		CONNECTION *pconnection, char *reason, int length);

static int paragraph_filter(int action, int block_ID,
	MAIL_BLOCK* mail_blk, char* reason, int length);

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
	CONNECTION *pconnection, char *reason, int length);

static void console_talk(int argc, char **argv, char *result, int length);

static const char* extract_uri(const char *in_buff, int length, char *uri);

DECLARE_API;

static WHITELIST_QUERY ip_whitelist_query;
static WHITELIST_QUERY domain_whitelist_query;
static STRING_FILTER_QUERY from_filter_query;
static STRING_FILTER_QUERY domain_filter_query;
static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
static CHECK_TAGGING check_tagging;

static BOOL g_immediate_reject;
static char g_config_file[256];
static char g_return_string[1024];
static URI_INFORMATION *g_context_list = NULL;

BOOL AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char temp_buff[64];
	char file_name[256];
	char temp_path[256];
	char surbl_dns[256];
	char uribl_dns[256];
	char *str_value, *psearch;
	int black_size, black_valid;
	
	/* path conatins the config files directory */
	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[content_filter]: fail to get "
					"\"check_retrying\" service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[content_filter]: fail to get "
					"\"check_tagging\" service\n");
			return FALSE;
		}
		ip_whitelist_query = (WHITELIST_QUERY)query_service(
							"ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[content_filter]: fail to get "
				"\"ip_whitelist_query\" service\n");
			return FALSE;
		}
		domain_whitelist_query = (WHITELIST_QUERY)
			query_service("domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[content_filter]: fail to get "
				"\"domain_whitelist_query\" service\n");
			return FALSE;
		}
		from_filter_query = (STRING_FILTER_QUERY)
				query_service("from_filter_query");
		if (NULL == from_filter_query) {
			printf("[content_filter]: fail to get "
				"\"from_filter_query\" service\n");
			return FALSE;
		}
		domain_filter_query = (STRING_FILTER_QUERY)
				query_service("domain_filter_query");
		if (NULL == domain_filter_query) {
			printf("[content_filter]: fail to get "
				"\"domain_filter_query\" service\n");
			return FALSE;
		}
		spam_statistic = (SPAM_STATISTIC)
			query_service("spam_statistic");
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		strcpy(g_config_file, temp_path);
		pconfig_file = config_file_init(temp_path);
		if (NULL == pconfig_file) {
			printf("[content_filter]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(
			pconfig_file, "BLACKLIST_CACHE_SIZE");
		if (NULL == str_value) {
			black_size = 10000;
			config_file_set_value(pconfig_file,
				"BLACKLIST_CACHE_SIZE", "10000");
		} else {
			black_size = atoi(str_value);
		}
		printf("[content_filter]: blacklist cache size is %d\n", black_size);
		str_value = config_file_get_value(pconfig_file,
						"BLACKLIST_VALID_INTERVAL");
		if (NULL == str_value) {
			black_valid = 24*60*60;
			config_file_set_value(pconfig_file,
					"BLACKLIST_VALID_INTERVAL", "1day");
		} else {
			black_valid = atoitvl(str_value);
		}
		itvltoa(black_valid, temp_buff);
		printf("[content_filter]: blacklist "
			"cache interval is %s\n", temp_buff);
		str_value = config_file_get_value(pconfig_file, "IMMEDIATE_REJECT");
		if (NULL == str_value || 0 == strcasecmp(str_value, "FALSE")) {
			g_immediate_reject = FALSE;
			printf("[content_filter]: message can "
				"be resent if uri spam is found\n");
		} else {
			g_immediate_reject = TRUE;
			printf("[content_filter]: spam message"
					" will be reject immediately\n");
		}
		str_value = config_file_get_value(pconfig_file, "SURBL_DNS");
		if (NULL == str_value || 0 == strcasecmp(str_value, "NULL")) {
			surbl_dns[0] = '\0';
		} else {
			ltrim_string(surbl_dns);
			rtrim_string(surbl_dns);
			strncpy(surbl_dns, str_value, 255);
			surbl_dns[255] = '\0';
		}
		str_value = config_file_get_value(pconfig_file, "URIBL_DNS");
		if (NULL == str_value || 0 == strcasecmp(str_value, "NULL")) {
			uribl_dns[0] = '\0';
		} else {
			ltrim_string(uribl_dns);
			rtrim_string(uribl_dns);
			strncpy(uribl_dns, str_value, 255);
			uribl_dns[255] = '\0';
		}
		if (FALSE == config_file_save(pconfig_file)) {
			printf("[content_filter]: fail to save config file\n");
			config_file_free(pconfig_file);
			return FALSE;
		}
		config_file_free(pconfig_file);
		g_context_list = malloc(sizeof(URI_INFORMATION)*get_context_num());
		if (NULL == g_context_list) {
			printf("[content_filter]: fail to allocate context list memory\n");
			return FALSE;
		}
		sprintf(temp_path, "%s/cctld.txt", get_data_path());
		uri_rbl_init(temp_path, surbl_dns, uribl_dns);
		uri_cache_init(black_size, black_valid);
		if (0 != uri_rbl_run() || 0 != uri_cache_run()) {
			free(g_context_list);
			g_context_list = NULL;
			return FALSE;
		}
		if (FALSE == register_judge(envelop_judge)) {
			return FALSE;
		}
		if (FALSE == register_auditor(head_auditor)) {
			return FALSE;
		}
		if (FALSE == register_filter("text/plain", paragraph_filter) ||
			FALSE == register_filter("text/html", paragraph_filter)) {
			return FALSE;
		}
		/* invoke register_statistic for registering statistic of mail */
		if (FALSE == register_statistic(mail_statistic)) {
			return FALSE;
		}
		register_talk(console_talk);
		return TRUE;
	case PLUGIN_FREE:
		uri_cache_stop();
		uri_rbl_stop();
		uri_cache_free();
		uri_rbl_free();
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
	char *pdomain;

	memset(g_context_list + context_ID, 0 , sizeof(URI_INFORMATION));
	if (TRUE == penvelop->is_outbound || TRUE == penvelop->is_relay) {
		g_context_list[context_ID].type = CONTEXT_URI_IGNORE;
		return MESSAGE_ACCEPT;
	}
	pdomain = strchr(penvelop->from, '@') + 1;
	if (TRUE == ip_whitelist_query(pconnection->client_ip) ||
		TRUE == domain_whitelist_query(pdomain)) {
		g_context_list[context_ID].type = CONTEXT_URI_IGNORE;
		return MESSAGE_ACCEPT;
	}
	g_context_list[context_ID].type = CONTEXT_URI_NONE;
	return MESSAGE_ACCEPT;
}

static int head_auditor(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection,  char *reason, int length)
{
	char uri[256];
	char buff[1024];
	int tag_len, val_len;
	EMAIL_ADDR email_addr;
	
	if (CONTEXT_URI_IGNORE == g_context_list[context_ID].type) {
		return MESSAGE_ACCEPT;
	}
	while (MEM_END_OF_FILE != mem_file_read(
		&pmail->phead->f_others, &tag_len, sizeof(int))) {
		if (6 == tag_len || 8 == tag_len || 27 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("Sender", buff, tag_len) ||
				0 == strncasecmp("Reply-To", buff, tag_len) ||
				0 == strncasecmp("Disposition-Notification-To",
				buff, tag_len)) {
				mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
				if (val_len >= 1024) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others, buff, val_len);
				buff[val_len] = '\0';
				parse_email_addr(&email_addr, buff);
				sprintf(buff, "%s@%s", email_addr.local_part,
					email_addr.domain);
				if (TRUE == from_filter_query(buff)) {
					snprintf(reason, length, "000035 address %s"
							" in mail header is forbidden", buff);
					if (NULL!= spam_statistic) {
						spam_statistic(SPAM_STATISTIC_FROM_FILTER);
					}
					return MESSAGE_REJECT;
				}
				if (TRUE == domain_filter_query(email_addr.domain)) {
					snprintf(reason, length, "000018 domain %s in "
						"mail header is forbidden", email_addr.domain);
					if (NULL!= spam_statistic) {
						spam_statistic(SPAM_STATISTIC_DOMAIN_FILTER);
					}
					return MESSAGE_REJECT;
				}
				continue;
			}
		} else if (16 == tag_len) {
			mem_file_read(&pmail->phead->f_others, buff, tag_len);
			if (0 == strncasecmp("List-Unsubscribe", buff, 16)) {
				mem_file_read(&pmail->phead->f_others,
					&val_len, sizeof(int));
				if (val_len > 1024) {
					return MESSAGE_ACCEPT;
				}
				mem_file_read(&pmail->phead->f_others, buff, val_len);
				if (NULL == extract_uri(buff, val_len, uri)) {
					return MESSAGE_ACCEPT;
				}
				if (TRUE == domain_filter_query(uri)) {
					snprintf(reason, length, "000018 domain %s "
							"in mail header is forbidden", uri);
					if (NULL!= spam_statistic) {
						spam_statistic(SPAM_STATISTIC_DOMAIN_FILTER);
					}
					return MESSAGE_REJECT;
				}
				if (TRUE == uri_rbl_judge(uri, reason, length)) {
					return MESSAGE_ACCEPT;
				}
				if (FALSE == g_immediate_reject) {
					if (FALSE == check_retrying(pconnection->client_ip,
						pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {	
						if (NULL!= spam_statistic) {
							spam_statistic(SPAM_STATISTIC_URI_RBL);
						}
						return MESSAGE_RETRYING;
					} else {
						return MESSAGE_ACCEPT;
					}
				} else {
					if (NULL!= spam_statistic) {
						spam_statistic(SPAM_STATISTIC_URI_RBL);
					}
					return MESSAGE_REJECT;
				}
				continue;
			}
		} else {
			mem_file_seek(&pmail->phead->f_others,
				MEM_FILE_READ_PTR, tag_len, MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others,
			&val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others,
			MEM_FILE_READ_PTR, val_len, MEM_FILE_SEEK_CUR);
	}
	return MESSAGE_ACCEPT;
}

static int paragraph_filter(int action, int context_ID,
	MAIL_BLOCK* mail_blk, char* reason, int length)
{
	int len;
	int addr_len;
	char *pdomain;
	char *paddress;
	const char *ptr;
	const char *ptr1;
	char tmp_buff[256];
	MAIL_ENTITY mail_entity;
	CONNECTION *pconnection;
	
	switch (action) {
	case ACTION_BLOCK_NEW:
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_PROCESSING:
		if (CONTEXT_URI_NONE != g_context_list[context_ID].type) {
			return MESSAGE_ACCEPT;
		}
		if (FALSE == mail_blk->is_parsed) {
			ptr = mail_blk->original_buff;
			len = mail_blk->original_length;
		} else {
			ptr = mail_blk->parsed_buff;
			len = mail_blk->parsed_length;
		}
		while (ptr1 = extract_uri(ptr, len, tmp_buff)) {
			if (TRUE == domain_filter_query(tmp_buff)) {
				snprintf(reason, length, "000018 domain %s "
					"in mail content is forbidden", tmp_buff);
				if (NULL!= spam_statistic) {
					spam_statistic(SPAM_STATISTIC_DOMAIN_FILTER);
				}
				return MESSAGE_REJECT;
			}
			if (CONTEXT_URI_NONE == g_context_list[context_ID].type) {
				strcpy(g_context_list[context_ID].uri, tmp_buff);
				g_context_list[context_ID].type = CONTEXT_URI_HAS;
			}
			len -= ptr1 - ptr;
			ptr = ptr1;
		}
		if (FALSE == mail_blk->is_parsed) {
			ptr = mail_blk->original_buff;
			len = mail_blk->original_length;
		} else {
			ptr = mail_blk->parsed_buff;
			len = mail_blk->parsed_length;
		}
		while (paddress = find_mail_address((void*)ptr, len, &addr_len)) {
			if (addr_len < sizeof(tmp_buff)) {
				memcpy(tmp_buff, paddress, addr_len);
				tmp_buff[addr_len] = '\0';
				if (TRUE == from_filter_query(tmp_buff)) {
					snprintf(reason, length, "000035 address %s "
						"in mail content is forbidden", tmp_buff);
					if (NULL!= spam_statistic) {
						spam_statistic(SPAM_STATISTIC_FROM_FILTER);
					}
					return MESSAGE_REJECT;
				}
				pdomain = strchr(tmp_buff, '@');
				if (NULL != pdomain && TRUE ==
					domain_filter_query(pdomain + 1)) {
					snprintf(reason, length, "000018 domain %s "
						"in mail content is forbidden", pdomain + 1);
					if (NULL!= spam_statistic) {
						spam_statistic(SPAM_STATISTIC_DOMAIN_FILTER);
					}
					return MESSAGE_REJECT;
				}
			}
			len = ptr + len - (paddress + addr_len);
			ptr = paddress + addr_len;
		}
		return MESSAGE_ACCEPT;
	case ACTION_BLOCK_FREE:
		return MESSAGE_ACCEPT;
	}
}

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
	CONNECTION *pconnection, char *reason, int length)
{
	int tmp_len;
	char *pdomain;
	char tmp_buff[1024];
	EMAIL_ADDR email_addr;
	
	if (CONTEXT_URI_IGNORE == g_context_list[context_ID].type) {
		return MESSAGE_ACCEPT;
	}
	pdomain = strchr(pmail->penvelop->from, '@');
	pdomain ++;
	if (0 != strcmp(pmail->penvelop->from, "none@none") &&
		FALSE == uri_rbl_judge(pdomain, reason, length)) {
		goto SPAM_FOUND;
	}
	memset(&email_addr, 0, sizeof(EMAIL_ADDR));
	tmp_len = mem_file_read(&pmail->phead->f_mime_from, tmp_buff, 1024);
	if (MEM_END_OF_FILE != tmp_len) {
		parse_email_addr(&email_addr, tmp_buff);
		sprintf(tmp_buff, "%s@%s", email_addr.local_part, email_addr.domain);
		if (TRUE == from_filter_query(tmp_buff)) {
			snprintf(reason, length, "000035 address %s "
				"in mail header is forbidden", tmp_buff);
			if (NULL!= spam_statistic) {
				spam_statistic(SPAM_STATISTIC_FROM_FILTER);
			}
			return MESSAGE_REJECT;
		}
		if (TRUE == domain_filter_query(email_addr.domain)) {
			snprintf(reason, length, "000018 domain %s in "
				"mail header is forbidden", email_addr.domain);
			if (NULL!= spam_statistic) {
				spam_statistic(SPAM_STATISTIC_DOMAIN_FILTER);
			}
			return MESSAGE_REJECT;
		}
		if ('\0' != email_addr.domain[0] && 0 != strcasecmp(
			pdomain, email_addr.domain) && FALSE ==
			uri_rbl_judge(email_addr.domain, reason, length)) {
			goto SPAM_FOUND;
		}
	}
	if (CONTEXT_URI_HAS != g_context_list[context_ID].type) {
		return MESSAGE_ACCEPT;
	}
	if (0 != strcasecmp(pdomain, g_context_list[context_ID].uri) &&
		0 != strcasecmp(email_addr.domain, g_context_list[context_ID].uri)) {
		if (TRUE == domain_filter_query(g_context_list[context_ID].uri)) {
			snprintf(reason, length, "000018 domain %s in mail "
				"content is forbidden", g_context_list[context_ID].uri);
			if (NULL!= spam_statistic) {
				spam_statistic(SPAM_STATISTIC_DOMAIN_FILTER);
			}
			return MESSAGE_REJECT;
		}
		if (FALSE == uri_rbl_judge(g_context_list[context_ID].uri,
			reason, length)) {
			goto SPAM_FOUND;
		}
	}
	return MESSAGE_ACCEPT;
	
SPAM_FOUND:
	if (TRUE == check_tagging(pmail->penvelop->from,
		&pmail->penvelop->f_rcpt_to)) {
		mark_context_spam(context_ID);
		return MESSAGE_ACCEPT;
	} else {
		if (FALSE == g_immediate_reject) {
			if (FALSE == check_retrying(pconnection->client_ip,
				pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {	
				if (NULL!= spam_statistic) {
					spam_statistic(SPAM_STATISTIC_URI_RBL);
				}
				return MESSAGE_RETRYING;
			} else {
				return MESSAGE_ACCEPT;
			}
		} else {
			if (NULL!= spam_statistic) {
				spam_statistic(SPAM_STATISTIC_URI_RBL);
			}
			return MESSAGE_REJECT;
		}
	}
}

static int htoi(char *s)
{
	int c;
	int value;

	c = ((unsigned char *)s)[0];
	if (isupper(c)) {
		c = tolower(c);
	}
	value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;
	c = ((unsigned char *)s)[1];
	if (isupper(c)) {
		c = tolower(c);
	}
	value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;
	return value;
}

static int url_decode(char *str, int len)
{
	char *dest = str;
	char *data = str;

	while (len--) {
		if ('+' == *data) {
			*dest = ' ';
		} else if ('%' == *data && len >= 2
			&& isxdigit((int)*(data + 1)) &&
			isxdigit((int)*(data + 2))) {
			*dest = (char)htoi(data + 1);
			data += 2;
			len -= 2;
		} else {
			*dest = *data;
		}
		data++;
		dest++;
	}
	*dest = '\0';
	return dest - str;
}

static const char* extract_uri(const char *in_buff, int length, char *uri)
{
	char url[256];
	char *d1, *d2, *d3;
	char *ptr, *presult;
	char *pinterrogation;
	char *pslash, *pcolon;
	int len, buff_len, url_len;

	ptr = (char*)in_buff;
	buff_len = length;
	while (TRUE) {
		presult = find_url(ptr, buff_len, &url_len);
		if (NULL == presult) {
			return NULL;
		}
		if (url_len > 255) {
			url_len = 255;
		}
		/* trim the "http://", "https://" or "www." of found url */
		if (url_len >= 7 && 0 == strncasecmp(presult, "http://", 7)) {
			presult += 7;
			url_len -= 7;
		} else if (url_len >= 8 &&
			0 == strncasecmp(presult, "https://", 8)) {
			presult += 8;
			url_len -= 8;
		}
		if (url_len >= 4 && 0 == strncasecmp(presult, "www.", 4)) {
			presult += 4;
			url_len -= 4;
		}
		memcpy(url, presult, url_len);
		url[url_len] = '\0';
		url_decode(url, url_len);
		if (0 == strncasecmp(url, "w3.org", 6) ||
			0 == strncasecmp(url, "w3c.org", 7) ||
			0 == strncasecmp(url, "internet.e-mail", 15) ||
			'\0' == url[0]) {
			ptr = presult + url_len;
			buff_len = length - (ptr - in_buff);
			continue;
		}
		/* uri such as 192.168.0.1.mail.com will not be considered as ip uri */
		if (url == extract_ip(url, uri)) {
			len = strlen(uri);
			if ('\0' == url[len] || '/' == url[len] ||
				':' == url[len] || '?' == url[len]) {
				return presult + url_len;
			}
		}
		pslash = strchr(url, '/');
		if (NULL != pslash) {
			*pslash = '\0';
			url_len = pslash - url;
		}
		pcolon = strchr(url, ':');
		if (NULL != pcolon) {
			*pcolon = '\0';
			url_len = pcolon - url;
		}
		pinterrogation = strchr(url, '?');
		if (NULL != pinterrogation) {
			*pinterrogation = '\0';
			url_len = pinterrogation - url;
		}
		d1 = memrchr(url, '.', url_len);
		if (NULL == d1) {
			ptr = presult + url_len;
			buff_len = length - (ptr - in_buff);
			continue;
		}
		d2 = memrchr(url, '.', d1 - url);
		if (NULL == d2) {
			strncpy(uri, url, 255);
		} else {
			if (TRUE == uri_rbl_check_cctld(d2 + 1)) {
				d3 = memrchr(url, '.', d2 - url);
				if (NULL == d3) {
					strncpy(uri, url, 255);
				} else {
					strncpy(uri, d3 + 1, 255);
				}
			} else {
				strncpy(uri, d2 + 1, 255);
			}
		}
		uri[255] = '\0';
		return presult + url_len;;	
	}
	return NULL;
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	int interval, len;
	CONFIG_FILE *pfile;
	char black_buff[32];
	char help_string[] = "250 uri rbl help information:\r\n"
	                     "\t%s info\r\n"
						 "\t    --printf uri rbl's information\r\n"
						 "\t%s set blacklist-interval <interval>\r\n"
						 "\t    --set the valid interval of blacklist uri\r\n"
						 "\t%s set immediate-reject [TRUE|FALSE]\r\n"
						 "\t    --set the reject type of spam message\r\n"
						 "\t%s reload\r\n"
						 "\t    --reload the cctld from file\r\n"
						 "\t%s dump blacklist <path>\r\n"
						 "\t    --dump cache of blacklist uris to file";

	if (1 == argc) {
	    strncpy(result, "550 too few arguments", length);
		return;
				  }
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0],
				argv[0], argv[0], argv[0]);
	    result[length - 1] ='\0';
	    return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		itvltoa(uri_cache_get_param(URI_CACHE_BLACK_INTERVAL), black_buff);
		len = snprintf(result, length, "250 %s information:\r\n"
								 "\tblacklist cache size             %d\r\n"
								 "\tblacklist interval               %s\r\n"
								 "\timmediate reject                 %s\r\n"
								 "\tsurbl-dns                        %s\r\n"
								 "\turibl-dns                        %s",
			                     argv[0],
								 uri_cache_get_param(URI_CACHE_BLACK_SIZE),
								 black_buff,
								 g_immediate_reject?"TRUE":"FALSE",
								 uri_rbl_get_dns(URI_RBL_SURBL),
								 uri_rbl_get_dns(URI_RBL_URIBL));
		return;
	}
	if (0 == strcmp("set", argv[1])) {
		if (4 == argc && 0 == strcmp("blacklist-interval", argv[2])) {
			interval = atoitvl(argv[3]);
			if (interval <= 0) {
				snprintf(result, length, "550 illegal interval %s", argv[3]);
				return;
			} else {
				pfile = config_file_init(g_config_file);
				if (NULL == pfile) {
					strncpy(result, "550 fail to open config file", length);
					return;
				}
				config_file_set_value(pfile,
						"BLACKLIST_VALID_INTERVAL", argv[3]);
				if (FALSE == config_file_save(pfile)) {
					strncpy(result, "550 fail to save config file", length);
					config_file_free(pfile);
					return;
				}
				config_file_free(pfile);
				uri_cache_set_param(URI_CACHE_BLACK_INTERVAL, interval);
				strncpy(result, "250 blacklist-interval set OK", length);
				return;
			}
		}
		if (4 == argc && 0 == strcmp("immediate-reject", argv[2])) {
			if (0 == strcasecmp(argv[3], "TRUE")) {
				pfile = config_file_init(g_config_file);
				if (NULL == pfile) {
					strncpy(result, "550 fail to open config file", length);
					return;
				}
				config_file_set_value(pfile, "IMMEDIATE_REJECT", "TRUE");
				if (FALSE == config_file_save(pfile)) {
					strncpy(result, "550 fail to save config file", length);
					config_file_free(pfile);
					return;
				}
				config_file_free(pfile);
				g_immediate_reject = TRUE;
				strncpy(result, "250 immediate-reject set OK", length);
			} else if (0 == strcasecmp(argv[3], "FALSE")) {
				pfile = config_file_init(g_config_file);
				if (NULL == pfile) {
					strncpy(result, "550 fail to open config file", length);
					return;
				}
				config_file_set_value(pfile, "IMMEDIATE_REJECT", "FALSE");
				if (FALSE == config_file_save(pfile)) {
					strncpy(result, "550 fail to save config file", length);
					config_file_free(pfile);
					return;
				}
				config_file_free(pfile);
				g_immediate_reject = FALSE;
				strncpy(result, "250 immediate-reject set OK", length);
			} else {
				strncpy(result, "550 argument should be TRUE or FALSE", length);
			}
			return;
		}
		snprintf(result, length, "550 invalid argument %s", argv[2]);
		return;
	}
	if (4 == argc && 0 == strcmp("dump", argv[1])) {
		if (0 == strcmp("blacklist", argv[2])) {
			if (TRUE == uri_cache_dump_black(argv[3])) {
				snprintf(result, length, "250 blacklist cache is dumped OK");
			} else {
				snprintf(result, length, "550 fail to dump blacklist cache");
			}
			return;
		}
		snprintf(result, length, "550 invalid argument %s", argv[2]);
		return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "reload")) {
		if (FALSE == uri_rbl_refresh()) {
			strncpy(result, "550 cctld file error", length);
		} else {
			strncpy(result, "250 cctld list reload OK", length);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}
