#include <errno.h>
#include <string.h>
#include "config_file.h"
#include <gromox/as_common.h>
#include "mail_func.h"
#include "util.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <spf2/spf.h>
#include <stdio.h>


#define SPAM_STATISTIC_SPF_FILTER			23

typedef BOOL (*WHITELIST_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);

static int spf_statistic(int context_ID, MAIL_WHOLE *pmail,
    CONNECTION *pconnection, char *reason, int length);

DECLARE_API;

static SPAM_STATISTIC spam_statistic;
static WHITELIST_QUERY ip_whitelist_query;
static WHITELIST_QUERY domain_whitelist_query;
static char g_return_string[1024];
static SPF_server_t *g_spf_server;

BOOL AS_LibMain(int reason, void **ppdata)
{
	char file_name[256];
	char temp_path[256];
	CONFIG_FILE *pconfig_file;
	char *str_value, *psearch;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		
		ip_whitelist_query = (WHITELIST_QUERY)
			query_service("ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[spf_filter]: failed to get service \"ip_whitelist_query\"\n");
			return FALSE;
		}
		domain_whitelist_query = (WHITELIST_QUERY)
			query_service("domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[spf_filter]: failed to get service \"domain_whitelist_query\"\n");
			return FALSE;
		}
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init2(NULL, temp_path);
		if (NULL == pconfig_file) {
			printf("[spf_filter]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000023 client IP address does not"
						" match the SPF record of your domain");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[spf_filter]: return string is \"%s\"\n", g_return_string);
		config_file_free(pconfig_file);
        g_spf_server = SPF_server_new(SPF_DNS_CACHE, 0);
		if (NULL == g_spf_server) {
			printf("[spf_filter]: fail to create libspf2 config\n");
			return FALSE;
		}
        if (FALSE == register_statistic(spf_statistic)) {
			SPF_server_free(g_spf_server);
			g_spf_server = NULL;
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
		if (NULL != g_spf_server) {
			SPF_server_free(g_spf_server);
			g_spf_server = NULL;
		}
        return TRUE;
    }
    return TRUE;
}

static int spf_statistic(int context_ID, MAIL_WHOLE *pmail,
    CONNECTION *pconnection, char *reason, int length)
{
	int tag_len;
	int val_len;
	int buff_len;
	char *pdomain;
	char temp_ip[16];
	SPF_result_t result;
	char mime_from[1024];
	char from_buff[1024];
	char temp_buff[1024];
	EMAIL_ADDR email_address;
	SPF_request_t *spf_request;
	SPF_response_t *spf_response;
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == ip_whitelist_query(pconnection->client_ip)) {
		return MESSAGE_ACCEPT;
	}
	buff_len = mem_file_get_total_length(&pmail->phead->f_mime_from);
	if (buff_len > 0 && buff_len < 1024) {
		mem_file_read(&pmail->phead->f_mime_from, from_buff, 1024);
		parse_email_addr(&email_address, from_buff);
		if ('\0' == email_address.local_part[0]
			|| '\0' == email_address.domain[0]) {
			return MESSAGE_ACCEPT;	
		}
		sprintf(mime_from, "%s@%s",
			email_address.local_part,
			email_address.domain);
	} else {
		mime_from[0] = '\0';
	}
	if ('\0' == pmail->penvelop->from[0]) {
		if ('\0' != mime_from[0]) {
			strcpy(from_buff, mime_from);
		} else {
			return MESSAGE_ACCEPT;
		}
	} else {
		pdomain = strchr(pmail->penvelop->from, '@') + 1;
		if (TRUE == domain_whitelist_query(pdomain)) {
			return MESSAGE_ACCEPT;
		}
		strcpy(from_buff, pmail->penvelop->from);
	}
	spf_request = SPF_request_new(g_spf_server);
	if (NULL == spf_request) {
		return MESSAGE_ACCEPT;
	}
	if (SPF_request_set_ipv4_str(
		spf_request, pconnection->client_ip)
		|| SPF_request_set_helo_dom(
		spf_request, pmail->penvelop->hello_domain)
		|| SPF_request_set_env_from(spf_request, from_buff)) {
		SPF_request_free(spf_request);
		return MESSAGE_ACCEPT;
	}
	SPF_request_query_mailfrom(spf_request, &spf_response);
	result = SPF_response_result(spf_response);
	SPF_response_free(spf_response);
	SPF_request_free(spf_request);
	if (SPF_RESULT_NONE == result && '\0' != mime_from[0]
		&& 0 != strcasecmp(mime_from, from_buff)) {
		spf_request = SPF_request_new(g_spf_server);
		if (NULL == spf_request) {
			return MESSAGE_ACCEPT;
		}
		if (SPF_request_set_ipv4_str(
			spf_request, pconnection->client_ip)
			|| SPF_request_set_helo_dom(
			spf_request, pmail->penvelop->hello_domain)
			|| SPF_request_set_env_from(spf_request, mime_from)) {
			SPF_request_free(spf_request);
			return MESSAGE_ACCEPT;
		}
		SPF_request_query_mailfrom(spf_request, &spf_response);
		result = SPF_response_result(spf_response);
		SPF_response_free(spf_response);
		SPF_request_free(spf_request);
	}
	if (SPF_RESULT_FAIL != result) {
		return MESSAGE_ACCEPT;
	}
	while (MEM_END_OF_FILE != mem_file_read(
		&pmail->phead->f_others, &tag_len, sizeof(int))) {
		if (8 == tag_len) {
			mem_file_read(&pmail->phead->f_others, temp_buff, tag_len);
			if (0 == strncasecmp("Received", temp_buff, 8)) {
				mem_file_read(&pmail->phead->f_others,
					&val_len, sizeof(int));
				if (val_len > 1023) {
					return MESSAGE_REJECT;
				}
				mem_file_read(&pmail->phead->f_others, temp_buff, val_len);
				temp_buff[val_len] = '\0';
				if (NULL == extract_ip(temp_buff, temp_ip) ||
					0 == strcmp(temp_ip, "127.0.0.1")) {
					continue;
				}
				spf_request = SPF_request_new(g_spf_server);
				if (NULL == spf_request) {
					return MESSAGE_ACCEPT;
				}
				if (SPF_request_set_ipv4_str(
					spf_request, temp_ip) ||
					SPF_request_set_helo_dom(spf_request,
					pmail->penvelop->hello_domain) ||
					SPF_request_set_env_from(
					spf_request, from_buff)) {
					SPF_request_free(spf_request);
					return MESSAGE_ACCEPT;
				}
				SPF_request_query_mailfrom(spf_request, &spf_response);
				result = SPF_response_result(spf_response);
				SPF_response_free(spf_response);
				SPF_request_free(spf_request);
				if (SPF_RESULT_NONE == result && '\0' != mime_from[0]
					&& 0 != strcasecmp(mime_from, from_buff)) {
					spf_request = SPF_request_new(g_spf_server);
					if (NULL == spf_request) {
						return MESSAGE_ACCEPT;
					}
					if (SPF_request_set_ipv4_str(
						spf_request, temp_ip) ||
						SPF_request_set_helo_dom(spf_request,
						pmail->penvelop->hello_domain) ||
						SPF_request_set_env_from(
						spf_request, mime_from)) {
						SPF_request_free(spf_request);
						return MESSAGE_ACCEPT;
					}
					SPF_request_query_mailfrom(spf_request, &spf_response);
					result = SPF_response_result(spf_response);
					SPF_response_free(spf_response);
					SPF_request_free(spf_request);
				}
				if (SPF_RESULT_FAIL != result) {
					return MESSAGE_ACCEPT;
				} else {
					continue;
				}
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
	if (NULL != spam_statistic) {
		spam_statistic(SPAM_STATISTIC_SPF_FILTER);
	}
	strncpy(reason, g_return_string, length);
	return MESSAGE_REJECT;
}
