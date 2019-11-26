#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include "dns_rbl.h"
#include "rbl_cache.h"
#include <stdio.h>

#define SPAM_STATISTIC_DNS_RBL         37

typedef BOOL (*WHITELIST_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_RETRYING)(const char*, const char*, MEM_FILE*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
    CONNECTION *pconnection, char *reason, int length);

static void console_talk(int argc, char **argv, char *result, int length);

DECLARE_API;

static WHITELIST_QUERY ip_whitelist_query;
static WHITELIST_QUERY domain_whitelist_query;
static SPAM_STATISTIC spam_statistic;
static CHECK_RETRYING check_retrying;
static CHECK_TAGGING check_tagging;

static char g_config_file[256];

BOOL AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char temp_buff[64];
	char *str_value, *psearch;
	int normal_size, black_size;
	int normal_valid, black_valid;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		check_retrying = (CHECK_RETRYING)query_service("check_retrying");
		if (NULL == check_retrying) {
			printf("[dns_rbl]: fail to get \"check_retrying\" service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[dns_rbl]: fail to get \"check_tagging\" service\n");
			return FALSE;
		}
		ip_whitelist_query = (WHITELIST_QUERY)query_service(
							"ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[dns_rbl]: fail to get \"ip_whitelist_query\" service\n");
			return FALSE;
		}
		domain_whitelist_query = (WHITELIST_QUERY)query_service(
				                "domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[dns_rbl]: fail to get \"domain_whitelist_query\" "
					"service\n");
			return FALSE;
		}
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		strcpy(g_config_file, temp_path);
		pconfig_file = config_file_init(temp_path);
		if (NULL == pconfig_file) {
			printf("[dns_rbl]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "NORMAL_CACHE_SIZE");
		if (NULL == str_value) {
			normal_size = 10000;
			config_file_set_value(pconfig_file, "NORMAL_CACHE_SIZE", "10000");
		} else {
			normal_size = atoi(str_value);
		}
		printf("[dns_rbl]: normal cache size is %d\n", normal_size);
		str_value = config_file_get_value(pconfig_file,"NORMAL_VALID_INTERVAL");
		if (NULL == str_value) {
			normal_valid = 3600;
			config_file_set_value(pconfig_file,
				"NORMAL_VALID_INTERVAL", "1hour");
		} else {
			normal_valid = atoitvl(str_value);
		}
		itvltoa(normal_valid, temp_buff);
		printf("[dns_rbl]: normal cache interval is %s\n", temp_buff);
		str_value = config_file_get_value(pconfig_file, "BLACKLIST_CACHE_SIZE");
		if (NULL == str_value) {
			black_size = 10000;
			config_file_set_value(pconfig_file, "BLACKLIST_CACHE_SIZE","10000");
		} else {
			black_size = atoi(str_value);
		}
		printf("[dns_rbl]: blacklist cache size is %d\n", black_size);
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
		printf("[dns_rbl]: blacklist cache interval is %s\n", temp_buff);
		config_file_free(pconfig_file);
		sprintf(temp_path, "%s/%s.txt", get_data_path(), file_name);
		dns_rbl_init(temp_path);
		rbl_cache_init(normal_size, normal_valid, black_size, black_valid);
		if (0 != dns_rbl_run() || 0 != rbl_cache_run()) {
			return FALSE;
		}
        /* invoke register_statistic for registering statistic of mail */
        if (FALSE == register_statistic(mail_statistic)) {
            return FALSE;
        }
        register_talk(console_talk);
        return TRUE;
    case PLUGIN_FREE:
		rbl_cache_stop();
		dns_rbl_stop();
		rbl_cache_free();
		dns_rbl_free();
        return TRUE;
    }
    return TRUE;
}


static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
    CONNECTION *pconnection, char *reason, int length)
{
	char *pdomain;
	int result;
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == ip_whitelist_query(pconnection->client_ip)) {
		return MESSAGE_ACCEPT;
	}
	pdomain = strchr(pmail->penvelop->from, '@');
	pdomain ++;
	if (TRUE == domain_whitelist_query(pdomain)) {
		return MESSAGE_ACCEPT;
	}
	/* ignore system messages */
	if (0 == strncasecmp(pmail->penvelop->from, "system-", 7) &&
		0 == strcasecmp(pdomain, "system.mail")) {
		return MESSAGE_ACCEPT;
	}
	result = rbl_cache_query(pconnection->client_ip, reason, length);
	if (RBL_CACHE_NORMAL == result) {
		return MESSAGE_ACCEPT;
	} else if (RBL_CACHE_BLACK == result) {
		if (TRUE == check_tagging(pmail->penvelop->from,
			&pmail->penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (FALSE == check_retrying(pconnection->client_ip,
				pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {
				if (NULL!= spam_statistic) {
					spam_statistic(SPAM_STATISTIC_DNS_RBL);
				}
				return MESSAGE_RETRYING;
			} else {
				return MESSAGE_ACCEPT;
			}
		}
	}
	if (FALSE == dns_rbl_judge(pconnection->client_ip, reason, length)) {
		rbl_cache_add(pconnection->client_ip, RBL_CACHE_BLACK, reason);
		if (TRUE == check_tagging(pmail->penvelop->from,
			&pmail->penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (FALSE == check_retrying(pconnection->client_ip,
				pmail->penvelop->from, &pmail->penvelop->f_rcpt_to)) {	
				if (NULL!= spam_statistic) {
					spam_statistic(SPAM_STATISTIC_DNS_RBL);
				}
				return MESSAGE_RETRYING;
			} else {
				return MESSAGE_ACCEPT;
			}
		}
	}
	rbl_cache_add(pconnection->client_ip, RBL_CACHE_NORMAL, NULL);
	return MESSAGE_ACCEPT;
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	int interval;
	CONFIG_FILE *pfile;
	char black_buff[32];
	char normal_buff[32];
	char help_string[] = "250 dns rbl help information:\r\n"
	                     "\t%s info\r\n"
						 "\t    --printf dns rbl's information\r\n"
						 "\t%s set normal-interval <interval>\r\n"
						 "\t    --set the valid interval of normal ip\r\n"
						 "\t%s set blacklist-interval <interval>\r\n"
						 "\t    --set the valid interval of blacklist ip\r\n"
						 "\t%s reload\r\n"
						 "\t    --reload the rbl list from file\r\n"
						 "\t%s dump normal <path>\r\n"
						 "\t    --dump cache of normal ips to file\r\n"
						 "\t%s dump blacklist <path>\r\n"
						 "\t    --dump cache of blacklist ips to file";

	if (1 == argc) {
	    strncpy(result, "550 too few arguments", length);
		return;
				  }
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0],
				argv[0], argv[0], argv[0]);
	    result[length - 1] ='\0';
	    return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		itvltoa(rbl_cache_get_param(RBL_CACHE_NORMAL_INTERVAL), normal_buff);
		itvltoa(rbl_cache_get_param(RBL_CACHE_BLACK_INTERVAL), black_buff);
		snprintf(result, length, "250 %s information:\r\n"
								 "\tnormal cache size                %d\r\n"
								 "\tnormal interval                  %s\r\n"
								 "\tblacklist cache size             %d\r\n"
								 "\tblacklist interval               %s",
			                     argv[0],
								 rbl_cache_get_param(RBL_CACHE_NORMAL_SIZE),
								 normal_buff,
								 rbl_cache_get_param(RBL_CACHE_BLACK_SIZE),
								 black_buff);
		return;
	}
	if (0 == strcmp("set", argv[1])) {
		if (4 == argc && 0 == strcmp("normal-interval", argv[2])) {
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
				config_file_set_value(pfile, "NORMAL_VALID_INTERVAL", argv[3]);
				if (FALSE == config_file_save(pfile)) {
					strncpy(result, "550 fail to save config file", length);
					config_file_free(pfile);
					return;
				}
				config_file_free(pfile);
				rbl_cache_set_param(RBL_CACHE_NORMAL_INTERVAL, interval);
				strncpy(result, "250 normal-interval set OK", length);
				return;
			}
		}
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
				rbl_cache_set_param(RBL_CACHE_BLACK_INTERVAL, interval);
				strncpy(result, "250 blacklist-interval set OK", length);
				return;
			}
		}
		snprintf(result, length, "550 invalid argument %s", argv[2]);
		return;
	}
	if (4 == argc && 0 == strcmp("dump", argv[1])) {
		if (0 == strcmp("normal", argv[2])) {
			if (TRUE == rbl_cache_dump_normal(argv[3])) {
				snprintf(result, length, "250 normal cache is dumped OK");
			} else {
				snprintf(result, length, "550 fail to dump normal cache");
			}
			return;
		}
		if (0 == strcmp("blacklist", argv[2])) {
			if (TRUE == rbl_cache_dump_black(argv[3])) {
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
		if (FALSE == dns_rbl_refresh()) {
			strncpy(result, "550 rbl list file error", length);
		} else {
			strncpy(result, "250 rbl list reload OK", length);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

