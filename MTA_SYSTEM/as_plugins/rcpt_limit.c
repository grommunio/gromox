#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_RCPT_LIMIT			36

typedef BOOL (*WHITELIST_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);

static SPAM_STATISTIC spam_statistic;
static WHITELIST_QUERY ip_whitelist_query;
static WHITELIST_QUERY domain_whitelist_query;


DECLARE_API;

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop, 
    CONNECTION *pconnection, char *reason, int length);

static void console_talk(int argc, char **argv, char *result, int length);

static int g_max_rcpt;
static int g_block_interval;
static char g_config_file[256];
static char g_return_reason[1024];

BOOL AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char temp_buff[64];
	char *str_value, *psearch;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		ip_whitelist_query = (WHITELIST_QUERY)query_service(
								"ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[rcpt_limit]: fail to get \"ip_whitelist_query\" "
					"service\n");
			return FALSE;
		}
		domain_whitelist_query = (WHITELIST_QUERY)query_service(
								"domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[rcpt_limit]: fail to get \"domain_whitelist_query\" "
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
		pconfig_file = config_file_init2(NULL, temp_path);
		if (NULL == pconfig_file) {
			printf("[rcpt_limit]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "MAX_RCPT_NUM");
		if (NULL == str_value) {
			g_max_rcpt = 256;
			config_file_set_value(pconfig_file, "MAX_RCPT_NUM", "256");
		} else {
			g_max_rcpt = atoi(str_value);
			if (g_max_rcpt <= 0) {
				g_max_rcpt = 256;
				config_file_set_value(pconfig_file, "MAX_RCPT_NUM", "256");
			}
		}
		printf("[rcpt_limit]: maximum rcpt number is %d\n", g_max_rcpt);
		str_value = config_file_get_value(pconfig_file, "BLOCK_INTERVAL");
		if (NULL == str_value) {
			g_block_interval = 60*60;
			config_file_set_value(pconfig_file, "BLOCK_INTERVAL", "1hour");
		} else {
			g_block_interval = atoitvl(str_value);
			if (g_block_interval < 0) {
				g_block_interval = 0;
				config_file_set_value(pconfig_file, "BLOCK_INTERVAL","0second");
			}
		}
		itvltoa(g_block_interval, temp_buff);
		printf("[rcpt_limit]: block interval is %s\n", temp_buff);
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000036 too many rcpt addresses");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[rcpt_limit]: return string is \"%s\"\n", g_return_reason);
		config_file_free(pconfig_file);
        /* invoke register_judge for registering judge of mail envelop */
        if (FALSE == register_judge(envelop_judge)) {
			printf("[rcpt_limit]: failed to register judge function\n");
            return FALSE;
        }
		register_talk(console_talk);
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
	return TRUE;
}

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop,
    CONNECTION *pconnection, char *reason, int length)
{
	char rcpt_buff[256];
	char *pdomain;
	int rcpt_count;
	
	
	if (TRUE == penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == ip_whitelist_query(pconnection->client_ip)) {
		return MESSAGE_ACCEPT;
	}
	pdomain = strchr(penvelop->from, '@');
	pdomain ++;
	if (TRUE == domain_whitelist_query(pdomain)) {
		return MESSAGE_ACCEPT;
	}
	rcpt_count = 0;
	while (MEM_END_OF_FILE != mem_file_readline(
		&penvelop->f_rcpt_to, rcpt_buff, 256)) {
		rcpt_count ++;
	}
	if (rcpt_count > g_max_rcpt) {
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_RCPT_LIMIT);
		}
		ip_filter_add(pconnection->client_ip, g_block_interval);
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}
	return MESSAGE_ACCEPT;
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	int block_interval;
	int max_rcpt, len;
	CONFIG_FILE *pfile;
	char help_string[] = "250 rcpt limit help information:\r\n"
						 "\t%s info\r\n"
						 "\t    --printf rcpt limit's information\r\n"
						 "\t%s set max-rcpt <number>\r\n"
						 "\t    --set the maximum rcpt number\r\n"
						 "\t%s set block-interval <interval>\r\n"
						 "\t    --set the block interval of client ip";
	
	if (1 == argc) {
	    strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		len = snprintf(result, length, "250 %s information:\r\n"
								 "\tmaximum rcpt                     %d\r\n"
								 "\tblock interval                   ",
								 argv[0], g_max_rcpt);
		itvltoa(g_block_interval, result + len);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("max-rcpt", argv[2])) {
		max_rcpt = atoi(argv[3]);
		if (max_rcpt <= 0) {
			snprintf(result, length, "550 illegal number %s", argv[3]);
		} else {
			pfile = config_file_init2(NULL, g_config_file);
			if (NULL == pfile) {
				strncpy(result, "550 fail to open config file", length);
				return;
			}
			config_file_set_value(pfile, "MAX_RCPT_NUM", argv[3]);
			if (FALSE == config_file_save(pfile)) {
				strncpy(result, "550 fail to save config file", length);
				config_file_free(pfile);
				return;
			}
			g_max_rcpt = max_rcpt;
			strncpy(result, "250 max-rcpt set OK", length);
		}
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("block-interval", argv[2])) {
		block_interval = atoitvl(argv[3]);
		if (block_interval < 0) {
			snprintf(result, length, "550 illegal interval %s", argv[3]);
		} else {
			pfile = config_file_init2(NULL, g_config_file);
			if (NULL == pfile) {
				strncpy(result, "550 fail to open config file", length);
				return;
			}
			config_file_set_value(pfile, "BLOCK_INTERVAL", argv[3]);
			if (FALSE == config_file_save(pfile)) {
				strncpy(result, "550 fail to save config file", length);
				config_file_free(pfile);
				return;
			}
			g_block_interval = block_interval;
			strncpy(result, "250 block-interval set OK", length);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;

}


