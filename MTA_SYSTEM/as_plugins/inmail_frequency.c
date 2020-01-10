#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_INMAIL_FREQUENCY         2

typedef BOOL (*WHITELIST_QUERY)(char*);
typedef BOOL (*INMAIL_FREQUENCY_AUDIT)(char*);
typedef void (*SPAM_STATISTIC)(int);

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
    CONNECTION *pconnection, char *reason, int length);

static void console_talk(int argc, char **argv, char *result, int length);

DECLARE_API;

static WHITELIST_QUERY ip_whitelist_query;
static WHITELIST_QUERY domain_whitelist_query;
static INMAIL_FREQUENCY_AUDIT inmail_frequency_audit;
static SPAM_STATISTIC spam_statistic;

static int g_block_interval;
static char g_config_file[256];
static char g_return_string[1024];

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

		inmail_frequency_audit = (INMAIL_FREQUENCY_AUDIT)query_service(
								"inmail_frequency_audit");
		if (NULL == inmail_frequency_audit) {
			printf("[inmail_frequency]: failed to get service \"inmail_frequency_audit\"\n");
			return FALSE;
		}
		ip_whitelist_query = (WHITELIST_QUERY)query_service(
								"ip_whitelist_query");
		if (NULL == ip_whitelist_query) {
			printf("[inmail_frequency]: failed to get service \"ip_whitelist_query\"\n");
			return FALSE;
		}
		domain_whitelist_query = (WHITELIST_QUERY)query_service(
									"domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[inmail_frequency]: failed to get service \"domain_whitelist_query\"\n");
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
			printf("[inmail_frequency]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "BLOCK_INTERVAL");
		if (NULL == str_value) {
			g_block_interval = 3600;
			config_file_set_value(pconfig_file, "BLOCK_INTERVAL", "1hour");
		} else {
			g_block_interval = atoitvl(str_value);
		}
		itvltoa(g_block_interval, temp_buff);
		printf("[inmail_frequency]: block interval is %s\n", temp_buff);
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000002 your IP address has sent too many "
				"mails, will be blocked for a while");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[inmail_frequency]: return string is \"%s\"\n", g_return_string);
		config_file_free(pconfig_file);
        /* invoke register_statistic for registering statistic of mail */
        if (FALSE == register_statistic(mail_statistic)) {
            return FALSE;
        }
        register_talk(console_talk);
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
    return TRUE;
}


static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
    CONNECTION *pconnection, char *reason, int length)
{
	char *pdomain;
	
	/* ignore the inbound mails */
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == ip_whitelist_query(pconnection->client_ip)) {
		return MESSAGE_ACCEPT;
	}
	pdomain = strchr(pmail->penvelop->from, '@') + 1;
	if (TRUE == domain_whitelist_query(pdomain)) {
		return MESSAGE_ACCEPT;
	}
	if (FALSE == inmail_frequency_audit(pconnection->client_ip)) {
		ip_filter_add(pconnection->client_ip, g_block_interval);
		if (NULL != spam_statistic) {
			spam_statistic(SPAM_STATISTIC_INMAIL_FREQUENCY);
		}
		strncpy(reason, g_return_string, length);
		return MESSAGE_REJECT;
	}
	return MESSAGE_ACCEPT;
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	int block_interval, len;
	CONFIG_FILE *pfile;
	char help_string[] = "250 inmail frequency help information:\r\n"
	                     "\t%s info\r\n"
						 "\t    --printf inmail frequency's information\r\n"
						 "\t%s set block-interval <interval>\r\n"
						 "\t    --set the block interval of inmail frequency";

	if (1 == argc) {
	    strncpy(result, "550 too few arguments", length);
		return;
				  }
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0]);
	    result[length - 1] ='\0';
	    return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "info")) {
		len = snprintf(result, length, "250 %s information:\r\n"
		                         "\tblock interval                   ",
								 argv[0]);
		itvltoa(g_block_interval, result + len);
		return;
	}
	if (0 == strcmp("set", argv[1])) {
		if (4 == argc && 0 == strcmp("block-interval", argv[2])) {
			block_interval = atoitvl(argv[3]);
			if (block_interval <= 0) {
				snprintf(result, length, "550 illegal interval %s", argv[3]);
				return;
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
				config_file_free(pfile);
				g_block_interval = block_interval;
				strncpy(result, "250 block-interval set OK", length);
				return;
			}
		}
		snprintf(result, length, "550 invalid argument %s", argv[2]);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

