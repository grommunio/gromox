#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_OUTMAIL_FREQUENCY			5


typedef BOOL (*OUTMAIL_FREQUENCY_AUDIT)(char*);
typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*WHITELIST_QUERY)(char*);

static BOOL (*check_virtual)(const char *username,
	const char *from, BOOL *pb_expanded, MEM_FILE *pfile);

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
    CONNECTION *pconnection, char *reason, int length);

static void console_talk(int argc, char **argv, char *result, int length);

DECLARE_API;

static OUTMAIL_FREQUENCY_AUDIT outmail_frequency_audit;
static SPAM_STATISTIC spam_statistic;
static WHITELIST_QUERY domain_whitelist_query;

static int g_block_interval;
static char g_config_file[256];
static char g_return_string_1[1024];
static char g_return_string_2[1024];

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
		
		check_virtual = query_service("check_virtual_mailbox");
		if (NULL == check_virtual) {
			printf("[outmail_frequency]: fail to get \"check_virtual_mailbox\" "
				"service\n");
			return FALSE;
		}
		outmail_frequency_audit = (OUTMAIL_FREQUENCY_AUDIT)query_service(
								"outmail_frequency_audit");
		if (NULL == outmail_frequency_audit) {
			printf("[outmail_frequency]: fail to get "
					"\"outmail_frequency_audit\" service\n");
			return FALSE;
		}
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		domain_whitelist_query =  (WHITELIST_QUERY)query_service(
									"domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[outmail_frequency]: fail to get "
				"\"domain_whitelist_query\" service\n");
			return FALSE;
		}
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		strcpy(g_config_file, temp_path);
		pconfig_file = config_file_init(temp_path);
		if (NULL == pconfig_file) {
			printf("[outmail_frequency]: config_file_init %s: %s\n", temp_path, strerror(errno));
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
		printf("[outmail_frequency]: block interval is %s\n", temp_buff);
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING_1");
		if (NULL == str_value) {
			strcpy(g_return_string_1, "000005 this account has sent too many "
				"mails, will be blocked for a while");
		} else {
			strcpy(g_return_string_1, str_value);
		}
		printf("[outmail_frequency]: return string 1 is %s\n",
				g_return_string_1);
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING_2");
		if (NULL == str_value) {
			strcpy(g_return_string_2, "000005 mail from address and account "
				"name differ");
		} else {
			strcpy(g_return_string_2, str_value);
		}
		printf("[outmail_frequency]: return string 2 is %s\n",
				g_return_string_2);
		if (FALSE == config_file_save(pconfig_file)) {
			printf("[outmail_frequency]: fail to save config file\n");
			config_file_free(pconfig_file);
			return FALSE;
		}
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
	BOOL b_expanded;
	MEM_FILE tmp_file;
	char rcpt_buff[256];
	const char *psrc_domain, *pdst_domain;
	
	/* ignore the inbound mails */
	if (TRUE == pmail->penvelop->is_relay ||
		FALSE == pmail->penvelop->is_outbound) {
		return MESSAGE_ACCEPT;
	}
	if (0 == strcmp(pmail->penvelop->from, "none@none")) {
		return MESSAGE_ACCEPT;
	}
	
	if (TRUE == pmail->penvelop->is_login &&
		0 != strcasecmp(pmail->penvelop->username, pmail->penvelop->from)) {
		mem_file_init(&tmp_file, pmail->penvelop->f_rcpt_to.allocator);
		check_virtual(pmail->penvelop->username,
			pmail->penvelop->from, &b_expanded, &tmp_file);
		if (TRUE != b_expanded) {
			mem_file_free(&tmp_file);
			strncpy(reason, g_return_string_2, length);
			return MESSAGE_REJECT;
		}
		while (MEM_END_OF_FILE != mem_file_readline(
			&tmp_file, rcpt_buff, 256)) {
			if (0 == strcasecmp(rcpt_buff, pmail->penvelop->username)) {
				mem_file_free(&tmp_file);
				goto CHECK_FREQUENCY;
			}
		}
		mem_file_free(&tmp_file);
		strncpy(reason, g_return_string_2, length);
		return MESSAGE_REJECT;
	}
	
CHECK_FREQUENCY:
	psrc_domain = strchr(pmail->penvelop->username, '@');
	if (NULL != psrc_domain) {
		psrc_domain ++;
		if (TRUE == domain_whitelist_query((char*)psrc_domain)) {
			return MESSAGE_ACCEPT;
		}
	}
	psrc_domain = strchr(pmail->penvelop->from, '@') + 1;
	if (TRUE == domain_whitelist_query((char*)psrc_domain)) {
		return MESSAGE_ACCEPT;
	}
	
	
	while (MEM_END_OF_FILE != mem_file_readline(
		&pmail->penvelop->f_rcpt_to, rcpt_buff, 256)) {
		pdst_domain = strchr(rcpt_buff, '@') + 1;
		if (0 == strcasecmp(pdst_domain, psrc_domain)) {
			continue;
		}
		if (FALSE == outmail_frequency_audit(pmail->penvelop->from)) {
			/* 
			 * if user uses client tools to send mail, block the account
			 * CAUSION!!! if user use webmail to send spam mail, smtp will
			 * not block such users, these users can only be blocked by webmail
			 * itself
			 */
			if (TRUE == pmail->penvelop->is_login) {
				user_filter_add(pmail->penvelop->username, g_block_interval);
			}
			if (NULL!= spam_statistic) {
				spam_statistic(SPAM_STATISTIC_OUTMAIL_FREQUENCY);
			}
			strncpy(reason, g_return_string_1, length);
			return MESSAGE_REJECT;
		 }
	}
	return MESSAGE_ACCEPT;
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	int block_interval, len;
	CONFIG_FILE *pfile;
	char help_string[] = "250 outmail frequency help information:\r\n"
	                     "\t%s info\r\n"
						 "\t    --printf outmail frequency's information\r\n"
						 "\t%s set block-interval <interval>\r\n"
						 "\t    --set the block interval of outmail frequency";

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
				pfile = config_file_init(g_config_file);
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

