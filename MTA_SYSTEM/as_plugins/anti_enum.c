#include "as_common.h"
#include "config_file.h"
#include <stdio.h>

#define SPAM_STATISTIC_ANTI_ENUM			21

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*WHITELIST_QUERY)(char*);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPAM_STATISTIC	spam_statistic;
static WHITELIST_QUERY	domain_whitelist_query;
static CHECK_TAGGING check_tagging;


DECLARE_API;

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop, 
    CONNECTION *pconnection, char *reason, int length);

static void console_talk(int argc, char **argv, char *result, int length);

static int g_min_rcpt;
static char g_config_file[256];
static char g_return_reason[1024];

BOOL AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		domain_whitelist_query = (WHITELIST_QUERY)query_service(
									"domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[anti_enum]: fail to get \"domain_whitelist_query\" "
				"service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[anti_enum]: fail to get \"check_tagging\" service\n");
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
			printf("[anti_enum]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "MIN_RCPT_NUM");
		if (NULL == str_value) {
			g_min_rcpt = 4;
			config_file_set_value(pconfig_file, "MIN_RCPT_NUM", "4");
		} else {
			g_min_rcpt = atoi(str_value);
			if (g_min_rcpt <= 1) {
				g_min_rcpt = 4;
				config_file_set_value(pconfig_file, "MIN_RCPT_NUM", "4");
			}
		}
		printf("[anti_enum]: minimum rcpt number is %d\n", g_min_rcpt);
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000021 you are now enumerating user "
				"accounts!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[anti_enum]: return string is %s\n", g_return_reason);
		if (FALSE == config_file_save(pconfig_file)) {
			printf("[anti_enum]: fail to save config file\n");
			config_file_free(pconfig_file);
			return FALSE;
		}
		config_file_free(pconfig_file);
        /* invoke register_judge for registering judge of mail envelop */
        if (FALSE == register_judge(envelop_judge)) {
			printf("[anti_enum]: fail to register judge function!!!\n");
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
	char *pdomain;
	char rcpt_buff[256];
	char first_alphabet;
	int rcpt_count, rcpt_num;
	
	if (TRUE == penvelop->is_outbound || TRUE == penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	rcpt_num = 0;
	rcpt_count = 1;
	first_alphabet = '\0';
	while (MEM_END_OF_FILE != mem_file_readline(
		&penvelop->f_rcpt_to, rcpt_buff, 256)) {
		if ('\0' == first_alphabet) {
			first_alphabet = rcpt_buff[0];
			pdomain = strchr(rcpt_buff, '@');
			if (NULL == pdomain) {
				return MESSAGE_ACCEPT;
			}
			pdomain ++;
			if (TRUE == domain_whitelist_query(pdomain)) {
				return MESSAGE_ACCEPT;
			}
		} else {
			if (rcpt_buff[0] == first_alphabet) {
				rcpt_count ++;
			}
		}
		rcpt_num ++;
	}
	if (rcpt_count >= g_min_rcpt && rcpt_num == rcpt_count) {
		if (TRUE == check_tagging(penvelop->from, &penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_ANTI_ENUM);
			}
			strncpy(reason, g_return_reason, length);
			return MESSAGE_REJECT;
		}
	}
	return MESSAGE_ACCEPT;
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	int min_rcpt;
	CONFIG_FILE *pfile;
	char help_string[] = "250 anti enumeration help information:\r\n"
						 "\t%s info\r\n"
						 "\t    --print minimum rcpt number\r\n"
						 "\t%s set min-rcpt <number>\r\n"
						 "\t    --set the minimum rcpt number";
	
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
		snprintf(result, length, "250 %s information:\r\n"
								 "\tminimum rcpt                     %d",
								 argv[0], g_min_rcpt);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("min-rcpt", argv[2])) {
		min_rcpt = atoi(argv[3]);
		if (min_rcpt <= 1) {
			snprintf(result, length, "550 illegal number %s", argv[3]);
		} else {
			pfile = config_file_init(g_config_file);
			if (NULL == pfile) {
				strncpy(result, "550 fail to open config file", length);
				return;
			}
			config_file_set_value(pfile, "MIN_RCPT_NUM", argv[3]);
			if (FALSE == config_file_save(pfile)) {
				strncpy(result, "550 fail to save config file", length);
				config_file_free(pfile);
				return;
			}
			g_min_rcpt = min_rcpt;
			strncpy(result, "250 min-rcpt set OK", length);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;

}


