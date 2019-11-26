/*
 *  special protection is a plugin that audits some "frequent rcpt" receivers
 *  of system and make these receiever visible by other anti-spamming plugins,
 *  these plugins then can use some special methods to protect these mailbox.
 *  these mothod may cause system to refuse some normal email, so we call them
 *  special protection, and only apply to some users.
 *  for these receivers, we also audit source IP, and if certain IP address sends too
 *  many mails to these receivers, such IP address will be blocked by system IP address filter
 */
#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROTECTION_BLOCK			1

typedef BOOL (*SPECIAL_PROTECTION_AUDIT)(char*);
typedef BOOL (*WHITELIST_QUERY)(char*);
typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static SPECIAL_PROTECTION_AUDIT special_protection_audit;
static SPECIAL_PROTECTION_AUDIT protection_ip_audit;
static SPAM_STATISTIC			spam_statistic;
static CHECK_TAGGING            check_tagging;
static WHITELIST_QUERY			ip_whitelist_query;
static WHITELIST_QUERY			domain_whitelist_query;

DECLARE_API;

static int special_protection(int context_ID, MAIL_ENTITY *pmail, 
    CONNECTION *pconnection, char *reason, int length);

static void console_talk(int argc, char **argv, char *result, int length);
	
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
			printf("[special_protection]: fail to get "
				"\"ip_whitelist_query\" service\n");
			return FALSE;
		}
		domain_whitelist_query = (WHITELIST_QUERY)query_service(
									"domain_whitelist_query");
		if (NULL == domain_whitelist_query) {
			printf("[special_protection]: fail to get "
				"\"domain_whitelist_query\" service\n");
			return FALSE;
		}
		special_protection_audit = (SPECIAL_PROTECTION_AUDIT)query_service(
									"special_protection_audit");
		if (NULL == special_protection_audit) {
			printf("[special_protection]: fail to get "
					"\"special_protection_audit\" service\n");
			return FALSE;
		}
		protection_ip_audit = (SPECIAL_PROTECTION_AUDIT)query_service(
								"protection_ip_audit");
		if (NULL == protection_ip_audit) {
			printf("[special_protection]: fail to get "
					"\"protection_ip_audit\" service\n");
			return FALSE;
		}
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[special_protection]: fail to get "
					"\"check_tagging\" service\n");
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
			printf("[special_protection]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "BLOCK_INTERVAL");
		if (NULL == str_value) {
			g_block_interval = 60*60;
			config_file_set_value(pconfig_file, "BLOCK_INTERVAL", "1hour");
		} else {
			g_block_interval = atoitvl(str_value);
			if (g_block_interval < 0) {
				g_block_interval = 60*60;
				config_file_set_value(pconfig_file, "BLOCK_INTERVAL", "1hour");
			}
		}
		itvltoa(g_block_interval, temp_buff);
		printf("[special_protection]: block interval is %s\n", temp_buff);
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "000001 you have sent too many mails to "
					"some clients, your ip will be blocked in %s");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[special_protection]: return string is \"%s\"\n", g_return_reason);
		config_file_free(pconfig_file);
        /* invoke register_auditor for registering auditor of mail head */
        if (FALSE == register_auditor(special_protection)) {
			printf("[special_protection]: fail to register statistic "
				"function!!!\n");
            return FALSE;
        }
		register_talk(console_talk);
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
	return TRUE;
}

static int special_protection(int context_ID, MAIL_ENTITY *pmail,
    CONNECTION *pconnection, char *reason, int length)
{
	char temp_buff[1024];
	char tag_val[256];
	char *pdomain;
	int buff_len;
	int tag_len, val_len;
	BOOL is_hint;
	
	if (TRUE == pmail->penvelop->is_outbound ||
		TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == ip_whitelist_query(pconnection->client_ip)) {
		return MESSAGE_ACCEPT;
	}
	pdomain = strchr(pmail->penvelop->from, '@');
	pdomain ++;
	/* ignore system mails */
	if (0 == strncasecmp(pmail->penvelop->from, "system-", 7) &&
		0 == strcasecmp(pdomain, "system.mail")) {
		return MESSAGE_ACCEPT;
	}
	if (TRUE == domain_whitelist_query(pdomain)) {
		return MESSAGE_ACCEPT;
	}
	is_hint = FALSE;
	while (MEM_END_OF_FILE != mem_file_readline(
		&pmail->penvelop->f_rcpt_to, temp_buff, 256)) {
		/* ignore spam involved mails */
		if (0 == strncasecmp(temp_buff, "spam-", 5)) {
			return MESSAGE_ACCEPT;
		}
		if (FALSE == special_protection_audit(temp_buff)) {
			is_hint = TRUE;
		}
	}
	if (FALSE == is_hint) {
		return MESSAGE_ACCEPT;
	}
	if (g_block_interval > 0 &&
		FALSE == protection_ip_audit(pconnection->client_ip)) {
		if (TRUE == check_tagging(pmail->penvelop->from,
			&pmail->penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			ip_filter_add(pconnection->client_ip, g_block_interval);
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_PROTECTION_BLOCK);
			}
			itvltoa(g_block_interval, temp_buff);
			snprintf(reason, length, g_return_reason, temp_buff);
			return MESSAGE_REJECT;
		}
	}
	if (0 == strcmp(pmail->penvelop->from, "none@none")) {
		return MESSAGE_ACCEPT;
	}
	/* check if From is same as that in envelop */
	buff_len = mem_file_get_total_length(&pmail->phead->f_mime_from);
	if (buff_len > 0 && buff_len < 1024) {
		mem_file_read(&pmail->phead->f_mime_from, temp_buff, 1023);
		temp_buff[buff_len] = '\0';
		if (NULL == search_string(temp_buff, pmail->penvelop->from, buff_len)) {
			goto DUBIOUS_MAIL;
		}
	} else {
		goto DUBIOUS_MAIL;
	}
	buff_len = mem_file_get_total_length(&pmail->phead->f_mime_to);
	if (0 == buff_len) {
		buff_len = mem_file_get_total_length(&pmail->phead->f_mime_cc);
		if (0 == buff_len) {
			goto DUBIOUS_MAIL;
		}
		if (buff_len < 1024) {
			mem_file_read(&pmail->phead->f_mime_cc, temp_buff, 1023);
			temp_buff[buff_len] = '\0';
		}
	} else if (buff_len < 1024) {
		mem_file_read(&pmail->phead->f_mime_to, temp_buff, 1023);
		temp_buff[buff_len] = '\0';
	}
	if (buff_len < 1024  && NULL == strchr(temp_buff, '@')) {
		goto DUBIOUS_MAIL;
	}
	while (MEM_END_OF_FILE !=  mem_file_read(&pmail->phead->f_others, &tag_len,
		sizeof(int))) {
		if (tag_len <= 255) {
			mem_file_read(&pmail->phead->f_others, tag_val, tag_len);
			if (0 == strncasecmp("Received", tag_val, 8)) {
				return MESSAGE_ACCEPT;
			}
		} else {
			mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR, tag_len,
				MEM_FILE_SEEK_CUR);
		}
		mem_file_read(&pmail->phead->f_others, &val_len, sizeof(int));
		mem_file_seek(&pmail->phead->f_others, MEM_FILE_READ_PTR, val_len,
			MEM_FILE_SEEK_CUR);
	}
DUBIOUS_MAIL:
	mark_context_spam(context_ID);
	return MESSAGE_ACCEPT;
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	int block_interval, len;
	CONFIG_FILE *pfile;
	char help_string[] = "250 special protection help information:\r\n"
						 "\t%s info\r\n"
						 "\t    -- print special protection's information\r\n"
						 "\t%s set block-interval <interval>\r\n"
						 "\t    -- set the block interval of special protection";
	
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
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("block-interval", argv[2])) {
		block_interval = atoitvl(argv[3]);
		if (block_interval <= 0) {
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


