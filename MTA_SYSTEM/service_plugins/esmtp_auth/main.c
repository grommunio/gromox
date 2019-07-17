#include "service_common.h"
#include "lib_buffer.h"
#include "config_file.h"
#include "service_auth.h"
#include "auth_cache.h"
#include "esmtp_auth.h"
#include "host_list.h"
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <stdio.h>

#define INVALID_BUFFER_SIZE		4096

DECLARE_API;

static char g_config_path[256];
static char g_invalid_buffer[INVALID_BUFFER_SIZE];
static int g_invalid_buffer_size;

static BOOL user_login_auth(const char* username, const char* passwd,
    char* reason, int length);

static void console_talk(int argc, char** argv, char *reslut, int length);

static void dump_invalid(const char *ip, int port);

BOOL SVC_LibMain(int reason, void** ppdata)
{
	char *str_val, *psearch;
    char cfg_path[256];
	char list_path[256];
	char file_name[256];
	char temp_buff[256];
	int cache_size;
	int scan_interval;
	int retrying_times;
    CONFIG_FILE *cfg_file;

    switch(reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(cfg_path, "%s/%s.cfg", get_config_path(), file_name);
		sprintf(list_path, "%s/%s.txt", get_data_path(), file_name);
		strcpy(g_config_path, cfg_path);
        if (NULL == (cfg_file = config_file_init(cfg_path))) {
            printf("[service_auth]: can not open config file %s\n", cfg_path);
            return FALSE;
        }
		str_val = config_file_get_value(cfg_file, "CACHE_SIZE");
		if (NULL == str_val) {
			cache_size = 0;
			config_file_set_value(cfg_file, "CACHE_SIZE", "0");
		} else {
			cache_size = atoi(str_val);
			if (cache_size < 0) {
				cache_size = 0;
				config_file_set_value(cfg_file, "CACHE_SIZE", "0");
			}
		}
		printf("[esmtp_auth]: cache size is %d\n", cache_size);
		str_val = config_file_get_value(cfg_file, "RETRYING_TIMES");
		if (NULL == str_val) {
			retrying_times = 2;
			config_file_set_value(cfg_file, "RETRYING_TIMES", "2");
		} else {
			retrying_times = atoi(str_val);
			if (retrying_times <= 0) {
				retrying_times = 2;
				config_file_set_value(cfg_file, "RETRYING_TIMES", "2");
			}
		}
		printf("[esmtp_auth]: retrying times is %d\n", retrying_times);
		str_val =  config_file_get_value(cfg_file, "SCAN_INTERVAL");
		if (NULL == str_val) {
			scan_interval = 60;
			config_file_set_value(cfg_file, "SCAN_INTERVAL", "1minute");
		} else {
			scan_interval = atoitvl(str_val);
			if (scan_interval <= 0) {
				scan_interval = 60;
				config_file_set_value(cfg_file, "SCAN_INTERVAL", "1minute");
			}
		}
		itvltoa(scan_interval, temp_buff);
		printf("[esmtp_auth]: scan interval is %s\n", temp_buff);
		config_file_save(cfg_file);
        config_file_free(cfg_file);
		
		auth_cache_init(cache_size);
		host_list_init(list_path, scan_interval);
		esmtp_auth_init(retrying_times);
		service_auth_init(get_context_num(), user_login_auth);
		if (0 != auth_cache_run()) {
			printf("[esmtp_auth]: fail to run auth cache module\n");
			return FALSE;
		}
		if (0 != host_list_run()) {
			printf("[esmtp_auth]: fail to run host list module\n");
			return FALSE;
		}
		if (0 != esmtp_auth_run()) {
			printf("[esmtp_auth]: fail to run esmtp auth module\n");
			return FALSE;
		}
		if (0 != service_auth_run()) {
			printf("[service_auth]: fail to run service auth module\n");
			return FALSE;
		}
        if (FALSE == register_service("auth_ehlo", service_auth_ehlo) ||
			FALSE == register_service("auth_process", service_auth_process) ||
			FALSE == register_service("auth_retrieve", service_auth_retrieve)||
			FALSE == register_service("auth_clear", service_auth_clear)) {
            printf("[service_auth]: fail to register auth services\n");
            return FALSE;
        }
        if (FALSE == register_talk(console_talk)) {
            printf("[service_auth]: fail to register console_talk\n");
            return FALSE;
        }
        return TRUE;

    case PLUGIN_FREE:
		service_auth_stop();
		esmtp_auth_stop();
		host_list_stop();
		auth_cache_stop();
		service_auth_free();
		esmtp_auth_free();
		host_list_free();
		auth_cache_free();
        return TRUE;
    }
    return FALSE;
}

/*
 *  smtp user login authentication, if fail give the reason
 *
 *  @param
 *      username [in]       the email address including the
 *                          domain
 *      passwd   [in]       the password of the user
 *      reason   [out]      contains the error message
 *
 *  @return
 *      TRUE            authenticate successfully
 *      FALSE           fail or error happens
 */
static BOOL user_login_auth(const char* username, const char* passwd,
    char* reason, int length)
{
	if (TRUE == auth_cache_login(username, passwd)) {
		return TRUE;
	}
	if (TRUE == esmtp_auth_login(username, passwd, reason, length)) {
		auth_cache_add(username, passwd);
		return TRUE;
	} else {
		return FALSE;
	}
}

static void console_talk(int argc, char** argv, char* result, int length)
{
	CONFIG_FILE *pfile;
	int scan_interval;
	int retrying_times;
	char str_interval[256];
	char help_string[] = "250 esmtp auth help information:\r\n"
						"\t%s info\r\n"
						"\t    --print the module information\r\n"
						"\t%s set retrying-times <times>\r\n"
						"\t    --set the auth retrying times\r\n"
						"\t%s set invalid-scan <interval>\r\n"
						"\t    --set invalid auth host scanning interval\r\n"
						"\t%s hosts reload\r\n"
						"\t    --reload auth hosts from list file\r\n"
						"\t%s echo invalid-hosts\r\n"
						"\t    --print the invalid auth host(s)";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0],
				argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp("info", argv[1])) {
		itvltoa(host_list_get_param(HOST_LIST_SCAN_INTERVAL), str_interval);
		snprintf(result, length,
				"250 remote delivery module information:\r\n"
				"\tretring times            %d\r\n"
				"\tinvalid-scan interval    %s\r\n"
				"\ttotal cache size         %d\r\n"
				"\tcurrent used items       %d",
				esmtp_auth_get_param(ESMTP_AUTH_RETRYING_TIMES),
				str_interval,
				auth_cache_get_param(AUTH_CACHE_TOTAL_SIZE),
				auth_cache_get_param(AUTH_CACHE_CURRENT_SIZE));
		return;
	}
	
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("retrying-times", argv[2])) {
		retrying_times = atoi(argv[3]);
		if (retrying_times <= 0) {
			snprintf(result, length, "550 invalid retrying-times %s", argv[3]);
			return;
		}
		pfile = config_file_init(g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 fail to open config file");
			return;
		}
		config_file_set_value(pfile, "RETRYING_TIMES", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		esmtp_auth_set_param(ESMTP_AUTH_RETRYING_TIMES, retrying_times);
		strncpy(result, "250 retrying-times set OK", length);
		return;
	}
	
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("invalid-scan", argv[2])) {
		scan_interval = atoitvl(argv[3]);
		if (scan_interval <=0 ) {
			snprintf(result, length, "550 invalid scan-interval %s", argv[3]);
			return;
		}
		pfile = config_file_init(g_config_path);
		if (NULL == pfile) {
			snprintf(result, length, "550 fail to open config file");
			return;
		}
		config_file_set_value(pfile, "SCAN_INTERVAL", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			snprintf(result, length, "550 fail to save config file");
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		host_list_set_param(HOST_LIST_SCAN_INTERVAL, scan_interval);
		strncpy(result, "250 invalid-scan set OK", length);
		return;
	}
	
	if (3 == argc && 0 == strcmp("hosts", argv[1]) &&
		0 == strcmp("reload", argv[2])) {
		if (TRUE == host_list_refresh()) {
			snprintf(result, length, "250 auth hosts list reload OK");
		} else {
			snprintf(result, length, "550 fail to reload auth hosts from "
				"list file");
		}
		return;
	}

	if (3 == argc && 0 == strcmp("echo", argv[1]) &&
		0 == strcmp("invalid-hosts", argv[2])) {
		g_invalid_buffer_size = 0;
		host_list_enum_invalid(dump_invalid);
		if (0 == g_invalid_buffer_size) {
			strncpy(result, "250 there's no invalid hosts", length);
		} else {
			g_invalid_buffer[g_invalid_buffer_size] = '\0';
			strncpy(result, g_invalid_buffer, length);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

static void dump_invalid(const char *ip, int port)
{
	if (g_invalid_buffer_size < INVALID_BUFFER_SIZE - strlen(ip) - 7) {
		g_invalid_buffer_size +=
			snprintf(g_invalid_buffer + g_invalid_buffer_size,
				INVALID_BUFFER_SIZE - g_invalid_buffer_size, "\t%s:%d\r\n",
				ip, port);
		}
}



