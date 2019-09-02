#include "service_common.h"
#include "config_file.h"
#include "rbl_cache.h"
#include "dns_rbl.h"
#include "util.h"
#include <stdio.h>
#include <string.h>

DECLARE_API;

static char g_config_file[256];

static void console_talk(int argc, char **argv, char *result, int length);

BOOL SVC_LibMain(int reason, void **ppdata)
{
	char tmp_path[256];
	char temp_buff[64];
	CONFIG_FILE *pfile;
	char file_name[256];
	char *str_value, *psearch;
	int normal_size, black_size;
	int normal_valid, black_valid;
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
	   
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init(tmp_path);
		if (NULL == pfile) {
			printf("[dns_rbl]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pfile, "NORMAL_CACHE_SIZE");
		if (NULL == str_value) {
			normal_size = 10000;
			config_file_set_value(file, "NORMAL_CACHE_SIZE", "10000");
		} else {
			normal_size = atoi(str_value);
		}
		printf("[dns_rbl]: normal cache size is %d\n", normal_size);
		str_value = config_file_get_value(pfile,"NORMAL_VALID_INTERVAL");
		if (NULL == str_value) {
			normal_valid = 3600;
			config_file_set_value(pfile,
				"NORMAL_VALID_INTERVAL", "1hour");
		} else {
			normal_valid = atoitvl(str_value);
		}
		itvltoa(normal_valid, temp_buff);
		printf("[dns_rbl]: normal cache interval is %s\n", temp_buff);
		str_value = config_file_get_value(pfile, "BLACKLIST_CACHE_SIZE");
		if (NULL == str_value) {
			black_size = 10000;
			config_file_set_value(pfile, "BLACKLIST_CACHE_SIZE","10000");
		} else {
			black_size = atoi(str_value);
		}
		printf("[dns_rbl]: blacklist cache size is %d\n", black_size);
		str_value = config_file_get_value(pfile,
						"BLACKLIST_VALID_INTERVAL");
		if (NULL == str_value) {
			black_valid = 24*60*60;
			config_file_set_value(pfile,
					"BLACKLIST_VALID_INTERVAL", "1day");
		} else {
			black_valid = atoitvl(str_value);
		}
		itvltoa(black_valid, temp_buff);
		printf("[dns_rbl]: blacklist cache interval is %s\n", temp_buff);
		if (FALSE == config_file_save(pfile)) {
			printf("[dns_rbl]: fail to save config file\n");
			config_file_free(pfile);
			return FALSE;
		}
		config_file_free(pfile);
		sprintf(tmp_path, "%s/%s.txt", get_data_path(), file_name);
		dns_rbl_init(tmp_path);
		rbl_cache_init(normal_size, normal_valid, black_size, black_valid);
		if (0 != dns_rbl_run()) {
			printf("[dns_rbl]: fail to dns_rbl\n");
			return FALSE;
		}
		if (0 != rbl_cache_run()) {
			printf("[dns_rbl]: fail to rbl_cache\n");
			return FALSE;
		}
		if (FALSE == register_service("dns_query_A",
			dns_adaptor_query_A)) {
			printf("[dns_rbl]: fail to register \"dns_query_A\""
					"service\n");
			return FALSE;

		}
		if (FALSE == register_service("dns_rbl_judge", dns_rbl_judge)) {
			printf("[dns_rbl]: fail to register"
				" \"dns_rbl_judge\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("rbl_cache_query", rbl_cache_query)) {
			printf("[dns_rbl]: fail to register"
				" \"rbl_cache_query\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("rbl_cache_add", rbl_cache_add)) {
			printf("[dns_rbl]: fail to register"
				" \"rbl_cache_add\" service\n");
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
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	int interval, len;
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
		len = snprintf(result, length, "250 %s information:\r\n"
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
