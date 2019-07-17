#include "service_common.h"
#include "log_plugin.h"
#include "config_file.h"
#include <string.h>
#include <stdio.h>

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char file_name[256], tmp_path[256];
	char temp_buff[64], log_file_name[256];
	char *str_value, *psearch;
	int cache_size, log_level, files_num;
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
       
		if (FALSE == register_talk(log_plugin_console_talk)) {
			printf("[log_plugin]: fail to register console talk\n");
			return FALSE;
		}
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init(tmp_path);
		if (NULL == pfile) {
			printf("[log_plugin]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pfile, "LOG_LEVEL");
		if (NULL == str_value) {
			log_level = 0;
			config_file_set_value(pfile, "LOG_LEVEL", "0");
		} else {
			log_level = atoi(str_value);
			if (log_level < 0 || log_level > 8) {
				log_level = 0;
				config_file_set_value(pfile, "LOG_LEVEL", "0");
			}
		}
		printf("[log_plugin]: log level is %d\n", log_level);
		str_value = config_file_get_value(pfile, "LOG_CACHE_SIZE");
		if (NULL == str_value) {
			cache_size = 1024*1024;
			config_file_set_value(pfile, "LOG_CACHE_SIZE", "1M");
		} else {
			cache_size = atobyte(str_value);
			if (cache_size <= 0) {
				cache_size = 1024*1024;
				config_file_set_value(pfile, "LOG_CACHE_SIZE", "1M");
			}
		}
		bytetoa(cache_size, temp_buff);
		printf("[log_plugin]: log cache size is %s\n", temp_buff);
		str_value = config_file_get_value(pfile, "FILES_NUM");
		if (NULL == str_value) {
			files_num = 30;
			config_file_set_value(pfile, "FILES_NUM", "30");
		} else {
			files_num = atoi(str_value);
			if (files_num < 0) {
				files_num = 0;
				config_file_set_value(pfile, "FILES_NUM", "30");
			} else if (files_num > 1024) {
				files_num = 1024;
				config_file_set_value(pfile, "FILES_NUM", "1024");
			}
		}
		printf("[log_plugin]: files number is %d\n", files_num);
		str_value = config_file_get_value(pfile, "LOG_FILE_NAME");
		if (NULL == str_value) {
			strcpy(log_file_name, "log.txt");
			config_file_set_value(pfile, "LOG_FILE_NAME", "log.txt");
		} else {
			strcpy(log_file_name, str_value);
		}
		printf("[log_plugin]: log file name is %s\n", log_file_name);
		if (FALSE == config_file_save(pfile)) {
			config_file_free(pfile);
			printf("[log_plugin]: fail to save config file\n");
			return FALSE;
		}
		config_file_free(pfile);
		log_plugin_init(tmp_path, log_file_name, log_level, files_num,
			cache_size);
		if (0 != log_plugin_run()) {
			printf("[log_plugin]: fail to run log plugin\n");
			return FALSE;
		}
		if (FALSE == register_service("log_info", log_plugin_log_info)) {
			printf("[log_plugin]: fail to register \"log_info\" service\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		log_plugin_stop();
		log_plugin_free();
		return TRUE;
	}
}


