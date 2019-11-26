#include <stdbool.h>
#include "service_common.h"
#include "retrying_table.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#include <string.h>

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char *str_value, *psearch;
	int table_size, min_interval, valid_interval;
	char file_name[256], tmp_path[256], temp_buff[32];
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		if (FALSE == register_talk(retrying_table_console_talk)) {
			printf("[retrying_table]: fail to register console talk\n");
			return FALSE;
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init(tmp_path);
		if (NULL == pfile) {
			printf("[retrying_table]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pfile, "TABLE_MAX_NUM");
		if (NULL == str_value) {
			table_size = 10000;
			config_file_set_value(pfile, "TABLE_MAX_NUM", "10000");
		} else {
			table_size = atoi(str_value);
			if (table_size <= 0) {
				table_size = 10000;
				config_file_set_value(pfile, "TABLE_MAX_NUM", "10000");
			}
		}
		printf("[retrying_table]: table size is %d\n", table_size);
		
		str_value = config_file_get_value(pfile, "MINIMUM_INTERVAL");
		if (NULL == str_value) {
			min_interval = 300;
			config_file_set_value(pfile, "MINIMUM_INTERVAL", "5minutes");
		} else {
			min_interval = atoitvl(str_value);
			if (min_interval <= 0) {
				min_interval = 300;
				config_file_set_value(pfile, "MINIMUM_INTERVAL", "5minutes");
			}
		}
		itvltoa(min_interval, temp_buff);
		printf("[retrying_table]: minimum interval is %s\n", temp_buff);
		str_value = config_file_get_value(pfile, "VALID_INTERVAL");
		if (NULL == str_value) {
			valid_interval = 7200;
			config_file_set_value(pfile, "VALID_INTERVAL", "2hours");
		} else {
			valid_interval = atoitvl(str_value);
			if (valid_interval < min_interval) {
				valid_interval = min_interval;
				itvltoa(valid_interval, temp_buff);
				config_file_set_value(pfile, "VALID_INTERVAL", temp_buff);
			}
		}
		itvltoa(valid_interval, temp_buff);
		printf("[retrying_table]: valid interval is %s\n", temp_buff);
		if (FALSE == config_file_save(pfile)) {
			config_file_free(pfile);
			printf("[retrying_table]: fail to write configuration back "
				"to file\n");
			return FALSE;
		}
		config_file_free(pfile);
		retrying_table_init(tmp_path, table_size, min_interval, valid_interval);
		if (0 != retrying_table_run()) {
			printf("[retrying_table]: fail to run the module\n");
			return FALSE;
		}
		if (FALSE == register_service("check_retrying", retrying_table_check)) {
			printf("[retrying_table]: fail to register \"check_retrying\" "
				"service\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		retrying_table_stop();
		retrying_table_free();
		return TRUE;
	}
	return false;
}


