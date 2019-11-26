#include <stdbool.h>
#include "service_common.h"
#include "multiple_retrying.h"
#include "proxy_retrying.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#include <string.h>

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char *str_value, *psearch;
	int table_size, min_interval;
	int valid_interval, port, time_out;
	int ping_interval, channel_num;
	char file_name[256], config_path[256];
	char list_path[256], temp_buff[32];
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		if (FALSE == register_talk(multiple_retrying_console_talk)) {
			printf("[multiple_retrying]: fail to register console talk\n");
			return FALSE;
		}
		sprintf(config_path, "%s/%s.cfg", get_config_path(), file_name);
		sprintf(list_path, "%s/%s.txt", get_data_path(), file_name);
		pfile = config_file_init(config_path);
		if (NULL == pfile) {
			printf("[multiple_retrying]: error to open config file!!!\n");
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
		printf("[multiple_retrying]: table size is %d\n", table_size);
		
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
		printf("[multiple_retrying]: minimum interval is %s\n", temp_buff);
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
		printf("[multiple_retrying]: valid interval is %s\n", temp_buff);
		str_value = config_file_get_value(pfile, "TIME_OUT");
		if (NULL == str_value) {
			time_out = 3;
			config_file_set_value(pfile, "TIME_OUT", "3seconds");
		} else {
			time_out = atoitvl(str_value);
			if (time_out < 3) {
				time_out = 3;
				config_file_set_value(pfile, "TIME_OUT", "3seconds");
			}
		}
		itvltoa(time_out, temp_buff);
		printf("[multiple_retrying]: time-out value is %s\n", temp_buff);
		str_value = config_file_get_value(pfile, "PING_INTERVAL");
		if (NULL == str_value) {
			ping_interval = time_out / 3;
			itvltoa(ping_interval, temp_buff);
			config_file_set_value(pfile, "PING_INTERVAL", temp_buff);
		} else {
			ping_interval = atoitvl(str_value);
			if (ping_interval > time_out) {
				ping_interval = time_out;
			}
			itvltoa(ping_interval, temp_buff);
			config_file_set_value(pfile, "PING_INTERVAL", temp_buff);
		}
		itvltoa(ping_interval, temp_buff);
		printf("[multiple_retrying]: ping interval is %s\n", temp_buff);
		str_value = config_file_get_value(pfile, "LISTEN_PORT");
		if (NULL == str_value) {
			port = 8888;
			config_file_set_value(pfile, "LISTEN_PORT", "8888");
		} else {
			port = atoi(str_value);
			if (port <= 0) {
				port = 8888;
				config_file_set_value(pfile, "LISTEN_PORT", "8888");
			}
		}
		printf("[multiple_retrying]: listen port is %d\n", port);
		str_value = config_file_get_value(pfile, "CHANNEL_NUM");
		if (NULL == str_value) {
			channel_num = 4;
			config_file_set_value(pfile, "CHANNEL_NUM", "4");
		} else {
			channel_num = atoi(str_value);
			if (channel_num < 2) {
				channel_num = 2;
				config_file_set_value(pfile, "CHANNEL_NUM", "2");
			}
		}
		printf("[multiple_retrying]: channel number per unit is %d\n",
			channel_num);
		if (FALSE == config_file_save(pfile)) {
			config_file_free(pfile);
			printf("[multiple_retrying]: fail to write configuration back "
				"to file\n");
			return FALSE;
		}
		config_file_free(pfile);
		multiple_retrying_init(config_path, list_path, table_size, min_interval,
			valid_interval, port, time_out, ping_interval, channel_num);
		if (0 != multiple_retrying_run()) {
			return FALSE;
		}
		if (FALSE == register_service("check_retrying", proxy_retrying_check)) {
			printf("[multiple_retrying]: fail to register \"check_retrying\" "
				"service\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		multiple_retrying_stop();
		multiple_retrying_free();
		return TRUE;
	}
	return false;
}


