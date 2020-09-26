#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <gromox/hook_common.h>
#include "config_file.h"
#include "exmdb_local.h"
#include "cache_queue.h"
#include "net_failure.h"
#include "bounce_audit.h"
#include "exmdb_client.h"
#include "bounce_producer.h"
#include "util.h"
#include <stdio.h>

DECLARE_API;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	int conn_num;
	char charset[32];
	char timezone[64];
	char org_name[256];
	char separator[16];
	char temp_buff[32];
	char tmp_path[256];
	int cache_interval;
	int retrying_times;
	int alarm_interval;
	CONFIG_FILE *pfile;
	int times, interval;
	char file_name[256];
	char cache_path[256];
	int response_capacity;
	int response_interval;
	char resource_path[256];
	char propnames_path[256];
	char exmdb_list_path[256];
	char *str_value, *psearch;
	 
	/* path contains the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init2(NULL, tmp_path);
		if (NULL == pfile) {
			printf("[exmdb_local]: config_file_init %s: %s\n", tmp_path, strerror(errno));
			return FALSE;
		}

		sprintf(resource_path, "%s/local_bounce", get_data_path());
		sprintf(propnames_path, "%s/propnames.txt", get_data_path());
		sprintf(exmdb_list_path, "%s/exmdb_list.txt", get_data_path());

		str_value = config_file_get_value(pfile, "SEPARATOR_FOR_BOUNCE");
		if (NULL == str_value) {
			strcpy(separator, " ");
		} else {
			strcpy(separator, str_value);
		}

		sprintf(cache_path, "%s/cache", get_queue_path());
		
		str_value = config_file_get_value(pfile, "X500_ORG_NAME");
		if (NULL == str_value) {
			HX_strlcpy(org_name, "Gromox default", sizeof(org_name));
			config_file_set_value(pfile, "X500_ORG_NAME", org_name);
		} else {
			strcpy(org_name, str_value);
		}
		printf("[exmdb_local]: x500 org name is \"%s\"\n", org_name);
		
		str_value = config_file_get_value(pfile, "DEFAULT_CHARSET");
		if (NULL == str_value) {
			strcpy(charset, "windows-1252");
			config_file_set_value(pfile, "DEFAULT_CHARSET", charset);
		} else {
			strcpy(charset, str_value);
		}
		printf("[exmdb_local]: default charset is \"%s\"\n", charset);
		
		str_value = config_file_get_value(pfile, "DEFAULT_TIMEZONE");
		if (NULL == str_value) {
			strcpy(timezone, "Asia/Shanghai");
			config_file_set_value(pfile, "DEFAULT_TIMEZONE", timezone);
		} else {
			strcpy(timezone, str_value);
		}
		printf("[exmdb_local]: default timezone is \"%s\"\n", timezone);
		
		str_value = config_file_get_value(pfile, "EXMDB_CONNECTION_NUM");
		if (NULL == str_value) {
			conn_num = 5;
			config_file_set_value(pfile, "EXMDB_CONNECTION_NUM", "5");
		} else {
			conn_num = atoi(str_value);
			if (conn_num < 2 || conn_num > 100) {
				conn_num = 5;
				config_file_set_value(pfile, "EXMDB_CONNECTION_NUM", "5");
			}
		}
		printf("[exmdb_local]: exmdb connection number is %d\n", conn_num);
		
		str_value = config_file_get_value(pfile, "CACHE_SCAN_INTERVAL");
		if (NULL == str_value) {
			cache_interval = 180;
			config_file_set_value(pfile, "CACHE_SCAN_INTERVAL", "3minutes");
		} else {
			cache_interval = atoitvl(str_value);
			if (cache_interval <= 0) {
				cache_interval = 180;
				config_file_set_value(pfile, "CACHE_SCAN_INTERVAL", "3minutes");
			}
		}
		itvltoa(cache_interval, temp_buff);
		printf("[exmdb_local]: cache scanning interval is %s\n", temp_buff);

		str_value = config_file_get_value(pfile, "RETRYING_TIMES");
		if (NULL == str_value) {
			retrying_times = 30;
			config_file_set_value(pfile, "RETRYING_TIMES", "30");
		} else {
			retrying_times = atoi(str_value);
			if (retrying_times <= 0) {
				retrying_times = 30;
				config_file_set_value(pfile, "RETRYING_TIMES", "30");
			}
		}
		printf("[exmdb_local]: retrying times on temporary failure is %d\n",
			retrying_times);
		
		str_value = config_file_get_value(pfile, "FAILURE_TIMES_FOR_ALARM");
		if (NULL == str_value) {
			times = 10;
			config_file_set_value(pfile, "FAILURE_TIMES_FOR_ALARM", "10");
		} else {
			times = atoi(str_value);
			if (times <= 0) {
				times = 10;
				config_file_set_value(pfile, "FAILURE_TIMES_FOR_ALARM", "10");
			}
		}
		printf("[exmdb_local]: failure times for alarm is %d\n", times);

		str_value = config_file_get_value(pfile,
				"INTERVAL_FOR_FAILURE_STATISTIC");
		if (NULL == str_value) {
			interval = 3600;
			config_file_set_value(pfile, "INTERVAL_FOR_FAILURE_STATISTIC",
							        "1hour");
		} else {
			interval = atoitvl(str_value);
			if (interval <= 0) {
				interval = 3600;
				config_file_set_value(pfile, "INTERVAL_FOR_FAILURE_STATISTIC",
					"1hour");
			}
		}
		itvltoa(interval, temp_buff);
		printf("[exmdb_local]: interval for failure alarm is %s\n", temp_buff);

		str_value = config_file_get_value(pfile, "ALARM_INTERVAL");
		if (NULL == str_value) {
			alarm_interval = 1800;
			config_file_set_value(pfile, "ALARM_INTERVAL", "30minutes");
		} else {
			alarm_interval = atoitvl(str_value);
			if (alarm_interval <= 0) {
				alarm_interval = 1800;
				config_file_set_value(pfile, "ALARM_INTERVAL", "30minutes");
			}
		}
		itvltoa(alarm_interval, temp_buff);
		printf("[exmdb_local]: alarms interval is %s\n", temp_buff);

		str_value = config_file_get_value(pfile, "RESPONSE_AUDIT_CAPACITY");
		if (NULL == str_value) {
			response_capacity = 1000;
			config_file_set_value(pfile, "RESPONSE_AUDIT_CAPACITY", "1000");
		} else {
			response_capacity = atoi(str_value);
			if (response_capacity < 0) {
				response_capacity = 1000;
				config_file_set_value(pfile, "RESPONSE_AUDIT_CAPACITY", "1000");
			}
		}
		printf("[exmdb_local]: auto response audit capacity is %d\n",
			response_capacity);

		str_value = config_file_get_value(pfile, "RESPONSE_INTERVAL");
		if (NULL == str_value) {
			response_interval = 180;
			config_file_set_value(pfile, "RESPONSE_INTERVAL", "3minutes");
		} else {
			response_interval = atoitvl(str_value);
			if (response_interval <= 0) {
				response_interval = 180;
				config_file_set_value(pfile, "RESPONSE_INTERVAL", "3minutes");
			}
		}
		itvltoa(response_interval, temp_buff);
		printf("[exmdb_local]: auto response interval is %s\n", temp_buff);

		config_file_free(pfile);
		net_failure_init(times, interval, alarm_interval);
		bounce_producer_init(resource_path, separator);
		bounce_audit_init(response_capacity, response_interval);
		cache_queue_init(cache_path, cache_interval, retrying_times);
		exmdb_client_init(conn_num, exmdb_list_path);
		exmdb_local_init(tmp_path, org_name,
			charset, timezone, propnames_path);
		
		if (0 != net_failure_run()) {
			printf("[exmdb_local]: failed to run net failure\n");
			return FALSE;
		}
		if (0 != bounce_producer_run()) {
			printf("[exmdb_local]: failed to run bounce producer\n");
			return FALSE;
		}
		if (0 != bounce_audit_run()) {
			printf("[exmdb_local]: failed to run bounce audit\n");
			return FALSE;
		}
		if (0 != cache_queue_run()) {
			printf("[exmdb_local]: failed to run cache queue\n");
			return FALSE;
		}
		if (0 != exmdb_client_run()) {
			printf("[exmdb_local]: failed to run exmdb client\n");
			return FALSE;
		}
		if (0 != exmdb_local_run()) {
			printf("[exmdb_local]: failed to run exmdb local\n");
			return FALSE;
		}
		register_talk(exmdb_local_console_talk);
        if (FALSE == register_local(exmdb_local_hook)) {
			printf("[exmdb_local]: failed to register the hook function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
		exmdb_local_stop();
		exmdb_local_free();
		exmdb_client_stop();
		exmdb_client_free();
		cache_queue_stop();
		cache_queue_free();
		bounce_audit_stop();
		bounce_audit_free();
		bounce_producer_stop();
		bounce_producer_free();
		net_failure_stop();
		net_failure_free();
        return TRUE;
    }
	return false;
}
