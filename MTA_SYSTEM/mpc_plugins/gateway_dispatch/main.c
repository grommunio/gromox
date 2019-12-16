#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <gromox/hook_common.h>
#include "gateway_dispatch.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>

DECLARE_API;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
    char file_name[256], tmp_path[256];
    char *str_value, *psearch, *mask_string;
    char list_path[256];
    int times, interval, alarm_interval;
	int cache_interval, backend_interval;
	int block_interval, bounce_policy;
	int files_num, retrying_times;
    char resource_path[256];
	char temp_buff[256];
	char separator[16];
    char cache_path[256];

    /* path conatins the config files directory */
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
			printf("[gateway_dispatch]: config_file_init %s: %s\n",
				tmp_path, strerror(errno));
            return FALSE;
        }
		files_num = 256 * get_threads_num();
		
        sprintf(list_path, "%s/%s.txt", get_data_path(), file_name);
		
		str_value = config_file_get_value(pfile, "BACKEND_SCAN_INTERVAL");
        if (NULL == str_value) {
            backend_interval = 60;
			config_file_set_value(pfile, "BACKEND_SCAN_INTERVAL", "1minute");
        } else {
            backend_interval = atoitvl(str_value);
            if (backend_interval <= 0) {
                backend_interval = 60;
				config_file_set_value(pfile, "BACKEND_SCAN_INTERVAL",
					"1minute");
            }
		}
		itvltoa(backend_interval, temp_buff);
        printf("[gateway_dispatch]: back-end list scanning interval is %s\n",
			temp_buff);
		str_value = config_file_get_value(pfile, "FAILURE_TIMES_FOR_ALARM");
        if (NULL == str_value) {
            times = 30;
			config_file_set_value(pfile, "FAILURE_TIMES_FOR_ALARM", "30");
        } else {
            times = atoi(str_value);
            if (times <= 0) {
                times = 30;
				config_file_set_value(pfile, "FAILURE_TIMES_FOR_ALARM", "30");
            }
		}
        printf("[gateway_dispatch]: failure times for alarm is %d\n", times);

		str_value = config_file_get_value(pfile, 
				"INTERVAL_FOR_FAILURE_STATISTIC");
        if (NULL == str_value) {
            interval = 600;
            config_file_set_value(pfile, "INTERVAL_FOR_FAILURE_STATISTIC",
				"10minutes");
        } else {
            interval = atoitvl(str_value);
            if (interval <= 0) {
                interval = 600;
				config_file_set_value(pfile, "INTERVAL_FOR_FAILURE_STATISTIC",
					"10minutes");
            }
		}
		itvltoa(interval, temp_buff);
        printf("[gateway_dispatch]: interval for failure alarm is %s\n",
			temp_buff);
		
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
        printf("[gateway_dispatch]: alarms interval is %s\n", temp_buff);
		
		mask_string = config_file_get_value(pfile, "USER_MASK_STRING");
		sprintf(resource_path, "%s/gateway_bounce", get_data_path());	
		
		str_value = config_file_get_value(pfile, "BOUNCE_POLICY");
		if (NULL == str_value) {
			bounce_policy = 1;
			config_file_set_value(pfile, "BOUNCE_POLICY", "1");
		} else {
			bounce_policy = atoi(str_value);
			if (bounce_policy < 0 || bounce_policy > 2) {
				bounce_policy = 1;
				config_file_set_value(pfile, "BOUNCE_POLICY", "1");
			}
		}
		switch (bounce_policy) {
		case 0:
			printf("[gateway_dispatch]: bounce policy is \"none\"\n");
			break;
		case 1:
			printf("[gateway_dispatch]: bounce policy is \"verify\"\n");
			break;
		case 2:
			printf("[gateway_dispatch]: bounce policy is \"always\"\n");
			break;
		}
		
		str_value = config_file_get_value(pfile, "SEPARATOR_FOR_BOUNCE");
        if (NULL == str_value) {
			strcpy(separator, " ");
        } else {
			strcpy(separator, str_value);
		}

		sprintf(cache_path, "%s/cache", get_queue_path());
		
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
        printf("[gateway_dispatch]: cache queue scanning interval is %s\n",
			temp_buff);

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
		printf("[gateway_dispatch]: retrying times on temporary failure is %d\n",
			retrying_times);
		
		str_value = config_file_get_value(pfile, "NOUSER_BLOCK_INTERVAL");
		if (NULL == str_value) {
			block_interval = 12*3600;
			config_file_set_value(pfile, "NOUSER_BLOCK_INTERVAL", "12hours");
		} else {
			block_interval = atoitvl(str_value);
			if (block_interval <= 0) {
				block_interval = 12*3600;
				config_file_set_value(pfile, "NOUSER_BLOCK_INTERVAL","12hours");
			}
		}
		itvltoa(block_interval, temp_buff);
		printf("[gateway_dispatch]: nouser block interval is %s\n", temp_buff);
		
		gateway_dispatch_init(list_path, backend_interval, files_num,
			times, interval, alarm_interval, bounce_policy, mask_string,
			resource_path, separator, cache_path, cache_interval,
			retrying_times, block_interval, tmp_path);

		config_file_free(pfile);
		
		if (0 != gateway_dispatch_run()) {
			printf("[gateway_dispatch]: fail to run gateway dispatch\n");
            return FALSE;
        }
		register_talk(gateway_dispatch_console_talk);
        if (FALSE == register_local(gateway_dispatch_hook)) {
			printf("[gateway_dispatch]: failed to register the hook function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
		gateway_dispatch_stop();
		gateway_dispatch_free();
        return TRUE;
    }
	return false;
}

