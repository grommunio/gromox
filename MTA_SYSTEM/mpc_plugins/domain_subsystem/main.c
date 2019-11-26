#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <gromox/hook_common.h>
#include "domain_subsystem.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>

DECLARE_API;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
    char file_name[256];
	char tmp_path[256];
	char temp_buff[32];
    char list_path[256];
    char queue_path[256];
    char *str_value, *psearch;
    int times, interval, max_thr;

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
        sprintf(list_path, "%s/%s.txt", get_data_path(), file_name);
        pfile = config_file_init(tmp_path);
        if (NULL == pfile) {
			printf("[domain_subsystem]: config_file_init %s: %s\n", tmp_path, strerror(errno));
            return FALSE;
        }
		
		sprintf(queue_path, "%s/clone", get_queue_path());
		
		str_value = config_file_get_value(pfile, "QUEUE_SCAN_INTERVAL");
        if (NULL == str_value) {
            interval = 7200;
			config_file_set_value(pfile, "QUEUE_SCAN_INTERVAL", "2hours");
        } else {
            interval = atoitvl(str_value);
            if (interval <= 0) {
                interval =7200;
				config_file_set_value(pfile, "QUEUE_SCAN_INTERVAL",
					"2hours");
            }
		}
		itvltoa(interval, temp_buff);
        printf("[domain_subsystem]: clone queue scanning interval is %s\n",
			temp_buff);

		str_value = config_file_get_value(pfile, "RETRYING_TIMES");
        if (NULL == str_value) {
            times = 6;
			config_file_set_value(pfile, "RETRYING_TIMES", "6");
        } else {
            times = atoi(str_value);
            if (times <= 0) {
                times = 6;
				config_file_set_value(pfile, "RETRYING_TIMES", "6");
            }
		}
        printf("[domain_subsystem]: retring times on temporary failure is %d\n",
			times);
		
		if (get_threads_num() - 4 > 0) {
			max_thr = get_threads_num() - 4;
		} else {
			max_thr = get_threads_num();
		}
		
		if (FALSE == config_file_save(pfile)) {
			printf("[domain_subsystem]: fail to save config file\n");
			config_file_free(pfile);
			return FALSE;
		}
		
		domain_subsystem_init(tmp_path, list_path, queue_path, times, interval,
			max_thr);

		config_file_free(pfile);
		
		if (0 != domain_subsystem_run()) {
			printf("[domain_subsystem]: fail to run domain subsystem\n");
            return FALSE;
        }
		register_talk(domain_subsystem_console_talk);
        if (FALSE == register_hook(domain_subsystem_hook)) {
			printf("[domain_subsystem]: fail to register the hook function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
		domain_subsystem_stop();
		domain_subsystem_free();
        return TRUE;
    }
	return false;
}

