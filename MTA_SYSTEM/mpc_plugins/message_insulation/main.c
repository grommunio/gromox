#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <gromox/hook_common.h>
#include "config_file.h"
#include "bounce_producer.h"
#include "message_insulation.h"
#include "util.h"
#include <stdio.h>

DECLARE_API;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char temp_buff[32];
	char file_name[256];
	char config_path[256];
	char queue_path[256];
	char resource_path[256];
	char *psearch, *str_val;
	int scan_interval;
	int on_valid_interval;
	int anon_valid_interval;
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
		sprintf(config_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init(config_path);
		if (NULL == pfile) {
			printf("[message_insulation]: config_file_init %s: %s\n", config_path, strerror(errno));
			return FALSE;
		}
		str_val = config_file_get_value(pfile, "SCAN_INTERVAL");
		if (NULL == str_val) {
			scan_interval = 3600;
			config_file_set_value(pfile, "SCAN_INTERVAL", "1hour");
		} else {
			scan_interval = atoitvl(str_val);
			if (scan_interval <= 0) {
				scan_interval = 3600;
				config_file_set_value(pfile, "SCAN_INTERVAL", "1hour");
			}
		}
		itvltoa(scan_interval, temp_buff);
		printf("[message_insulation]: scan interval is %s\n", temp_buff);
		str_val = config_file_get_value(pfile, "ANONYMOUS_VALID_INTERVAL");
		if (NULL == str_val) {
			anon_valid_interval = 3600*24;
			config_file_set_value(pfile, "ANONYMOUS_VALID_INTERVAL", "1day");
		} else {
			anon_valid_interval = atoitvl(str_val);
			if (anon_valid_interval < scan_interval) {
				anon_valid_interval = scan_interval * 24;
				itvltoa(anon_valid_interval, temp_buff);
				config_file_set_value(pfile, "ANONYMOUS_VALID_INTERVAL", temp_buff);
			}
		}
		itvltoa(anon_valid_interval, temp_buff);
		printf("[message_insulation]: anonymus valid interval is %s\n", temp_buff);
		
		str_val = config_file_get_value(pfile, "ONYMOUS_VALID_INTERVAL");
		if (NULL == str_val) {
			on_valid_interval = 3600*6;
			config_file_set_value(pfile, "ONYMOUS_VALID_INTERVAL", "6hours");
		} else {
			on_valid_interval = atoitvl(str_val);
			if (on_valid_interval < scan_interval) {
				on_valid_interval = scan_interval * 6;
				itvltoa(on_valid_interval, temp_buff);
				config_file_set_value(pfile, "ONYMOUS_VALID_INTERVAL", temp_buff);
			}
		}
		itvltoa(on_valid_interval, temp_buff);
		printf("[message_insulation]: onymus valid interval is %s\n", temp_buff);
		
		config_file_free(pfile);
		sprintf(queue_path, "%s/insulation", get_queue_path());
		sprintf(resource_path, "%s/insulation_bounce", get_data_path());
		bounce_producer_init(resource_path, ";");
		message_insulation_init(config_path, queue_path, scan_interval,
			on_valid_interval, anon_valid_interval);
		if (0 != bounce_producer_run()) {
			printf("[message_insulation]: fail to run bounce producer\n");
			return FALSE;
		}
		if (0 != message_insulation_run()) {
			printf("[message_insulation]: fail to run message insulation\n");
			return FALSE;
		}
		register_talk(message_insulation_console_talk);
        return TRUE;
    case PLUGIN_FREE:
		bounce_producer_stop();
		message_insulation_stop();
		bounce_producer_free();
		message_insulation_free();
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
	return false;
}

