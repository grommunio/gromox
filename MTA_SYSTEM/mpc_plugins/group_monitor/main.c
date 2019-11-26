#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <gromox/hook_common.h>
#include "group_monitor.h"
#include "config_file.h"
#include <stdio.h>

DECLARE_API;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char file_name[256], tmp_path[256];
	char *psearch, *str_val;
	const char *str_subject;
	int growing_num;
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
		pfile = config_file_init(tmp_path);
		if (NULL == pfile) {
			printf("[group_monitor]: config_file_init %s: %s\n", tmp_path, strerror(errno));
			return FALSE;
		}
		str_val = config_file_get_value(pfile, "GROWING_NUM");
		if (NULL== str_val) {
			growing_num = 100;
			config_file_set_value(pfile, "GROWING_NUM", "100");
		} else {
			growing_num = atoi(str_val);
			if (growing_num <= 0) {
				growing_num = 100;
				config_file_set_value(pfile, "GROWING_NUM", "100");
			}
		}
		printf("[group_monitor]: growing number is %d\n", growing_num);
		
		str_subject = config_file_get_value(pfile, "FORWARD_MAIL_SUBJECT");
		if (NULL == str_subject) {
			str_subject = "group monitor mail";
		}
		printf("[group_monitor]: forward mail subject is %s\n", str_subject);
		if (FALSE == config_file_save(pfile)) {
			printf("[group_monitor]: fail to save config file\n");
			config_file_free(pfile);
			return FALSE;
		}
		sprintf(tmp_path, "%s/%s", get_data_path(), file_name);
		group_monitor_init(tmp_path, str_subject, growing_num);
		if (0 != group_monitor_run()) {
			printf("[group_monitor]: fail to run group monitor\n");
			config_file_free(pfile);
			return FALSE;
		}
		config_file_free(pfile);
		register_talk(group_monitor_console_talk);
        if (FALSE == register_hook(group_monitor_process)) {
			printf("[group_monitor]: fail to register the hook function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
		group_monitor_stop();
		group_monitor_free();
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
	return false;
}

