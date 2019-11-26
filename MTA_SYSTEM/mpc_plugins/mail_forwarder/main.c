#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <gromox/hook_common.h>
#include "mail_forwarder.h"
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
			printf("[mail_forwarder]: config_file_init %s: %s\n", tmp_path, strerror(errno));
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
		printf("[mail_forwarder]: growing number is %d\n", growing_num);
		
		str_subject = config_file_get_value(pfile, "FORWARD_MAIL_SUBJECT");
		if (NULL == str_subject) {
			str_subject = "system forward mail";
		}
		printf("[mail_forwarder]: forward mail subject is %s\n", str_subject);
		sprintf(tmp_path, "%s/%s.txt", get_data_path(), file_name);
		mail_forwarder_init(tmp_path, str_subject, get_host_ID(), growing_num);
		if (0 != mail_forwarder_run()) {
			printf("[mail_forwarder]: fail to run mail forwarder\n");
			config_file_free(pfile);
			return FALSE;
		}
		config_file_free(pfile);
		register_talk(mail_forwarder_console_talk);
        if (FALSE == register_hook(mail_forwarder_process)) {
			printf("[mail_forwarder]: fail to register the hook function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
		mail_forwarder_stop();
		mail_forwarder_free();
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
	return false;
}

