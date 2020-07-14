#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <gromox/hook_common.h>
#include "mail_approving.h"
#include "bounce_producer.h"
#include "config_file.h"
#include <stdio.h>

DECLARE_API;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char separator[16];
	char dm_host[256];
	char file_name[256], tmp_path[256];
	char *psearch, *str_val;
	int growing_num;
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
			printf("[mail_approving]: config_file_init %s: %s\n", tmp_path, strerror(errno));
			return FALSE;
		}

		str_val = config_file_get_value(pfile, "DOMAIN_ADMIN_HOST");
		if (NULL == str_val) {
			printf("[mail_approving]: DOMAIN_ADMIN_HOST must be set\n");
			config_file_free(pfile);
			return FALSE;
		}
		strcpy(dm_host, str_val);
		
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
		printf("[mail_approving]: growing number is %d\n", growing_num);

		str_val = config_file_get_value(pfile, "SEPARATOR_FOR_BOUNCE");
		if (NULL == str_val) {
			strcpy(separator, " ");
		} else {
			strcpy(separator, str_val);
		}

		sprintf(tmp_path, "%s/approving_bounce", get_data_path());
		bounce_producer_init(tmp_path, separator);
		sprintf(tmp_path, "%s/%s", get_data_path(), file_name);
		mail_approving_init(tmp_path, growing_num, dm_host);
		if (0 != bounce_producer_run()) {
			printf("[mail_approving]: failed to run bounce producer\n");
			config_file_free(pfile);
			return FALSE;
		}
		if (0 != mail_approving_run()) {
			printf("[mail_approving]: failed to run mail approving\n");
			config_file_free(pfile);
			return FALSE;
		}
		config_file_free(pfile);
		register_talk(mail_approving_console_talk);
        if (FALSE == register_hook(mail_approving_process)) {
			printf("[mail_approving]: failed to register the hook function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
		mail_approving_stop();
		bounce_producer_stop();
		mail_approving_free();
		bounce_producer_free();
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
	return false;
}
