#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <gromox/mtasvc_common.h>
#include "invalid_user.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#include <string.h>

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char *str_value, *psearch;
	int table_size, valid_interval;
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
		if (FALSE == register_talk(invalid_user_console_talk)) {
			printf("[invalid_user]: failed to register console talk\n");
			return FALSE;
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init2(NULL, tmp_path);
		if (NULL == pfile) {
			printf("[invalid_user]: config_file_init %s: %s\n", tmp_path, strerror(errno));
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
		printf("[invalid_user]: table size is %d\n", table_size);
		
		str_value = config_file_get_value(pfile, "VALID_INTERVAL");
		if (NULL == str_value) {
			valid_interval = 3600*4;
			config_file_set_value(pfile, "VALID_INTERVAL", "4hours");
		} else {
			valid_interval = atoitvl(str_value);
			if (valid_interval <= 0) {
				valid_interval = 3600*4;
				config_file_set_value(pfile, "VALID_INTERVAL", "4hours");
			}
		}
		itvltoa(valid_interval, temp_buff);
		printf("[invalid_user]: valid interval is %s\n", temp_buff);
		config_file_free(pfile);
		invalid_user_init(tmp_path, table_size, valid_interval);
		if (0 != invalid_user_run()) {
			printf("[invalid_user]: failed to run the module\n");
			return FALSE;
		}
		if (FALSE == register_service("check_user", invalid_user_check)) {
			printf("[invalid_user]: failed to register \"check_user\" service\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		invalid_user_stop();
		invalid_user_free();
		return TRUE;
	}
	return false;
}


