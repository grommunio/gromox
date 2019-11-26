#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <gromox/mtasvc_common.h>
#include "tagging_table.h"
#include "config_file.h"
#include <stdio.h>

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char file_name[256], tmp_path[256];
	char *str_value, *psearch;
	int growing_num;
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		if (FALSE == register_talk(tagging_table_console_talk)) {
			printf("[tagging_table]: fail to register console talk\n");
			return FALSE;
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init2(NULL, tmp_path);
		if (NULL == pfile) {
			printf("[tagging_table]: config_file_init %s: %s\n", tmp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pfile, "GROWING_NUM");
		if (NULL == str_value) {
			growing_num = 100;
			config_file_set_value(pfile, "GROWING_NUM", "100");
		} else {
			growing_num = atoi(str_value);
			if (growing_num <= 0) {
				growing_num = 100;
				config_file_set_value(pfile, "GROWING_NUM", "100");
			}
		}
		printf("[tagging_table]: table growing number is %d\n", growing_num);
		config_file_free(pfile);
		sprintf(tmp_path, "%s/%s.txt", get_data_path(), file_name);
		tagging_table_init(tmp_path, growing_num);
		if (0 != tagging_table_run()) {
			printf("[tagging_table]: fail to run the module\n");
			return FALSE;
		}
		if (FALSE == register_service("check_tagging", tagging_table_check)) {
			printf("[tagging_table]: fail to register \"check_tagging\" "
				"service\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		tagging_table_stop();
		tagging_table_free();
		return TRUE;
	}
	return false;
}


