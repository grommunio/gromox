#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <gromox/exsvc_common.h>
#include "str_table.h"
#include "config_file.h"
#include <stdio.h>
#include <string.h>

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char file_name[256], tmp_path[256];
	char *str_value, *psearch;
	char *query_name, *add_name, *remove_name;
	BOOL case_sensitive;
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
		if (FALSE == register_talk(str_table_console_talk)) {
			printf("[%s]: failed to register console talk\n", file_name);
			return FALSE;
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init2(NULL, tmp_path);
		if (NULL == pfile) {
			printf("[%s]: config_file_init %s: %s\n", file_name, tmp_path, strerror(errno));
			return FALSE;
		}
		query_name = config_file_get_value(pfile, "QUERY_SERVICE_NAME");
		add_name = config_file_get_value(pfile, "ADD_SERVICE_NAME");
		remove_name = config_file_get_value(pfile, "REMOVE_SERVICE_NAME");

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
		printf("[%s]: table growing number is %d\n", file_name, growing_num);
		str_value = config_file_get_value(pfile, "IS_CASE_SENSITIVE");
		if (NULL == str_value) {
			case_sensitive = FALSE;
			config_file_set_value(pfile, "IS_CASE_SENSITIVE", "FALSE");
			printf("[%s]: case-insensitive\n", file_name);
		} else {
			if (0 == strcasecmp(str_value, "FALSE")) {
				case_sensitive = FALSE;
				printf("[%s]: case-insensitive\n", file_name);
			} else if (0 == strcasecmp(str_value, "TRUE")) {
			    case_sensitive = TRUE;
			    printf("[%s]: case-sensitive\n", file_name);
			} else {
				case_sensitive = FALSE;
				config_file_set_value(pfile, "IS_CASE_SENSITIVE", "FALSE");
				printf("[%s]: case-insensitive\n", file_name);
			}
		}
		sprintf(tmp_path, "%s/%s.txt", get_data_path(), file_name);
		str_table_init(file_name, case_sensitive, tmp_path, growing_num);
		if (0 != str_table_run()) {
			printf("[%s]: fail to run the module\n", file_name);
			config_file_free(pfile);
			return FALSE;
		}
		if (NULL != query_name && FALSE == register_service(query_name,
			str_table_query)) {
			printf("[%s]: failed to register \"%s\" service\n", file_name,
					query_name);
			config_file_free(pfile);
			return FALSE;
		}
		if (NULL != add_name && FALSE == register_service(add_name,
			str_table_add)) {
			printf("[%s]: failed to register \"%s\" service\n", file_name,
					add_name);
			config_file_free(pfile);
			return FALSE;
		}
		if (NULL != remove_name && FALSE == register_service(remove_name,
			str_table_remove)) {
			printf("[%s]: failed to register \"%s\" service\n", file_name,
					remove_name);
			config_file_free(pfile);
			return FALSE;
		}
		config_file_free(pfile);
		return TRUE;
	case PLUGIN_FREE:
		str_table_stop();
		str_table_free();
		return TRUE;
	}
	return false;
}


