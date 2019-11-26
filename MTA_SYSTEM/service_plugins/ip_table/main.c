#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <gromox/exsvc_common.h>
#include "ip_table.h"
#include "config_file.h"
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE  *pfile;
	char file_name[256], tmp_path[256];
	char *str_value, *psearch;
	char *query_name, *add_name, *remove_name;
	int growing_num, fd;
	struct stat node_stat;
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
       
		if (FALSE == register_talk(ip_table_console_talk)) {
			printf("[%s]: fail to register console talk\n", file_name);
			return FALSE;
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init(tmp_path);
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
		if (FALSE == config_file_save(pfile)) {
			printf("[%s]: config_file_save: %s\n", file_name, strerror(errno));
			config_file_free(pfile);
			return FALSE;
		}
		sprintf(tmp_path, "%s/%s.txt", get_data_path(), file_name);
		if (0 != stat(tmp_path, &node_stat)) {
			fd = open(tmp_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
			close(fd);
			printf("[%s]: warning! cannot find data file!!!\n", file_name);
		}
		ip_table_init(file_name, tmp_path, growing_num);
		if (0 != ip_table_run()) {
			printf("[%s]: fail to run the module\n", file_name);
			config_file_free(pfile);
			return FALSE;
		}
		if (NULL != query_name && FALSE == register_service(query_name,
			ip_table_query)) {
			printf("[%s]: fail to register \"%s\" service\n", file_name,
					query_name);
			config_file_free(pfile);
			return FALSE;
		}
		if (NULL != add_name && FALSE == register_service(add_name,
			ip_table_add)) {
			printf("[%s]: fail to register \"%s\" service\n", file_name,
					add_name);
			config_file_free(pfile);
			return FALSE;
		}
		if (NULL != remove_name && FALSE == register_service(remove_name,
			ip_table_remove)) {
			printf("[%s]: fail to register \"%s\" service\n", file_name,
				remove_name);
			config_file_free(pfile);
			return FALSE;
		}
		config_file_free(pfile);
		return TRUE;
	case PLUGIN_FREE:
		ip_table_stop();
		ip_table_free();
		return TRUE;
	}
	return false;
}


