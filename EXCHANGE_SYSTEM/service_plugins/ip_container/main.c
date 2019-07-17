#include "service_common.h"
#include "ip_container.h"
#include "config_file.h"
#include <stdio.h>
#include <string.h>

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pfile;
	int max_num;
	char file_name[256], tmp_path[256];
	char *str_value, *psearch;
	
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
       
		if (FALSE == register_talk(ip_container_console_talk)) {
			printf("[ip_container]: fail to register console talk\n");
			return FALSE;
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init(tmp_path);
		if (NULL == pfile) {
			printf("[ip_container]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pfile, "CONNECTION_MAX_NUM");
		if (NULL == str_value) {
			max_num = 8;
			config_file_set_value(pfile, "CONNECTION_MAX_NUM", "8");
		} else {
			max_num = atoi(str_value);
			if (max_num <= 0) {
				max_num = 8;
				config_file_set_value(pfile, "CONNECTION_MAX_NUM", "8");
			}
		}
		printf("[ip_containe]: maximum connection number is %d\n", max_num);
		if (FALSE == config_file_save(pfile)) {
			printf("[ip_container]: fail to write configuration "
				"back to file\n");
			config_file_free(pfile);
			return FALSE;
		}
		config_file_free(pfile);
		ip_container_init(2*get_context_num(), max_num);
		if (0 != ip_container_run()) {
			printf("[ip_container]: fail to run the module\n");
			return FALSE;
		}
		if (FALSE == register_service("ip_container_add", ip_container_add)) {
			printf("[ip_container]: fail to register \"ip_container_add\" "
				"service\n");
			return FALSE;
		}
		if (FALSE == register_service("ip_container_remove",
			ip_container_remove)) {
			printf("[ip_container]: fail to register \"ip_container_remove\" "
				"service\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		ip_container_stop();
		ip_container_free();
		return TRUE;
	}
}


