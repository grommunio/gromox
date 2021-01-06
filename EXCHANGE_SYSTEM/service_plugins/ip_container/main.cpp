// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <gromox/svc_common.h>
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
			printf("[ip_container]: failed to register console talk\n");
			return FALSE;
		}
		sprintf(tmp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init2(NULL, tmp_path);
		if (NULL == pfile) {
			printf("[ip_container]: config_file_init %s: %s\n", tmp_path, strerror(errno));
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
		config_file_free(pfile);
		ip_container_init(2*get_context_num(), max_num);
		if (0 != ip_container_run()) {
			printf("[ip_container]: failed to run the module\n");
			return FALSE;
		}
		if (!register_service("ip_container_add", reinterpret_cast<void *>(ip_container_add))) {
			printf("[ip_container]: failed to register \"ip_container_add\" "
				"service\n");
			return FALSE;
		}
		if (!register_service("ip_container_remove",
		    reinterpret_cast<void *>(ip_container_remove))) {
			printf("[ip_container]: failed to register \"ip_container_remove\" "
				"service\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		ip_container_stop();
		ip_container_free();
		return TRUE;
	}
	return false;
}


