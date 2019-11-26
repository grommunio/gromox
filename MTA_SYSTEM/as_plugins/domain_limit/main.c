#include <errno.h>
#include <string.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "domain_limit.h"
#include <stdio.h>


DECLARE_API;

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop, 
    CONNECTION *pconnection, char *reason, int length);

static char g_return_reason[1024];

BOOL AS_LibMain(int reason, void **ppdata)
{
	int growing_num;
	char file_name[256];
	char temp_path[256];
	char *str_value, *psearch;
	CONFIG_FILE *pconfig_file;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init(temp_path);
		if (NULL == pconfig_file) {
			printf("[domain_limit]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "GROWING_NUM");
		if (NULL == str_value) {
			growing_num = 100;
			config_file_set_value(pconfig_file, "GROWING_NUM", "100");
		} else {
			growing_num = atoi(str_value);
			if (growing_num <= 0) {
				growing_num = 100;
				config_file_set_value(pconfig_file, "GROWING_NUM", "100");			
			}
		}
		printf("[domain_limit]: growing num of hash table is %d\n", growing_num);
		
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_reason, "authorization needed for sending "
				"mail, please contact the administrator!");
		} else {
			strcpy(g_return_reason, str_value);
		}
		printf("[domain_limit]: return string is %s\n", g_return_reason);
		if (FALSE == config_file_save(pconfig_file)) {
			printf("[domain_limit]: fail to save config file\n");
			config_file_free(pconfig_file);
			return FALSE;
		}
		config_file_free(pconfig_file);
		
		sprintf(temp_path, "%s/%s", get_data_path(), file_name);
		domain_limit_init(growing_num, temp_path);
		if (0 != domain_limit_run()) {
			printf("[domain_limit]: fail to domain limit module\n");
			return FALSE;
		}
		
        /* invoke register_judge for registering judge of mail envelop */
        if (FALSE == register_judge(envelop_judge)) {
			printf("[domain_limit]: fail to register judge function!!!\n");
            return FALSE;
        }
		register_talk(domain_limit_console_talk);
        return TRUE;
    case PLUGIN_FREE:
		domain_limit_stop();
		domain_limit_free();
        return TRUE;
    }
	return TRUE;
}

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop,
    CONNECTION *pconnection, char *reason, int length)
{
	if (FALSE == domain_limit_check(penvelop->from, &penvelop->f_rcpt_to)) {
		strncpy(reason, g_return_reason, length);
		return MESSAGE_REJECT;
	}
	return MESSAGE_ACCEPT;
}

