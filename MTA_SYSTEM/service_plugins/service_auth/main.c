#include <stdbool.h>
#include <gromox/mtasvc_common.h>
#include "lib_buffer.h"
#include "config_file.h"
#include "service_auth.h"
#include <string.h>
#include <stdio.h>
#include <pthread.h>


DECLARE_API;


static BOOL user_login_auth(const char* username, const char* passwd,
    char* reason, int length);

static void console_talk(int argc, char** argv, char *reslut, int length);

BOOL SVC_LibMain(int reason, void** ppdata)
{
	char cfg_path[256], *psearch;
	char file_name[256];
    CONFIG_FILE *cfg_file   = NULL;

    switch(reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(cfg_path, "%s/%s.cfg", get_config_path(), file_name);
		cfg_file = config_file_init2(NULL, cfg_path);
		if (cfg_file == NULL) {
            printf("[service_auth]: can not open config file %s\n", cfg_path);
            return FALSE;
        }
		//TODO
        config_file_free(cfg_file);
		
		service_auth_init(get_context_num(), user_login_auth);
		if (0 != service_auth_run()) {
			printf("[service_auth]: fail to run module\n");
			return FALSE;
		}
        if (FALSE == register_service("auth_ehlo", service_auth_ehlo) ||
			FALSE == register_service("auth_process", service_auth_process) ||
			FALSE == register_service("auth_retrieve", service_auth_retrieve)||
			FALSE == register_service("auth_clear", service_auth_clear)) {
			printf("[service_auth]: failed to register auth services\n");
			service_auth_stop();
            return FALSE;
        }
        if (FALSE == register_talk(console_talk)) {
			printf("[service_auth]: failed to register console_talk\n");
			service_auth_stop();
            return FALSE;
        }
        return TRUE;

    case PLUGIN_FREE:
		service_auth_stop();
		service_auth_free();
        return TRUE;
    }
    return FALSE;
}

/*
 *  smtp user login authentication, if fail give the reason
 *
 *  @param
 *      username [in]       the email address including the
 *                          domain
 *      passwd   [in]       the password of the user
 *      reason   [out]      contains the error message
 *
 *  @return
 *      TRUE            authenticate successfully
 *      FALSE           fail or error happens
 */
static BOOL user_login_auth(const char* username, const char* passwd,
    char* reason, int length)
{
	//TODO
	return false;
}

/*
 *  console server interface to communicate with the server
 *  @param
 *      argc        the number of arguments, including the service name
 *      argv [in]   the arguments list
 *      buf  [out]  fill in the operation result
 *      len         the length of the buffer
 *
 */
static void console_talk(int argc, char** argv, char* buf, int len)
{
	//TODO
}
