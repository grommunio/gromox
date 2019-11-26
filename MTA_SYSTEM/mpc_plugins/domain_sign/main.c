#include <stdbool.h>
#include <gromox/hook_common.h>
#include "domain_sign.h"
#include <stdio.h>
#include <pthread.h>

DECLARE_API;


static BOOL sign_hook(MESSAGE_CONTEXT *pcontext);

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	char *psearch;
	char file_name[256];
	char temp_path[256];
	
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s", get_data_path(), file_name);
		domain_sign_init(temp_path);
		if (0 != domain_sign_run()) {
			printf("[system_sign]: fail to run message sign\n");
			return FALSE;
		}
        if (FALSE == register_hook(sign_hook)) {
            return FALSE;
        }
		register_talk(domain_sign_console_talk);
		printf("[system_sign]: plugin is loaded into system\n");
        return TRUE;
    case PLUGIN_FREE:
		domain_sign_stop();
		domain_sign_free();
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
	return false;
}

static BOOL sign_hook(MESSAGE_CONTEXT *pcontext)
{
	char *pdomain;

	if (BOUND_OUT != pcontext->pcontrol->bound_type &&
		BOUND_RELAY != pcontext->pcontrol->bound_type) {
		return FALSE;
	}

	pdomain = strchr(pcontext->pcontrol->from, '@');
	if (NULL == pdomain) {
		return FALSE;
	}
	pdomain ++;
	domain_sign_mark(pdomain, pcontext->pmail);
	return FALSE;
}



