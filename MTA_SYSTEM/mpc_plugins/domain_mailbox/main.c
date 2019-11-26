#include <stdbool.h>
#include "hook_common.h"
#include "domain_mailbox.h"
#include <stdio.h>

DECLARE_API;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
    char file_name[256], tmp_path[256];
	char *psearch;

    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		/* get the plugin name from system api */
        strcpy(file_name, get_plugin_name());
        psearch = strrchr(file_name, '.');
        if (NULL != psearch) {
            *psearch = '\0';
        }
        sprintf(tmp_path, "%s/%s.txt", get_data_path(), file_name);
		
		domain_mailbox_init(tmp_path);
		
		if (0 != domain_mailbox_run()) {
			printf("[domain_mailbox]: fail to run module\n");
            return FALSE;
		}
		register_talk(domain_mailbox_console_talk);
        if (FALSE == register_hook(domain_mailbox_hook)) {
			printf("[domain_mailbox]: fail to register the hook function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
		domain_mailbox_stop();
		domain_mailbox_free();
        return TRUE;
    }
	return false;
}

