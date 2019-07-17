#include "hook_common.h"
#include "spam_complain.h"
#include <stdio.h>

DECLARE_API;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		spam_complain_init();
		if (0 != spam_complain_run()) {
			printf("[spam_complain]: fail to run spam complain\n");
			return FALSE;
		}
        if (FALSE == register_hook(spam_complain_process)) {
			printf("[spam_complain]: fail to register the hook function\n");
            return FALSE;
        }
		printf("[spam_complain]: plugin is loaded into system\n");
        return TRUE;
    case PLUGIN_FREE:
		spam_complain_stop();
		spam_complain_free();
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
}

