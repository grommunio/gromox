#include <stdbool.h>
#include "hook_common.h"

DECLARE_API;

static BOOL mail_hook(MESSAGE_CONTEXT *pcontext);

static void console_talk(int argc, char **argv, char *result, int length);

BOOL HOOK_LibMain(int reason, void **ppdata)
{
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);	
        if (FALSE == register_hook(mail_hook)) {
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
	return false;
}

static BOOL mail_hook(MESSAGE_CONTEXT *pcontext)
{
    /* TODO add code here for statisticing the mail */
	return false;
}

static void console_talk(int argc, char **argv, char *result, int length)
{
    /* TODO add code here for read command from console talk */
}


