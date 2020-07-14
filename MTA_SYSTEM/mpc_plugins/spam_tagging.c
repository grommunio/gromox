#include <stdbool.h>
#include <gromox/hook_common.h>
#include <stdio.h>

DECLARE_API;

static BOOL mail_hook(MESSAGE_CONTEXT *pcontext);


BOOL HOOK_LibMain(int reason, void **ppdata)
{
	/* path contains the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);	
        if (FALSE == register_hook(mail_hook)) {
			printf("[spam_tagging]: failed to register tagging hook\n");
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
	MIME *pmime;
	char subject[1200];
	
	if (FALSE == pcontext->pcontrol->is_spam) {
		return FALSE;
	}
	
	pmime = mail_get_head(pcontext->pmail);
	if (NULL == pmime) {
		return FALSE;
	}
	if (FALSE == mime_get_field(pmime, "Subject", subject, 1024)) {
		mime_set_field(pmime, "Subject", "Spam mail ...");
	} else {
		strcat(subject, "--spam mail");
		mime_set_field(pmime, "Subject", subject);
	}
	return FALSE;
}

