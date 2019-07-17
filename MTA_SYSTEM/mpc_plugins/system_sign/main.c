#include "hook_common.h"
#include "message_sign.h"
#include <stdio.h>
#include <pthread.h>

DECLARE_API;


static BOOL sign_hook(MESSAGE_CONTEXT *pcontext);

static void console_talk(int argc, char **argv, char *result, int length);

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
		message_sign_init(temp_path);
		if (0 != message_sign_run()) {
			printf("[system_sign]: fail to run message sign\n");
			return FALSE;
		}
        if (FALSE == register_hook(sign_hook)) {
            return FALSE;
        }
		register_talk(console_talk);
		printf("[system_sign]: plugin is loaded into system\n");
        return TRUE;
    case PLUGIN_FREE:
		message_sign_stop();
		message_sign_free();
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
}

static BOOL sign_hook(MESSAGE_CONTEXT *pcontext)
{
	message_sign_mark(pcontext->pmail);
	return FALSE;
}

/*
 *  string table's console talk
 *  @param
 *      argc            arguments number
 *      argv [in]       arguments value
 *      result [out]    buffer for retrieving result
 *      length          result buffer length
 */
static void console_talk(int argc, char **argv, char *result, int length)
{
	char help_string[] = "250 system sign help information:\r\n"
						 "\t%s reload\r\n"
						 "\t    --reload the sign list from files";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0]);
		result[length - 1] ='\0';
		return;
	}
	
	if (2 == argc && 0 == strcmp("reload", argv[1])) {
		if (TRUE == message_sign_refresh()) {
			strncpy(result, "250 sign list reload OK", length);
		} else {
			strncpy(result, "550 fail to reload sign list", length);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


