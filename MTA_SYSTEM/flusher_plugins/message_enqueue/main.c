#include <errno.h>
#include <string.h>
#include <gromox/flusher_common.h>
#include <gromox/paths.h>
#include "message_enqueue.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>

DECLARE_API;

BOOL FLH_LibMain(int reason, void** ppdata)
{
	const char *queue_path;
	char *psearch;
    char file_name[256], temp_path[256];
    CONFIG_FILE *pfile;

    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init2(NULL, temp_path);
		if (NULL == pfile) {
			printf("[message_enqueue]: config_file_init %s: %s\n",
				temp_path, strerror(errno));
			return FALSE;
		}
        queue_path = config_file_get_value(pfile, "ENQUEUE_PATH");
        if (NULL == queue_path) {
			queue_path = PKGSTATEQUEUEDIR;
			config_file_set_value(pfile, "ENQUEUE_PATH", queue_path);
        }
		printf("[message_enqueue]: enqueue path is %s\n", queue_path);

		message_enqueue_init(queue_path);
        if (0 != message_enqueue_run()) {
			printf("[message_enqueue]: failed to run the module\n");
			config_file_free(pfile);
            return FALSE;
        }
        config_file_free(pfile);
		register_talk(message_enqueue_console_talk);
        if (FALSE == register_cancel(message_enqueue_cancel)) {
			printf("[message_enqueue]: failed to register cancel flushing\n");
            return FALSE;
        }
		set_flush_ID(message_enqueue_retrieve_flush_ID());
        return TRUE;
    case PLUGIN_FREE:
        if (0 != message_enqueue_stop()) {
            return FALSE;
		}
        message_enqueue_free();
        return TRUE;
    }
    return FALSE;
}

