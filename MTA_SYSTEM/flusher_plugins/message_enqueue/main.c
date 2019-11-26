#include <errno.h>
#include <string.h>
#include <gromox/flusher_common.h>
#include "message_enqueue.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>

DECLARE_API;

BOOL FLH_LibMain(int reason, void** ppdata)
{
	const char *queue_path;
	char *str_value, *psearch;
    char file_name[256], temp_path[256];
	char temp_buff[64];
    CONFIG_FILE *pfile;
    int tape_units;

    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init(temp_path);
		if (NULL == pfile) {
			printf("[message_enqueue]: config_file_init %s: %s\n",
				temp_path, strerror(errno));
			return FALSE;
		}
        queue_path = config_file_get_value(pfile, "ENQUEUE_PATH");
        if (NULL == queue_path) {
			queue_path = "../queue";
			config_file_set_value(pfile, "ENQUEUE_PATH", "../queue");
        }
		printf("[message_enqueue]: enqueue path is %s\n", queue_path);
        str_value = config_file_get_value(pfile, "ENQUEUE_TAPE_SIZE");
        if (NULL == str_value) {
			tape_units = 0;
			config_file_set_value(pfile, "ENQUEUE_TAPE_SIZE", "0");
		} else {
			tape_units = atobyte(str_value)/(2*64*1024);
			if (tape_units < 0) {
				tape_units = 0;
				config_file_set_value(pfile, "ENQUEUE_TAPE_SIZE", "0");
			}
        }
		bytetoa(tape_units*2*64*1024, temp_buff);
		printf("[message_enqueue]: enqueue tape size is %s\n", temp_buff);

        message_enqueue_init(queue_path, tape_units);
        if (0 != message_enqueue_run()) {
            printf("[message_enqueue]: fail to run the module\n");
			config_file_free(pfile);
            return FALSE;
        }
        config_file_free(pfile);
		register_talk(message_enqueue_console_talk);
        if (FALSE == register_cancel(message_enqueue_cancel)) {
            printf("[message_enqueue]: fail to register cancel flushing\n");
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

