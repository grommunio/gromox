#ifndef _H_GROUP_MONITOR_
#define _H_GROUP_MONITOR_
#include "hook_common.h"

void group_monitor_init(const char *root_path, const char *subject,
	int growing_num);

int group_monitor_run();

BOOL group_monitor_process(MESSAGE_CONTEXT *pcontext);

int group_monitor_stop();

void group_monitor_free();

void group_monitor_console_talk(int argc, char **argv, char *result,
	int length);

#endif

