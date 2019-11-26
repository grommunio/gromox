#ifndef _H_GROUP_MONITOR_
#define _H_GROUP_MONITOR_
#include <gromox/hook_common.h>

void group_monitor_init(const char *root_path, const char *subject,
	int growing_num);
extern int group_monitor_run(void);
BOOL group_monitor_process(MESSAGE_CONTEXT *pcontext);
extern int group_monitor_stop(void);
extern void group_monitor_free(void);
void group_monitor_console_talk(int argc, char **argv, char *result,
	int length);

#endif

