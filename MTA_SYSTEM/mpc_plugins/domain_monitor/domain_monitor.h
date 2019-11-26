#ifndef _H_DOMAIN_MONITOR_
#define _H_DOMAIN_MONITOR_
#include "hook_common.h"

void domain_monitor_init(const char *root_path, const char *subject,
	int growing_num);
extern int domain_monitor_run(void);
BOOL domain_monitor_process(MESSAGE_CONTEXT *pcontext);
extern int domain_monitor_stop(void);
extern void domain_monitor_free(void);
void domain_monitor_console_talk(int argc, char **argv, char *result,
	int length);

#endif

