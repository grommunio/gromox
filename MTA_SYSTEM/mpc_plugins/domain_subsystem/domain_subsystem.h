#ifndef _H_DOMAIN_SUBSYSTEM_
#define _H_DOMAIN_SUBSYSTEM_

#include <gromox/hook_common.h>

void domain_subsystem_init(const char *config_path, const char *list_path,
	const char *queue_path, int times, int interval, int max_thr);
extern int domain_subsystem_run(void);
extern int domain_subsystem_stop(void);
extern void domain_subsystem_free(void);
BOOL domain_subsystem_hook(MESSAGE_CONTEXT *pcontext);

void domain_subsystem_console_talk(int argc, char **argv, char *result,
	int length);


#endif /* _H_DOMAIN_SUBSYSTEM_ */
