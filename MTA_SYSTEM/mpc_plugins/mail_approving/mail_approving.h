#ifndef _H_MAIL_APPROVING_
#define _H_MAIL_APPROVING_
#include "hook_common.h"

void mail_approving_init(const char *root_path, int growing_num,
	const char *dm_host);
extern int mail_approving_run(void);
BOOL mail_approving_process(MESSAGE_CONTEXT *pcontext);
extern int mail_approving_stop(void);
extern void mail_approving_free(void);
void mail_approving_console_talk(int argc, char **argv, char *result,
	int length);

#endif

