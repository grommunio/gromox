#pragma once
#include <gromox/hook_common.h>

void mail_forwarder_init(const char *path, const char *subject,
	const char *domain, int growing_num);
extern int mail_forwarder_run(void);
BOOL mail_forwarder_process(MESSAGE_CONTEXT *pcontext);
extern int mail_forwarder_stop(void);
extern void mail_forwarder_free(void);
void mail_forwarder_console_talk(int argc, char **argv, char *result,
	int length);
