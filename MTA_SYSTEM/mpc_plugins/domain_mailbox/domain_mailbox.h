#pragma once
#include <gromox/hook_common.h>

void domain_mailbox_init(const char *path);
extern int domain_mailbox_run(void);
extern int domain_mailbox_stop(void);
extern void domain_mailbox_free(void);
BOOL domain_mailbox_hook(MESSAGE_CONTEXT *pcontext);

void domain_mailbox_console_talk(int argc, char **argv, char *result,
	int length);
