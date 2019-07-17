#ifndef _H_DOMAIN_MAILBOX_
#define _H_DOMAIN_MAILBOX_
#include "hook_common.h"


void domain_mailbox_init(const char *path);

int domain_mailbox_run();

int domain_mailbox_stop();

void domain_mailbox_free();

BOOL domain_mailbox_hook(MESSAGE_CONTEXT *pcontext);

void domain_mailbox_console_talk(int argc, char **argv, char *result,
	int length);

#endif

