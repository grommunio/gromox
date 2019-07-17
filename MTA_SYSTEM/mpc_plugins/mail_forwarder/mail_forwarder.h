#ifndef _H_MAIL_FORWARDER_
#define _H_MAIL_FORWARDER_
#include "hook_common.h"

void mail_forwarder_init(const char *path, const char *subject,
	const char *domain, int growing_num);

int mail_forwarder_run();

BOOL mail_forwarder_process(MESSAGE_CONTEXT *pcontext);

int mail_forwarder_stop();

void mail_forwarder_free();

void mail_forwarder_console_talk(int argc, char **argv, char *result,
	int length);

#endif

