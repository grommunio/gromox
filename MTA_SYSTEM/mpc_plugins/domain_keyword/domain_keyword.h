#ifndef _H_DOMAIN_KEYWORD_
#define _H_DOMAIN_KEYWORD_
#include "hook_common.h"

void domain_keyword_init(const char *root_path, int growing_num,
	const char *dm_host);

int domain_keyword_run();

BOOL domain_keyword_process(MESSAGE_CONTEXT *pcontext);

int domain_keyword_stop();

void domain_keyword_free();

void domain_keyword_console_talk(int argc, char **argv, char *result,
	int length);

#endif

