#pragma once
#include <gromox/hook_common.h>

void domain_keyword_init(const char *root_path, int growing_num,
	const char *dm_host);
extern int domain_keyword_run(void);
BOOL domain_keyword_process(MESSAGE_CONTEXT *pcontext);
extern int domain_keyword_stop(void);
extern void domain_keyword_free(void);
void domain_keyword_console_talk(int argc, char **argv, char *result,
	int length);
