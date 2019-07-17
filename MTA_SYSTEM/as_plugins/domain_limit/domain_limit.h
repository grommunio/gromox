#ifndef _H_DOMAIN_LIMIT_
#define _H_DOMAIN_LIMIT_
#include "common_types.h"
#include "mem_file.h"

void domain_limit_init(int growing_num, const char *root_path);

int domain_limit_run();

BOOL domain_limit_check(const char *from, MEM_FILE *pf_rcpt_to);

int domain_limit_stop();

void domain_limit_free();

void domain_limit_console_talk(int argc, char **argv, char *result, int length);

#endif /* _H_DOMAIN_LIMIT_ */
