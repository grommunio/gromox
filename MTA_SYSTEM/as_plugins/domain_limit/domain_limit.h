#pragma once
#include "common_types.h"
#include "mem_file.h"

void domain_limit_init(int growing_num, const char *root_path);
extern int domain_limit_run(void);
BOOL domain_limit_check(const char *from, MEM_FILE *pf_rcpt_to);
extern int domain_limit_stop(void);
extern void domain_limit_free(void);
void domain_limit_console_talk(int argc, char **argv, char *result, int length);
