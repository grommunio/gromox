#pragma once
#include "common_types.h"
#include "mem_file.h"
#include <fcntl.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH


void tagging_table_init(const char *list_path, int growing_num);
extern int tagging_table_run(void);
BOOL tagging_table_check(const char *from, MEM_FILE *pfile);
extern int tagging_table_stop(void);
extern void tagging_table_free(void);
void tagging_table_console_talk(int argc, char **argv, char *result, int length);
