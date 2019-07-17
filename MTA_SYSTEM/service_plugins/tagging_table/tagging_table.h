#ifndef _H_TAGGING_TABLE_
#define _H_TAGGING_TABLE_
#include "common_types.h"
#include "mem_file.h"
#include <fcntl.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH


void tagging_table_init(const char *list_path, int growing_num);

int tagging_table_run();

BOOL tagging_table_check(const char *from, MEM_FILE *pfile);

int tagging_table_stop();

void tagging_table_free();

void tagging_table_console_talk(int argc, char **argv, char *result, int length);

#endif /* end of _H_TAGGING_TABLE_ */
