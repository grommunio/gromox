#ifndef _H_STR_TABLE_
#define _H_STR_TABLE_
#include "common_types.h"
#include <fcntl.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

void str_table_init(const char *module_name, BOOL case_sensitive,
	const char *path, int growing_num);

void str_table_free();

int str_table_run();

int str_table_stop();

BOOL str_table_query(const char* str);

BOOL str_table_add(const char* str);

BOOL str_table_remove(const char* str);

void str_table_console_talk(int argc, char **argv, char *result, int length);

void str_table_echo(const char *format, ...);

#endif /* _H_STR_TABLE_ */
