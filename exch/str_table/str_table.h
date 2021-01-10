#pragma once
#include <gromox/common_types.hpp>
#include <fcntl.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

void str_table_init(const char *module_name, BOOL case_sensitive,
	const char *path, int growing_num);
extern void str_table_free(void);
extern int str_table_run(void);
extern int str_table_stop(void);
BOOL str_table_query(const char* str);

BOOL str_table_add(const char* str);

BOOL str_table_remove(const char* str);

void str_table_console_talk(int argc, char **argv, char *result, int length);

void str_table_echo(const char *format, ...);
