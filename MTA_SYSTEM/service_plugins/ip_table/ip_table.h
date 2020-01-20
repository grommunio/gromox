#pragma once
#include "common_types.h"
#include <fcntl.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

void ip_table_init(const char *module_name, const char *path, int growing_num);
extern void ip_table_free(void);
extern int ip_table_run(void);
extern int ip_table_stop(void);
BOOL ip_table_query(const char* ip);

BOOL ip_table_add(const char* ip);

BOOL ip_table_remove(const char* ip);

void ip_table_console_talk(int argc, char **argv, char *result, int length);

void ip_table_echo(const char *format, ...);
