#pragma once
#include "common_types.h"

void ip_container_init(int table_size, int max_num);
extern void ip_container_free(void);
extern int ip_container_run(void);
extern int ip_container_stop(void);
BOOL ip_container_add(const char* ip);

BOOL ip_container_remove(const char* ip);

void ip_container_console_talk(int argc, char **argv, char *result, int length);
