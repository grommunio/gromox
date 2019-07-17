#ifndef _H_TEMP_LIST_
#define _H_TEMP_LIST_
#include "common_types.h"
#include <time.h>


void temp_list_init(int size);

int temp_list_run();

int temp_list_stop();

void temp_list_free();

BOOL temp_list_add_ip(const char *ip, int interval);

BOOL temp_list_query(const char *ip);

BOOL temp_list_judge(const char *ip);

BOOL temp_list_remove_ip(const char *ip);

BOOL temp_list_dump(const char *path);

BOOL temp_list_echo(const char *str, time_t *puntil);


#endif /* _H_TEMP_LIST_ */
