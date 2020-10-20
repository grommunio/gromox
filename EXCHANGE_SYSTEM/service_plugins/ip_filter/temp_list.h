#ifndef _H_TEMP_LIST_
#define _H_TEMP_LIST_
#include "common_types.h"
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

void temp_list_init(int size);
extern int temp_list_run(void);
extern int temp_list_stop(void);
extern void temp_list_free(void);
BOOL temp_list_add_ip(const char *ip, int interval);

BOOL temp_list_query(const char *ip);

BOOL temp_list_judge(const char *ip);

BOOL temp_list_remove_ip(const char *ip);

BOOL temp_list_dump(const char *path);

BOOL temp_list_echo(const char *str, time_t *puntil);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
