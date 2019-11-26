#ifndef _H_HOST_LIST_
#define _H_HOST_LIST_
#include "common_types.h"

enum {
	HOST_LIST_SCAN_INTERVAL
};

typedef void (*HOST_LIST_ENUM_FUNC)(const char *ip, int port);

void host_list_init(const char *list_path, int scan_interval);
extern int host_list_run(void);
BOOL host_list_get_unit(char *ip, int *port);

void host_list_invalid_unit(const char *ip, int port);
extern BOOL host_list_refresh(void);
extern int host_list_stop(void);
extern void host_list_free(void);
void host_list_enum_invalid(HOST_LIST_ENUM_FUNC enum_func);

int host_list_get_param(int param);

void host_list_set_param(int param, int value);

#endif /* _H_HOST_LIST_ */
