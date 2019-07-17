#ifndef _H_DOMAIN_LIST_
#define _H_DOMAIN_LIST_
#include "common_types.h"

void domain_list_init(const char *url, const char *list_path, BOOL b_noop);

int domain_list_run();

int domain_list_stop();

void domain_list_free();

#endif
