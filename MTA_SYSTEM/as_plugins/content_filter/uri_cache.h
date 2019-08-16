#ifndef _H_URI_CACHE_
#define _H_URI_CACHE_
#include "common_types.h"

enum {
	URI_CACHE_BLACK_SIZE,
	URI_CACHE_BLACK_INTERVAL
};

void uri_cache_init(int black_size, int black_interval);

int uri_cache_run();

int uri_cache_stop();

void uri_cache_free();

BOOL uri_cache_query(const char *uri, char *reason, int length);

void uri_cache_add(const char *uri, char *reason);

BOOL uri_cache_dump_black(const char *path);

void uri_cache_set_param(int type, int value);

int uri_cache_get_param(int type);

#endif /* _H_URI_CACHE_ */
