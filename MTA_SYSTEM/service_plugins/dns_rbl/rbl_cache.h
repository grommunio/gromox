#ifndef _H_RBL_CACHE_
#define _H_RBL_CACHE_
#include "common_types.h"

enum {
	RBL_CACHE_NORMAL,
	RBL_CACHE_BLACK,
	RBL_CACHE_NONE
};

enum {
	RBL_CACHE_NORMAL_SIZE,
	RBL_CACHE_NORMAL_INTERVAL,
	RBL_CACHE_BLACK_SIZE,
	RBL_CACHE_BLACK_INTERVAL
};

void rbl_cache_init(int normal_size, int normal_interval,
	int black_size, int black_interval);

int rbl_cache_run();

int rbl_cache_stop();

void rbl_cache_free();

int rbl_cache_query(char *ip, char *reason, int length);

void rbl_cache_add(char *ip, int type, char *reason);

BOOL rbl_cache_dump_normal(const char *path);

BOOL rbl_cache_dump_black(const char *path);

void rbl_cache_set_param(int type, int value);

int rbl_cache_get_param(int type);

#endif /* _H_RBL_CACHE_ */
