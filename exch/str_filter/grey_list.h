#pragma once
#include <gromox/common_types.hpp>

enum{
	GREY_LIST_ALLOW = 0,
	GREY_LIST_DENY,
	GREY_LIST_NOT_FOUND
};

enum{
	GREY_REFRESH_OK = 0,
	GREY_REFRESH_FILE_ERROR,
	GREY_REFRESH_HASH_FAIL
};

void grey_list_init(BOOL case_sensitive, const char *path, int growing_num);
extern int grey_list_run();
extern int grey_list_stop();
extern void grey_list_free();
extern int grey_list_refresh();
int grey_list_query(const char *str, BOOL b_count);

BOOL grey_list_add_string(const char *str, int times, int interval);

BOOL grey_list_remove_string(const char *str);

BOOL grey_list_dump(const char *path);

BOOL grey_list_echo(const char *str, int *ptimes, int *pinterval);
