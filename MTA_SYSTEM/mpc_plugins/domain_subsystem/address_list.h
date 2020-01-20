#pragma once
#include "common_types.h"

enum {
	REFRESH_OK,
	REFRESH_FILE_ERROR,
	REFRESH_HASH_FAIL
};


void address_list_init(const char *list_path);
extern int address_list_run(void);
extern int address_list_stop(void);
extern void address_list_free(void);
BOOL address_list_query(const char *domain, char *ip, int *port);
extern int address_list_refresh(void);
