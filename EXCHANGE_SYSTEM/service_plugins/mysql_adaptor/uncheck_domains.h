#pragma once
#include "common_types.h"

enum{
	TABLE_REFRESH_OK,
	TABLE_REFRESH_FILE_ERROR,
	TABLE_REFRESH_HASH_FAIL
};


void uncheck_domains_init(const char *list_path);
extern void uncheck_domains_free(void);
extern int uncheck_domains_run(void);
extern int uncheck_domains_stop(void);
BOOL uncheck_domains_query(const char* domain);
extern int uncheck_domains_refresh(void);
