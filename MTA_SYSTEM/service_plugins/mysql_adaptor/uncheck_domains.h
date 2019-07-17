#ifndef _H_UNCHECK_DOMAINS_
#define _H_UNCHECK_DOMAINS_
#include "common_types.h"

enum{
	TABLE_REFRESH_OK,
	TABLE_REFRESH_FILE_ERROR,
	TABLE_REFRESH_HASH_FAIL
};


void uncheck_domains_init(const char *list_path);

void uncheck_domains_free();

int uncheck_domains_run();

int uncheck_domains_stop();

BOOL uncheck_domains_query(const char* domain);

int uncheck_domains_refresh();


#endif
