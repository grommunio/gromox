#ifndef _H_ADDRESS_LIST_
#define _H_ADDRESS_LIST_
#include "common_types.h"

enum {
	REFRESH_OK,
	REFRESH_FILE_ERROR,
	REFRESH_HASH_FAIL
};


void address_list_init(const char *list_path);

int address_list_run();

int address_list_stop();

void address_list_free();

BOOL address_list_query(const char *domain, char *ip, int *port);

int address_list_refresh();


#endif
