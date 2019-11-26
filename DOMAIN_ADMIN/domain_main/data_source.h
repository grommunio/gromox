#ifndef _H_DATA_SOURCE_
#define _H_DATA_SOURCE_
#include "common_types.h"
#include <time.h>


void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name);

int data_source_run();

int data_source_stop();

void data_source_free();

BOOL data_source_info_domain(const char *domainname, int *pdomain_status,
	int *pdomain_type, char *password_buff, char *path_buff, BOOL *presult);

BOOL data_source_get_homedir(const char *domainname, char *path_buff);

#endif
