#ifndef _H_DATA_SOURCE_
#define _H_DATA_SOURCE_
#include "common_types.h"
#include <time.h>


void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name);
extern int data_source_run(void);
extern int data_source_stop(void);
extern void data_source_free(void);
BOOL data_source_info_group(const char *groupname, int *pprivilege_bits);

BOOL data_source_get_homedir(const char *domainname, char *path_buff);

BOOL data_source_check_group(const char *groupname, const char *username,
	BOOL *presult);


#endif
