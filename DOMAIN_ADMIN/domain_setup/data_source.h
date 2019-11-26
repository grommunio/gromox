#ifndef _H_DATA_SOURCE_
#define _H_DATA_SOURCE_
#include "common_types.h"
#include <time.h>


void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name);
extern int data_source_run(void);
extern int data_source_stop(void);
extern void data_source_free(void);
BOOL data_source_get_password(const char *domainname, char *password_buff,
	BOOL *presult);

BOOL data_source_set_password(const char *domainname, const char *password);

BOOL data_source_get_homedir(const char *domainname, char *path_buff);

BOOL data_source_info_domain(const char *domainname, int *pprivilege_bits);

#endif
