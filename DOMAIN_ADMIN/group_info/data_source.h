#ifndef _H_DATA_SOURCE_
#define _H_DATA_SOURCE_
#include "common_types.h"
#include <time.h>

#define RECORD_STATUS_NORMAL                0

#define RECORD_STATUS_SUSPEND               1

#define ADDRESS_TYPE_NORMAL                 0

#define ADDRESS_TYPE_ALIAS                  1

#define ADDRESS_TYPE_MLIST                  2

#define ADDRESS_TYPE_VIRTUAL                3

#define GROUP_PRIVILEGE_BACKUP              0x1

#define GROUP_PRIVILEGE_MONITOR             0x2

#define GROUP_PRIVILEGE_LOG                 0x4

#define GROUP_PRIVILEGE_ACCOUNT             0x8

#define GROUP_PRIVILEGE_DOMAIN_BACKUP       0x100

#define GROUP_PRIVILEGE_DOMAIN_MONITOR      0x200

void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name);
extern int data_source_run(void);
extern int data_source_stop(void);
extern void data_source_free(void);
BOOL data_source_group_info(const char *groupname, char *grouptitle,
	time_t *pcreate_day, int *pmax_size, int *pactual_size, int *pmax_user,
	int *pactual_user, int *palias_num, int *pprivilege_bits);


#endif
