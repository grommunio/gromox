#pragma once
#include "common_types.h"
#include <time.h>

#define RECORD_STATUS_NORMAL                0

#define RECORD_STATUS_SUSPEND               1

#define RECORD_STATUS_OUTOFDATE             2

#define RECORD_STATUS_DELETED               3

#define DOMAIN_TYPE_NORMAL                  0

#define DOMAIN_TYPE_ALIAS                   1

#define ADDRESS_TYPE_NORMAL                 0

#define ADDRESS_TYPE_ALIAS                  1

#define ADDRESS_TYPE_MLIST                  2

#define ADDRESS_TYPE_VIRTUAL                3

#define DOMAIN_PRIVILEGE_BACKUP             0x1

#define DOMAIN_PRIVILEGE_MONITOR            0x2

#define DOMAIN_PRIVILEGE_UNCHECKUSR         0x4

#define DOMAIN_PRIVILEGE_SUBSYSTEM          0x8

#define DOMAIN_PRIVILEGE_NETDISK            0x10

#define DOMAIN_PRIVILEGE_EXTPASSWD          0x20

void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name);
extern int data_source_run(void);
extern int data_source_stop(void);
extern void data_source_free(void);
BOOL data_source_domain_info(const char *domainname, time_t *pcreate_day,
	time_t *pend_day, int *pmax_size, int *pactual_size, int *pmax_user,
	int *pactual_user, int *palias_num, int *pgroup_num, int *pmlist_num,
	int *pprivilege_bits);
