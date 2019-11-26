#ifndef _H_DATA_SOURCE_
#define _H_DATA_SOURCE_
#include "common_types.h"
#include "double_list.h"
#include <time.h>

#define RECORD_STATUS_NORMAL                0

#define RECORD_STATUS_SUSPEND               1

#define RECORD_STATUS_OUTOFDATE             2

#define RECORD_STATUS_DELETED               3

#define MEDIA_TYPE_LIVING                   1

#define MEDIA_TYPE_IMMIGRATION              2

#define MEDIA_TYPE_EMIGRATION               3

#define MEDIA_STATUS_IMMIGRATED             1

#define MEDIA_STATUS_EMIGRATED              2

#define MEDIA_STATUS_IMMIGRATING            3

#define MEDIA_STATUS_EMIGRATING             4


typedef struct _BASIC_DOMAIN {
	char domainname[64];
	char homedir[128];
} DELETED_DOMAIN, EXTPASSWD_DOMAIN;

typedef struct _MEDIA_DOMAIN {
	char domainname[64];
	char homedir[128];
	char media[64];
} MEDIA_DOMAIN;

typedef struct _DOMAIN_INFO {
	char domainname[64];
	time_t end_day;
	char homedir[128];
	int status;
} DOMAIN_INFO;

typedef struct _USER_INFO {
	char username[128];
	char maildir[128];
	char password[128];
} USER_INFO;


typedef struct _DATA_COLLECT {
	DOUBLE_LIST list;
	DOUBLE_LIST_NODE *pnode;
} DATA_COLLECT;


DATA_COLLECT* data_source_collect_init();

void data_source_collect_free(DATA_COLLECT *pcollect);

void data_source_collect_clear(DATA_COLLECT *pcollect);

int data_source_collect_total(DATA_COLLECT *pcollect);

void data_source_collect_begin(DATA_COLLECT *pcollect);

int data_source_collect_done(DATA_COLLECT *pcollect);

void* data_source_collect_get_value(DATA_COLLECT *pcollect);

int data_source_collect_forward(DATA_COLLECT *pcollect);

void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name);

int data_source_run();

int data_source_stop();

void data_source_free();

BOOL data_source_clean_deleted_alias();

BOOL data_source_get_media_domain(int type, DATA_COLLECT *pcollect);

BOOL data_source_get_deleted_domain(DATA_COLLECT *pcollect);

BOOL data_source_get_extpasswd_domain(DATA_COLLECT *pcollect);

BOOL data_source_get_domain_list(DATA_COLLECT *pcollect);

BOOL data_source_get_user_list(const char *domainname, DATA_COLLECT *pcollect);

BOOL data_source_delete_domain(const char *domainname);

BOOL data_source_make_outofdate(const char *domainname);

BOOL data_source_status_media(const char *domainname, int status);

BOOL data_source_update_userpasswd(const char *username, const char *password);

#endif
