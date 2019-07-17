#ifndef _H_DATA_SOURCE_
#define _H_DATA_SOURCE_
#include "common_types.h"
#include "double_list.h"
#include <time.h>

enum {
	ADD_RESULT_OK = 0,
	ADD_RESULT_EXIST
};

enum {
	EDIT_RESULT_OK = 0,
	EDIT_RESULT_NOEXIST,
	EDIT_RESULT_MIGRATING,
	EDIT_RESULT_ERROR
};

enum {
	RESTORE_RESULT_OK = 0,
	RESTORE_RESULT_ALIAS,
	RESTORE_RESULT_ERROR
};

enum {
	ALIAS_RESULT_OK = 0,
	ALIAS_RESULT_EXIST,
	ALIAS_RESULT_NOEXIST,
	ALIAS_RESULT_NOTMAIN
};

enum {
	PASSWORD_RESULT_OK = 0,
	PASSWORD_RESULT_NOEXIST,
	PASSWORD_RESULT_ALIAS
};

#define RECORD_STATUS_NORMAL				0

#define RECORD_STATUS_SUSPEND				1

#define RECORD_STATUS_OUTOFDATE				2

#define RECORD_STATUS_DELETED				3

#define DOMAIN_TYPE_NORMAL					0

#define DOMAIN_TYPE_ALIAS					1

#define ADDRESS_TYPE_NORMAL					0

#define ADDRESS_TYPE_ALIAS					1

#define ADDRESS_TYPE_MLIST					2

#define ADDRESS_TYPE_VIRTUAL				3

#define DOMAIN_PRIVILEGE_BACKUP				0x1

#define DOMAIN_PRIVILEGE_MONITOR			0x2

#define DOMAIN_PRIVILEGE_UNCHECKUSR			0x4

#define DOMAIN_PRIVILEGE_SUBSYSTEM			0x8

#define DOMAIN_PRIVILEGE_NETDISK			0x10

#define DOMAIN_PRIVILEGE_EXTPASSWD			0x20

typedef struct _DOMAIN_ITEM {
	char domainname[64];
	char media[128];
	int max_size;
	int max_user;
	char title[128];
	char address[128];
	char admin_name[32];
	char tel[64];
	time_t create_day;
	time_t end_day;
	int privilege_bits;
	int domain_status;
	int domain_type;
} DOMAIN_ITEM;

typedef struct _DATA_COLLECT {
	DOUBLE_LIST list;
	DOUBLE_LIST_NODE *pnode;
} DATA_COLLECT;

typedef struct _DATA_NODE {
	DOUBLE_LIST_NODE node;
	DOMAIN_ITEM item;
} DATA_NODE;

DATA_COLLECT* data_source_collect_init();

void data_source_collect_free(DATA_COLLECT *pcollect);

int data_source_collect_total(DATA_COLLECT *pcollect);

void data_source_collect_begin(DATA_COLLECT *pcollect);

int data_source_collect_done(DATA_COLLECT *pcollect);

DOMAIN_ITEM* data_source_collect_get_value(DATA_COLLECT *pcollect);

int data_source_collect_forward(DATA_COLLECT *pcollect);


void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name);

int data_source_run();

int data_source_stop();

void data_source_free();

BOOL data_source_query(const char *domainname, int size_min, int size_max,
	int user_min, int user_max, const char *title, const char *address,
	const char *admin_name, const char *tel, time_t create_min,
	time_t create_max, time_t end_min, time_t end_max, int domain_status,
	int domain_type, DATA_COLLECT *pcollect);

BOOL data_source_info_domain(const char *domainname, DOMAIN_ITEM *pitem,
	int *pactual_size, int *pactual_user);

BOOL data_source_add_domain(const char *domainname, const char *homedir,
	const char *media, int max_size, int max_user, const char *title,
	const char *address, const char *admin_name, const char *tel,
	time_t create_day, time_t end_day, int privilege_bits,
	int domain_status, int *presult, int *pdomain_id);

BOOL data_source_add_alias(const char *domainname, const char *alias,
	int *presult);

BOOL data_source_edit_domain(const char *domainname, const char *media,
	int max_size, int max_user, const char *title, const char *address,
	const char *admin_name, const char *tel, time_t create_day,
	time_t end_day, int privilege_bits, int domain_status, int *presult);

BOOL data_source_get_domain_by_alias(const char *domainname, char *domain_buff);

BOOL data_source_remove_domain(const char *domainname);

BOOL data_source_restore_domain(const char *domainname, int *presult,
	int *pstatus);

BOOL data_source_get_alias(const char *domainname, DATA_COLLECT *pcollect);

BOOL data_source_num_domain(int *pnum);

BOOL data_source_domain_password(const char *domainname, const char *encryt_pw,
	int *presult);

#endif
