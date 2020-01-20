#pragma once
#include "common_types.h"
#include "double_list.h"
#include <time.h>

enum {
	ADD_RESULT_OK = 0,
	ADD_RESULT_NODOMAIN,
	ADD_RESULT_DOMAINNOTMAIN,
	ADD_RESULT_SIZEEXCEED,
	ADD_RESULT_USREXCEED,
	ADD_RESULT_FULL,
	ADD_RESULT_EXIST
};

enum {
	EDIT_RESULT_OK = 0,
	EDIT_RESULT_NODOMAIN,
	EDIT_RESULT_DOMAINNOTMAIN,
	EDIT_RESULT_NOEXIST,
	EDIT_RESULT_SIZEEXCEED,
	EDIT_RESULT_USREXCEED
};

enum {
	REMOVE_RESULT_OK = 0,
	REMOVE_RESULT_NOTEXIST,
	REMOVE_RESULT_NODOMAIN,
	REMOVE_RESULT_DOMAINERR
};


#define RECORD_STATUS_NORMAL				0

#define RECORD_STATUS_SUSPEND				1

#define DOMAIN_TYPE_NORMAL					0

#define DOMAIN_TYPE_ALIAS					1

#define ADDRESS_TYPE_NORMAL					0

#define ADDRESS_TYPE_ALIAS					1

#define ADDRESS_TYPE_MLIST					2

#define ADDRESS_TYPE_VIRTUAL				3

#define MLIST_TYPE_GROUP					1


typedef struct _GROUP_ITEM {
	char groupname[128];
	int max_size;
	int max_user;
	char title[128];
	time_t create_day;
	int privilege_bits;
	int group_status;
} GROUP_ITEM;

typedef struct _USER_INFO {
	char username[128];
	char maildir[128];
} USER_INFO;

typedef struct _DATA_COLLECT {
	DOUBLE_LIST list;
	DOUBLE_LIST_NODE *pnode;
} DATA_COLLECT;

extern DATA_COLLECT *data_source_collect_init(void);
void data_source_collect_free(DATA_COLLECT *pcollect);

int data_source_collect_total(DATA_COLLECT *pcollect);

void data_source_collect_begin(DATA_COLLECT *pcollect);

int data_source_collect_done(DATA_COLLECT *pcollect);

void* data_source_collect_get_value(DATA_COLLECT *pcollect);

int data_source_collect_forward(DATA_COLLECT *pcollect);


void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name);
extern int data_source_run(void);
extern int data_source_stop(void);
extern void data_source_free(void);
BOOL data_source_add_group(const char *groupname, const char *password,
	int max_size, int max_user, const char *title, int privilege_bits,
	int group_status, int *presult);

BOOL data_source_edit_group(const char *groupname, const char *password,
	int max_size, int max_user, const char *title, int privilege_bits,
	int group_status, int *presult);

BOOL data_source_info_group(const char *groupname, GROUP_ITEM *pitem,
	int *pactual_size, int *pactual_user);

BOOL data_source_info_domain(const char *domainname, int *pprivilege_bites);

BOOL data_source_get_domain_homedir(const char *domainname, char *path_buff);

BOOL data_source_remove_group(const char *groupname, int *presult);

BOOL data_source_get_group_list(const char *domainname, DATA_COLLECT *pcollect);

BOOL data_source_get_group_users(const char *groupname, DATA_COLLECT *pcollect);
