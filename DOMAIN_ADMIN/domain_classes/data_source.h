#pragma once
#include "common_types.h"
#include "double_list.h"
#include <time.h>

enum {
	ADD_RESULT_OK = 0,
	ADD_RESULT_NODOMAIN,
	ADD_RESULT_DOMAINNOTMAIN,
	ADD_RESULT_FULL,
	ADD_RESULT_EXIST,
	ADD_RESULT_CLASSERR
};

enum {
	RENAME_RESULT_OK = 0,
	RENAME_RESULT_NODOMAIN,
	RENAME_RESULT_DOMAINNOTMAIN,
	RENAME_RESULT_NOCLASS,
	RENAME_RESULT_CLASSERR,
	RENAME_RESULT_EXIST
};

enum {
	LINK_RESULT_OK = 0,
	LINK_RESULT_NODOMAIN,
	LINK_RESULT_DOMAINNOTMAIN,
	LINK_RESULT_NOPARENT,
	LINK_RESULT_PARENTERR,
	LINK_RESULT_NOCLASS,
	LINK_RESULT_EXIST,
	LINK_RESULT_CLASSERR,
};

#define DOMAIN_TYPE_NORMAL                  0

#define MAXIMUM_CLASS_NUM					200

typedef struct _CLASS_ITEM {
	int class_id;
	char classname[32];
	char listname[128];
} CLASS_ITEM;

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
BOOL data_source_add_class(const char *domainname, const char *classname,
	int *presult);

BOOL data_source_rename_class(const char *domainname, int class_id,
	const char *new_name, int *presult);

BOOL data_source_link_class(const char *domainname, int parent_id,
	int class_id, int *presult);

BOOL data_source_unlink_class(const char *domainname, int parent_id,
	int class_id);

BOOL data_source_get_class_list(const char *domainname, DATA_COLLECT *pcollect);

BOOL data_source_get_childrent_list(const char *domainname, int class_id,
	DATA_COLLECT *pcollect);
