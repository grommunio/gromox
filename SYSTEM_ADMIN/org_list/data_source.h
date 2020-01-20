#pragma once
#include "common_types.h"
#include "double_list.h"
#include <time.h>

enum {
	ADD_RESULT_OK = 0,
	ADD_RESULT_EXIST
};

typedef struct _DOMAIN_ITEM {
	DOUBLE_LIST_NODE node;
	int domain_id;
	char domainname[64];
	char title[128];
} DOMAIN_ITEM;

typedef struct _DATA_COLLECT {
	DOUBLE_LIST list;
	DOUBLE_LIST_NODE *pnode;
} DATA_COLLECT;

typedef struct _ORG_ITEM {
	DOUBLE_LIST_NODE node;
	int org_id;
	char memo[128];
	DATA_COLLECT collect;
} ORG_ITEM;

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
BOOL data_source_query(DATA_COLLECT *pcollect);

void data_source_add_domain(const char *domainname, int org_id);

void data_source_remove_domain(int domain_id, int org_id);

void data_source_add_org(const char *memo);

void data_source_remove_org(int org_id);
