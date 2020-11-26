#pragma once
#include "common_types.h"
#include "double_list.h"



typedef struct _DOMAIN_ITEM {
	char domainname[64];
	char homedir[128];
	int type;
} DOMAIN_ITEM;

typedef struct _ALIAS_ITEM {
	char aliasname[128];
	char mainname[128];
} ALIAS_ITEM;

typedef struct _GROUP_ITEM {
	char groupname[64];
	char homedir[128];
	int type;
} GROUP_ITEM;



typedef struct _DATA_COLLECT {
	DOUBLE_LIST list;
	DOUBLE_LIST_NODE *pnode;
} DATA_COLLECT;

extern DATA_COLLECT *data_source_collect_init(void);
void data_source_collect_free(DATA_COLLECT *pcollect);

void data_source_collect_clear(DATA_COLLECT *pcollect);

int data_source_collect_total(DATA_COLLECT *pcollect);

void data_source_collect_begin(DATA_COLLECT *pcollect);

int data_source_collect_done(DATA_COLLECT *pcollect);

void* data_source_collect_get_value(DATA_COLLECT *pcollect);

int data_source_collect_forward(DATA_COLLECT *pcollect);

void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name);
BOOL data_source_get_domain_list(DATA_COLLECT *pcollect);

BOOL data_source_get_alias_list(DATA_COLLECT *pcollect);
BOOL data_source_get_uncheckusr_list(DATA_COLLECT *pcollect);
