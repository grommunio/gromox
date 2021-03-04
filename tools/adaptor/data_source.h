#pragma once
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>

struct DOMAIN_ITEM {
	char domainname[64];
	char homedir[128];
	int type;
};

struct ALIAS_ITEM {
	char aliasname[324];
	char mainname[324];
};

struct DATA_COLLECT {
	DOUBLE_LIST list;
	DOUBLE_LIST_NODE *pnode;
};

extern DATA_COLLECT *data_source_collect_init();
void data_source_collect_free(DATA_COLLECT *pcollect);

void data_source_collect_clear(DATA_COLLECT *pcollect);
void data_source_collect_begin(DATA_COLLECT *pcollect);

int data_source_collect_done(DATA_COLLECT *pcollect);

void* data_source_collect_get_value(DATA_COLLECT *pcollect);

int data_source_collect_forward(DATA_COLLECT *pcollect);

void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name);
BOOL data_source_get_domain_list(DATA_COLLECT *pcollect);

BOOL data_source_get_alias_list(DATA_COLLECT *pcollect);
