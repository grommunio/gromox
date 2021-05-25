#pragma once
#include <string>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>

struct DOMAIN_ITEM {
	std::string domainname, homedir;
};

struct ALIAS_ITEM {
	std::string aliasname, mainname;
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
extern BOOL data_source_get_domain_list(std::vector<DOMAIN_ITEM> &);
extern BOOL data_source_get_alias_list(std::vector<ALIAS_ITEM> &);
