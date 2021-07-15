#pragma once
#include <cstdint>
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

extern void data_source_init(const char *host, uint16_t port, const char *user, const char *password, const char *db_name);
extern BOOL data_source_get_domain_list(std::vector<DOMAIN_ITEM> &);
extern BOOL data_source_get_alias_list(std::vector<ALIAS_ITEM> &);
