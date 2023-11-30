#pragma once
#include <atomic>
#include <cstdint>
#include <ctime>
#include <memory>
#include <unordered_map>
#include <vector>
#include <gromox/ab_tree.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/simple_tree.hpp>

/* PR_CONTAINER_FLAGS values */
#define	AB_RECIPIENTS						0x1
#define	AB_SUBCONTAINERS					0x2
#define	AB_UNMODIFIABLE						0x8

#define USER_MAIL_ADDRESS					0
#define USER_REAL_NAME						1
#define USER_JOB_TITLE						2
#define USER_COMMENT						3
#define USER_MOBILE_TEL						4
#define USER_BUSINESS_TEL					5
#define USER_NICK_NAME						6
#define USER_HOME_ADDRESS					7
#define USER_STORE_PATH						9

struct domain_node {
	domain_node(int d) : domain_id(d) {}
	domain_node(domain_node &&) noexcept;
	~domain_node();

	int domain_id = -1;
	SIMPLE_TREE tree{};
};
using DOMAIN_NODE = domain_node;

using stn_list_t = std::vector<SIMPLE_TREE_NODE *>;
struct ZAB_NODE;
/* See exch/nsp/ab_tree.h for commentary */
struct AB_BASE {
	AB_BASE() = default;
	~AB_BASE() { unload(); }
	NOMOVE(AB_BASE);
	void unload();

	std::atomic<int> status{0}, reference{0};
	time_t load_time = 0;
	size_t gal_hidden_count = 0;
	int base_id = 0;
	std::vector<domain_node> domain_list;
	stn_list_t gal_list;
	std::unordered_map<int, ZAB_NODE *> phash;
};

struct ab_tree_del {
	void operator()(AB_BASE *);
};

using AB_BASE_REF = std::unique_ptr<AB_BASE, ab_tree_del>;

extern void ab_tree_init(const char *org_name, int base_size, int cache_interval);
extern int ab_tree_run();
extern void ab_tree_stop();
extern AB_BASE_REF ab_tree_get_base(int base_id);
extern uint32_t ab_tree_make_minid(gromox::minid_type, uint32_t value);
extern gromox::minid_type ab_tree_get_minid_type(uint32_t minid);
extern uint32_t ab_tree_get_minid_value(uint32_t minid);
extern const SIMPLE_TREE_NODE *ab_tree_minid_to_node(const AB_BASE *, uint32_t minid);
extern const SIMPLE_TREE_NODE *ab_tree_guid_to_node(AB_BASE *, GUID);
extern uint32_t ab_tree_get_node_minid(const SIMPLE_TREE_NODE *);
extern gromox::abnode_type ab_tree_get_node_type(const SIMPLE_TREE_NODE *);
extern BOOL ab_tree_has_child(const SIMPLE_TREE_NODE *);
extern BOOL ab_tree_fetch_node_properties(const SIMPLE_TREE_NODE *, const PROPTAG_ARRAY *tags, TPROPVAL_ARRAY *vals);
extern bool ab_tree_resolvename(AB_BASE *, cpid_t codepage, char *str, stn_list_t &result);
extern BOOL ab_tree_match_minids(AB_BASE *, uint32_t container_id, cpid_t codepage, const RESTRICTION *filter, LONG_ARRAY *minids);
extern void ab_tree_invalidate_cache();
extern uint32_t ab_tree_hidden(const tree_node *);
