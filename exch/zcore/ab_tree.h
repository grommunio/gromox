#pragma once
#include <atomic>
#include <cstdint>
#include <ctime>
#include <memory>
#include <unordered_map>
#include <vector>
#include <gromox/simple_tree.hpp>
#include <gromox/single_list.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/int_hash.hpp>

/* PROP_TAG_CONTAINERFLAGS values */
#define	AB_RECIPIENTS						0x1
#define	AB_SUBCONTAINERS					0x2
#define	AB_UNMODIFIABLE						0x8

#define NODE_TYPE_DOMAIN					0x81
#define NODE_TYPE_GROUP						0x82
#define NODE_TYPE_CLASS						0x83
#define NODE_TYPE_REMOTE					0x0
#define NODE_TYPE_PERSON					0x1
#define NODE_TYPE_MLIST						0x2
#define NODE_TYPE_ROOM						0x3
#define NODE_TYPE_EQUIPMENT					0x4
#define NODE_TYPE_FOLDER					0x5

#define USER_MAIL_ADDRESS					0
#define USER_REAL_NAME						1
#define USER_JOB_TITLE						2
#define USER_COMMENT						3
#define USER_MOBILE_TEL						4
#define USER_BUSINESS_TEL					5
#define USER_NICK_NAME						6
#define USER_HOME_ADDRESS					7
#define USER_CREATE_DAY						8
#define USER_STORE_PATH						9

#define MINID_TYPE_ADDRESS					0x0
#define MINID_TYPE_DOMAIN					0x4
#define MINID_TYPE_GROUP					0x5
#define MINID_TYPE_CLASS					0x6

struct domain_node {
	domain_node(int);
	domain_node(domain_node &&);
	~domain_node();

	int domain_id = -1;
	SIMPLE_TREE tree{};
};
using DOMAIN_NODE = domain_node;

struct ZAB_NODE;
struct AB_BASE {
	AB_BASE() = default;
	~AB_BASE() { unload(); }
	NOMOVE(AB_BASE);
	void unload();

	std::atomic<int> status{0}, reference{0};
	time_t load_time = 0;
	int base_id = 0;
	std::vector<domain_node> domain_list;
	std::vector<SIMPLE_TREE_NODE *> gal_list;
	std::unordered_map<int, ZAB_NODE *> phash;
};

struct ab_tree_del {
	void operator()(AB_BASE *);
};

using AB_BASE_REF = std::unique_ptr<AB_BASE, ab_tree_del>;

void ab_tree_init(const char *org_name, int base_size,
	int cache_interval, int file_blocks);
extern int ab_tree_run();
extern void ab_tree_stop();
extern AB_BASE_REF ab_tree_get_base(int base_id);
uint32_t ab_tree_make_minid(uint8_t type, int value);
uint8_t ab_tree_get_minid_type(uint32_t minid);
int ab_tree_get_minid_value(uint32_t minid);
extern const SIMPLE_TREE_NODE *ab_tree_minid_to_node(const AB_BASE *, uint32_t minid);
extern const SIMPLE_TREE_NODE *ab_tree_guid_to_node(AB_BASE *, GUID);
extern uint32_t ab_tree_get_node_minid(const SIMPLE_TREE_NODE *);
extern uint8_t ab_tree_get_node_type(const SIMPLE_TREE_NODE *);
extern BOOL ab_tree_has_child(const SIMPLE_TREE_NODE *);
extern BOOL ab_tree_fetch_node_properties(const SIMPLE_TREE_NODE *, const PROPTAG_ARRAY *tags, TPROPVAL_ARRAY *vals);
BOOL ab_tree_resolvename(AB_BASE *pbase, uint32_t codepage,
	char *pstr, SINGLE_LIST *presult_list);
BOOL ab_tree_match_minids(AB_BASE *pbase, uint32_t container_id,
	uint32_t codepage, const RESTRICTION *pfilter, LONG_ARRAY *pminids);
extern void ab_tree_invalidate_cache();
