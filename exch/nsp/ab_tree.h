#pragma once
#include <atomic>
#include <cassert>
#include <cstdint>
#include <ctime>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <gromox/ab_tree.hpp>
#include <gromox/int_hash.hpp>
#include <gromox/proc_common.h>
#include <gromox/simple_tree.hpp>
#define USER_MAIL_ADDRESS					0
#define USER_REAL_NAME						1
#define USER_JOB_TITLE						2
#define USER_COMMENT						3
#define USER_MOBILE_TEL						4
#define USER_BUSINESS_TEL					5
#define USER_NICK_NAME						6
#define USER_HOME_ADDRESS					7
#define USER_STORE_PATH						9

struct PROPERTY_VALUE;

struct domain_node {
	domain_node(int d) : domain_id(d) {}
	domain_node(domain_node &&) noexcept;
	~domain_node();
	int domain_id = -1;
	/*
	 * All NSAB_NODE objects created for a domain are owned by this domain,
	 * or more specially, @tree. ~domain_node is in charge of destruction
	 * of all those NSAB_NODEs (since @tree is modeled as trivial-ct-dt).
	 *
	 * More than one NSAB_NODE in the tree may have the same minid, e.g.
	 * because a user can appear in different AB containers within this
	 * domain.
	 */
	SIMPLE_TREE tree{};
};
using DOMAIN_NODE = domain_node;

using gal_list_t = std::vector<SIMPLE_TREE_NODE *>;

struct NSAB_NODE {
	NSAB_NODE() = default;
	~NSAB_NODE();
	NOMOVE(NSAB_NODE);

	SIMPLE_TREE_NODE stree{};
	int id = 0;
	uint32_t minid = 0;
	void *d_info = nullptr;
	gromox::abnode_type node_type = gromox::abnode_type::remote;
};

struct AB_BASE {
	AB_BASE() = default;
	NOMOVE(AB_BASE);
	~AB_BASE() { unload(); }
	void unload();

	GUID guid{};
	std::atomic<int> status{0}, reference{0};
	time_t load_time = 0;
	/*
	 * base_id==0: not permitted (contains e.g. the AAPI administrator)
	 * base_id >0: Base is for an organization (multiple domains)
	 * base_id <0: Base is for one domain (base_id == -domain_id);
	 *             @domain_list will have exactly one entry.
	 */
	int base_id = 0;
	/*
	 * domain_node / domain_node::tree owns all the NSAB_NODEs
	 * that tree references.
	 * AB_BASE::gal_list and AB_BASE::phash can reference those nodes.
	 */
	std::vector<domain_node> domain_list;
	/*
	 * @remote_list owns all the NSAB_NODEs it references.
	 * No other AB_BASE members references these nodes.
	 */
	std::vector<NSAB_NODE *> remote_list;
	/*
	 * Ordered view (but in no particular order) over all NSAB_NODEs that represent users
	 * (so no AB containers).
	 */
	gal_list_t gal_list;
	/*
	 * A phash entry for a minid will point to _any one_ NSAB_NODE in this
	 * base that has this minid.
	 */
	std::unordered_map<int, NSAB_NODE *> phash;
	std::mutex remote_lock;
};

struct ab_tree_del {
	void operator()(AB_BASE *);
};

using AB_BASE_REF = std::unique_ptr<AB_BASE, ab_tree_del>;

extern void ab_tree_init(const char *org_name, size_t base_size, int cache_interval);
extern int ab_tree_run();
extern void ab_tree_stop();
extern AB_BASE_REF ab_tree_get_base(int base_id);
extern uint32_t ab_tree_get_leaves_num(const SIMPLE_TREE_NODE *);
extern bool ab_tree_node_to_guid(const SIMPLE_TREE_NODE *, GUID *) __attribute__((warn_unused_result));
extern BOOL ab_tree_node_to_dn(const SIMPLE_TREE_NODE *, char *buf, int len);
extern const SIMPLE_TREE_NODE *ab_tree_dn_to_node(AB_BASE *, const char *dn);
extern const SIMPLE_TREE_NODE *ab_tree_uid_to_node(const AB_BASE *, int user_id);
extern const SIMPLE_TREE_NODE *ab_tree_minid_to_node(AB_BASE *, uint32_t minid);
extern uint32_t ab_tree_get_node_minid(const SIMPLE_TREE_NODE *);
extern gromox::abnode_type ab_tree_get_node_type(const SIMPLE_TREE_NODE *);
extern void ab_tree_get_display_name(const SIMPLE_TREE_NODE *, cpid_t, char *str_dname, size_t dn_size);
extern std::vector<std::string> ab_tree_get_object_aliases(const SIMPLE_TREE_NODE *);
extern const char *ab_tree_get_user_info(const tree_node *, unsigned int type);
extern void ab_tree_get_mlist_info(const SIMPLE_TREE_NODE *, char *mail_address, char *create_day, int *list_priv);
extern void ab_tree_get_mlist_title(cpid_t, char *title);
extern void ab_tree_get_company_info(const SIMPLE_TREE_NODE *, char *name, char *address);
extern void ab_tree_get_department_name(const SIMPLE_TREE_NODE *, char *name);
extern void ab_tree_get_server_dn(const SIMPLE_TREE_NODE *, char *dn, int len);
int ab_tree_get_guid_base_id(GUID guid);
extern ec_error_t ab_tree_proplist(const tree_node *, std::vector<uint32_t> &);
extern ec_error_t ab_tree_fetchprop(const SIMPLE_TREE_NODE *, cpid_t, unsigned int proptag, PROPERTY_VALUE *);
extern void ab_tree_invalidate_cache();
extern uint32_t ab_tree_get_dtyp(const tree_node *);
extern std::optional<uint32_t> ab_tree_get_dtypx(const tree_node *);
extern void ab_tree_dump_base(const AB_BASE &);
extern uint32_t ab_tree_hidden(const tree_node *);
