#pragma once
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <gromox/simple_tree.hpp>
#define ROOT_HANDLE						0
#define INVALID_HANDLE					0xFFFFFFFF

static inline ec_error_t zh_error(uint32_t h)
{
	return h < 0x80000000 ? ecSuccess : static_cast<ec_error_t>(h);
}

struct object_node {
	object_node() = default;
	object_node(zs_objtype t, void *p) : type(t), pobject(p) {}
	template<typename T> object_node(zs_objtype t, std::unique_ptr<T> &&o) :
		type(t)
	{
		pobject = o.release();
	}
	object_node(object_node &&) noexcept;
	~object_node();
	void operator=(object_node &&) noexcept = delete;

	tree_node node{};
	uint32_t handle = INVALID_HANDLE;
	zs_objtype type = zs_objtype::invalid;
	void *pobject = nullptr;
};

struct OBJECT_TREE {
	OBJECT_TREE() = default;
	~OBJECT_TREE();
	NOMOVE(OBJECT_TREE);
	uint32_t add_object_handle(int parent, object_node &&);
	void *get_object1(uint32_t obj_handle, zs_objtype *);
	template<typename T> inline T *get_object(uint32_t h, zs_objtype *t)
		{ return static_cast<T *>(get_object1(h, t)); }
	void release_object_handle(uint32_t obj_handle);
	void *get_zstore_propval(uint32_t proptag);
	BOOL set_zstore_propval(const TAGGED_PROPVAL *);
	void remove_zstore_propval(uint32_t proptag);
	TPROPVAL_ARRAY *get_profile_sec(GUID sec_guid);
	void touch_profile_sec();
	uint32_t get_store_handle(BOOL b_private, int account_id);

	uint32_t last_handle = 0;
	SIMPLE_TREE /* <object_node> */ tree{};
	/* index into @tree elements */
	std::unordered_map<int, object_node *> m_hash;
};

extern std::unique_ptr<OBJECT_TREE> object_tree_create(const char *maildir);

extern unsigned int zcore_max_obh_per_session;
