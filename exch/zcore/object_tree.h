#pragma once
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <gromox/simple_tree.hpp>
#define ROOT_HANDLE						0
#define INVALID_HANDLE					0xFFFFFFFF

struct OBJECT_NODE;
struct OBJECT_TREE {
	OBJECT_TREE() = default;
	~OBJECT_TREE();
	NOMOVE(OBJECT_TREE);
	uint32_t add_object_handle(int parent_handle, int type, void *obj);
	void *get_object1(uint32_t obj_handle, uint8_t *type);
	template<typename T> inline T *get_object(uint32_t h, uint8_t *t)
		{ return static_cast<T *>(get_object1(h, t)); }
	void release_object_handle(uint32_t obj_handle);
	void *get_zstore_propval(uint32_t proptag);
	BOOL set_zstore_propval(const TAGGED_PROPVAL *);
	void remove_zstore_propval(uint32_t proptag);
	TPROPVAL_ARRAY *get_profile_sec(GUID sec_guid);
	void touch_profile_sec();
	uint32_t get_store_handle(BOOL b_private, int account_id);

	uint32_t last_handle = 0;
	SIMPLE_TREE /* <OBJECT_NODE> */ tree{};
	/* index into @tree elements */
	std::unordered_map<int, OBJECT_NODE *> m_hash;
};

extern std::unique_ptr<OBJECT_TREE> object_tree_create(const char *maildir);
