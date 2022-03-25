#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>

enum {
	SPECIAL_CONTAINER_ROOT = 0xc,
	SPECIAL_CONTAINER_EMPTY = 0xd,
	SPECIAL_CONTAINER_PROVIDER = 0xe,
	SPECIAL_CONTAINER_GAL = 0xf,
};

#define CONTAINER_TYPE_FOLDER					1
#define CONTAINER_TYPE_ABTREE					2

union CONTAINER_ID {
	struct {
		BOOL b_private;
		uint64_t folder_id;
	} exmdb_id;
	struct {
		int base_id;
		uint32_t minid;
	} abtree_id;
};

struct container_object {
	protected:
	container_object() = default;
	NOMOVE(container_object);

	public:
	~container_object() { clear(); }
	static std::unique_ptr<container_object> create(uint8_t type, CONTAINER_ID);
	BOOL fetch_special_property(uint8_t special_type, uint32_t proptag, void **out);
	void clear();
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL load_user_table(const RESTRICTION *);
	BOOL get_container_table_num(BOOL depth, uint32_t *num);
	BOOL query_container_table(const PROPTAG_ARRAY *, BOOL depth, uint32_t start_pos, int32_t row_needed, TARRAY_SET *);
	BOOL get_user_table_num(uint32_t *);
	BOOL query_user_table(const PROPTAG_ARRAY *, uint32_t start_pos, int32_t row_needed, TARRAY_SET *);

	uint8_t type = 0;
	CONTAINER_ID id{};
	union {
		TARRAY_SET *prow_set;
		LONG_ARRAY *pminid_array;
	} contents{};
};

BOOL container_object_fetch_special_property(
	uint8_t special_type, uint32_t proptag, void **ppvalue);
void container_object_get_container_table_all_proptags(
	PROPTAG_ARRAY *pproptags);
void container_object_get_user_table_all_proptags(
	PROPTAG_ARRAY *pproptags);
