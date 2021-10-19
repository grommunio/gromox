#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>

struct store_object;

struct folder_object {
	protected:
	folder_object() = default;

	public:
	static std::unique_ptr<folder_object> create(store_object *, uint64_t folder_id, uint8_t type, uint32_t tag_access);
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	BOOL check_readonly_property(uint32_t proptag) const;
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL set_properties(const TPROPVAL_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *);
	BOOL get_permissions(PERMISSION_SET *);
	BOOL set_permissions(const PERMISSION_SET *);
	BOOL updaterules(uint32_t flags, const RULE_LIST *);

	store_object *pstore = nullptr;
	uint64_t folder_id = 0;
	uint8_t type = 0;
	uint32_t tag_access = 0;
};
