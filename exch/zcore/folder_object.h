#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>
#include "common_util.h"
#include "store_object.h"

struct FOLDER_OBJECT {
	STORE_OBJECT *pstore = nullptr;
	uint64_t folder_id = 0;
	uint8_t type = 0;
	uint32_t tag_access = 0;
};

extern std::unique_ptr<FOLDER_OBJECT> folder_object_create(STORE_OBJECT *, uint64_t folder_id, uint8_t type, uint32_t tag_access);
BOOL folder_object_get_all_proptags(FOLDER_OBJECT *pfolder,
	PROPTAG_ARRAY *pproptags);
BOOL folder_object_check_readonly_property(
	FOLDER_OBJECT *pfolder, uint32_t proptag);
BOOL folder_object_get_properties(FOLDER_OBJECT *pfolder,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);
BOOL folder_object_set_properties(FOLDER_OBJECT *pfolder,
	const TPROPVAL_ARRAY *ppropvals);
BOOL folder_object_remove_properties(FOLDER_OBJECT *pfolder,
	const PROPTAG_ARRAY *pproptags);
BOOL folder_object_get_permissions(FOLDER_OBJECT *pfolder,
	PERMISSION_SET *pperm_set);
BOOL folder_object_set_permissions(FOLDER_OBJECT *pfolder,
	const PERMISSION_SET *pperm_set);
BOOL folder_object_updaterules(FOLDER_OBJECT *, uint32_t flags, const RULE_LIST *);
