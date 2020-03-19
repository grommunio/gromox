#pragma once
#include "mapi_types.h"
#include "common_util.h"
#include "store_object.h"


typedef struct _FOLDER_OBJECT {
	STORE_OBJECT *pstore;
	uint64_t folder_id;
	uint8_t type;
	uint32_t tag_access;
} FOLDER_OBJECT;

#ifdef __cplusplus
extern "C" {
#endif

FOLDER_OBJECT* folder_object_create(STORE_OBJECT *pstore,
	uint64_t folder_id, uint8_t type, uint32_t tag_access);

void folder_object_free(FOLDER_OBJECT *pfolder);

uint64_t folder_object_get_id(FOLDER_OBJECT *pfolder);

uint8_t folder_object_get_type(FOLDER_OBJECT *pfolder);

uint32_t folder_object_get_tag_access(FOLDER_OBJECT *pfolder);

STORE_OBJECT* folder_object_get_store(FOLDER_OBJECT *pfolder);

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

#ifdef __cplusplus
} /* extern "C" */
#endif
