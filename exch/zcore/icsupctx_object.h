#pragma once
#include <cstdint>
#include "folder_object.h"
#include <gromox/mapi_types.hpp>
#include "ics_state.h"

struct ICSUPCTX_OBJECT final {
	STORE_OBJECT *pstore = nullptr;
	uint64_t folder_id = 0;
	ICS_STATE *pstate = nullptr; /* public member */
	uint8_t sync_type = 0;
};

extern std::unique_ptr<ICSUPCTX_OBJECT> icsupctx_object_create(FOLDER_OBJECT *, uint8_t sync_type);
BOOL icsupctx_object_upload_state(
	ICSUPCTX_OBJECT *pctx, const BINARY *pstate);
BINARY* icsupctx_object_get_state(ICSUPCTX_OBJECT *pctx);
STORE_OBJECT* icsupctx_object_get_store(ICSUPCTX_OBJECT *pctx);
uint8_t icsupctx_object_get_type(ICSUPCTX_OBJECT *pctx);
uint64_t icsupctx_object_get_parent_folder_id(ICSUPCTX_OBJECT *pctx);
