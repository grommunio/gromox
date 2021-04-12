#pragma once
#include <cstdint>
#include "folder_object.h"
#include <gromox/mapi_types.hpp>
#include "ics_state.h"

struct ICSUPCTX_OBJECT {
	STORE_OBJECT *pstore;
	uint64_t folder_id;
	ICS_STATE *pstate; /* public member */
	uint8_t sync_type;
};

ICSUPCTX_OBJECT* icsupctx_object_create(
	FOLDER_OBJECT *pfolder, uint8_t sync_type);
void icsupctx_object_free(ICSUPCTX_OBJECT *pctx);
BOOL icsupctx_object_upload_state(
	ICSUPCTX_OBJECT *pctx, const BINARY *pstate);
BINARY* icsupctx_object_get_state(ICSUPCTX_OBJECT *pctx);
STORE_OBJECT* icsupctx_object_get_store(ICSUPCTX_OBJECT *pctx);
uint8_t icsupctx_object_get_type(ICSUPCTX_OBJECT *pctx);
uint64_t icsupctx_object_get_parent_folder_id(ICSUPCTX_OBJECT *pctx);
