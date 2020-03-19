#pragma once
#include "folder_object.h"
#include "mapi_types.h"
#include "ics_state.h"

typedef struct _ICSUPCTX_OBJECT {
	STORE_OBJECT *pstore;
	uint64_t folder_id;
	ICS_STATE *pstate; /* public member */
	uint8_t sync_type;
} ICSUPCTX_OBJECT;

#ifdef __cplusplus
extern "C" {
#endif

ICSUPCTX_OBJECT* icsupctx_object_create(
	FOLDER_OBJECT *pfolder, uint8_t sync_type);

void icsupctx_object_free(ICSUPCTX_OBJECT *pctx);

BOOL icsupctx_object_upload_state(
	ICSUPCTX_OBJECT *pctx, const BINARY *pstate);

BINARY* icsupctx_object_get_state(ICSUPCTX_OBJECT *pctx);

STORE_OBJECT* icsupctx_object_get_store(ICSUPCTX_OBJECT *pctx);

uint8_t icsupctx_object_get_type(ICSUPCTX_OBJECT *pctx);

uint64_t icsupctx_object_get_parent_folder_id(ICSUPCTX_OBJECT *pctx);

#ifdef __cplusplus
} /* extern "C" */
#endif
