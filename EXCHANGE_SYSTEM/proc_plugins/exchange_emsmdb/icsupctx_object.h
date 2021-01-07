#pragma once
#include "folder_object.h"
#include "mapi_types.h"
#include "ics_state.h"
#include "mem_file.h"

struct ICSUPCTX_OBJECT {
	LOGON_OBJECT *plogon;
	FOLDER_OBJECT *pfolder;
	ICS_STATE *pstate; /* public member */
	uint32_t state_property;
	MEM_FILE f_state_stream;
	BOOL b_started;
	uint8_t sync_type;
};

#ifdef __cplusplus
extern "C" {
#endif

ICSUPCTX_OBJECT* icsupctx_object_create(
	LOGON_OBJECT *plogon, FOLDER_OBJECT *pfolder,
	uint8_t sync_type);

void icsupctx_object_free(ICSUPCTX_OBJECT *pctx);

uint8_t icsupctx_object_get_sync_type(ICSUPCTX_OBJECT *pctx);

FOLDER_OBJECT* icsupctx_object_get_parent_object(
	ICSUPCTX_OBJECT *pctx);

BOOL icsupctx_object_begin_state_stream(ICSUPCTX_OBJECT *pctx,
	uint32_t state_property);

BOOL icsupctx_object_continue_state_stream(ICSUPCTX_OBJECT *pctx,
	const BINARY *pstream_data);

BOOL icsupctx_object_end_state_stream(ICSUPCTX_OBJECT *pctx);

ICS_STATE* icsupctx_object_get_state(ICSUPCTX_OBJECT *pctx);

BOOL icsupctx_object_check_started(ICSUPCTX_OBJECT *pctx);

void icsupctx_object_mark_started(ICSUPCTX_OBJECT *pctx);

#ifdef __cplusplus
} /* extern "C" */
#endif
