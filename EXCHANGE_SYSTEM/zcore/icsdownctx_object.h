#pragma once
#include "mem_file.h"
#include "ics_state.h"
#include "mapi_types.h"
#include "common_util.h"
#include "folder_object.h"

typedef struct _ICSDOWNCTX_OBJECT {
	uint8_t sync_type;
	STORE_OBJECT *pstore;
	uint64_t folder_id;
	ICS_STATE *pstate;
	BOOL b_started;
	uint64_t last_changenum;
	uint64_t last_readcn;
	EID_ARRAY *pgiven_eids;
	EID_ARRAY *pchg_eids;
	EID_ARRAY *pupdated_eids;
	EID_ARRAY *pdeleted_eids;
	EID_ARRAY *pnolonger_messages;
	EID_ARRAY *pread_messags;
	EID_ARRAY *punread_messags;
	uint32_t eid_pos;
} ICSDOWNCTX_OBJECT;


ICSDOWNCTX_OBJECT* icsdownctx_object_create(
	FOLDER_OBJECT *pfolder, uint8_t sync_type);

uint8_t icsdownctx_object_get_type(ICSDOWNCTX_OBJECT *pctx);

BOOL icsdownctx_object_make_content(ICSDOWNCTX_OBJECT *pctx,
	const BINARY *pstate_bin, const RESTRICTION *prestriction,
	uint16_t sync_flags, BOOL *pb_changed, uint32_t *pmsg_count);

BOOL icsdownctx_object_make_hierarchy(ICSDOWNCTX_OBJECT *pctx,
	const BINARY *pstate, uint16_t sync_flags, BOOL *pb_changed,
	uint32_t *pfld_count);

BINARY* icsdownctx_object_get_state(ICSDOWNCTX_OBJECT *pctx);

void icsdownctx_object_free(ICSDOWNCTX_OBJECT *pctx);

BOOL icsdownctx_object_sync_message_change(ICSDOWNCTX_OBJECT *pctx,
	BOOL *pb_found, BOOL *pb_new, TPROPVAL_ARRAY *pproplist);

BOOL icsdownctx_object_sync_folder_change(ICSDOWNCTX_OBJECT *pctx,
	BOOL *pb_found, TPROPVAL_ARRAY *pproplist);

BOOL icsdownctx_object_sync_deletions(ICSDOWNCTX_OBJECT *pctx,
	uint32_t flags, BINARY_ARRAY *pbins);

BOOL icsdownctx_object_sync_readstates(
	ICSDOWNCTX_OBJECT *pctx, STATE_ARRAY *pstates);
