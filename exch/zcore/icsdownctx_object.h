#pragma once
#include <cstdint>
#include <memory>
#include "ics_state.h"
#include <gromox/mapi_types.hpp>
#include "common_util.h"
#include "folder_object.h"

struct ICSDOWNCTX_OBJECT final {
	~ICSDOWNCTX_OBJECT();

	uint8_t sync_type = 0;
	STORE_OBJECT *pstore = nullptr;
	uint64_t folder_id = 0;
	ICS_STATE *pstate = nullptr;
	BOOL b_started = false;
	uint64_t last_changenum = 0, last_readcn = 0;
	EID_ARRAY *pgiven_eids = nullptr, *pchg_eids = nullptr;
	EID_ARRAY *pupdated_eids = nullptr, *pdeleted_eids = nullptr;
	EID_ARRAY *pnolonger_messages = nullptr, *pread_messags = nullptr;
	EID_ARRAY *punread_messags = nullptr;
	uint32_t eid_pos = 0;
};

extern std::unique_ptr<ICSDOWNCTX_OBJECT> icsdownctx_object_create(FOLDER_OBJECT *, uint8_t sync_type);
uint8_t icsdownctx_object_get_type(ICSDOWNCTX_OBJECT *pctx);
BOOL icsdownctx_object_make_content(ICSDOWNCTX_OBJECT *pctx,
	const BINARY *pstate_bin, const RESTRICTION *prestriction,
	uint16_t sync_flags, BOOL *pb_changed, uint32_t *pmsg_count);
BOOL icsdownctx_object_make_hierarchy(ICSDOWNCTX_OBJECT *pctx,
	const BINARY *pstate, uint16_t sync_flags, BOOL *pb_changed,
	uint32_t *pfld_count);
BINARY* icsdownctx_object_get_state(ICSDOWNCTX_OBJECT *pctx);
BOOL icsdownctx_object_sync_message_change(ICSDOWNCTX_OBJECT *pctx,
	BOOL *pb_found, BOOL *pb_new, TPROPVAL_ARRAY *pproplist);
BOOL icsdownctx_object_sync_folder_change(ICSDOWNCTX_OBJECT *pctx,
	BOOL *pb_found, TPROPVAL_ARRAY *pproplist);
BOOL icsdownctx_object_sync_deletions(ICSDOWNCTX_OBJECT *pctx,
	uint32_t flags, BINARY_ARRAY *pbins);
BOOL icsdownctx_object_sync_readstates(
	ICSDOWNCTX_OBJECT *pctx, STATE_ARRAY *pstates);
