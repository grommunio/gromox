#pragma once
#include <cstdint>
#include <memory>
#include "folder_object.h"
#include <gromox/mapi_types.hpp>
#include "ics_state.h"
#include <gromox/mem_file.hpp>

struct ICSUPCTX_OBJECT final {
	~ICSUPCTX_OBJECT();

	LOGON_OBJECT *plogon = nullptr;
	FOLDER_OBJECT *pfolder = nullptr;
	std::unique_ptr<ICS_STATE> pstate; /* public member */
	uint32_t state_property = 0;
	MEM_FILE f_state_stream{};
	BOOL b_started = false;
	uint8_t sync_type = 0;
};

extern std::unique_ptr<ICSUPCTX_OBJECT> icsupctx_object_create(LOGON_OBJECT *, FOLDER_OBJECT *, uint8_t sync_type);
uint8_t icsupctx_object_get_sync_type(ICSUPCTX_OBJECT *pctx);
FOLDER_OBJECT* icsupctx_object_get_parent_object(
	ICSUPCTX_OBJECT *pctx);
BOOL icsupctx_object_begin_state_stream(ICSUPCTX_OBJECT *pctx,
	uint32_t state_property);
BOOL icsupctx_object_continue_state_stream(ICSUPCTX_OBJECT *pctx,
	const BINARY *pstream_data);
BOOL icsupctx_object_end_state_stream(ICSUPCTX_OBJECT *pctx);
ICS_STATE* icsupctx_object_get_state(ICSUPCTX_OBJECT *pctx);
void icsupctx_object_mark_started(ICSUPCTX_OBJECT *pctx);
