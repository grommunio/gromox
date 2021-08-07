#pragma once
#include <cstdint>
#include "folder_object.h"
#include <gromox/mapi_types.hpp>
#include "ics_state.h"

struct ICSUPCTX_OBJECT final {
	BOOL upload_state(const BINARY *state);
	BINARY *get_state();
	STORE_OBJECT *get_store() const { return pstore; }
	uint8_t get_type() const { return sync_type; }
	uint64_t get_parent_folder_id() const { return folder_id; }

	STORE_OBJECT *pstore = nullptr;
	uint64_t folder_id = 0;
	ICS_STATE *pstate = nullptr; /* public member */
	uint8_t sync_type = 0;
};

extern std::unique_ptr<ICSUPCTX_OBJECT> icsupctx_object_create(FOLDER_OBJECT *, uint8_t sync_type);
