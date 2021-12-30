#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>
#include "ics_state.h"

struct folder_object;
struct store_object;

struct icsdownctx_object final {
	protected:
	icsdownctx_object() = default;
	NOMOVE(icsdownctx_object);

	public:
	~icsdownctx_object();
	static std::unique_ptr<icsdownctx_object> create(folder_object *, uint8_t sync_type);
	uint8_t get_type() const { return sync_type; }
	BOOL make_content(const BINARY *state, const RESTRICTION *, uint16_t sync_flags, BOOL *changed, uint32_t *msg_count);
	BOOL make_hierarchy(const BINARY *state, uint16_t sync_flags, BOOL *changed, uint32_t *fld_count);
	BINARY *get_state();
	BOOL sync_message_change(BOOL *found, BOOL *b_new, TPROPVAL_ARRAY *);
	BOOL sync_folder_change(BOOL *found, TPROPVAL_ARRAY *);
	BOOL sync_deletions(uint32_t flags, BINARY_ARRAY *);
	BOOL sync_readstates(STATE_ARRAY *);

	uint8_t sync_type = 0;
	store_object *pstore = nullptr;
	uint64_t folder_id = 0;
	std::unique_ptr<ics_state> pstate;
	BOOL b_started = false;
	uint64_t last_changenum = 0, last_readcn = 0;
	EID_ARRAY *pgiven_eids = nullptr, *pchg_eids = nullptr;
	EID_ARRAY *pupdated_eids = nullptr, *pdeleted_eids = nullptr;
	EID_ARRAY *pnolonger_messages = nullptr, *pread_messags = nullptr;
	EID_ARRAY *punread_messags = nullptr;
	uint32_t eid_pos = 0;
};
