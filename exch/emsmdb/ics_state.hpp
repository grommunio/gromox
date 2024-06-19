#pragma once
#include <memory>
#include <gromox/mapi_types.hpp>

struct logon_object;

enum {
	ICS_STATE_CONTENTS_DOWN,
	ICS_STATE_CONTENTS_UP,
	ICS_STATE_HIERARCHY_DOWN,
	ICS_STATE_HIERARCHY_UP
};

struct ics_state {
	ics_state() = default;
	NOMOVE(ics_state);
	static std::unique_ptr<ics_state> create(logon_object *, int type);
	static std::shared_ptr<ics_state> create_shared(logon_object *, int type);
	BOOL append_idset(uint32_t state_property, std::unique_ptr<idset> &&);
	TPROPVAL_ARRAY *serialize();

	int type = 0;
	std::unique_ptr<idset> pgiven, pseen, pseen_fai, pread;
};
