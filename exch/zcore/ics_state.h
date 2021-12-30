#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>

struct ics_state {
	ics_state(uint8_t t) : type(t) {}
	~ics_state();
	NOMOVE(ics_state);

	int type = 0;
	IDSET *pgiven = nullptr, *pread = nullptr;
	IDSET *pseen = nullptr, *pseen_fai = nullptr;
};
using ICS_STATE = ics_state;

extern std::unique_ptr<ics_state> ics_state_create(uint8_t type);
BINARY* ics_state_serialize(ICS_STATE *pstate);
BOOL ics_state_deserialize(ICS_STATE *pstate, const BINARY *pbin);
