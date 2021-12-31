#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>

struct ics_state {
	ics_state(uint8_t t) : type(t) {}
	~ics_state();
	NOMOVE(ics_state);
	static std::unique_ptr<ics_state> create(uint8_t type);
	BINARY *serialize();
	BOOL deserialize(const BINARY *);

	int type = 0;
	IDSET *pgiven = nullptr, *pread = nullptr;
	IDSET *pseen = nullptr, *pseen_fai = nullptr;
};
using ICS_STATE = ics_state;

