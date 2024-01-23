#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>

struct ics_state {
	ics_state(uint8_t t) : type(t) {}
	NOMOVE(ics_state);
	static std::unique_ptr<ics_state> create(uint8_t type);
	static std::shared_ptr<ics_state> create_shared(uint8_t type);
	BINARY *serialize();
	BOOL deserialize(const BINARY &);

	int type = 0;
	std::unique_ptr<idset> pgiven, pread, pseen, pseen_fai;
};

