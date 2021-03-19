#pragma once
#include <cstdint>
#include <gromox/mapidefs.h>

struct CONTEXT_HANDLE {
	uint32_t handle_type;
	GUID guid;
};

struct SYNTAX_ID {
	GUID uuid;
	uint32_t version;
};
