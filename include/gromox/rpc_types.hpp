#pragma once
#include <cstdint>
#include <gromox/mapidefs.h>

struct GX_EXPORT CONTEXT_HANDLE {
	uint32_t handle_type;
	GUID guid;
};

struct GX_EXPORT SYNTAX_ID {
	GUID uuid;
	uint32_t version;
};

using CXH = CONTEXT_HANDLE;
using ACXH = CONTEXT_HANDLE;
