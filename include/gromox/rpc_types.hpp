#pragma once
#include <cstdint>
#include <gromox/mapidefs.h>

struct GX_EXPORT CONTEXT_HANDLE {
	uint32_t handle_type = 0;
	GUID guid{};
};

struct GX_EXPORT SYNTAX_ID {
	GUID uuid{};
	uint32_t version = 0;
	bool operator==(const SYNTAX_ID &) const = default;
};

using CXH = CONTEXT_HANDLE;
using ACXH = CONTEXT_HANDLE;
