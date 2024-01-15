#pragma once
#include <cstdint>
#include <gromox/mapi_types.hpp>

extern GX_EXPORT void restriction_free(RESTRICTION *);
extern GX_EXPORT RESTRICTION *restriction_dup(const RESTRICTION *);
extern GX_EXPORT uint32_t restriction_size(const RESTRICTION *);
