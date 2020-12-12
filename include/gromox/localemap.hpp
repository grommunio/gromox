#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include "common_types.h"
namespace gromox {
extern GX_EXPORT void localemap_init();
extern GX_EXPORT BOOL verify_cpid(uint32_t);
extern GX_EXPORT const char *cpid_to_cset(uint32_t);
extern GX_EXPORT uint32_t cset_to_cpid(const char *);
extern GX_EXPORT const char *lcid_to_ltag(uint32_t);
extern GX_EXPORT uint32_t ltag_to_lcid(const char *);
}
