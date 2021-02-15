#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/common_types.hpp>
namespace gromox {
extern GX_EXPORT void textmaps_init(const char *datapath);
extern GX_EXPORT bool verify_cpid(uint32_t);
extern GX_EXPORT const char *cpid_to_cset(uint32_t);
extern GX_EXPORT uint32_t cset_to_cpid(const char *);
extern GX_EXPORT const char *lcid_to_ltag(uint32_t);
extern GX_EXPORT uint32_t ltag_to_lcid(const char *);
extern GX_EXPORT const char *mime_to_extension(const char *);
extern GX_EXPORT const char *extension_to_mime(const char *);
}
