#pragma once
#include <cstdint>
#include <string>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
namespace gromox {
extern GX_EXPORT void textmaps_init(const char *datapath = nullptr);
extern GX_EXPORT bool verify_cpid(uint32_t);
extern GX_EXPORT const char *cpid_to_cset(cpid_t);
extern GX_EXPORT cpid_t cset_to_cpid(const char *);
extern GX_EXPORT const char *lcid_to_ltag(uint32_t);
extern GX_EXPORT uint32_t ltag_to_lcid(const char *);
extern GX_EXPORT const char *mime_to_extension(const char *);
extern GX_EXPORT const char *extension_to_mime(const char *);
extern GX_EXPORT const char *lang_to_charset(const char *);
extern GX_EXPORT const char *folder_namedb_resolve(const char *locale);
extern GX_EXPORT const char *folder_namedb_get(const char *resolved_locale, unsigned int tid);
extern GX_EXPORT errno_t cpl_get_string(cpid_t, const char *tag, char *out, size_t l);
}
