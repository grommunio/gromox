#pragma once
#include <cstdint>
#include <gromox/common_types.hpp>

extern GX_EXPORT void *propval_dup(uint16_t type, const void *);
void propval_free(uint16_t type, void *pvalue);
extern GX_EXPORT uint32_t propval_size(uint16_t type, void *) __attribute__((nonnull(2)));
extern GX_EXPORT int propval_compare(const void *, const void *, uint16_t proptype) __attribute__((nonnull(1,2)));
extern GX_EXPORT bool propval_compare_relop(relop, uint16_t proptype, const void *, const void *) __attribute__((nonnull(3,4)));
extern GX_EXPORT int SVREID_compare(const SVREID *, const SVREID *);
namespace gromox {
extern GX_EXPORT bool three_way_eval(enum relop, int);
extern GX_EXPORT bool propval_compare_relop_nullok(relop, uint16_t proptype, const void *, const void *);
}
