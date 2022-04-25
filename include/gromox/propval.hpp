#pragma once
#include <cstdint>
#include <gromox/common_types.hpp>

extern GX_EXPORT void *propval_dup(uint16_t type, const void *);
void propval_free(uint16_t type, void *pvalue);
uint32_t propval_size(uint16_t type, void *pvalue);
extern GX_EXPORT BOOL propval_compare_relop(uint8_t relop, uint16_t proptype, const void *, const void *);
extern GX_EXPORT int SVREID_compare(const SVREID *, const SVREID *);
