#pragma once
#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif
#include <gromox/common_types.hpp>

#ifdef __cplusplus
extern "C" {
#endif

void* propval_dup(uint16_t type, void *pvalue);

void propval_free(uint16_t type, void *pvalue);

uint32_t propval_size(uint16_t type, void *pvalue);

BOOL propval_compare_relop(uint8_t relop,
	uint16_t proptype, void *pvalue1, void *pvalue2);

#ifdef __cplusplus
}
#endif
