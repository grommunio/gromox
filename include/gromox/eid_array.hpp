#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

extern GX_EXPORT EID_ARRAY *eid_array_init();
extern GX_EXPORT void eid_array_free(EID_ARRAY *);
extern GX_EXPORT bool eid_array_append(EID_ARRAY *, uint64_t);
extern GX_EXPORT bool eid_array_batch_append(EID_ARRAY *, uint32_t count, uint64_t *ids);
extern GX_EXPORT EID_ARRAY *eid_array_dup(const EID_ARRAY *);
extern GX_EXPORT bool eid_array_check(const EID_ARRAY *, uint64_t);
extern GX_EXPORT void eid_array_remove(EID_ARRAY *, uint64_t eid);
