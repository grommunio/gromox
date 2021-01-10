#pragma once
#include <gromox/mapi_types.hpp>

#ifdef __cplusplus
extern "C" {
#endif

extern EID_ARRAY *eid_array_init(void);
void eid_array_free(EID_ARRAY *parray);

BOOL eid_array_append(EID_ARRAY *parray, uint64_t eid);

BOOL eid_array_batch_append(EID_ARRAY *parray,
	uint32_t count, uint64_t *pids);

EID_ARRAY* eid_array_dup(const EID_ARRAY *parray);

BOOL eid_array_check(const EID_ARRAY *parray, uint64_t eid);

void eid_array_remove(EID_ARRAY *parray, uint64_t eid);

#ifdef __cplusplus
}
#endif
