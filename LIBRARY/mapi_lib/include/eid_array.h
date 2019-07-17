#ifndef _H_EID_ARRAY_
#define _H_EID_ARRAY_
#include "mapi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

EID_ARRAY* eid_array_init();

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

#endif /* _H_EID_ARRAY_ */
