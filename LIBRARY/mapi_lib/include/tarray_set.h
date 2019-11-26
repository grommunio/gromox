#ifndef _H_TARRAY_SET_
#define _H_TARRAY_SET_
#include "mapi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

extern TARRAY_SET *tarray_set_init(void);
void tarray_set_free(TARRAY_SET *pset);

void tarray_set_remove(TARRAY_SET *pset, uint32_t index);

BOOL tarray_set_append_internal(TARRAY_SET *pset, TPROPVAL_ARRAY *pproplist);

TARRAY_SET* tarray_set_dup(TARRAY_SET *pset);

#ifdef __cplusplus
}
#endif

#endif /* _H_TARRAY_SET_ */
