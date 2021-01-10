#pragma once
#include <gromox/mapi_types.hpp>

#ifdef __cplusplus
extern "C" {
#endif

extern TPROPVAL_ARRAY *tpropval_array_init(void);
void tpropval_array_free(TPROPVAL_ARRAY *parray);

BOOL tpropval_array_init_internal(TPROPVAL_ARRAY *parray);

void tpropval_array_free_internal(TPROPVAL_ARRAY *parray);

BOOL tpropval_array_set_propval(TPROPVAL_ARRAY *parray,
	const TAGGED_PROPVAL *ppropval);

void tpropval_array_remove_propval(TPROPVAL_ARRAY *parray, uint32_t proptag);
extern void *tpropval_array_get_propval(const TPROPVAL_ARRAY *parray, uint32_t proptag);
TPROPVAL_ARRAY* tpropval_array_dup(TPROPVAL_ARRAY *parray);

#ifdef __cplusplus
}
#endif
