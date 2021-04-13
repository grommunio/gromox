#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>

extern TPROPVAL_ARRAY *tpropval_array_init();
void tpropval_array_free(TPROPVAL_ARRAY *parray);
extern GX_EXPORT bool tpropval_array_init_internal(TPROPVAL_ARRAY *);
void tpropval_array_free_internal(TPROPVAL_ARRAY *parray);
extern GX_EXPORT bool tpropval_array_set_propval(TPROPVAL_ARRAY *, const TAGGED_PROPVAL *);
static inline bool tpropval_array_set_propval(TPROPVAL_ARRAY *a, uint32_t tag, const void *d) {
	TAGGED_PROPVAL v{tag, const_cast<void *>(d)};
	return tpropval_array_set_propval(a, &v);
}
void tpropval_array_remove_propval(TPROPVAL_ARRAY *parray, uint32_t proptag);
extern void *tpropval_array_get_propval(const TPROPVAL_ARRAY *parray, uint32_t proptag);
TPROPVAL_ARRAY* tpropval_array_dup(TPROPVAL_ARRAY *parray);
