#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

extern TPROPVAL_ARRAY *tpropval_array_init();
void tpropval_array_free(TPROPVAL_ARRAY *parray);
extern GX_EXPORT bool tpropval_array_init_internal(TPROPVAL_ARRAY *);
void tpropval_array_free_internal(TPROPVAL_ARRAY *parray);
extern GX_EXPORT bool tpropval_array_set_propval(TPROPVAL_ARRAY *, const TAGGED_PROPVAL *);
void tpropval_array_remove_propval(TPROPVAL_ARRAY *parray, uint32_t proptag);
extern void *tpropval_array_get_propval(const TPROPVAL_ARRAY *parray, uint32_t proptag);
TPROPVAL_ARRAY* tpropval_array_dup(TPROPVAL_ARRAY *parray);
