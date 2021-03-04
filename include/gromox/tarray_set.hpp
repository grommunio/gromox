#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

extern TARRAY_SET *tarray_set_init();
void tarray_set_free(TARRAY_SET *pset);

void tarray_set_remove(TARRAY_SET *pset, uint32_t index);
extern GX_EXPORT bool tarray_set_append_internal(TARRAY_SET *, TPROPVAL_ARRAY *);
TARRAY_SET* tarray_set_dup(TARRAY_SET *pset);
