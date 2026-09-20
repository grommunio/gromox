#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

extern GX_EXPORT PROPTAG_ARRAY *proptag_array_init();
extern GX_EXPORT void proptag_array_free_internal(PROPTAG_ARRAY *);
extern GX_EXPORT void proptag_array_free(PROPTAG_ARRAY *);
extern GX_EXPORT void proptag_array_clear(PROPTAG_ARRAY *);
extern GX_EXPORT bool proptag_array_append(PROPTAG_ARRAY *, gromox::proptag_t);
extern GX_EXPORT void proptag_array_remove(PROPTAG_ARRAY *, gromox::proptag_t);
extern GX_EXPORT PROPTAG_ARRAY *proptag_array_dup(const PROPTAG_ARRAY *);
