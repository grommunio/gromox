#pragma once
#include <cstdint>
#include <gromox/mapi_types.hpp>

IDSET* idset_init(BOOL b_serialize, uint8_t repl_type);
void idset_free(IDSET *pset);
