#pragma once
#include <gromox/mapi_types.hpp>

void restriction_free(RESTRICTION *prestriction);

RESTRICTION* restriction_dup(const RESTRICTION *prestriction);

uint32_t restriction_size(const RESTRICTION *r);
