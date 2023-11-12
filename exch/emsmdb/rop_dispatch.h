#pragma once
#include <cstdint>
#include <gromox/mapierr.hpp>
#include "processor_types.h"

extern ec_error_t rop_dispatch(const rop_request &, rop_response *&, uint32_t *handles, uint8_t hnum);

extern unsigned int g_rop_debug;
