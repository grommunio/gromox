#pragma once
#include <cstdint>
#include <gromox/mapierr.hpp>
#include "processor_types.h"

extern ec_error_t rop_dispatch(ROP_REQUEST *, ROP_RESPONSE **, uint32_t *handles, uint8_t hnum);

extern unsigned int g_rop_debug;
