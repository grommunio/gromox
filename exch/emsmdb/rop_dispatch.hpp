#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapierr.hpp>
#include "processor_types.hpp"

extern ec_error_t rop_dispatch(const rop_request &, std::unique_ptr<rop_response> &, uint32_t *handles, uint8_t hnum);

extern unsigned int g_rop_debug;
