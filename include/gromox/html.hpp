#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>

extern ec_error_t html_init_library();
extern GX_EXPORT ec_error_t html_to_rtf(const void *in, size_t inlen, cpid_t, char **outp, size_t *outlen);
