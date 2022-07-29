#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>

extern BOOL html_init_library();
extern GX_EXPORT BOOL html_to_rtf(const void *in, size_t inlen, uint32_t cpid, char **outp, size_t *outlen);
