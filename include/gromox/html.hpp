#pragma once
#include <gromox/defs.h>
#include <gromox/element_data.hpp>

BOOL html_init_library(CPID_TO_CHARSET cpid_to_charset);
extern GX_EXPORT BOOL html_to_rtf(const void *in, size_t inlen, uint32_t cpid, char **outp, size_t *outlen);
