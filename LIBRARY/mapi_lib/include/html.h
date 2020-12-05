#pragma once
#include <gromox/defs.h>
#include "element_data.h"

#ifdef __cplusplus
extern "C" {
#endif

BOOL html_init_library(CPID_TO_CHARSET cpid_to_charset);
extern GX_EXPORT BOOL html_to_rtf(const void *in, size_t inlen, uint32_t cpid, char **outp, size_t *outlen);

#ifdef __cplusplus
}
#endif
