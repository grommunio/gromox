#pragma once
#include <gromox/defs.h>
#include "element_data.h"


#ifdef __cplusplus
extern "C" {
#endif

BOOL rtf_init_library(CPID_TO_CHARSET cpid_to_charset);
extern GX_EXPORT BOOL rtf_to_html(const char *in, size_t inlen, const char *charset, char **outp, size_t *outlen, ATTACHMENT_LIST *);

#ifdef __cplusplus
}
#endif
