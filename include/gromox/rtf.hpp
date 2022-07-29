#pragma once
#include <gromox/defs.h>
#include <gromox/element_data.hpp>

extern GX_EXPORT bool rtf_init_library();
extern GX_EXPORT bool rtf_to_html(const char *in, size_t inlen, const char *charset, char **outp, size_t *outlen, ATTACHMENT_LIST *);
