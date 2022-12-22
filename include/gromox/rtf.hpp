#pragma once
#include <string>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>

extern GX_EXPORT bool rtf_init_library();
extern GX_EXPORT bool rtf_to_html(const char *in, size_t inlen, const char *charset, std::string &out, ATTACHMENT_LIST *);
