#pragma once
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

extern GX_EXPORT bool rtfcp_uncompress(const BINARY *prtf_bin, char *pbuff_out, size_t *plength);
BINARY* rtfcp_compress(const char *pin_buff, const size_t in_length);
extern ssize_t rtfcp_uncompressed_size(const BINARY *);
