#pragma once
#include "mapi_types.h"


#ifdef __cplusplus
extern "C" {
#endif

BOOL rtfcp_uncompress(const BINARY *prtf_bin, char *pbuff_out, size_t *plength);

BINARY* rtfcp_compress(const char *pin_buff, const size_t in_length);

#ifdef __cplusplus
}
#endif
