#pragma once
#include "element_data.h"

#ifdef __cplusplus
extern "C" {
#endif

BOOL html_init_library(CPID_TO_CHARSET cpid_to_charset);

BOOL html_to_rtf(const char *pbuff_in, size_t length,
	uint32_t cpid, char *pbuff_out, size_t *plength);


#ifdef __cplusplus
}
#endif
