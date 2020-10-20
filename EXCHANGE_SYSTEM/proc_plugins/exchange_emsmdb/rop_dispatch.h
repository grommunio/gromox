#pragma once
#include "processor_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int rop_dispatch(ROP_REQUEST *prequest,
	ROP_RESPONSE **ppresponse,
	uint32_t *phandles, uint8_t hnum);

#ifdef __cplusplus
} /* extern "C" */
#endif
