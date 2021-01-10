#pragma once
#include <cstdint>
#include "processor_types.h"

int rop_dispatch(ROP_REQUEST *prequest,
	ROP_RESPONSE **ppresponse,
	uint32_t *phandles, uint8_t hnum);
