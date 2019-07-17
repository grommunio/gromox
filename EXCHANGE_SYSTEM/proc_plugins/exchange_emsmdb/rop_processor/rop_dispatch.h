#ifndef _H_ROP_DISPATCH_
#define _H_ROP_DISPATCH_
#include "processor_types.h"

int rop_dispatch(ROP_REQUEST *prequest,
	ROP_RESPONSE **ppresponse,
	uint32_t *phandles, uint8_t hnum);

#endif /* _H_ROP_DISPATCH_ */