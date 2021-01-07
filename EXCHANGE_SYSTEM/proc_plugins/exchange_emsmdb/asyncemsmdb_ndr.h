#pragma once
#include "emsmdb_interface.h"
#include <gromox/proc_common.h>

struct ECDOASYNCWAITEX_IN {
	ACXH acxh;
	uint32_t flags_in;
};

struct ECDOASYNCWAITEX_OUT {
	uint32_t flags_out;
	int32_t result;
};

#ifdef __cplusplus
extern "C" {
#endif

int asyncemsmdb_ndr_pull_ecdoasyncwaitex(NDR_PULL *pndr,
	ECDOASYNCWAITEX_IN *r);
	
int asyncemsmdb_ndr_push_ecdoasyncwaitex(NDR_PUSH *pndr,
	const ECDOASYNCWAITEX_OUT *r);

#ifdef __cplusplus
} /* extern "C" */
#endif
