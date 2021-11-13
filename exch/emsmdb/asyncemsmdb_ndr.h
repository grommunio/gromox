#pragma once
#include <cstdint>
#include <gromox/rpc_types.hpp>

struct NDR_PULL;
struct NDR_PUSH;

struct ECDOASYNCWAITEX_IN {
	ACXH acxh;
	uint32_t flags_in;
};

struct ECDOASYNCWAITEX_OUT {
	uint32_t flags_out;
	int32_t result;
};

int asyncemsmdb_ndr_pull_ecdoasyncwaitex(NDR_PULL *pndr,
	ECDOASYNCWAITEX_IN *r);
int asyncemsmdb_ndr_push_ecdoasyncwaitex(NDR_PUSH *pndr,
	const ECDOASYNCWAITEX_OUT *r);
