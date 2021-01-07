// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include "asyncemsmdb_ndr.h"

int asyncemsmdb_ndr_pull_ecdoasyncwaitex(NDR_PULL *pndr,
	ECDOASYNCWAITEX_IN *r)
{
	int status;
		
	status = ndr_pull_context_handle(pndr, &r->acxh);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_uint32(pndr, &r->flags_in);
}

int asyncemsmdb_ndr_push_ecdoasyncwaitex(NDR_PUSH *pndr,
	const ECDOASYNCWAITEX_OUT *r)
{
	int status;
	
	status = ndr_push_uint32(pndr, r->flags_out);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_int32(pndr, r->result);
}
