// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstring>
#include <gromox/ndr.hpp>
#include "emsmdb_interface.h"
#include "emsmdb_ndr.h"
#define TRY(expr) do { int v = (expr); if (v != NDR_ERR_SUCCESS) return v; } while (false)

int asyncemsmdb_ndr_pull_ecdoasyncwaitex(NDR_PULL *pndr, ECDOASYNCWAITEX_IN *r)
{
	TRY(ndr_pull_context_handle(pndr, &r->acxh));
	return ndr_pull_uint32(pndr, &r->flags_in);
}

int asyncemsmdb_ndr_push_ecdoasyncwaitex(NDR_PUSH *pndr,
	const ECDOASYNCWAITEX_OUT *r)
{
	TRY(ndr_push_uint32(pndr, r->flags_out));
	return ndr_push_int32(pndr, r->result);
}

int emsmdb_ndr_pull_ecdodisconnect(NDR_PULL *pndr, ECDODISCONNECT_IN *r)
{
	return ndr_pull_context_handle(pndr, &r->cxh);
}

int emsmdb_ndr_push_ecdodisconnect(NDR_PUSH *pndr,
	const ECDODISCONNECT_OUT *r)
{
	TRY(ndr_push_context_handle(pndr, &r->cxh));
	return ndr_push_int32(pndr, r->result);
}

int emsmdb_ndr_pull_ecrregisterpushnotification(NDR_PULL *pndr,
	ECRREGISTERPUSHNOTIFICATION_IN *r)
{
	uint32_t size;
	
	TRY(ndr_pull_context_handle(pndr, &r->cxh));
	TRY(ndr_pull_uint32(pndr, &r->rpc));
	TRY(ndr_pull_ulong(pndr, &size));
	r->pctx = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->pctx == nullptr)
		return NDR_ERR_ALLOC;
	TRY(ndr_pull_array_uint8(pndr, r->pctx, size));
	TRY(ndr_pull_uint16(pndr, &r->cb_ctx));
	if (r->cb_ctx != size)
		return NDR_ERR_ARRAY_SIZE;
	TRY(ndr_pull_uint32(pndr, &r->advise_bits));
	TRY(ndr_pull_ulong(pndr, &size));
	r->paddr = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->paddr == nullptr)
		return NDR_ERR_ALLOC;
	TRY(ndr_pull_array_uint8(pndr, r->paddr, size));
	TRY(ndr_pull_uint16(pndr, &r->cb_addr));
	if (r->cb_addr != size)
		return NDR_ERR_ARRAY_SIZE;
	return NDR_ERR_SUCCESS;
}

int emsmdb_ndr_push_ecrregisterpushnotification(NDR_PUSH *pndr,
	const ECRREGISTERPUSHNOTIFICATION_OUT *r)
{
	TRY(ndr_push_context_handle(pndr, &r->cxh));
	TRY(ndr_push_uint32(pndr, r->hnotification));
	return ndr_push_int32(pndr, r->result);
}

int emsmdb_ndr_push_ecdummyrpc(NDR_PUSH *pndr, int32_t *r)
{
	return ndr_push_int32(pndr, *r);
}

int emsmdb_ndr_pull_ecdoconnectex(NDR_PULL *pndr, ECDOCONNECTEX_IN *r)
{
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	
	TRY(ndr_pull_uint32(pndr, &size));
	TRY(ndr_pull_ulong(pndr, &offset));
	TRY(ndr_pull_ulong(pndr, &length));
	if (offset != 0 || length > size || length > 1024)
		return NDR_ERR_ARRAY_SIZE;
	TRY(ndr_pull_check_string(pndr, length, sizeof(uint8_t)));
	TRY(ndr_pull_string(pndr, r->puserdn, length));
	TRY(ndr_pull_uint32(pndr, &r->flags));
	TRY(ndr_pull_uint32(pndr, &r->conmod));
	TRY(ndr_pull_uint32(pndr, &r->limit));
	TRY(ndr_pull_uint32(pndr, &r->cpid));
	TRY(ndr_pull_uint32(pndr, &r->lcid_string));
	TRY(ndr_pull_uint32(pndr, &r->lcid_sort));
	TRY(ndr_pull_uint32(pndr, &r->cxr_link));
	TRY(ndr_pull_uint16(pndr, &r->cnvt_cps));
	TRY(ndr_pull_uint16(pndr, &r->pclient_vers[0]));
	TRY(ndr_pull_uint16(pndr, &r->pclient_vers[1]));
	TRY(ndr_pull_uint16(pndr, &r->pclient_vers[2]));
	TRY(ndr_pull_uint32(pndr, &r->timestamp));
	TRY(ndr_pull_ulong(pndr, &size));
	r->pauxin = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->pauxin == nullptr)
		return NDR_ERR_ALLOC;
	TRY(ndr_pull_array_uint8(pndr, r->pauxin, size));
	TRY(ndr_pull_uint32(pndr, &r->cb_auxin));
	if (r->cb_auxin != size)
		return NDR_ERR_ARRAY_SIZE;
	TRY(ndr_pull_uint32(pndr, &r->cb_auxout));
	if (r->cb_auxout > 0x1008)
		return NDR_ERR_RANGE;
	return NDR_ERR_SUCCESS;
}

int emsmdb_ndr_push_ecdoconnectex(NDR_PUSH *pndr, const ECDOCONNECTEX_OUT *r)
{
	uint32_t length;
	
	TRY(ndr_push_context_handle(pndr, &r->cxh));
	TRY(ndr_push_uint32(pndr, r->max_polls));
	TRY(ndr_push_uint32(pndr, r->max_retry));
	TRY(ndr_push_uint32(pndr, r->retry_delay));
	TRY(ndr_push_uint16(pndr, r->cxr));
	TRY(ndr_push_unique_ptr(pndr, r->pdn_prefix));
	length = strlen(r->pdn_prefix) + 1;
	TRY(ndr_push_ulong(pndr, length));
	TRY(ndr_push_ulong(pndr, 0));
	TRY(ndr_push_ulong(pndr, length));
	TRY(ndr_push_string(pndr, r->pdn_prefix, length));

	TRY(ndr_push_unique_ptr(pndr, r->pdisplayname));
	length = strlen(r->pdisplayname) + 1;
	TRY(ndr_push_ulong(pndr, length));
	TRY(ndr_push_ulong(pndr, 0));
	TRY(ndr_push_ulong(pndr, length));
	TRY(ndr_push_string(pndr, r->pdisplayname, length));
	TRY(ndr_push_uint16(pndr, r->pserver_vers[0]));
	TRY(ndr_push_uint16(pndr, r->pserver_vers[1]));
	TRY(ndr_push_uint16(pndr, r->pserver_vers[2]));
	TRY(ndr_push_uint16(pndr, r->pbest_vers[0]));
	TRY(ndr_push_uint16(pndr, r->pbest_vers[1]));
	TRY(ndr_push_uint16(pndr, r->pbest_vers[2]));
	TRY(ndr_push_uint32(pndr, r->timestamp));
	if (r->cb_auxout > 0x1008)
		return NDR_ERR_RANGE;
	TRY(ndr_push_ulong(pndr, r->cb_auxout));
	TRY(ndr_push_ulong(pndr, 0));
	TRY(ndr_push_ulong(pndr, r->cb_auxout));
	TRY(ndr_push_array_uint8(pndr, r->pauxout, r->cb_auxout));
	TRY(ndr_push_uint32(pndr, r->cb_auxout));
	return ndr_push_int32(pndr, r->result);
}

int emsmdb_ndr_pull_ecdorpcext2(NDR_PULL *pndr, ECDORPCEXT2_IN *r)
{
	uint32_t size;
	
	TRY(ndr_pull_context_handle(pndr, &r->cxh));
	TRY(ndr_pull_uint32(pndr, &r->flags));
	TRY(ndr_pull_ulong(pndr, &size));
	r->pin = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->pin == nullptr)
		return NDR_ERR_ALLOC;
	TRY(ndr_pull_array_uint8(pndr, r->pin, size));
	TRY(ndr_pull_uint32(pndr, &r->cb_in));
	if (r->cb_in != size)
		return NDR_ERR_ARRAY_SIZE;
	TRY(ndr_pull_uint32(pndr, &r->cb_out));
	if (r->cb_out > 0x40000)
		return NDR_ERR_RANGE;
	TRY(ndr_pull_ulong(pndr, &size));
	r->pauxin = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->pauxin == nullptr)
		return NDR_ERR_ALLOC;
	TRY(ndr_pull_array_uint8(pndr, r->pauxin, size));
	TRY(ndr_pull_uint32(pndr, &r->cb_auxin));
	if (r->cb_auxin != size)
		return NDR_ERR_ARRAY_SIZE;
	TRY(ndr_pull_uint32(pndr, &r->cb_auxout));
	if (r->cb_auxout > 0x1008)
		return NDR_ERR_RANGE;
	return NDR_ERR_SUCCESS;
}

int emsmdb_ndr_push_ecdorpcext2(NDR_PUSH *pndr, const ECDORPCEXT2_OUT *r)
{
	TRY(ndr_push_context_handle(pndr, &r->cxh));
	TRY(ndr_push_uint32(pndr, r->flags));
	if (r->cb_out > 0x40000)
		return NDR_ERR_RANGE;
	TRY(ndr_push_ulong(pndr, r->cb_out));
	TRY(ndr_push_ulong(pndr, 0));
	TRY(ndr_push_ulong(pndr, r->cb_out));
	TRY(ndr_push_array_uint8(pndr, r->pout, r->cb_out));
	TRY(ndr_push_uint32(pndr, r->cb_out));
	if (r->cb_auxout > 0x1008)
		return NDR_ERR_RANGE;
	TRY(ndr_push_ulong(pndr, r->cb_auxout));
	TRY(ndr_push_ulong(pndr, 0));
	TRY(ndr_push_ulong(pndr, r->cb_auxout));
	TRY(ndr_push_array_uint8(pndr, r->pauxout, r->cb_auxout));
	TRY(ndr_push_uint32(pndr, r->cb_auxout));
	TRY(ndr_push_uint32(pndr, r->trans_time));
	return ndr_push_int32(pndr, r->result);
}

int emsmdb_ndr_pull_ecdoasyncconnectex(NDR_PULL *pndr,
	ECDOASYNCCONNECTEX_IN *r)
{
	return ndr_pull_context_handle(pndr, &r->cxh);
}

int emsmdb_ndr_push_ecdoasyncconnectex(NDR_PUSH *pndr,
	const ECDOASYNCCONNECTEX_OUT *r)
{
	TRY(ndr_push_context_handle(pndr, &r->acxh));
	return ndr_push_int32(pndr, r->result);
}
