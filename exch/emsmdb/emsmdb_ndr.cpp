// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstring>
#include <gromox/ndr.hpp>
#include "emsmdb_interface.h"
#include "emsmdb_ndr.h"
#define TRY(expr) do { int v = (expr); if (v != NDR_ERR_SUCCESS) return v; } while (false)

static int asyncemsmdb_ndr_pull_ecdoasyncwaitex(NDR_PULL *pndr, ECDOASYNCWAITEX_IN *r)
{
	TRY(ndr_pull_context_handle(pndr, &r->acxh));
	return pndr->g_uint32(&r->flags_in);
}

static int asyncemsmdb_ndr_push_ecdoasyncwaitex(NDR_PUSH *pndr,
	const ECDOASYNCWAITEX_OUT *r)
{
	TRY(pndr->p_uint32(r->flags_out));
	return pndr->p_int32(r->result);
}

int asyncemsmdb_ndr_pull(int opnum, NDR_PULL *pndr, void **ppin)
{
	switch (opnum) {
	case ecDoAsyncWaitEx:
		*ppin = ndr_stack_anew<ECDOASYNCWAITEX_IN>(NDR_STACK_IN);
		if (*ppin == nullptr)
			return NDR_ERR_ALLOC;
		return asyncemsmdb_ndr_pull_ecdoasyncwaitex(pndr, static_cast<ECDOASYNCWAITEX_IN *>(*ppin));
	default:
		return NDR_ERR_BAD_SWITCH;
	}
}

int asyncemsmdb_ndr_push(int opnum, NDR_PUSH *pndr, void *pout)
{
	switch (opnum) {
	case ecDoAsyncWaitEx:
		return asyncemsmdb_ndr_push_ecdoasyncwaitex(pndr, static_cast<ECDOASYNCWAITEX_OUT *>(pout));
	default:
		return NDR_ERR_BAD_SWITCH;
	}
}

static int emsmdb_ndr_pull_ecdodisconnect(NDR_PULL *pndr, ECDODISCONNECT_IN *r)
{
	return ndr_pull_context_handle(pndr, &r->cxh);
}

static int emsmdb_ndr_push_ecdodisconnect(NDR_PUSH *pndr,
	const ECDODISCONNECT_OUT *r)
{
	TRY(pndr->p_ctx_handle(r->cxh));
	return pndr->p_int32(r->result);
}

static int emsmdb_ndr_pull_ecrregisterpushnotification(NDR_PULL *pndr,
	ECRREGISTERPUSHNOTIFICATION_IN *r)
{
	uint32_t size;
	
	TRY(ndr_pull_context_handle(pndr, &r->cxh));
	TRY(pndr->g_uint32(&r->rpc));
	TRY(pndr->g_ulong(&size));
	r->pctx = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->pctx == nullptr)
		return NDR_ERR_ALLOC;
	TRY(ndr_pull_array_uint8(pndr, r->pctx, size));
	TRY(pndr->g_uint16(&r->cb_ctx));
	if (r->cb_ctx != size)
		return NDR_ERR_ARRAY_SIZE;
	TRY(pndr->g_uint32(&r->advise_bits));
	TRY(pndr->g_ulong(&size));
	r->paddr = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->paddr == nullptr)
		return NDR_ERR_ALLOC;
	TRY(ndr_pull_array_uint8(pndr, r->paddr, size));
	TRY(pndr->g_uint16(&r->cb_addr));
	if (r->cb_addr != size)
		return NDR_ERR_ARRAY_SIZE;
	return NDR_ERR_SUCCESS;
}

static int emsmdb_ndr_push_ecrregisterpushnotification(NDR_PUSH *pndr,
	const ECRREGISTERPUSHNOTIFICATION_OUT *r)
{
	TRY(pndr->p_ctx_handle(r->cxh));
	TRY(pndr->p_uint32(r->hnotification));
	return pndr->p_int32(r->result);
}

static int emsmdb_ndr_push_ecdummyrpc(NDR_PUSH *pndr, int32_t *r)
{
	return pndr->p_int32(*r);
}

static int emsmdb_ndr_pull_ecdoconnectex(NDR_PULL *pndr, ECDOCONNECTEX_IN *r)
{
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	
	TRY(pndr->g_uint32(&size));
	TRY(pndr->g_ulong(&offset));
	TRY(pndr->g_ulong(&length));
	if (offset != 0 || length > size || length > 1024)
		return NDR_ERR_ARRAY_SIZE;
	TRY(ndr_pull_check_string(pndr, length, sizeof(uint8_t)));
	TRY(ndr_pull_string(pndr, r->puserdn, length));
	TRY(pndr->g_uint32(&r->flags));
	TRY(pndr->g_uint32(&r->conmod));
	TRY(pndr->g_uint32(&r->limit));
	TRY(pndr->g_uint32(&r->cpid));
	TRY(pndr->g_uint32(&r->lcid_string));
	TRY(pndr->g_uint32(&r->lcid_sort));
	TRY(pndr->g_uint32(&r->cxr_link));
	TRY(pndr->g_uint16(&r->cnvt_cps));
	TRY(pndr->g_uint16(&r->pclient_vers[0]));
	TRY(pndr->g_uint16(&r->pclient_vers[1]));
	TRY(pndr->g_uint16(&r->pclient_vers[2]));
	TRY(pndr->g_uint32(&r->timestamp));
	TRY(pndr->g_ulong(&size));
	r->pauxin = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->pauxin == nullptr)
		return NDR_ERR_ALLOC;
	TRY(ndr_pull_array_uint8(pndr, r->pauxin, size));
	TRY(pndr->g_uint32(&r->cb_auxin));
	if (r->cb_auxin != size)
		return NDR_ERR_ARRAY_SIZE;
	TRY(pndr->g_uint32(&r->cb_auxout));
	if (r->cb_auxout > 0x1008)
		return NDR_ERR_RANGE;
	return NDR_ERR_SUCCESS;
}

static int emsmdb_ndr_push_ecdoconnectex(NDR_PUSH *pndr,
    const ECDOCONNECTEX_OUT *r)
{
	uint32_t length;
	
	TRY(pndr->p_ctx_handle(r->cxh));
	TRY(pndr->p_uint32(r->max_polls));
	TRY(pndr->p_uint32(r->max_retry));
	TRY(pndr->p_uint32(r->retry_delay));
	TRY(pndr->p_uint16(r->cxr));
	TRY(pndr->p_unique_ptr(r->pdn_prefix));
	length = strlen(r->pdn_prefix) + 1;
	TRY(pndr->p_ulong(length));
	TRY(pndr->p_ulong(0));
	TRY(pndr->p_ulong(length));
	TRY(pndr->p_str(r->pdn_prefix, length));

	TRY(pndr->p_unique_ptr(r->pdisplayname));
	length = strlen(r->pdisplayname) + 1;
	TRY(pndr->p_ulong(length));
	TRY(pndr->p_ulong(0));
	TRY(pndr->p_ulong(length));
	TRY(pndr->p_str(r->pdisplayname, length));
	TRY(pndr->p_uint16(r->pserver_vers[0]));
	TRY(pndr->p_uint16(r->pserver_vers[1]));
	TRY(pndr->p_uint16(r->pserver_vers[2]));
	TRY(pndr->p_uint16(r->pbest_vers[0]));
	TRY(pndr->p_uint16(r->pbest_vers[1]));
	TRY(pndr->p_uint16(r->pbest_vers[2]));
	TRY(pndr->p_uint32(r->timestamp));
	if (r->cb_auxout > 0x1008)
		return NDR_ERR_RANGE;
	TRY(pndr->p_ulong(r->cb_auxout));
	TRY(pndr->p_ulong(0));
	TRY(pndr->p_ulong(r->cb_auxout));
	TRY(pndr->p_uint8_a(r->pauxout, r->cb_auxout));
	TRY(pndr->p_uint32(r->cb_auxout));
	return pndr->p_int32(r->result);
}

static int emsmdb_ndr_pull_ecdorpcext2(NDR_PULL *pndr, ECDORPCEXT2_IN *r)
{
	uint32_t size;
	
	TRY(ndr_pull_context_handle(pndr, &r->cxh));
	TRY(pndr->g_uint32(&r->flags));
	TRY(pndr->g_ulong(&size));
	r->pin = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->pin == nullptr)
		return NDR_ERR_ALLOC;
	TRY(ndr_pull_array_uint8(pndr, r->pin, size));
	TRY(pndr->g_uint32(&r->cb_in));
	if (r->cb_in != size)
		return NDR_ERR_ARRAY_SIZE;
	TRY(pndr->g_uint32(&r->cb_out));
	if (r->cb_out > 0x40000)
		return NDR_ERR_RANGE;
	TRY(pndr->g_ulong(&size));
	r->pauxin = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->pauxin == nullptr)
		return NDR_ERR_ALLOC;
	TRY(ndr_pull_array_uint8(pndr, r->pauxin, size));
	TRY(pndr->g_uint32(&r->cb_auxin));
	if (r->cb_auxin != size)
		return NDR_ERR_ARRAY_SIZE;
	TRY(pndr->g_uint32(&r->cb_auxout));
	if (r->cb_auxout > 0x1008)
		return NDR_ERR_RANGE;
	return NDR_ERR_SUCCESS;
}

static int emsmdb_ndr_push_ecdorpcext2(NDR_PUSH *pndr, const ECDORPCEXT2_OUT *r)
{
	TRY(pndr->p_ctx_handle(r->cxh));
	TRY(pndr->p_uint32(r->flags));
	if (r->cb_out > 0x40000)
		return NDR_ERR_RANGE;
	TRY(pndr->p_ulong(r->cb_out));
	TRY(pndr->p_ulong(0));
	TRY(pndr->p_ulong(r->cb_out));
	TRY(pndr->p_uint8_a(r->pout, r->cb_out));
	TRY(pndr->p_uint32(r->cb_out));
	if (r->cb_auxout > 0x1008)
		return NDR_ERR_RANGE;
	TRY(pndr->p_ulong(r->cb_auxout));
	TRY(pndr->p_ulong(0));
	TRY(pndr->p_ulong(r->cb_auxout));
	TRY(pndr->p_uint8_a(r->pauxout, r->cb_auxout));
	TRY(pndr->p_uint32(r->cb_auxout));
	TRY(pndr->p_uint32(r->trans_time));
	return pndr->p_int32(r->result);
}

static int emsmdb_ndr_pull_ecdoasyncconnectex(NDR_PULL *pndr,
	ECDOASYNCCONNECTEX_IN *r)
{
	return ndr_pull_context_handle(pndr, &r->cxh);
}

static int emsmdb_ndr_push_ecdoasyncconnectex(NDR_PUSH *pndr,
	const ECDOASYNCCONNECTEX_OUT *r)
{
	TRY(pndr->p_ctx_handle(r->acxh));
	return pndr->p_int32(r->result);
}

int emsmdb_ndr_pull(int opnum, NDR_PULL *pndr, void **ppin)
{
	switch (opnum) {
	case ecDoDisconnect:
		*ppin = ndr_stack_anew<ECDODISCONNECT_IN>(NDR_STACK_IN);
		if (*ppin == nullptr)
			return NDR_ERR_ALLOC;
		return emsmdb_ndr_pull_ecdodisconnect(pndr, static_cast<ECDODISCONNECT_IN *>(*ppin));
	case ecRRegisterPushNotification:
		*ppin = ndr_stack_anew<ECRREGISTERPUSHNOTIFICATION_IN>(NDR_STACK_IN);
		if (*ppin == nullptr)
			return NDR_ERR_ALLOC;
		return emsmdb_ndr_pull_ecrregisterpushnotification(pndr, static_cast<ECRREGISTERPUSHNOTIFICATION_IN *>(*ppin));
	case ecDummyRpc:
		*ppin = NULL;
		return NDR_ERR_SUCCESS;
	case ecDoConnectEx:
		*ppin = ndr_stack_anew<ECDOCONNECTEX_IN>(NDR_STACK_IN);
		if (*ppin == nullptr)
			return NDR_ERR_ALLOC;
		return emsmdb_ndr_pull_ecdoconnectex(pndr, static_cast<ECDOCONNECTEX_IN *>(*ppin));
	case ecDoRpcExt2:
		*ppin = ndr_stack_anew<ECDORPCEXT2_IN>(NDR_STACK_IN);
		if (*ppin == nullptr)
			return NDR_ERR_ALLOC;
		return emsmdb_ndr_pull_ecdorpcext2(pndr, static_cast<ECDORPCEXT2_IN *>(*ppin));
	case ecDoAsyncConnectEx:
		*ppin = ndr_stack_anew<ECDOASYNCCONNECTEX_IN>(NDR_STACK_IN);
		if (*ppin == nullptr)
			return NDR_ERR_ALLOC;
		return emsmdb_ndr_pull_ecdoasyncconnectex(pndr, static_cast<ECDOASYNCCONNECTEX_IN *>(*ppin));
	default:
		return NDR_ERR_BAD_SWITCH;
	}
}

int emsmdb_ndr_push(int opnum, NDR_PUSH *pndr, void *pout)
{
	switch (opnum) {
	case ecDoDisconnect:
		return emsmdb_ndr_push_ecdodisconnect(pndr, static_cast<ECDODISCONNECT_OUT *>(pout));
	case ecRRegisterPushNotification:
		return emsmdb_ndr_push_ecrregisterpushnotification(pndr, static_cast<ECRREGISTERPUSHNOTIFICATION_OUT *>(pout));
	case ecDummyRpc:
		return emsmdb_ndr_push_ecdummyrpc(pndr, static_cast<int32_t *>(pout));
	case ecDoConnectEx:
		return emsmdb_ndr_push_ecdoconnectex(pndr, static_cast<ECDOCONNECTEX_OUT *>(pout));
	case ecDoRpcExt2:
		return emsmdb_ndr_push_ecdorpcext2(pndr, static_cast<ECDORPCEXT2_OUT *>(pout));
	case ecDoAsyncConnectEx:
		return emsmdb_ndr_push_ecdoasyncconnectex(pndr, static_cast<ECDOASYNCCONNECTEX_OUT *>(pout));
	default:
		return NDR_ERR_BAD_SWITCH;
	}
}
