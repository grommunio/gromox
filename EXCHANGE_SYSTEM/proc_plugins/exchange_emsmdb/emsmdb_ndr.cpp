#include "emsmdb_interface.h"
#include "emsmdb_ndr.h"
#include <string.h>

int emsmdb_ndr_pull_ecdodisconnect(NDR_PULL *pndr, ECDODISCONNECT_IN *r)
{
	return ndr_pull_context_handle(pndr, &r->cxh);
}

int emsmdb_ndr_push_ecdodisconnect(NDR_PUSH *pndr,
	const ECDODISCONNECT_OUT *r)
{
	int status;
	
	status = ndr_push_context_handle(pndr, &r->cxh);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_int32(pndr, r->result);
}

int emsmdb_ndr_pull_ecrregisterpushnotification(NDR_PULL *pndr,
	ECRREGISTERPUSHNOTIFICATION_IN *r)
{
	int status;
	uint32_t size;
	
	status = ndr_pull_context_handle(pndr, &r->cxh);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->rpc);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_ulong(pndr, &size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	r->pctx = static_cast<uint8_t *>(ndr_stack_alloc(NDR_STACK_IN, size));
	if (NULL == r->pctx) {
		return NDR_ERR_ALLOC;
	}
	status = ndr_pull_array_uint8(pndr, r->pctx, size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->cb_ctx);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (size != r->cb_ctx) {
		return NDR_ERR_ARRAY_SIZE;
	}
	status = ndr_pull_uint32(pndr, &r->advise_bits);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_ulong(pndr, &size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	r->paddr = static_cast<uint8_t *>(ndr_stack_alloc(NDR_STACK_IN, size));
	if (NULL == r->paddr) {
		return NDR_ERR_ALLOC;
	}
	status = ndr_pull_array_uint8(pndr, r->paddr, size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->cb_addr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (size != r->cb_addr) {
		return NDR_ERR_ARRAY_SIZE;
	}
	return NDR_ERR_SUCCESS;
}

int emsmdb_ndr_push_ecrregisterpushnotification(NDR_PUSH *pndr,
	const ECRREGISTERPUSHNOTIFICATION_OUT *r)
{
	int status;
	
	status = ndr_push_context_handle(pndr, &r->cxh);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->hnotification);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_int32(pndr, r->result);
}

int emsmdb_ndr_push_ecdummyrpc(NDR_PUSH *pndr, int32_t *r)
{
	return ndr_push_int32(pndr, *r);
}

int emsmdb_ndr_pull_ecdoconnectex(NDR_PULL *pndr, ECDOCONNECTEX_IN *r)
{
	int status;
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	
	status = ndr_pull_uint32(pndr, &size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_ulong(pndr, &offset);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_ulong(pndr, &length);
	if (NDR_ERR_SUCCESS!= status) {
		return status;
	}
	if (0 != offset || length > size || length > 1024) {
		return NDR_ERR_ARRAY_SIZE;
	}
	status = ndr_pull_check_string(pndr, length, sizeof(uint8_t));
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_string(pndr, r->puserdn, length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->conmod);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->limit);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->cpid);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->lcid_string);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->lcid_sort);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->cxr_link);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->cnvt_cps);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->pclient_vers[0]);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->pclient_vers[1]);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->pclient_vers[2]);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->timestamp);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_ulong(pndr, &size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	r->pauxin = static_cast<uint8_t *>(ndr_stack_alloc(NDR_STACK_IN, size));
	if (NULL == r->pauxin) {
		return NDR_ERR_ALLOC;
	}
	status = ndr_pull_array_uint8(pndr, r->pauxin, size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->cb_auxin);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (r->cb_auxin != size) {
		return NDR_ERR_ARRAY_SIZE;
	}
	status = ndr_pull_uint32(pndr, &r->cb_auxout);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (r->cb_auxout > 0x1008) {
		return NDR_ERR_RANGE;
	}
	return NDR_ERR_SUCCESS;
}

int emsmdb_ndr_push_ecdoconnectex(NDR_PUSH *pndr, const ECDOCONNECTEX_OUT *r)
{
	int status;
	uint32_t length;
	
	status = ndr_push_context_handle(pndr, &r->cxh);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->max_polls);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->max_retry);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->retry_delay);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->cxr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_unique_ptr(pndr, r->pdn_prefix);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	length = strlen(r->pdn_prefix) + 1;
	status = ndr_push_ulong(pndr, length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_ulong(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_ulong(pndr, length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_string(pndr, r->pdn_prefix, length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}

	status = ndr_push_unique_ptr(pndr, r->pdisplayname);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	length = strlen(r->pdisplayname) + 1;
	status = ndr_push_ulong(pndr, length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_ulong(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_ulong(pndr, length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_string(pndr, r->pdisplayname, length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->pserver_vers[0]);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->pserver_vers[1]);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->pserver_vers[2]);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->pbest_vers[0]);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->pbest_vers[1]);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->pbest_vers[2]);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->timestamp);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (r->cb_auxout > 0x1008) {
		return NDR_ERR_RANGE;
	}
	status = ndr_push_ulong(pndr, r->cb_auxout);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_ulong(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_ulong(pndr, r->cb_auxout);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_array_uint8(pndr, r->pauxout, r->cb_auxout);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->cb_auxout);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_int32(pndr, r->result);
}

int emsmdb_ndr_pull_ecdorpcext2(NDR_PULL *pndr, ECDORPCEXT2_IN *r)
{
	int status;
	uint32_t size;
	
	status = ndr_pull_context_handle(pndr, &r->cxh);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_ulong(pndr, &size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	r->pin = static_cast<uint8_t *>(ndr_stack_alloc(NDR_STACK_IN, size));
	if (NULL == r->pin) {
		return NDR_ERR_ALLOC;
	}
	status = ndr_pull_array_uint8(pndr, r->pin, size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->cb_in);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (r->cb_in != size) {
		return NDR_ERR_ARRAY_SIZE;
	}
	status = ndr_pull_uint32(pndr, &r->cb_out);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (r->cb_out > 0x40000) {
		return NDR_ERR_RANGE;
	}
	status = ndr_pull_ulong(pndr, &size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	r->pauxin = static_cast<uint8_t *>(ndr_stack_alloc(NDR_STACK_IN, size));
	if (NULL == r->pauxin) {
		return NDR_ERR_ALLOC;
	}
	status = ndr_pull_array_uint8(pndr, r->pauxin, size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->cb_auxin);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (size != r->cb_auxin) {
		return NDR_ERR_ARRAY_SIZE;
	}
	status = ndr_pull_uint32(pndr, &r->cb_auxout);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (r->cb_auxout > 0x1008) {
		return NDR_ERR_RANGE;
	}
	return NDR_ERR_SUCCESS;
}

int emsmdb_ndr_push_ecdorpcext2(NDR_PUSH *pndr, const ECDORPCEXT2_OUT *r)
{
	int status;
	
	status = ndr_push_context_handle(pndr, &r->cxh);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (r->cb_out > 0x40000) {
		return NDR_ERR_RANGE;
	}
	status = ndr_push_ulong(pndr, r->cb_out);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_ulong(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_ulong(pndr, r->cb_out);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_array_uint8(pndr, r->pout, r->cb_out);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->cb_out);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (r->cb_auxout > 0x1008) {
		return NDR_ERR_RANGE;
	}
	status = ndr_push_ulong(pndr, r->cb_auxout);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_ulong(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_ulong(pndr, r->cb_auxout);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_array_uint8(pndr, r->pauxout, r->cb_auxout);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->cb_auxout);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->trans_time);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
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
	int status;
	
	status = ndr_push_context_handle(pndr, &r->acxh);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_int32(pndr, r->result);
}
