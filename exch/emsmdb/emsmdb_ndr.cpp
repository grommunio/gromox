// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstring>
#include <memory>
#include <gromox/ndr.hpp>
#include <gromox/util.hpp>
#include "emsmdb_interface.hpp"
#include "emsmdb_ndr.hpp"
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != pack_result::ok) return klfdv; } while (false)

using namespace gromox;

static pack_result asyncemsmdb_ndr_pull(NDR_PULL &x, ECDOASYNCWAITEX_IN *r)
{
	TRY(x.g_ctx_handle(&r->acxh));
	return x.g_uint32(&r->flags_in);
}

static pack_result asyncemsmdb_ndr_push(NDR_PUSH &x, const ECDOASYNCWAITEX_OUT &r)
{
	TRY(x.p_uint32(r.flags_out));
	return x.p_err32(r.result);
}

pack_result asyncemsmdb_ndr_pull(unsigned int opnum, NDR_PULL &x,
    std::unique_ptr<rpc_request> &in) try
{
	switch (opnum) {
	case ecDoAsyncWaitEx: {
		auto r0 = std::make_unique<ECDOASYNCWAITEX_IN>();
		auto v = asyncemsmdb_ndr_pull(x, static_cast<ECDOASYNCWAITEX_IN *>(r0.get()));
		in = std::move(r0);
		return v;
	}
	default:
		return pack_result::bad_switch;
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return pack_result::alloc;
}

pack_result asyncemsmdb_ndr_push(unsigned int opnum, NDR_PUSH &x, const rpc_response *r)
{
	switch (opnum) {
	case ecDoAsyncWaitEx:
		return asyncemsmdb_ndr_push(x, *static_cast<const ECDOASYNCWAITEX_OUT *>(r));
	default:
		return pack_result::bad_switch;
	}
}

static pack_result emsmdb_ndr_pull(NDR_PULL &x, ECDODISCONNECT_IN *r)
{
	return x.g_ctx_handle(&r->cxh);
}

static pack_result emsmdb_ndr_push(NDR_PUSH &x, const ECDODISCONNECT_OUT &r)
{
	TRY(x.p_ctx_handle(r.cxh));
	return x.p_err32(r.result);
}

static pack_result emsmdb_ndr_pull(NDR_PULL &x, ECRREGISTERPUSHNOTIFICATION_IN *r)
{
	uint32_t size;
	
	TRY(x.g_ctx_handle(&r->cxh));
	TRY(x.g_uint32(&r->rpc));
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	r->pctx = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->pctx == nullptr)
		return pack_result::alloc;
	TRY(x.g_uint8_a(r->pctx, size));
	TRY(x.g_uint16(&r->cb_ctx));
	if (r->cb_ctx != size)
		return pack_result::array_size;
	TRY(x.g_uint32(&r->advise_bits));
	TRY(x.g_ulong(&size));
	r->paddr = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->paddr == nullptr)
		return pack_result::alloc;
	TRY(x.g_uint8_a(r->paddr, size));
	TRY(x.g_uint16(&r->cb_addr));
	if (r->cb_addr != size)
		return pack_result::array_size;
	return pack_result::ok;
}

static pack_result emsmdb_ndr_push(NDR_PUSH &x, const ECRREGISTERPUSHNOTIFICATION_OUT &r)
{
	TRY(x.p_ctx_handle(r.cxh));
	TRY(x.p_uint32(r.hnotification));
	return x.p_err32(r.result);
}

static pack_result emsmdb_ndr_push(NDR_PUSH &x, const ECDUMMYRPC_OUT &r)
{
	return x.p_err32(r.result);
}

static pack_result emsmdb_ndr_pull(NDR_PULL &x, ECDOCONNECTEX_IN *r)
{
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	
	TRY(x.g_uint32(&size));
	TRY(x.g_ulong(&offset));
	TRY(x.g_ulong(&length));
	if (offset != 0 || length > size || length > 1024)
		return pack_result::array_size;
	TRY(x.check_str(length, sizeof(uint8_t)));
	TRY(x.g_str(r->puserdn, length));
	TRY(x.g_uint32(&r->flags));
	TRY(x.g_uint32(&r->conmod));
	TRY(x.g_uint32(&r->limit));
	uint32_t v;
	TRY(x.g_uint32(&v));
	r->cpid = static_cast<cpid_t>(v);
	TRY(x.g_uint32(&r->lcid_string));
	TRY(x.g_uint32(&r->lcid_sort));
	TRY(x.g_uint32(&r->cxr_link));
	TRY(x.g_uint16(&r->cnvt_cps));
	TRY(x.g_uint16(&r->pclient_vers[0]));
	TRY(x.g_uint16(&r->pclient_vers[1]));
	TRY(x.g_uint16(&r->pclient_vers[2]));
	TRY(x.g_uint32(&r->timestamp));
	TRY(x.g_ulong(&size));
	r->pauxin = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->pauxin == nullptr)
		return pack_result::alloc;
	TRY(x.g_uint8_a(r->pauxin, size));
	TRY(x.g_uint32(&r->cb_auxin));
	if (r->cb_auxin != size)
		return pack_result::array_size;
	TRY(x.g_uint32(&r->cb_auxout));
	if (r->cb_auxout > 0x1008)
		return pack_result::range;
	return pack_result::ok;
}

static pack_result emsmdb_ndr_push(NDR_PUSH &x, const ECDOCONNECTEX_OUT &r)
{
	uint32_t length;
	
	TRY(x.p_ctx_handle(r.cxh));
	TRY(x.p_uint32(r.max_polls));
	TRY(x.p_uint32(r.max_retry));
	TRY(x.p_uint32(r.retry_delay));
	TRY(x.p_uint16(r.cxr));
	TRY(x.p_unique_ptr(r.pdn_prefix));
	length = strlen(r.pdn_prefix) + 1;
	TRY(x.p_ulong(length));
	TRY(x.p_ulong(0));
	TRY(x.p_ulong(length));
	TRY(x.p_str(r.pdn_prefix, length));

	TRY(x.p_unique_ptr(r.pdisplayname));
	length = strlen(r.pdisplayname) + 1;
	TRY(x.p_ulong(length));
	TRY(x.p_ulong(0));
	TRY(x.p_ulong(length));
	TRY(x.p_str(r.pdisplayname, length));
	TRY(x.p_uint16(r.pserver_vers[0]));
	TRY(x.p_uint16(r.pserver_vers[1]));
	TRY(x.p_uint16(r.pserver_vers[2]));
	TRY(x.p_uint16(r.pbest_vers[0]));
	TRY(x.p_uint16(r.pbest_vers[1]));
	TRY(x.p_uint16(r.pbest_vers[2]));
	TRY(x.p_uint32(r.timestamp));
	if (r.cb_auxout > 0x1008)
		return pack_result::range;
	TRY(x.p_ulong(r.cb_auxout));
	TRY(x.p_ulong(0));
	TRY(x.p_ulong(r.cb_auxout));
	TRY(x.p_uint8_a(r.pauxout, r.cb_auxout));
	TRY(x.p_uint32(r.cb_auxout));
	return x.p_err32(r.result);
}

static pack_result emsmdb_ndr_pull(NDR_PULL &x, ECDORPCEXT2_IN *r)
{
	uint32_t size;
	
	TRY(x.g_ctx_handle(&r->cxh));
	TRY(x.g_uint32(&r->flags));
	/*
	 * NDR Transfer Syntax (C706, §14.3.3.2 & §14.3.3.3) specifies the
	 * encoding of arrays. It makes sense in the context of serializing
	 * e.g. a std::vector<> object. But: C706 does not mention any
	 * object-oriented language and focuses heavily on ISO C instead, where
	 * the programmer has to manage an array's size manually, e.g.
	 * struct S { size_t z; [length_is(z)] uint32_t *array; };, and
	 * NDR-encoding such a NDR struct then unfortunately causes the length
	 * to be encoded twice.
	 *
	 * Anecdotes: https://lists.samba.org/archive/samba-technical/2009-April/064319.html
	 */
	TRY(x.g_ulong(&size));
	r->pin = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->pin == nullptr)
		return pack_result::alloc;
	TRY(x.g_uint8_a(r->pin, size));
	TRY(x.g_uint32(&r->cb_in));
	if (r->cb_in != size)
		return pack_result::array_size;
	TRY(x.g_uint32(&r->cb_out));
	if (r->cb_out > 0x40000)
		return pack_result::range;
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	r->pauxin = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (r->pauxin == nullptr)
		return pack_result::alloc;
	TRY(x.g_uint8_a(r->pauxin, size));
	TRY(x.g_uint32(&r->cb_auxin));
	if (r->cb_auxin != size)
		return pack_result::array_size;
	TRY(x.g_uint32(&r->cb_auxout));
	if (r->cb_auxout > 0x1008)
		return pack_result::range;
	return pack_result::ok;
}

static pack_result emsmdb_ndr_push(NDR_PUSH &x, const ECDORPCEXT2_OUT &r)
{
	TRY(x.p_ctx_handle(r.cxh));
	TRY(x.p_uint32(r.flags));
	if (r.cb_out > 0x40000)
		return pack_result::range;
	TRY(x.p_ulong(r.cb_out));
	TRY(x.p_ulong(0));
	TRY(x.p_ulong(r.cb_out));
	TRY(x.p_uint8_a(r.pout, r.cb_out));
	TRY(x.p_uint32(r.cb_out));
	if (r.cb_auxout > 0x1008)
		return pack_result::range;
	TRY(x.p_ulong(r.cb_auxout));
	TRY(x.p_ulong(0));
	TRY(x.p_ulong(r.cb_auxout));
	TRY(x.p_uint8_a(r.pauxout, r.cb_auxout));
	TRY(x.p_uint32(r.cb_auxout));
	TRY(x.p_uint32(r.trans_time));
	return x.p_err32(r.result);
}

static pack_result emsmdb_ndr_pull(NDR_PULL &x, ECDOASYNCCONNECTEX_IN *r)
{
	return x.g_ctx_handle(&r->cxh);
}

static pack_result emsmdb_ndr_push(NDR_PUSH &x, const ECDOASYNCCONNECTEX_OUT &r)
{
	TRY(x.p_ctx_handle(r.acxh));
	return x.p_err32(r.result);
}

pack_result emsmdb_ndr_pull(unsigned int opnum, NDR_PULL &x,
    std::unique_ptr<rpc_request> &in) try
{
	switch (opnum) {
	case ecDoDisconnect: {
		auto r0 = std::make_unique<ECDODISCONNECT_IN>();
		auto v = emsmdb_ndr_pull(x, static_cast<ECDODISCONNECT_IN *>(r0.get()));
		in = std::move(r0);
		return v;
	}
	case ecRRegisterPushNotification: {
		auto r0 = std::make_unique<ECRREGISTERPUSHNOTIFICATION_IN>();
		auto v = emsmdb_ndr_pull(x, static_cast<ECRREGISTERPUSHNOTIFICATION_IN *>(r0.get()));
		in = std::move(r0);
		return v;
	}
	case ecDummyRpc:
		in.reset();
		return pack_result::ok;
	case ecDoConnectEx: {
		auto r0 = std::make_unique<ECDOCONNECTEX_IN>();
		auto v = emsmdb_ndr_pull(x, static_cast<ECDOCONNECTEX_IN *>(r0.get()));
		in = std::move(r0);
		return v;
	}
	case ecDoRpcExt2: {
		auto r0 = std::make_unique<ECDORPCEXT2_IN>();
		auto v = emsmdb_ndr_pull(x, static_cast<ECDORPCEXT2_IN *>(r0.get()));
		in = std::move(r0);
		return v;
	}
	case ecDoAsyncConnectEx: {
		auto r0 = std::make_unique<ECDOASYNCCONNECTEX_IN>();
		auto v = emsmdb_ndr_pull(x, static_cast<ECDOASYNCCONNECTEX_IN *>(r0.get()));
		in = std::move(r0);
		return v;
	}
	default:
		return pack_result::bad_switch;
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return pack_result::alloc;
}

pack_result emsmdb_ndr_push(unsigned int opnum, NDR_PUSH &x, const rpc_response *r)
{
	switch (opnum) {
	case ecDoDisconnect:
		return emsmdb_ndr_push(x, *static_cast<const ECDODISCONNECT_OUT *>(r));
	case ecRRegisterPushNotification:
		return emsmdb_ndr_push(x, *static_cast<const ECRREGISTERPUSHNOTIFICATION_OUT *>(r));
	case ecDummyRpc:
		return emsmdb_ndr_push(x, *static_cast<const ECDUMMYRPC_OUT *>(r));
	case ecDoConnectEx:
		return emsmdb_ndr_push(x, *static_cast<const ECDOCONNECTEX_OUT *>(r));
	case ecDoRpcExt2:
		return emsmdb_ndr_push(x, *static_cast<const ECDORPCEXT2_OUT *>(r));
	case ecDoAsyncConnectEx:
		return emsmdb_ndr_push(x, *static_cast<const ECDOASYNCCONNECTEX_OUT *>(r));
	default:
		return pack_result::bad_switch;
	}
}
