// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*

The AUX headers sent with EcDoConnectEx are rather boring in
practice.

AUX_PERF_CLIENTINFO: adapter_speed=1000000, client_id=1, machine_name="",
user_name="", adapter_name="Ethernet0", adapter_name="LAN", macaddr="",
ipaddr=""/""

AUX_PERF_ACCOUNTINFO: client_id=1, account=<someguid>

AUX_PERF_SESSIONINFO_V2: session_id=1, guid=<someguid>, conn_id=<integer
matching Outlook Connection Status dialog CID column>

AUX_PERF_PROCESSINFO: pid=1, guid=<someguid>, name="MFCMapi64.exe",
name="MFCMapi.exe", name="OUTLOOK.EXE"

AUX_CLIENT_CONNECTION_INFO: guid=<someguid>, ctxinfo="",
connection_attempts=<integer>, connection_flags=0

HTTP headers are more informative:

User-Agent: Microsoft Office/16.0 (Windows NT 10.0; MAPI 16.0.15928; Pro)
X-ClientApplication: Outlook/16.0.15928.20006

*/
#include <cstdint>
#include <cstring>
#include <gromox/lzxpress.hpp>
#include <gromox/proc_common.h>
#include <gromox/util.hpp>
#include "aux_types.h"
#include "common_util.h"
#define AUX_ALIGN_SIZE									4
#define TRY(expr) do { int v = (expr); if (v != EXT_ERR_SUCCESS) return v; } while (false)

using namespace gromox;

/* Code for parsing a bunch of other AUX blocks is present in commit history */

static int aux_ext_push_aux_client_control(EXT_PUSH &x, const AUX_CLIENT_CONTROL &r)
{
	TRY(x.p_uint32(r.enable_flags));
	return x.p_uint32(r.expiry_time);
}

static int aux_ext_push_aux_exorginfo(EXT_PUSH &x, const AUX_EXORGINFO &r)
{
	return x.p_uint32(r.org_flags);
}

static int aux_ext_push_aux_endpoint_capabilities(EXT_PUSH &x,
    const AUX_ENDPOINT_CAPABILITIES &r)
{
	return x.p_uint32(r.endpoint_capability_flag);
}

static int aux_ext_push_aux_header_type_union1(EXT_PUSH &x, uint8_t type,
    const void *payload)
{
	switch (type) {
	case AUX_TYPE_CLIENT_CONTROL:
		return aux_ext_push_aux_client_control(x, *static_cast<const AUX_CLIENT_CONTROL *>(payload));
	case AUX_TYPE_EXORGINFO:
		return aux_ext_push_aux_exorginfo(x, *static_cast<const AUX_EXORGINFO *>(payload));
	case AUX_TYPE_ENDPOINT_CAPABILITIES:
		return aux_ext_push_aux_endpoint_capabilities(x, *static_cast<const AUX_ENDPOINT_CAPABILITIES *>(payload));
	default:
		return EXT_CTRL_SKIP;
	}
}

static int aux_ext_push_aux_header(EXT_PUSH &x, const AUX_HEADER &r) try
{
	uint16_t size;
	EXT_PUSH subext;
	static constexpr size_t tmp_buff_size = 0x1008;
	auto tmp_buff = std::make_unique<uint8_t[]>(tmp_buff_size);
	uint8_t paddings[AUX_ALIGN_SIZE]{};
	
	if (!subext.init(tmp_buff.get(), tmp_buff_size, EXT_FLAG_UTF16))
		return EXT_ERR_ALLOC;
	switch (r.version) {
	case AUX_VERSION_1: {
		auto ret = aux_ext_push_aux_header_type_union1(subext, r.type, r.ppayload);
		if (ret == EXT_CTRL_SKIP)
			return EXT_ERR_SUCCESS;
		else if (ret != EXT_ERR_SUCCESS)
			return ret;
		break;
	}
	default:
		return EXT_ERR_SUCCESS;
	}
	uint16_t actual_size = subext.m_offset + sizeof(uint16_t) + 2 * sizeof(uint8_t);
	size = (actual_size + (AUX_ALIGN_SIZE - 1)) & ~(AUX_ALIGN_SIZE - 1);
	TRY(x.p_uint16(size));
	TRY(x.p_uint8(r.version));
	TRY(x.p_uint8(r.type));
	TRY(x.p_bytes(subext.m_udata, subext.m_offset));
	return x.p_bytes(paddings, size - actual_size);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1169: ENOMEM");
	return EXT_ERR_ALLOC;
}

int aux_ext_push_aux_info(EXT_PUSH *pext, const AUX_INFO &r) try
{
	EXT_PUSH subext;
	static constexpr size_t ext_buff_size = 0x1008;
	auto ext_buff = std::make_unique<uint8_t[]>(ext_buff_size);
	auto tmp_buff = std::make_unique<uint8_t[]>(ext_buff_size);
	RPC_HEADER_EXT rpc_header_ext;

	if (!(r.rhe_flags & RHE_FLAG_LAST))
		return EXT_ERR_HEADER_FLAGS;
	if (!subext.init(ext_buff.get(), ext_buff_size, EXT_FLAG_UTF16))
		return EXT_ERR_ALLOC;
	for (const auto &ah : r.aux_list)
		TRY(aux_ext_push_aux_header(subext, ah));
	rpc_header_ext.version = r.rhe_version;
	rpc_header_ext.flags = r.rhe_flags;
	rpc_header_ext.size_actual = subext.m_offset;
	rpc_header_ext.size = rpc_header_ext.size_actual;
	if (rpc_header_ext.flags & RHE_FLAG_COMPRESSED) {
		if (rpc_header_ext.size_actual < MINIMUM_COMPRESS_SIZE) {
			rpc_header_ext.flags &= ~RHE_FLAG_COMPRESSED;
		} else {
			auto compressed_len = lzxpress_compress(ext_buff.get(), subext.m_offset, tmp_buff.get());
			if (compressed_len == 0 || compressed_len >= subext.m_offset) {
				/* if we can not get benefit from the
					compression, unmask the compress bit */
				rpc_header_ext.flags &= ~RHE_FLAG_COMPRESSED;
			} else {
				rpc_header_ext.size = compressed_len;
				memcpy(ext_buff.get(), tmp_buff.get(), compressed_len);
			}
		}
	}
	if (rpc_header_ext.flags & RHE_FLAG_XORMAGIC)
		rpc_header_ext.flags &= ~RHE_FLAG_XORMAGIC;
	TRY(pext->p_rpchdr(rpc_header_ext));
	return pext->p_bytes(ext_buff.get(), rpc_header_ext.size);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1167: ENOMEM");
	return EXT_ERR_ALLOC;
}
