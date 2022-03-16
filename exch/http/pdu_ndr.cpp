// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include "pdu_ndr.h"
#define TRY(expr) do { int klfdv = (expr); if (klfdv != NDR_ERR_SUCCESS) return klfdv; } while (false)
#define IPV6_BYTES		16

using namespace gromox;

static int pdu_ndr_pull_dcerpc_object(NDR_PULL *pndr, DCERPC_OBJECT *r)
{
	TRY(ndr_pull_union_align(pndr, 4));
	if (pndr->flags & NDR_FLAG_OBJECT_PRESENT) {
		TRY(ndr_pull_guid(pndr, &r->object));
	}
	return NDR_ERR_SUCCESS;
}

static int pdu_ndr_pull_dcerpc_ctx_list(NDR_PULL *pndr, DCERPC_CTX_LIST *r)
{
	uint32_t i;
	
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint16(pndr, &r->context_id));
	TRY(ndr_pull_uint8(pndr, &r->num_transfer_syntaxes));
	TRY(ndr_pull_syntax_id(pndr, &r->abstract_syntax));
	
	if (r->num_transfer_syntaxes > 0) {
		r->transfer_syntaxes = me_alloc<SYNTAX_ID>(r->num_transfer_syntaxes);
		if (NULL == r->transfer_syntaxes) {
			r->num_transfer_syntaxes = 0;
			return NDR_ERR_ALLOC;
		}
		
		for (i=0; i<r->num_transfer_syntaxes; i++) {
			auto status = ndr_pull_syntax_id(pndr, &r->transfer_syntaxes[i]);
			if (NDR_ERR_SUCCESS != status) {
				free(r->transfer_syntaxes);
				r->transfer_syntaxes = NULL;
				r->num_transfer_syntaxes = 0;
				return status;
			}
		}
	} else {
		r->transfer_syntaxes = NULL;
	}
	
	auto status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		if (NULL != r->transfer_syntaxes) {
			free(r->transfer_syntaxes);
			r->transfer_syntaxes = NULL;
		}
		r->num_transfer_syntaxes = 0;
		return status;
	}
	return NDR_ERR_SUCCESS;
}

/* free memory internal of ctx list except of ctx list itself */
static void pdu_ndr_free_dcerpc_ctx_list(DCERPC_CTX_LIST *r)
{
	if (NULL != r->transfer_syntaxes) {
		free(r->transfer_syntaxes);
		r->transfer_syntaxes = NULL;
	}
	r->num_transfer_syntaxes = 0;
}

static int pdu_ndr_pull_dcerpc_ack_ctx(NDR_PULL *pndr, DCERPC_ACK_CTX *r)
{
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint16(pndr, &r->result));
	TRY(ndr_pull_uint16(pndr, &r->reason));
	TRY(ndr_pull_syntax_id(pndr, &r->syntax));
	return ndr_pull_trailer_align(pndr, 4);
}

static int pdu_ndr_pull_dcerpc_bind_nak(NDR_PULL *pndr, DCERPC_BIND_NAK *r)
{
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint16(pndr, &r->reject_reason));
	TRY(ndr_pull_align(pndr, 4));
	
	if (DECRPC_BIND_REASON_VERSION_NOT_SUPPORTED == r->reject_reason) {
		TRY(pndr->g_uint32(&r->num_versions));
		if (r->num_versions > 0) {
			r->versions = me_alloc<uint32_t>(r->num_versions);
			if (NULL == r->versions) {
				r->num_versions = 0;
				return NDR_ERR_ALLOC;
			}
			for (size_t i = 0; i < r->num_versions; ++i) {
				auto status = pndr->g_uint32(&r->versions[i]);
				if (NDR_ERR_SUCCESS != status) {
					free(r->versions);
					r->versions = NULL;
					r->num_versions = 0;
					return status;
				}
			}
		} else {
			r->versions = NULL;
		}
	}
	auto status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		if (NULL != r->versions) {
			free(r->versions);
			r->versions = NULL;
		}
		r->num_versions = 0;
		return status;
	}
	return NDR_ERR_SUCCESS;
}

/* free memory internal of bind ack except of bind ack itself */
static void pdu_ndr_free_dcerpc_bind_nak(DCERPC_BIND_NAK *r)
{
	if (NULL != r->versions) {
		free(r->versions);
		r->versions = NULL;
	}
	r->num_versions = 0;
}

static int pdu_ndr_pull_dcerpc_request(NDR_PULL *pndr, DCERPC_REQUEST *r)
{
	int status;
	uint32_t saved_flags;
	
	TRY(ndr_pull_align(pndr, 4));
	TRY(pndr->g_uint32(&r->alloc_hint));
	TRY(ndr_pull_uint16(pndr, &r->context_id));
	TRY(ndr_pull_uint16(pndr, &r->opnum));
	TRY(pdu_ndr_pull_dcerpc_object(pndr, &r->object));
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_ALIGN8);
	status = ndr_pull_data_blob(pndr, &r->pad);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->stub_and_verifier);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->pad);
		return status;
	}
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->stub_and_verifier);
		ndr_free_data_blob(&r->pad);
		return status;
	}
	return NDR_ERR_SUCCESS;
}

/* free memory internal of request except of request itself */
static void pdu_ndr_free_dcerpc_request(DCERPC_REQUEST *r)
{
	ndr_free_data_blob(&r->stub_and_verifier);
	ndr_free_data_blob(&r->pad);
}

static int pdu_ndr_pull_dcerpc_response(NDR_PULL *pndr, DCERPC_RESPONSE *r)
{
	int status;
	uint32_t saved_flags;
	
	TRY(ndr_pull_align(pndr, 4));
	TRY(pndr->g_uint32(&r->alloc_hint));
	TRY(ndr_pull_uint16(pndr, &r->context_id));
	TRY(ndr_pull_uint8(pndr, &r->cancel_count));
	
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_ALIGN8);
	status = ndr_pull_data_blob(pndr, &r->pad);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->stub_and_verifier);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->pad);
		return status;
	}
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->stub_and_verifier);
		ndr_free_data_blob(&r->pad);
		return status;
	}
	return NDR_ERR_SUCCESS;
}

/* free memory internal of response except of response itself */
static void pdu_ndr_free_dcerpc_response(DCERPC_RESPONSE *r)
{
	ndr_free_data_blob(&r->stub_and_verifier);
	ndr_free_data_blob(&r->pad);
}

static int pdu_ndr_pull_dcerpc_fault(NDR_PULL *pndr, DCERPC_FAULT *r)
{
	int status;
	uint32_t saved_flags;
	
	TRY(ndr_pull_align(pndr, 4));
	TRY(pndr->g_uint32(&r->alloc_hint));
	TRY(ndr_pull_uint16(pndr, &r->context_id));
	TRY(ndr_pull_uint8(pndr, &r->cancel_count));
	TRY(pndr->g_uint32(reinterpret_cast<uint32_t *>(&r->status)));
	
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->pad);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->pad);
		return status;
	}
	
	return NDR_ERR_SUCCESS;
}

/* free memory internal of fault except of fault itself */
static void pdu_ndr_free_dcerpc_fault(DCERPC_FAULT *r)
{
	ndr_free_data_blob(&r->pad);
}

static int pdu_ndr_pull_dcerpc_fack(NDR_PULL *pndr, DCERPC_FACK *r)
{
	int i;
	
	TRY(ndr_pull_align(pndr, 4));
	TRY(pndr->g_uint32(&r->version));
	TRY(ndr_pull_uint8(pndr, &r->pad));
	TRY(ndr_pull_uint16(pndr, &r->window_size));
	TRY(pndr->g_uint32(&r->max_tdsu));
	TRY(pndr->g_uint32(&r->max_frag_size));
	TRY(ndr_pull_uint16(pndr, &r->serial_no));
	TRY(ndr_pull_uint16(pndr, &r->selack_size));
	if (r->selack_size > 0) {
		r->selack = me_alloc<uint32_t>(r->selack_size);
		if (NULL == r->selack) {
			r->selack_size = 0;
			return NDR_ERR_ALLOC;
		}
		
		for (i=0; i<r->selack_size; i++) {
			auto status = pndr->g_uint32(&r->selack[i]);
			if (NDR_ERR_SUCCESS != status) {
				free(r->selack);
				r->selack = NULL;
				r->selack_size = 0;
				return status;
			}
		}
	} else {
		r->selack = NULL;
	}
	auto status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		if (NULL != r->selack) {
			free(r->selack);
			r->selack = NULL;
		}
		r->selack_size = 0;
		return status;
	}
	return NDR_ERR_SUCCESS;
}

/* free memory internal of fack except of fack itself */
static void pdu_ndr_free_dcerpc_fack(DCERPC_FACK *r)
{
	if (NULL != r->selack) {
		free(r->selack);
		r->selack = NULL;
	}
	r->selack_size = 0;
}

static int pdu_ndr_pull_dcerpc_cancel_ack(NDR_PULL *pndr, DCERPC_CANCEL_ACK *r)
{
	TRY(ndr_pull_align(pndr, 4));
	TRY(pndr->g_uint32(&r->version));
	TRY(pndr->g_uint32(&r->id));
	TRY(pndr->g_uint32(&r->server_is_accepting));
	return ndr_pull_trailer_align(pndr, 4);
}

static int pdu_ndr_pull_dcerpc_bind(NDR_PULL *pndr, DCERPC_BIND *r)
{
	int i;
	int status;
	uint32_t saved_flags;
	
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint16(pndr, &r->max_xmit_frag));
	TRY(ndr_pull_uint16(pndr, &r->max_recv_frag));
	TRY(pndr->g_uint32(&r->assoc_group_id));
	TRY(ndr_pull_uint8(pndr, &r->num_contexts));
	
	if (r->num_contexts > 0) {
		r->ctx_list = me_alloc<DCERPC_CTX_LIST>(r->num_contexts);
		if (NULL == r->ctx_list) {
			r->num_contexts = 0;
			return NDR_ERR_ALLOC;
		}
		for (i=0; i<r->num_contexts; i++) {
			status = pdu_ndr_pull_dcerpc_ctx_list(pndr, &r->ctx_list[i]);
			if (NDR_ERR_SUCCESS != status) {
				for (i-=1; i>=0; i--) {
					pdu_ndr_free_dcerpc_ctx_list(&r->ctx_list[i]);
				}
				free(r->ctx_list);
				r->ctx_list = NULL;
				r->num_contexts = 0;
			}
		}
	} else {
		r->ctx_list = NULL;
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->auth_info);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		for (i=0; i<r->num_contexts; i++) {
			pdu_ndr_free_dcerpc_ctx_list(&r->ctx_list[i]);
		}
		if (NULL != r->ctx_list) {
			free(r->ctx_list);
			r->ctx_list = NULL;
		}
		r->num_contexts = 0;
		return status;
	}
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->auth_info);
		for (i=0; i<r->num_contexts; i++) {
			pdu_ndr_free_dcerpc_ctx_list(&r->ctx_list[i]);
		}
		if (NULL != r->ctx_list) {
			free(r->ctx_list);
			r->ctx_list = NULL;
		}
		r->num_contexts = 0;
		return status;
	}
	
	return NDR_ERR_SUCCESS;
}

/* free memory internal of bind except of bind itself */
static void pdu_ndr_free_dcerpc_bind(DCERPC_BIND *r)
{
	int i;
	
	ndr_free_data_blob(&r->auth_info);
	for (i=0; i<r->num_contexts; i++) {
		pdu_ndr_free_dcerpc_ctx_list(&r->ctx_list[i]);
	}
	if (NULL != r->ctx_list) {
		free(r->ctx_list);
		r->ctx_list = NULL;
	}
	r->num_contexts = 0;
}

static int pdu_ndr_pull_dcerpc_bind_ack(NDR_PULL *pndr, DCERPC_BIND_ACK *r)
{
	int i;
	int status;
	uint32_t saved_flags;
	
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint16(pndr, &r->max_xmit_frag));
	TRY(ndr_pull_uint16(pndr, &r->max_recv_frag));
	TRY(pndr->g_uint32(&r->assoc_group_id));
	TRY(ndr_pull_uint16(pndr, &r->secondary_address_size));
	if (r->secondary_address_size > sizeof(r->secondary_address)) {
		return NDR_ERR_RANGE;
	}
	TRY(ndr_pull_string(pndr, r->secondary_address, r->secondary_address_size));
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_ALIGN4);
	status = ndr_pull_data_blob(pndr, &r->pad);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	TRY(ndr_pull_uint8(pndr, &r->num_contexts));
	if (r->num_contexts > 0) {
		r->ctx_list = me_alloc<DCERPC_ACK_CTX>(r->num_contexts);
		if (NULL == r->ctx_list) {
			r->num_contexts = 0;
			ndr_free_data_blob(&r->pad);
			return NDR_ERR_ALLOC;
		}
			
		for (i=0; i<r->num_contexts; i++) {
			status = pdu_ndr_pull_dcerpc_ack_ctx(pndr, &r->ctx_list[i]);
			if (NDR_ERR_SUCCESS != status) {
				ndr_free_data_blob(&r->pad);
				free(r->ctx_list);
				r->num_contexts = 0;
				return status;
			}
		}
	} else {
		r->ctx_list = NULL;
	}
		
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->auth_info);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->pad);
		if (NULL != r->ctx_list) {
			free(r->ctx_list);
			r->ctx_list = NULL;
		}
		r->num_contexts = 0;
		return status;
	}
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->pad);
		if (NULL != r->ctx_list) {
			free(r->ctx_list);
			r->ctx_list = NULL;
		}
		r->num_contexts = 0;
		ndr_free_data_blob(&r->auth_info);
		return status;
	}
	return NDR_ERR_SUCCESS;
}

/* free memory internal of bind ack except of bind ack itself */
static void pdu_ndr_free_dcerpc_bind_ack(DCERPC_BIND_ACK *r)
{
	ndr_free_data_blob(&r->pad);
	if (NULL != r->ctx_list) {
		free(r->ctx_list);
		r->ctx_list = NULL;
	}
	r->num_contexts = 0;
	ndr_free_data_blob(&r->auth_info);
}

static int pdu_ndr_pull_dcerpc_co_cancel(NDR_PULL *pndr, DCERPC_CO_CANCEL *r)
{
	int status;
	uint32_t saved_flags;
	
	TRY(ndr_pull_align(pndr, 4));
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->auth_info);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->auth_info);
		return status;
	}
	return NDR_ERR_SUCCESS;
}

/* free memory internal of co cancel except of co cancel itself */
static void pdu_ndr_free_dcerpc_co_cancel(DCERPC_CO_CANCEL *r)
{
	ndr_free_data_blob(&r->auth_info);
}

static int pdu_ndr_pull_dcerpc_orphaned(NDR_PULL *pndr, DCERPC_ORPHANED *r)
{
	int status;
	uint32_t saved_flags;
	
	TRY(ndr_pull_align(pndr, 4));
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->auth_info);
	pndr->flags = saved_flags;
	if (status != NDR_ERR_SUCCESS)
		return status;
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->auth_info);
		return status;
	}
	return NDR_ERR_SUCCESS;
}

/* free memory internal of orphaned except of orphaned itself */
static void pdu_ndr_free_dcerpc_orphaned(DCERPC_ORPHANED *r)
{
	ndr_free_data_blob(&r->auth_info);
}

static int pdu_ndr_pull_dcerpc_auth3(NDR_PULL *pndr, DCERPC_AUTH3 *r)
{
	int status;
	uint32_t saved_flags;
	
	TRY(ndr_pull_align(pndr, 4));
	TRY(pndr->g_uint32(&r->pad));
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->auth_info);
	pndr->flags = saved_flags;
	if (status != NDR_ERR_SUCCESS)
		return status;
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->auth_info);
		return status;
	}
	return NDR_ERR_SUCCESS;
}

/* free memory internal of auth3 except of auth3 itself */
static void pdu_ndr_free_dcerpc_auth3(DCERPC_AUTH3 *r)
{	
	ndr_free_data_blob(&r->auth_info);
}

int pdu_ndr_pull_dcerpc_auth(NDR_PULL *pndr, DCERPC_AUTH *r)
{
	int status;
	uint32_t saved_flags;
	
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint8(pndr, &r->auth_type));
	TRY(ndr_pull_uint8(pndr, &r->auth_level));
	if (0 == r->auth_level) {
		r->auth_level = RPC_C_AUTHN_LEVEL_CONNECT;
	}
	TRY(ndr_pull_uint8(pndr, &r->auth_pad_length));
	TRY(ndr_pull_uint8(pndr, &r->auth_reserved));
	TRY(pndr->g_uint32(&r->auth_context_id));
	
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->credentials);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->credentials);
		return status;
	}
	return NDR_ERR_SUCCESS;
}

/* free memory internal of auth except of auth itself */
void pdu_ndr_free_dcerpc_auth(DCERPC_AUTH *r)
{
	ndr_free_data_blob(&r->credentials);
}

static int pdu_ndr_pull_rts_flowcontrolack(NDR_PULL *pndr,
	RTS_FLOWCONTROLACK *r)
{
	TRY(ndr_pull_align(pndr, 4));
	TRY(pndr->g_uint32(&r->bytes_received));
	TRY(pndr->g_uint32(&r->available_window));
	TRY(ndr_pull_guid(pndr, &r->channel_cookie));
	return ndr_pull_trailer_align(pndr, 4);
}


static int pdu_ndr_pull_rts_padding(NDR_PULL *pndr, uint32_t *r)
{
	uint32_t size_padding;
	
	TRY(ndr_pull_align(pndr, 4));
	TRY(pndr->g_uint32(r));
	size_padding = *r;
	if (size_padding > 0xFFFF) {
		return NDR_ERR_RANGE;
	}
	TRY(ndr_pull_advance(pndr, size_padding));
	return ndr_pull_trailer_align(pndr, 4);
	
}

static int pdu_ndr_pull_ipv4address(NDR_PULL *pndr, char *address, size_t asz)
{
	struct in_addr in{};
	TRY(pndr->g_uint32(&in.s_addr));
	in.s_addr = htonl(in.s_addr);
	inet_ntop(AF_INET, &in, address, asz);
	return NDR_ERR_SUCCESS;
}

static int pdu_ndr_pull_ipv6address(NDR_PULL *pndr, char *address, size_t asz)
{
	struct in6_addr in6;
	TRY(ndr_pull_array_uint8(pndr, in6.s6_addr, GX_ARRAY_SIZE(in6.s6_addr)));
	inet_ntop(AF_INET6, &in6, address, asz);
	return NDR_ERR_SUCCESS;
}

static int pdu_ndr_pull_rts_clientaddress(NDR_PULL *pndr,
	RTS_CLIENTADDRESS *r)
{
	uint32_t size_padding;
	
	TRY(ndr_pull_align(pndr, 4));
	TRY(pndr->g_uint32(&r->address_type));
	TRY(ndr_pull_union_align(pndr, 4));
	switch (r->address_type) {
	case RTS_IPV4:
		TRY(pdu_ndr_pull_ipv4address(pndr, r->client_address, GX_ARRAY_SIZE(r->client_address)));
		break;
	case RTS_IPV6:
		TRY(pdu_ndr_pull_ipv6address(pndr, r->client_address, GX_ARRAY_SIZE(r->client_address)));
		break;
	default:
		return NDR_ERR_BAD_SWITCH;
	}
	
	size_padding = 12;
	TRY(ndr_pull_advance(pndr, size_padding));
	TRY(ndr_pull_trailer_align(pndr, 4));
	
	return NDR_ERR_SUCCESS;
}

static int pdu_ndr_pull_rts_cmds(NDR_PULL *pndr,
	uint32_t command_type, RTS_CMDS *r)
{
	TRY(ndr_pull_union_align(pndr, 4));
	switch (command_type) {
	case RTS_CMD_RECEIVE_WINDOW_SIZE:
		TRY(pndr->g_uint32(&r->receivewindowsize));
		break;
	case RTS_CMD_FLOW_CONTROL_ACK:
		TRY(pdu_ndr_pull_rts_flowcontrolack(pndr,
					&r->flowcontrolack));
		break;
	case RTS_CMD_CONNECTION_TIMEOUT:
		TRY(pndr->g_uint32(&r->connectiontimeout));
		break;
	case RTS_CMD_COOKIE:
		TRY(ndr_pull_guid(pndr, &r->cookie));
		break;
	case RTS_CMD_CHANNEL_LIFETIME:
		TRY(pndr->g_uint32(&r->channellifetime));
		break;
	case RTS_CMD_CLIENT_KEEPALIVE:
		TRY(pndr->g_uint32(&r->clientkeepalive));
		break;
	case RTS_CMD_VERSION:
		TRY(pndr->g_uint32(&r->version));
		break;
	case RTS_CMD_EMPTY:
		/* do nothing */
		break;
	case RTS_CMD_PADDING:
		TRY(pdu_ndr_pull_rts_padding(pndr, &r->padding));
		break;
	case RTS_CMD_NEGATIVE_ANCE:
		/* do nothing */
		break;
	case RTS_CMD_ANCE:
		/* do nothing */
		break;
	case RTS_CMD_CLIENT_ADDRESS:
		TRY(pdu_ndr_pull_rts_clientaddress(pndr, &r->clientaddress));
		break;
	case RTS_CMD_ASSOCIATION_GROUP_ID:
		TRY(ndr_pull_guid(pndr, &r->associationgroupid));
		break;
	case RTS_CMD_DESTINATION:
		TRY(pndr->g_uint32(&r->destination));
		break;
	case RTS_CMD_PING_TRAFFIC_SENT_NOTIFY:
		TRY(pndr->g_uint32(&r->pingtrafficsentnotify));
		break;
	default:
		return NDR_ERR_BAD_SWITCH;
	}
	
	return NDR_ERR_SUCCESS;
}

static int pdu_ndr_pull_rts_cmd(NDR_PULL *pndr, RTS_CMD *r)
{
	TRY(ndr_pull_align(pndr, 4));
	TRY(pndr->g_uint32(&r->command_type));
	TRY(pdu_ndr_pull_rts_cmds(pndr, r->command_type, &r->command));
	return ndr_pull_trailer_align(pndr, 4);
		
}

static int pdu_ndr_pull_dcerpc_rts(NDR_PULL *pndr, DCERPC_RTS *r)
{
	int status;
	
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint16(pndr, &r->flags));
	TRY(ndr_pull_uint16(pndr, &r->num));
	if (r->num > 0) {
		r->commands = me_alloc<RTS_CMD>(r->num);
		if (NULL == r->commands) {
			r->num = 0;
			return NDR_ERR_ALLOC;
		}
		for (size_t i = 0; i < r->num; ++i) {
			status = pdu_ndr_pull_rts_cmd(pndr, &r->commands[i]);
			if (NDR_ERR_SUCCESS != status) {
				free(r->commands);
				r->commands = NULL;
				r->num = 0;
				return status;
			}
		}
	} else {
		r->commands = NULL;
	}
	
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		if (NULL != r->commands) {
			free(r->commands);
			r->commands = NULL;
		}
		r->num = 0;
		return status;
	}
	return NDR_ERR_SUCCESS;
}

/* free memory internal of rts except of rts itself */
static void pdu_ndr_free_dcerpc_rts(DCERPC_RTS *r)
{
	if (NULL != r->commands) {
		free(r->commands);
		r->commands = NULL;
	}
	r->num = 0;
}

static int pdu_ndr_pull_dcerpc_payload(NDR_PULL *pndr, uint8_t pkt_type,
	DCERPC_PAYLOAD *r)
{
	TRY(ndr_pull_union_align(pndr, 4));
	switch (pkt_type) {
	case DCERPC_PKT_REQUEST:
		return pdu_ndr_pull_dcerpc_request(pndr, &r->request);
	case DCERPC_PKT_PING:
		/* do nothing */
		break;
	case DCERPC_PKT_RESPONSE:
		return pdu_ndr_pull_dcerpc_response(pndr, &r->response);
	case DCERPC_PKT_FAULT:
		return pdu_ndr_pull_dcerpc_fault(pndr, &r->fault);
	case DCERPC_PKT_WORKING:
		/* do nothing */
		break;
	case DCERPC_PKT_NOCALL:
		return pdu_ndr_pull_dcerpc_fack(pndr, &r->nocall);
	case DCERPC_PKT_REJECT:
		return pdu_ndr_pull_dcerpc_fault(pndr, &r->reject);
	case DCERPC_PKT_ACK:
		/* do nothing */
		break;
	case DCERPC_PKT_FACK:
		return pdu_ndr_pull_dcerpc_fack(pndr, &r->fack);
	case DCERPC_PKT_CANCEL_ACK:
		return pdu_ndr_pull_dcerpc_cancel_ack(pndr, &r->cancel_ack);
	case DCERPC_PKT_BIND:
		return pdu_ndr_pull_dcerpc_bind(pndr, &r->bind);
	case DCERPC_PKT_BIND_ACK:
		return pdu_ndr_pull_dcerpc_bind_ack(pndr, &r->bind_ack);
	case DCERPC_PKT_BIND_NAK:
		return pdu_ndr_pull_dcerpc_bind_nak(pndr, &r->bind_nak);
	case DCERPC_PKT_ALTER:
		return pdu_ndr_pull_dcerpc_bind(pndr, &r->alter);
	case DCERPC_PKT_ALTER_ACK:
		return pdu_ndr_pull_dcerpc_bind_ack(pndr, &r->alter_ack);
	case DCERPC_PKT_SHUTDOWN:
		/* do nothing */
		break;
	case DCERPC_PKT_CO_CANCEL:
		return pdu_ndr_pull_dcerpc_co_cancel(pndr, &r->co_cancel);
	case DCERPC_PKT_ORPHANED:
		return pdu_ndr_pull_dcerpc_orphaned(pndr, &r->orphaned);
	case DCERPC_PKT_AUTH3:
		return pdu_ndr_pull_dcerpc_auth3(pndr, &r->auth3);
	case DCERPC_PKT_RTS:
		return pdu_ndr_pull_dcerpc_rts(pndr, &r->rts);
	default:
		return NDR_ERR_BAD_SWITCH;
	}
	return NDR_ERR_SUCCESS;
}

static void pdu_ndr_free_dcerpc_payload(uint8_t pkt_type,
	DCERPC_PAYLOAD *r)
{
	switch (pkt_type) {
	case DCERPC_PKT_REQUEST:
		pdu_ndr_free_dcerpc_request(&r->request);
		break;
	case DCERPC_PKT_PING:
		/* do nothing */
		break;
	case DCERPC_PKT_RESPONSE:
		pdu_ndr_free_dcerpc_response(&r->response);
		break;
	case DCERPC_PKT_FAULT:
		pdu_ndr_free_dcerpc_fault(&r->fault);
		break;
	case DCERPC_PKT_WORKING:
		/* do nothing */
		break;
	case DCERPC_PKT_NOCALL:
		pdu_ndr_free_dcerpc_fack(&r->nocall);
		break;
	case DCERPC_PKT_REJECT:
		pdu_ndr_free_dcerpc_fault(&r->reject);
		break;
	case DCERPC_PKT_ACK:
		/* do nothing */
		break;
	case DCERPC_PKT_FACK:
		pdu_ndr_free_dcerpc_fack(&r->fack);
		break;
	case DCERPC_PKT_CANCEL_ACK:
		/* do nothing */
		break;
	case DCERPC_PKT_BIND:
		pdu_ndr_free_dcerpc_bind(&r->bind);
		break;
	case DCERPC_PKT_BIND_ACK:
		pdu_ndr_free_dcerpc_bind_ack(&r->bind_ack);
		break;
	case DCERPC_PKT_BIND_NAK:
		pdu_ndr_free_dcerpc_bind_nak(&r->bind_nak);
		break;
	case DCERPC_PKT_ALTER:
		pdu_ndr_free_dcerpc_bind(&r->alter);
		break;
	case DCERPC_PKT_ALTER_ACK:
		pdu_ndr_free_dcerpc_bind_ack(&r->alter_ack);
		break;
	case DCERPC_PKT_SHUTDOWN:
		/* do nothing */
		break;
	case DCERPC_PKT_CO_CANCEL:
		pdu_ndr_free_dcerpc_co_cancel(&r->co_cancel);
		break;
	case DCERPC_PKT_ORPHANED:
		pdu_ndr_free_dcerpc_orphaned(&r->orphaned);
		break;
	case DCERPC_PKT_AUTH3:
		pdu_ndr_free_dcerpc_auth3(&r->auth3);
		break;
	case DCERPC_PKT_RTS:
		pdu_ndr_free_dcerpc_rts(&r->rts);
	}
}


int pdu_ndr_pull_ncacnpkt(NDR_PULL *pndr, DCERPC_NCACN_PACKET *pkt)
{
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint8(pndr, &pkt->rpc_vers));
	TRY(ndr_pull_uint8(pndr, &pkt->rpc_vers_minor));
	TRY(ndr_pull_uint8(pndr, &pkt->pkt_type));
	TRY(ndr_pull_uint8(pndr, &pkt->pfc_flags));
	TRY(ndr_pull_array_uint8(pndr, pkt->drep, 4));
	TRY(ndr_pull_uint16(pndr, &pkt->frag_length));
	TRY(ndr_pull_uint16(pndr, &pkt->auth_length));
	TRY(pndr->g_uint32(&pkt->call_id));
	TRY(pdu_ndr_pull_dcerpc_payload(pndr, pkt->pkt_type, &pkt->payload));
	TRY(ndr_pull_trailer_align(pndr, 4));
	
	return NDR_ERR_SUCCESS;
}

void pdu_ndr_free_ncacnpkt(DCERPC_NCACN_PACKET *pkt)
{
	pdu_ndr_free_dcerpc_payload(pkt->pkt_type, &pkt->payload);
}

static int pdu_ndr_push_dcerpc_object(NDR_PUSH *pndr,
	const DCERPC_OBJECT *r)
{
	TRY(pndr->union_align(4));
	if (pndr->flags & NDR_FLAG_OBJECT_PRESENT) {
		return pndr->p_guid(r->object);
	}
	return NDR_ERR_SUCCESS;
}


static int pdu_ndr_push_dcerpc_request(NDR_PUSH *pndr,
	const DCERPC_REQUEST *r)
{
	uint32_t saved_flags;
	
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(r->alloc_hint));
	TRY(pndr->p_uint16(r->context_id));
	TRY(pndr->p_uint16(r->opnum));
	TRY(pdu_ndr_push_dcerpc_object(pndr, &r->object));
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_ALIGN8);
	auto status = pndr->p_blob(r->pad);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = pndr->p_blob(r->stub_and_verifier);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return pndr->trailer_align(4);
}


static int pdu_ndr_push_dcerpc_response(NDR_PUSH *pndr,
	const DCERPC_RESPONSE *r)
{
	uint32_t saved_flags;
	
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(r->alloc_hint));
	TRY(pndr->p_uint16(r->context_id));
	TRY(pndr->p_uint8(r->cancel_count));
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_ALIGN8);
	auto status = pndr->p_blob(r->pad);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = pndr->p_blob(r->stub_and_verifier);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return pndr->trailer_align(4);
}

static int pdu_ndr_push_dcerpc_fault(NDR_PUSH *pndr,
	const DCERPC_FAULT *r)
{
	uint32_t saved_flags;
	
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(r->alloc_hint));
	TRY(pndr->p_uint16(r->context_id));
	TRY(pndr->p_uint8(r->cancel_count));
	TRY(pndr->p_uint32(r->status));
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	auto status = pndr->p_blob(r->pad);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return pndr->trailer_align(4);
}

static int pdu_ndr_push_dcerpc_fack(NDR_PUSH *pndr, const DCERPC_FACK *r)
{
	int i;
	
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(r->version));
	TRY(pndr->p_uint8(r->pad));
	TRY(pndr->p_uint16(r->window_size));
	TRY(pndr->p_uint32(r->max_tdsu));
	TRY(pndr->p_uint32(r->max_frag_size));
	TRY(pndr->p_uint16(r->serial_no));
	TRY(pndr->p_uint16(r->selack_size));
	for (i=0; i<r->selack_size; i++) {
		TRY(pndr->p_uint32(r->selack[i]));
	}
	return pndr->trailer_align(4);
}

static int pdu_ndr_push_dcerpc_cancel_ack(NDR_PUSH *pndr,
	const DCERPC_CANCEL_ACK *r)
{
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(r->version));
	TRY(pndr->p_uint32(r->id));
	TRY(pndr->p_uint32(r->server_is_accepting));
	return pndr->trailer_align(4);
}

static int pdu_ndr_push_dcerpc_ctx_list(NDR_PUSH *pndr,
	const DCERPC_CTX_LIST *r)
{
	int i;
	
	TRY(pndr->align(4));
	TRY(pndr->p_uint16(r->context_id));
	TRY(pndr->p_uint8(r->num_transfer_syntaxes));
	TRY(pndr->p_syntax(r->abstract_syntax));
	for (i=0; i<r->num_transfer_syntaxes; i++) {
		TRY(pndr->p_syntax(r->transfer_syntaxes[i]));
	}
	return pndr->trailer_align(4);
}

static int pdu_ndr_push_dcerpc_bind(NDR_PUSH *pndr, const DCERPC_BIND *r)
{
	int i;
	uint32_t saved_flags;
	
	TRY(pndr->align(4));
	TRY(pndr->p_uint16(r->max_xmit_frag));
	TRY(pndr->p_uint16(r->max_recv_frag));
	TRY(pndr->p_uint32(r->assoc_group_id));
	TRY(pndr->p_uint8(r->num_contexts));
	for (i=0; i<r->num_contexts; i++) {
		TRY(pdu_ndr_push_dcerpc_ctx_list(pndr, &r->ctx_list[i]));
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	auto status = pndr->p_blob(r->auth_info);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return pndr->trailer_align(4);
}

static int pdu_ndr_push_dcerpc_ack_ctx(NDR_PUSH *pndr,
	const DCERPC_ACK_CTX *r)
{
	TRY(pndr->align(4));
	TRY(pndr->p_uint16(r->result));
	TRY(pndr->p_uint16(r->reason));
	TRY(pndr->p_syntax(r->syntax));
	return pndr->trailer_align(4);
}


static int pdu_ndr_push_dcerpc_bind_ack(NDR_PUSH *pndr,
	const DCERPC_BIND_ACK *r)
{
	int i;
	uint32_t saved_flags;
	
	TRY(pndr->align(4));
	TRY(pndr->p_uint16(r->max_xmit_frag));
	TRY(pndr->p_uint16(r->max_recv_frag));
	TRY(pndr->p_uint32(r->assoc_group_id));
	if ('\0' == r->secondary_address[0]) {
		TRY(pndr->p_uint16(0));
	} else {
		TRY(pndr->p_uint16(strlen(r->secondary_address) + 1));
		TRY(pndr->p_str(r->secondary_address,
					strlen(r->secondary_address) + 1));
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_ALIGN4);
	auto status = pndr->p_blob(r->pad);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	TRY(pndr->p_uint8(r->num_contexts));
	for (i=0; i<r->num_contexts; i++) {
		TRY(pdu_ndr_push_dcerpc_ack_ctx(pndr, &r->ctx_list[i]));
	}
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = pndr->p_blob(r->auth_info);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return pndr->trailer_align(4);
}


static int pdu_ndr_push_dcerpc_bind_nak(NDR_PUSH *pndr,
	DCERPC_BIND_NAK *r)
{
	TRY(pndr->align(4));
	TRY(pndr->p_uint16(r->reject_reason));
	TRY(pndr->align(4));
	
	if (DECRPC_BIND_REASON_VERSION_NOT_SUPPORTED == r->reject_reason) {
		TRY(pndr->p_uint32(r->num_versions));
		for (size_t i = 0; i < r->num_versions; ++i)
			TRY(pndr->p_uint32(r->versions[i]));
	}
	return pndr->trailer_align(4);
}

static int pdu_ndr_push_dcerpc_co_cancel(NDR_PUSH *pndr,
	const DCERPC_CO_CANCEL *r)
{
	uint32_t saved_flags;
	
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(0));
	
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	auto status = pndr->p_blob(r->auth_info);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return pndr->trailer_align(4);
}


static int pdu_ndr_push_dcerpc_orphaned(NDR_PUSH *pndr,
	const DCERPC_ORPHANED *r)
{
	uint32_t saved_flags;
	
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(0));
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	auto status = pndr->p_blob(r->auth_info);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return pndr->trailer_align(4);
}

static int pdu_ndr_push_dcerpc_auth3(NDR_PUSH *pndr,
	const DCERPC_AUTH3 *r)
{
	uint32_t saved_flags;
	
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(0));
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	auto status = pndr->p_blob(r->auth_info);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return pndr->trailer_align(4);
}

static int pdu_ndr_push_rts_flowcontrolack(NDR_PUSH *pndr,
	const RTS_FLOWCONTROLACK *r)
{
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(r->bytes_received));
	TRY(pndr->p_uint32(r->available_window));
	TRY(pndr->p_guid(r->channel_cookie));
	return pndr->trailer_align(4);
}

static int pdu_ndr_push_rts_padding(NDR_PUSH *pndr, uint32_t v)
{
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(v));
	TRY(pndr->p_uint8_a(nullptr, v));
	return pndr->trailer_align(4);
	
}

static int pdu_ndr_push_ipv4address(NDR_PUSH *pndr, const char *address)
{
	struct in_addr in;
	uint32_t v = ntohl(0);
	if (inet_pton(AF_INET, address, &in) > 0)
		v = ntohl(in.s_addr);
	TRY(pndr->p_uint32(v));
	return pndr->trailer_align(4);
}

static int pdu_ndr_push_ipv6address(NDR_PUSH *pndr, const char *address)
{
	struct in6_addr in6;
	auto ret = inet_pton(AF_INET6, address, &in6);
	if (ret <= 0) {
		return NDR_ERR_IPV6ADDRESS;
	}
	TRY(pndr->p_uint8_a(in6.s6_addr, GX_ARRAY_SIZE(in6.s6_addr)));
	return pndr->trailer_align(4);
}

static int pdu_ndr_push_rts_clientaddress(NDR_PUSH *pndr,
	const RTS_CLIENTADDRESS *r)
{
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(r->address_type));
	TRY(pndr->union_align(4));
	switch (r->address_type) {
	case RTS_IPV4:
		TRY(pdu_ndr_push_ipv4address(pndr, r->client_address));
		break;
	case RTS_IPV6:
		TRY(pdu_ndr_push_ipv6address(pndr, r->client_address));
		break;
	default:
		return NDR_ERR_BAD_SWITCH;
	}
	TRY(pndr->p_uint8_a(nullptr, 12));
	return pndr->trailer_align(4);
}

static int pdu_ndr_push_rts_cmds(NDR_PUSH *pndr,
	uint32_t command_type, const RTS_CMDS *r)
{
	TRY(pndr->union_align(4));
	switch (command_type) {
	case RTS_CMD_RECEIVE_WINDOW_SIZE:
		TRY(pndr->p_uint32(r->receivewindowsize));
		break;
	case RTS_CMD_FLOW_CONTROL_ACK:
		TRY(pdu_ndr_push_rts_flowcontrolack(pndr, &r->flowcontrolack));
		break;
	case RTS_CMD_CONNECTION_TIMEOUT:
		TRY(pndr->p_uint32(r->connectiontimeout));
		break;
	case RTS_CMD_COOKIE:
		TRY(pndr->p_guid(r->cookie));
		break;
	case RTS_CMD_CHANNEL_LIFETIME:
		TRY(pndr->p_uint32(r->channellifetime));
		break;
	case RTS_CMD_CLIENT_KEEPALIVE:
		TRY(pndr->p_uint32(r->clientkeepalive));
		break;
	case RTS_CMD_VERSION:
		TRY(pndr->p_uint32(r->version));
		break;
	case RTS_CMD_EMPTY:
		/* do nothing */
		break;
	case RTS_CMD_PADDING:
		TRY(pdu_ndr_push_rts_padding(pndr, r->padding));
		break;
	case RTS_CMD_NEGATIVE_ANCE:
		/* do nothing */
		break;
	case RTS_CMD_ANCE:
		/* do nothing */
		break;
	case RTS_CMD_CLIENT_ADDRESS:
		TRY(pdu_ndr_push_rts_clientaddress(pndr, &r->clientaddress));
		break;
	case RTS_CMD_ASSOCIATION_GROUP_ID:
		TRY(pndr->p_guid(r->associationgroupid));
		break;
	case RTS_CMD_DESTINATION:
		TRY(pndr->p_uint32(r->destination));
		break;
	case RTS_CMD_PING_TRAFFIC_SENT_NOTIFY:
		TRY(pndr->p_uint32(r->pingtrafficsentnotify));
		break;
	default:
		return NDR_ERR_BAD_SWITCH;
	}
	
	return NDR_ERR_SUCCESS;
}

static int pdu_ndr_push_rts_cmd(NDR_PUSH *pndr, const RTS_CMD *r)
{
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(r->command_type));
	TRY(pdu_ndr_push_rts_cmds(pndr, r->command_type, &r->command));
	return pndr->trailer_align(4);
	
}

static int pdu_ndr_push_dcerpc_rts(NDR_PUSH *pndr, const DCERPC_RTS *r)
{
	int i;
	
	TRY(pndr->align(4));
	TRY(pndr->p_uint16(r->flags));
	TRY(pndr->p_uint16(r->num));
	for (i=0; i<r->num; i++) {
		TRY(pdu_ndr_push_rts_cmd(pndr, &r->commands[i]));
	}
	return pndr->trailer_align(4);
}


static int pdu_ndr_push_dcerpc_payload(NDR_PUSH *pndr, uint8_t pkt_type,
	DCERPC_PAYLOAD *r)
{
	TRY(pndr->union_align(4));
	switch (pkt_type) {
	case DCERPC_PKT_REQUEST:
		return pdu_ndr_push_dcerpc_request(pndr, &r->request);
	case DCERPC_PKT_PING:
		/* do nothing */
		break;
	case DCERPC_PKT_RESPONSE:
		return pdu_ndr_push_dcerpc_response(pndr, &r->response);
	case DCERPC_PKT_FAULT:
		return pdu_ndr_push_dcerpc_fault(pndr, &r->fault);
	case DCERPC_PKT_WORKING:
		/* do nothing */
		break;
	case DCERPC_PKT_NOCALL:
		return pdu_ndr_push_dcerpc_fack(pndr, &r->nocall);
	case DCERPC_PKT_REJECT:
		return pdu_ndr_push_dcerpc_fault(pndr, &r->reject);
	case DCERPC_PKT_ACK:
		/* do nothing */
		break;
	case DCERPC_PKT_FACK:
		return pdu_ndr_push_dcerpc_fack(pndr, &r->fack);
	case DCERPC_PKT_CANCEL_ACK:
		return pdu_ndr_push_dcerpc_cancel_ack(pndr, &r->cancel_ack);
	case DCERPC_PKT_BIND:
		return pdu_ndr_push_dcerpc_bind(pndr, &r->bind);
	case DCERPC_PKT_BIND_ACK:
		return pdu_ndr_push_dcerpc_bind_ack(pndr, &r->bind_ack);
	case DCERPC_PKT_BIND_NAK:
		return pdu_ndr_push_dcerpc_bind_nak(pndr, &r->bind_nak);
	case DCERPC_PKT_ALTER:
		return pdu_ndr_push_dcerpc_bind(pndr, &r->alter);
	case DCERPC_PKT_ALTER_ACK:
		return pdu_ndr_push_dcerpc_bind_ack(pndr, &r->alter_ack);
	case DCERPC_PKT_SHUTDOWN:
		/* do nothing */
		break;
	case DCERPC_PKT_CO_CANCEL:
		return pdu_ndr_push_dcerpc_co_cancel(pndr, &r->co_cancel);
	case DCERPC_PKT_ORPHANED:
		return pdu_ndr_push_dcerpc_orphaned(pndr, &r->orphaned);
	case DCERPC_PKT_AUTH3:
		return pdu_ndr_push_dcerpc_auth3(pndr, &r->auth3);
	case DCERPC_PKT_RTS:
		return pdu_ndr_push_dcerpc_rts(pndr, &r->rts);
	}	
	return NDR_ERR_BAD_SWITCH;
}

int pdu_ndr_push_ncacnpkt(NDR_PUSH *pndr, DCERPC_NCACN_PACKET *pkt)
{
	TRY(pndr->align(4));
	TRY(pndr->p_uint8(pkt->rpc_vers));
	TRY(pndr->p_uint8(pkt->rpc_vers_minor));
	TRY(pndr->p_uint8(pkt->pkt_type));
	TRY(pndr->p_uint8(pkt->pfc_flags));
	TRY(pndr->p_uint8_a(pkt->drep, 4));
	TRY(pndr->p_uint16(pkt->frag_length));
	TRY(pndr->p_uint16(pkt->auth_length));
	TRY(pndr->p_uint32(pkt->call_id));
	TRY(pdu_ndr_push_dcerpc_payload(pndr, pkt->pkt_type, &pkt->payload));
	return pndr->trailer_align(4);
}

int pdu_ndr_push_dcerpc_auth(NDR_PUSH *pndr, const DCERPC_AUTH *r)
{
	uint32_t saved_flags;
	
	TRY(pndr->align(4));
	TRY(pndr->p_uint8(r->auth_type));
	TRY(pndr->p_uint8(r->auth_level));
	TRY(pndr->p_uint8(r->auth_pad_length));
	TRY(pndr->p_uint8(r->auth_reserved));
	TRY(pndr->p_uint32(r->auth_context_id));
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	auto status = pndr->p_blob(r->credentials);
	pndr->flags = saved_flags;
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return pndr->trailer_align(4);
}

