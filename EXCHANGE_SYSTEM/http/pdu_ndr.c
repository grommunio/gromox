#include "pdu_ndr.h"
#include "common_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define IPV6_BYTES		16

static int pdu_ndr_pull_dcerpc_object(NDR_PULL *pndr, DCERPC_OBJECT *r)
{
	int status;
		
	status = ndr_pull_union_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (pndr->flags & NDR_FLAG_OBJECT_PRESENT) {
		status = ndr_pull_guid(pndr, &r->object);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return NDR_ERR_SUCCESS;
}

static int pdu_ndr_pull_dcerpc_ctx_list(NDR_PULL *pndr, DCERPC_CTX_LIST *r)
{
	uint32_t i;
	int status;
	uint8_t num;
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->context_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &r->num_transfer_syntaxes);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_syntax_id(pndr, &r->abstract_syntax);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	num = r->num_transfer_syntaxes;
	if (num > 0) {
		r->transfer_syntaxes = (SYNTAX_ID*)malloc(sizeof(SYNTAX_ID)*num);
		if (NULL == r->transfer_syntaxes) {
			return NDR_ERR_ALLOC;
		}
		
		for (i=0; i<r->num_transfer_syntaxes; i++) {
			status = ndr_pull_syntax_id(pndr, &r->transfer_syntaxes[i]);
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
	
	status = ndr_pull_trailer_align(pndr, 4);
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
	int status;
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->result);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->reason);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_syntax_id(pndr, &r->syntax);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_trailer_align(pndr, 4);
}

static int pdu_ndr_pull_dcerpc_bind_nak(NDR_PULL *pndr, DCERPC_BIND_NAK *r)
{
	int i;
	int status;

	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->reject_reason);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	if (DECRPC_BIND_REASON_VERSION_NOT_SUPPORTED == r->reject_reason) {
		status = ndr_pull_uint32(pndr, &r->num_versions);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (r->num_versions > 0) {
			r->versions = (uint32_t*)malloc(sizeof(uint32_t)*r->num_versions);
			if (NULL == r->versions) {
				return NDR_ERR_ALLOC;
			}
			for (i=0; i<r->num_versions; i++) {
				status = ndr_pull_uint32(pndr, &r->versions[i]);
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
	status = ndr_pull_trailer_align(pndr, 4);
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
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->alloc_hint);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->context_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->opnum);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	status = pdu_ndr_pull_dcerpc_object(pndr, &r->object);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_ALIGN8);
	status = ndr_pull_data_blob(pndr, &r->pad);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->stub_and_verifier);
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->pad);
		return status;
	}
	pndr->flags = saved_flags;
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
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->alloc_hint);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->context_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &r->cancel_count);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_ALIGN8);
	status = ndr_pull_data_blob(pndr, &r->pad);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->stub_and_verifier);
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->pad);
		return status;
	}
	pndr->flags = saved_flags;
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
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->alloc_hint);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->context_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &r->cancel_count);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->status);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->pad);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
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
	int status;
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->version);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &r->pad);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->window_size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->max_tdsu);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->max_frag_size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->serial_no);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->selack_size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (r->selack_size > 0) {
		r->selack = (uint32_t*)malloc(sizeof(uint32_t)*r->selack_size);
		if (NULL == r->selack) {
			return NDR_ERR_ALLOC;
		}
		
		for (i=0; i<r->selack_size; i++) {
			status = ndr_pull_uint32(pndr, &r->selack[i]);
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
	status = ndr_pull_trailer_align(pndr, 4);
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
	int status;
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->version);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->server_is_accepting);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_trailer_align(pndr, 4);
}

static int pdu_ndr_pull_dcerpc_bind(NDR_PULL *pndr, DCERPC_BIND *r)
{
	int i;
	int status;
	uint32_t saved_flags;
	
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->max_xmit_frag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->max_recv_frag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->assoc_group_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &r->num_contexts);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	if (r->num_contexts > 0) {
		r->ctx_list =
			(DCERPC_CTX_LIST*)malloc(sizeof(DCERPC_CTX_LIST)*r->num_contexts);
		if (NULL == r->ctx_list) {
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
	pndr->flags = saved_flags;
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
	
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->max_xmit_frag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->max_recv_frag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->assoc_group_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->secondary_address_size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (r->secondary_address_size > sizeof(r->secondary_address)) {
		return NDR_ERR_RANGE;
	}
	status = ndr_pull_string(pndr, r->secondary_address, r->secondary_address_size);
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_ALIGN4);
	status = ndr_pull_data_blob(pndr, &r->pad);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	status = ndr_pull_uint8(pndr, &r->num_contexts);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (r->num_contexts > 0) {
		r->ctx_list =
			(DCERPC_ACK_CTX*)malloc(sizeof(DCERPC_ACK_CTX)*r->num_contexts);
		if (NULL == r->ctx_list) {
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
	if (NDR_ERR_SUCCESS != status) {
		ndr_free_data_blob(&r->pad);
		if (NULL != r->ctx_list) {
			free(r->ctx_list);
			r->ctx_list = NULL;
		}
		r->num_contexts = 0;
		return status;
	}
	pndr->flags = saved_flags;
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
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->auth_info);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
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
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->auth_info);
	pndr->flags = saved_flags;
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
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->pad);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->auth_info);
	pndr->flags = saved_flags;
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
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &r->auth_type);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &r->auth_level);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->auth_level) {
		r->auth_level = DCERPC_AUTH_LEVEL_CONNECT;
	}
	status = ndr_pull_uint8(pndr, &r->auth_pad_length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &r->auth_reserved);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->auth_context_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_pull_data_blob(pndr, &r->credentials);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
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
	int status;
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->bytes_received);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->available_window);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_guid(pndr, &r->channel_cookie);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_trailer_align(pndr, 4);
}


static int pdu_ndr_pull_rts_padding(NDR_PULL *pndr, uint32_t *r)
{
	int status;
	uint32_t size_padding;
	
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, r);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	size_padding = *r;
	if (size_padding > 0xFFFF) {
		return NDR_ERR_RANGE;
	}
	status = ndr_pull_advance(pndr, size_padding);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_trailer_align(pndr, 4);
	
}

static int pdu_ndr_pull_ipv4address(NDR_PULL *pndr, char *address)
{
	int status;
	uint32_t addr;
	struct in_addr in;
	
	status = ndr_pull_uint32(pndr, &addr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	in.s_addr = htonl(addr);
	strcpy(address, inet_ntoa(in));
	return NDR_ERR_SUCCESS;
}

static int pdu_ndr_pull_ipv6address(NDR_PULL *pndr, char *address)
{
	int i;
	int offset;
	int status;
	uint8_t addr[16];
	
	status = ndr_pull_array_uint8(pndr, addr, 16);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	offset = 0;
	for (i=0; i<16; i++) {
		offset += sprintf(address + offset, "%02x", addr[i]);
		/* We need a ':' every second byte but the last one */
		if (i%2 == 1 && i != (16 - 1)) {
			address[offset] = ':';
			offset ++;
		}
	}
	address[offset] = '\0';
	return NDR_ERR_SUCCESS;
}

static int pdu_ndr_pull_rts_clientaddress(NDR_PULL *pndr,
	RTS_CLIENTADDRESS *r)
{
	int status;
	uint32_t size_padding;
	
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->address_type);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	status = ndr_pull_union_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	switch (r->address_type) {
	case RTS_IPV4:
		status = pdu_ndr_pull_ipv4address(pndr, r->client_address);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_IPV6:
		status = pdu_ndr_pull_ipv6address(pndr, r->client_address);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	default:
		return NDR_ERR_BAD_SWITCH;
	}
	
	size_padding = 12;
	status = ndr_pull_advance(pndr, size_padding);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	return NDR_ERR_SUCCESS;
}

static int pdu_ndr_pull_rts_cmds(NDR_PULL *pndr,
	uint32_t command_type, RTS_CMDS *r)
{
	int status;
	
	status = ndr_pull_union_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	switch (command_type) {
	case RTS_CMD_RECEIVE_WINDOW_SIZE:
		status = ndr_pull_uint32(pndr, &r->receivewindowsize);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_FLOW_CONTROL_ACK:
		status = pdu_ndr_pull_rts_flowcontrolack(pndr,
					&r->flowcontrolack);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_CONNECTION_TIMEOUT:
		status = ndr_pull_uint32(pndr, &r->connectiontimeout);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_COOKIE:
		status = ndr_pull_guid(pndr, &r->cookie);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_CHANNEL_LIFETIME:
		status = ndr_pull_uint32(pndr, &r->channellifetime);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_CLIENT_KEEPALIVE:
		status = ndr_pull_uint32(pndr, &r->clientkeepalive);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_VERSION:
		status = ndr_pull_uint32(pndr, &r->version);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_EMPTY:
		/* do nothing */
		break;
	case RTS_CMD_PADDING:
		status = pdu_ndr_pull_rts_padding(pndr, &r->padding);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_NEGATIVE_ANCE:
		/* do nothing */
		break;
	case RTS_CMD_ANCE:
		/* do nothing */
		break;
	case RTS_CMD_CLIENT_ADDRESS:
		status = pdu_ndr_pull_rts_clientaddress(pndr, &r->clientaddress);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_ASSOCIATION_GROUP_ID:
		status = ndr_pull_guid(pndr, &r->associationgroupid);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_DESTINATION:
		status = ndr_pull_uint32(pndr, &r->destination);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_PING_TRAFFIC_SENT_NOTIFY:
		status = ndr_pull_uint32(pndr, &r->pingtrafficsentnotify);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	default:
		return NDR_ERR_BAD_SWITCH;
	}
	
	return NDR_ERR_SUCCESS;
}

static int pdu_ndr_pull_rts_cmd(NDR_PULL *pndr, RTS_CMD *r)
{
	int status;
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->command_type);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	status = pdu_ndr_pull_rts_cmds(pndr, r->command_type, &r->command);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_trailer_align(pndr, 4);
		
}

static int pdu_ndr_pull_dcerpc_rts(NDR_PULL *pndr, DCERPC_RTS *r)
{
	int i;
	int status;
	uint32_t size_commands;
	
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &r->num);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	size_commands = r->num;
	if (size_commands > 0) {
		r->commands = (RTS_CMD*)malloc(sizeof(RTS_CMD)*size_commands);
		if (NULL == r->commands) {
			return NDR_ERR_ALLOC;
		}
		for (i=0; i<size_commands; i++) {
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
	int status;
	
	status = ndr_pull_union_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
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
	int status;
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &pkt->rpc_vers);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &pkt->rpc_vers_minor);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &pkt->pkt_type);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint8(pndr, &pkt->pfc_flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_array_uint8(pndr, pkt->drep, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &pkt->frag_length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint16(pndr, &pkt->auth_length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &pkt->call_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = pdu_ndr_pull_dcerpc_payload(pndr, pkt->pkt_type, &pkt->payload);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	return NDR_ERR_SUCCESS;
}

void pdu_ndr_free_ncacnpkt(DCERPC_NCACN_PACKET *pkt)
{
	pdu_ndr_free_dcerpc_payload(pkt->pkt_type, &pkt->payload);
}


/*--------------------------------------- PUSH ------------------------------*/


static int pdu_ndr_push_dcerpc_object(NDR_PUSH *pndr,
	const DCERPC_OBJECT *r)
{
	int status;
	
	status = ndr_push_union_align(pndr, 4);
	if (status != NDR_ERR_SUCCESS)
		return status;
	if (pndr->flags & NDR_FLAG_OBJECT_PRESENT) {
		return ndr_push_guid(pndr, &r->object);
	}
	return NDR_ERR_SUCCESS;
}


static int pdu_ndr_push_dcerpc_request(NDR_PUSH *pndr,
	const DCERPC_REQUEST *r)
{
	int status;
	uint32_t saved_flags;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->alloc_hint);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->context_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->opnum);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	status = pdu_ndr_push_dcerpc_object(pndr, &r->object);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_ALIGN8);
	status = ndr_push_data_blob(pndr, r->pad);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_push_data_blob(pndr, r->stub_and_verifier);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	return ndr_push_trailer_align(pndr, 4);
}


static int pdu_ndr_push_dcerpc_response(NDR_PUSH *pndr,
	const DCERPC_RESPONSE *r)
{
	int status;
	uint32_t saved_flags;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->alloc_hint);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->context_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, r->cancel_count);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_ALIGN8);
	status = ndr_push_data_blob(pndr, r->pad);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_push_data_blob(pndr, r->stub_and_verifier);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	return ndr_push_trailer_align(pndr, 4);
}

static int pdu_ndr_push_dcerpc_fault(NDR_PUSH *pndr,
	const DCERPC_FAULT *r)
{
	int status;
	uint32_t saved_flags;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->alloc_hint);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->context_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, r->cancel_count);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->status);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_push_data_blob(pndr, r->pad);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	return ndr_push_trailer_align(pndr, 4);
}

static int pdu_ndr_push_dcerpc_fack(NDR_PUSH *pndr, const DCERPC_FACK *r)
{
	int i;
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->version);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, r->pad);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->window_size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->max_tdsu);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->max_frag_size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->serial_no);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->selack_size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->selack_size; i++) {
		status = ndr_push_uint32(pndr, r->selack[i]);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_trailer_align(pndr, 4);
}

static int pdu_ndr_push_dcerpc_cancel_ack(NDR_PUSH *pndr,
	const DCERPC_CANCEL_ACK *r)
{
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->version);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->server_is_accepting);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_trailer_align(pndr, 4);
}

static int pdu_ndr_push_dcerpc_ctx_list(NDR_PUSH *pndr,
	const DCERPC_CTX_LIST *r)
{
	int i;
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->context_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, r->num_transfer_syntaxes);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_syntax_id(pndr, &r->abstract_syntax);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->num_transfer_syntaxes; i++) {
		status = ndr_push_syntax_id(pndr, &r->transfer_syntaxes[i]);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_trailer_align(pndr, 4);
}

static int pdu_ndr_push_dcerpc_bind(NDR_PUSH *pndr, const DCERPC_BIND *r)
{
	int i;
	int status;
	uint32_t saved_flags;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->max_xmit_frag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->max_recv_frag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->assoc_group_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, r->num_contexts);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->num_contexts; i++) {
		status = pdu_ndr_push_dcerpc_ctx_list(pndr, &r->ctx_list[i]);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_push_data_blob(pndr, r->auth_info);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	return ndr_push_trailer_align(pndr, 4);
}

static int pdu_ndr_push_dcerpc_ack_ctx(NDR_PUSH *pndr,
	const DCERPC_ACK_CTX *r)
{
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->result);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->reason);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_syntax_id(pndr, &r->syntax);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_trailer_align(pndr, 4);
}


static int pdu_ndr_push_dcerpc_bind_ack(NDR_PUSH *pndr,
	const DCERPC_BIND_ACK *r)
{
	int i;
	int status;
	uint32_t saved_flags;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->max_xmit_frag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->max_recv_frag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->assoc_group_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if ('\0' == r->secondary_address[0]) {
		status = ndr_push_uint16(pndr, 0);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ndr_push_uint16(pndr, strlen(r->secondary_address) + 1);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_string(pndr, r->secondary_address,
					strlen(r->secondary_address) + 1);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_ALIGN4);
	status = ndr_push_data_blob(pndr, r->pad);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	status = ndr_push_uint8(pndr, r->num_contexts);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->num_contexts; i++) {
		status = pdu_ndr_push_dcerpc_ack_ctx(pndr, &r->ctx_list[i]);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_push_data_blob(pndr, r->auth_info);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	return ndr_push_trailer_align(pndr, 4);
}


static int pdu_ndr_push_dcerpc_bind_nak(NDR_PUSH *pndr,
	DCERPC_BIND_NAK *r)
{
	int i;
	int status;

	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->reject_reason);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	if (DECRPC_BIND_REASON_VERSION_NOT_SUPPORTED == r->reject_reason) {
		status = ndr_push_uint32(pndr, r->num_versions);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		for (i=0; i<r->num_versions; i++) {
			status = ndr_push_uint32(pndr, r->versions[i]);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return ndr_push_trailer_align(pndr, 4);
}

static int pdu_ndr_push_dcerpc_co_cancel(NDR_PUSH *pndr,
	const DCERPC_CO_CANCEL *r)
{
	int status;
	uint32_t saved_flags;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_push_data_blob(pndr, r->auth_info);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	return ndr_push_trailer_align(pndr, 4);
}


static int pdu_ndr_push_dcerpc_orphaned(NDR_PUSH *pndr,
	const DCERPC_ORPHANED *r)
{
	int status;
	uint32_t saved_flags;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_push_data_blob(pndr, r->auth_info);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	return ndr_push_trailer_align(pndr, 4);
}

static int pdu_ndr_push_dcerpc_auth3(NDR_PUSH *pndr,
	const DCERPC_AUTH3 *r)
{
	int status;
	uint32_t saved_flags;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_push_data_blob(pndr, r->auth_info);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	return ndr_push_trailer_align(pndr, 4);
}

static int pdu_ndr_push_rts_flowcontrolack(NDR_PUSH *pndr,
	const RTS_FLOWCONTROLACK *r)
{
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->bytes_received);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->available_window);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_guid(pndr, &r->channel_cookie);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_trailer_align(pndr, 4);
}

static int pdu_ndr_push_rts_padding(NDR_PUSH *pndr, uint32_t v)
{
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, v);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_array_uint8(pndr, 0, v);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_trailer_align(pndr, 4);
	
}

static int pdu_ndr_push_ipv4address(NDR_PUSH *pndr, const char *address)
{
	int status;
	uint32_t addr;
	
	addr = inet_addr(address);
	status = ndr_push_uint32(pndr, htonl(addr));
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_trailer_align(pndr, 4);
}

static int pdu_ndr_push_ipv6address(NDR_PUSH *pndr, const char *address)
{

	int ret;
	int status;
	uint8_t addr[IPV6_BYTES];
	
	ret = inet_pton(AF_INET6, address, addr);
	if (ret <= 0) {
		return NDR_ERR_IPV6ADDRESS;
	}

	status = ndr_push_array_uint8(pndr, addr, IPV6_BYTES);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_trailer_align(pndr, 4);
}

static int pdu_ndr_push_rts_clientaddress(NDR_PUSH *pndr,
	const RTS_CLIENTADDRESS *r)
{
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	status = ndr_push_uint32(pndr, r->address_type);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
		
	status = ndr_push_union_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	switch (r->address_type) {
	case RTS_IPV4:
		status = pdu_ndr_push_ipv4address(pndr, r->client_address);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_IPV6:
		status = pdu_ndr_push_ipv6address(pndr, r->client_address);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	default:
		return NDR_ERR_BAD_SWITCH;
	}
	
	status = ndr_push_array_uint8(pndr, 0, 12);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_trailer_align(pndr, 4);
}

static int pdu_ndr_push_rts_cmds(NDR_PUSH *pndr,
	uint32_t command_type, const RTS_CMDS *r)
{
	int status;
	
	status = ndr_push_union_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	switch (command_type) {
	case RTS_CMD_RECEIVE_WINDOW_SIZE:
		status = ndr_push_uint32(pndr, r->receivewindowsize);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_FLOW_CONTROL_ACK:
		status = pdu_ndr_push_rts_flowcontrolack(pndr, &r->flowcontrolack);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_CONNECTION_TIMEOUT:
		status = ndr_push_uint32(pndr, r->connectiontimeout);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_COOKIE:
		status = ndr_push_guid(pndr, &r->cookie);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_CHANNEL_LIFETIME:
		status = ndr_push_uint32(pndr, r->channellifetime);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_CLIENT_KEEPALIVE:
		status = ndr_push_uint32(pndr, r->clientkeepalive);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_VERSION:
		status = ndr_push_uint32(pndr, r->version);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_EMPTY:
		/* do nothing */
		break;
	case RTS_CMD_PADDING:
		status = pdu_ndr_push_rts_padding(pndr, r->padding);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_NEGATIVE_ANCE:
		/* do nothing */
		break;
	case RTS_CMD_ANCE:
		/* do nothing */
		break;
	case RTS_CMD_CLIENT_ADDRESS:
		status = pdu_ndr_push_rts_clientaddress(pndr, &r->clientaddress);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_ASSOCIATION_GROUP_ID:
		status = ndr_push_guid(pndr, &r->associationgroupid);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_DESTINATION:
		status = ndr_push_uint32(pndr, r->destination);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case RTS_CMD_PING_TRAFFIC_SENT_NOTIFY:
		status = ndr_push_uint32(pndr, r->pingtrafficsentnotify);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		break;
	default:
		return NDR_ERR_BAD_SWITCH;
	}
	
	return NDR_ERR_SUCCESS;
}

static int pdu_ndr_push_rts_cmd(NDR_PUSH *pndr, const RTS_CMD *r)
{
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->command_type);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	status = pdu_ndr_push_rts_cmds(pndr, r->command_type, &r->command);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_trailer_align(pndr, 4);
	
}

static int pdu_ndr_push_dcerpc_rts(NDR_PUSH *pndr, const DCERPC_RTS *r)
{
	int i;
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, r->num);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->num; i++) {
		status = pdu_ndr_push_rts_cmd(pndr, &r->commands[i]);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_trailer_align(pndr, 4);
}


static int pdu_ndr_push_dcerpc_payload(NDR_PUSH *pndr, uint8_t pkt_type,
	DCERPC_PAYLOAD *r)
{
	int status;
	
	status = ndr_push_union_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
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
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, pkt->rpc_vers);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, pkt->rpc_vers_minor);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, pkt->pkt_type);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, pkt->pfc_flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_array_uint8(pndr, pkt->drep, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, pkt->frag_length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint16(pndr, pkt->auth_length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, pkt->call_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = pdu_ndr_push_dcerpc_payload(pndr, pkt->pkt_type, &pkt->payload);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_trailer_align(pndr, 4);
}

int pdu_ndr_push_dcerpc_auth(NDR_PUSH *pndr, const DCERPC_AUTH *r)
{
	int status;
	uint32_t saved_flags;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, r->auth_type);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, r->auth_level);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, r->auth_pad_length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint8(pndr, r->auth_reserved);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->auth_context_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	saved_flags = pndr->flags;
	ndr_set_flags(&pndr->flags, NDR_FLAG_REMAINING);
	status = ndr_push_data_blob(pndr, r->credentials);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	pndr->flags = saved_flags;
	return ndr_push_trailer_align(pndr, 4);
}

