// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstring>
#include <gromox/lzxpress.hpp>
#include <gromox/proc_common.h>
#include "aux_ext.hpp"
#include "aux_types.h"
#include "common_util.h"
#define AUX_ALIGN_SIZE									4
#define TRY(expr) do { int v = (expr); if (v != EXT_ERR_SUCCESS) return v; } while (false)

static int aux_ext_pull_aux_perf_requestid(
	EXT_PULL *pext, AUX_PERF_REQUESTID *r)
{
	TRY(pext->g_uint16(&r->session_id));
	return pext->g_uint16(&r->request_id);
}

static int aux_ext_push_aux_perf_requestid(
	EXT_PUSH *pext, const AUX_PERF_REQUESTID *r)
{
	TRY(pext->p_uint16(r->session_id));
	return pext->p_uint16(r->request_id);
}

static int aux_ext_pull_aux_perf_sessioninfo(
	EXT_PULL *pext, AUX_PERF_SESSIONINFO *r)
{
	TRY(pext->g_uint16(&r->session_id));
	TRY(pext->g_uint16(&r->reserved));
	return pext->g_guid(&r->session_guid);
}

static int aux_ext_push_aux_perf_sessioninfo(
	EXT_PUSH *pext, const AUX_PERF_SESSIONINFO *r)
{
	TRY(pext->p_uint16(r->session_id));
	TRY(pext->p_uint16(r->reserved));
	return pext->p_guid(r->session_guid);
}

static int aux_ext_pull_aux_perf_sessioninfo_v2(
	EXT_PULL *pext, AUX_PERF_SESSIONINFO_V2 *r)
{
	TRY(pext->g_uint16(&r->session_id));
	TRY(pext->g_uint16(&r->reserved));
	TRY(pext->g_guid(&r->session_guid));
	return pext->g_uint32(&r->connection_id);
}

static int aux_ext_push_aux_perf_sessioninfo_v2(
	EXT_PUSH *pext, const AUX_PERF_SESSIONINFO_V2 *r)
{
	TRY(pext->p_uint16(r->session_id));
	TRY(pext->p_uint16(r->reserved));
	TRY(pext->p_guid(r->session_guid));
	return pext->p_uint32(r->connection_id);
}

static int aux_ext_pull_aux_perf_clientinfo(
	EXT_PULL *pext, AUX_PERF_CLIENTINFO *r)
{
	auto &ext = *pext;
	uint16_t machine_name_offset;
	uint16_t user_name_offset;
	uint16_t client_ip_offset;
	uint16_t client_ip_mask_offset;
	uint16_t adapter_name_offset;
	uint16_t mac_address_offset;
	uint32_t payload_offset = ext.m_offset;

	TRY(pext->g_uint32(&r->adapter_speed));
	TRY(pext->g_uint16(&r->client_id));
	TRY(pext->g_uint16(&machine_name_offset));
	TRY(pext->g_uint16(&user_name_offset));
	TRY(pext->g_uint16(&r->client_ip_size));
	TRY(pext->g_uint16(&client_ip_offset));
	TRY(pext->g_uint16(&r->client_ip_mask_size));
	TRY(pext->g_uint16(&client_ip_mask_offset));
	TRY(pext->g_uint16(&adapter_name_offset));
	TRY(pext->g_uint16(&r->mac_address_size));
	TRY(pext->g_uint16(&mac_address_offset));
	TRY(pext->g_uint16(&r->client_mode));
	TRY(pext->g_uint16(&r->reserved));
	if (0 != machine_name_offset) {
		ext.m_offset = payload_offset + machine_name_offset - 4;
		TRY(pext->g_str(&r->machine_name));
	} else {
		r->machine_name = NULL;
	}
	if (0 != user_name_offset) {
		ext.m_offset = payload_offset + user_name_offset - 4;
		TRY(pext->g_str(&r->user_name));
	} else {
		r->user_name = NULL;
	}
	if (0 != client_ip_offset && 0 != r->client_ip_size) {
		r->client_ip = pext->anew<uint8_t>(r->client_ip_size);
		if (NULL == r->client_ip) {
			r->client_ip_size = 0;
			return EXT_ERR_ALLOC;
		}
		ext.m_offset = payload_offset + client_ip_offset - 4;
		TRY(pext->g_bytes(r->client_ip, r->client_ip_size));
	} else {
		r->client_ip = NULL;
	}
	if (0 != client_ip_mask_offset && 0 != r->client_ip_mask_size) {
		r->client_ip_mask = pext->anew<uint8_t>(r->client_ip_mask_size);
		if (NULL == r->client_ip_mask) {
			r->client_ip_mask_size = 0;
			return EXT_ERR_ALLOC;
		}
		ext.m_offset = payload_offset + client_ip_mask_offset - 4;
		TRY(pext->g_bytes(r->client_ip_mask, r->client_ip_mask_size));
	} else {
		r->client_ip_mask = NULL;
	}
	if (0 != adapter_name_offset) {
		ext.m_offset = payload_offset + adapter_name_offset - 4;
		TRY(pext->g_str(&r->adapter_name));
	} else {
		r->adapter_name = NULL;
	}
	if (0 != mac_address_offset && 0 != r->mac_address_size) {
		r->mac_address = pext->anew<uint8_t>(r->mac_address_size);
		if (NULL == r->mac_address) {
			r->mac_address_size = 0;
			return EXT_ERR_ALLOC;
		}
		ext.m_offset = payload_offset + mac_address_offset - 4;
		TRY(pext->g_bytes(r->mac_address, r->mac_address_size));
	} else {
		r->mac_address = NULL;
	}
	return EXT_ERR_SUCCESS;
}

static int aux_ext_push_aux_perf_clientinfo(
	EXT_PUSH *pext, AUX_PERF_CLIENTINFO *r)
{
	uint16_t machine_name_offset;
	uint16_t machine_name_size;
	uint16_t user_name_offset;
	uint16_t user_name_size;
	uint16_t adapter_name_offset;
	uint16_t adapter_name_size;
	
	TRY(pext->p_uint32(r->adapter_speed));
	TRY(pext->p_uint16(r->client_id));
	if (NULL == r->machine_name) {
		machine_name_offset = 0;
		machine_name_size = 0;
	} else {
		machine_name_offset = 32;
		machine_name_size =  strlen(r->machine_name) + 1;
	}
	TRY(pext->p_uint16(machine_name_offset));
	
	if (NULL == r->user_name) {
		user_name_offset = 0;
		user_name_size = 0;
	} else {
		user_name_offset = 32 + machine_name_size;
		user_name_size = strlen(r->user_name) + 1;
	}
	TRY(pext->p_uint16(user_name_offset));
	TRY(pext->p_uint16(r->client_ip_size));
	uint16_t client_ip_offset = r->client_ip == nullptr ? 0 :
	                            32 + machine_name_size + user_name_size;
	TRY(pext->p_uint16(client_ip_offset));
	TRY(pext->p_uint16(r->client_ip_mask_size));
	uint16_t client_ip_mask_offset = r->client_ip_mask == nullptr ? 0 :
	                                 32 + machine_name_size + user_name_size + r->client_ip_size;
	TRY(pext->p_uint16(client_ip_mask_offset));
	if (NULL == r->adapter_name) {
		adapter_name_offset = 0;
		adapter_name_size = 0;
	} else {
		adapter_name_offset = 32 + machine_name_size + user_name_size +
								r->client_ip_size + r->client_ip_mask_size;
		adapter_name_size = strlen(r->adapter_name) + 1;
	}
	TRY(pext->p_uint16(adapter_name_offset));
	TRY(pext->p_uint16(r->mac_address_size));
	uint16_t mac_address_offset = r->mac_address == nullptr ? 0 :
		32 + machine_name_size + user_name_size +
		r->client_ip_size + r->client_ip_mask_size + adapter_name_size;
	TRY(pext->p_uint16(mac_address_offset));
	TRY(pext->p_uint16(r->client_mode));
	TRY(pext->p_uint16(r->reserved));
	if (r->machine_name != nullptr)
		TRY(pext->p_str(r->machine_name));
	if (r->user_name != nullptr)
		TRY(pext->p_str(r->user_name));
	if (r->client_ip != nullptr)
		TRY(pext->p_bytes(r->client_ip, r->client_ip_size));
	if (r->client_ip_mask != nullptr)
		TRY(pext->p_bytes(r->client_ip_mask, r->client_ip_mask_size));
	if (r->adapter_name != nullptr)
		TRY(pext->p_str(r->adapter_name));
	if (r->mac_address != nullptr)
		TRY(pext->p_bytes(r->mac_address, r->mac_address_size));
	return EXT_ERR_SUCCESS;
}

static int aux_ext_pull_aux_perf_serverinfo(
	EXT_PULL *pext, AUX_PERF_SERVERINFO *r)
{
	auto &ext = *pext;
	uint16_t server_dn_offset;
	uint16_t server_name_offset;
	uint32_t payload_offset = ext.m_offset;

	TRY(pext->g_uint16(&r->server_id));
	TRY(pext->g_uint16(&r->server_type));
	TRY(pext->g_uint16(&server_dn_offset));
	TRY(pext->g_uint16(&server_name_offset));
	if (0 != server_dn_offset) {
		ext.m_offset = payload_offset + server_dn_offset - 4;
		TRY(pext->g_str(&r->server_dn));
	}
	if (0 != server_name_offset) {
		ext.m_offset = payload_offset + server_name_offset - 4;
		TRY(pext->g_str(&r->server_name));
	} else {
		r->server_name = NULL;
	}
	return EXT_ERR_SUCCESS;
}

static int aux_ext_push_aux_perf_serverinfo(
	EXT_PUSH *pext, AUX_PERF_SERVERINFO *r)
{
	uint16_t server_dn_offset;
	uint16_t server_dn_size;
	
	TRY(pext->p_uint16(r->server_id));
	TRY(pext->p_uint16(r->server_type));
	if (NULL == r->server_dn) {
		server_dn_offset = 0;
		server_dn_size = 0;
	} else {
		server_dn_offset = 12;
		server_dn_size = strlen(r->server_dn) + 1;
	}
	TRY(pext->p_uint16(server_dn_offset));
	uint16_t server_name_offset = r->server_name == nullptr ? 0 : 12 + server_dn_size;
	TRY(pext->p_uint16(server_name_offset));
	if (r->server_dn != nullptr)
		TRY(pext->p_str(r->server_dn));
	if (r->server_name != nullptr)
		TRY(pext->p_str(r->server_name));
	return EXT_ERR_SUCCESS;
}
static int aux_ext_pull_aux_perf_processinfo(
	EXT_PULL *pext, AUX_PERF_PROCESSINFO *r)
{
	auto &ext = *pext;
	uint16_t process_name_offset;
	uint32_t payload_offset = ext.m_offset;

	TRY(pext->g_uint16(&r->process_id));
	TRY(pext->g_uint16(&r->reserved1));
	TRY(pext->g_guid(&r->process_guid));
	TRY(pext->g_uint16(&process_name_offset));
	TRY(pext->g_uint16(&r->reserved2));
	if (0 != process_name_offset) {
		ext.m_offset = payload_offset + process_name_offset - 4;
		TRY(pext->g_str(&r->process_name));
	} else {
		r->process_name = NULL;
	}
	return EXT_ERR_SUCCESS;
}

static int aux_ext_push_aux_perf_processinfo(
	EXT_PUSH *pext, AUX_PERF_PROCESSINFO *r)
{
	TRY(pext->p_uint16(r->process_id));
	TRY(pext->p_uint16(r->reserved1));
	TRY(pext->p_guid(r->process_guid));
	uint16_t process_name_offset = r->process_name == nullptr ? 0 : 28;
	TRY(pext->p_uint16(process_name_offset));
	TRY(pext->p_uint16(r->reserved2));
	if (r->process_name != nullptr)
		TRY(pext->p_str(r->process_name));
	return EXT_ERR_SUCCESS;
}

static int aux_ext_pull_aux_perf_defmdb_success(
	EXT_PULL *pext, AUX_PERF_DEFMDB_SUCCESS *r)
{
	TRY(pext->g_uint32(&r->time_since_request));
	TRY(pext->g_uint32(&r->time_to_complete_request));
	TRY(pext->g_uint16(&r->request_id));
	return pext->g_uint16(&r->reserved);
}

static int aux_ext_push_aux_perf_defmdb_success(
	EXT_PUSH *pext, const AUX_PERF_DEFMDB_SUCCESS *r)
{
	TRY(pext->p_uint32(r->time_since_request));
	TRY(pext->p_uint32(r->time_to_complete_request));
	TRY(pext->p_uint16(r->request_id));
	return pext->p_uint16(r->reserved);
}

static int aux_ext_pull_aux_perf_defgc_success(
	EXT_PULL *pext, AUX_PERF_DEFGC_SUCCESS *r)
{
	TRY(pext->g_uint16(&r->server_id));
	TRY(pext->g_uint16(&r->session_id));
	TRY(pext->g_uint32(&r->time_since_request));
	TRY(pext->g_uint32(&r->time_to_complete_request));
	TRY(pext->g_uint8(&r->request_operation));
	return pext->g_bytes(r->reserved, 3);
}

static int aux_ext_push_aux_perf_defgc_success(
	EXT_PUSH *pext, const AUX_PERF_DEFGC_SUCCESS *r)
{
	TRY(pext->p_uint16(r->server_id));
	TRY(pext->p_uint16(r->session_id));
	TRY(pext->p_uint32(r->time_since_request));
	TRY(pext->p_uint32(r->time_to_complete_request));
	TRY(pext->p_uint8(r->request_operation));
	return pext->p_bytes(r->reserved, 3);
}

static int aux_ext_pull_aux_perf_mdb_success(
	EXT_PULL *pext, AUX_PERF_MDB_SUCCESS *r)
{
	TRY(pext->g_uint16(&r->client_id));
	TRY(pext->g_uint16(&r->server_id));
	TRY(pext->g_uint16(&r->session_id));
	TRY(pext->g_uint16(&r->request_id));
	TRY(pext->g_uint32(&r->time_since_request));
	return pext->g_uint32(&r->time_to_complete_request);
}

static int aux_ext_push_aux_perf_mdb_success(
	EXT_PUSH *pext, const AUX_PERF_MDB_SUCCESS *r)
{
	TRY(pext->p_uint16(r->client_id));
	TRY(pext->p_uint16(r->server_id));
	TRY(pext->p_uint16(r->session_id));
	TRY(pext->p_uint16(r->request_id));
	TRY(pext->p_uint32(r->time_since_request));
	return pext->p_uint32(r->time_to_complete_request);
}

static int aux_ext_pull_aux_perf_mdb_success_v2(
	EXT_PULL *pext, AUX_PERF_MDB_SUCCESS_V2 *r)
{
	TRY(pext->g_uint16(&r->process_id));
	TRY(pext->g_uint16(&r->client_id));
	TRY(pext->g_uint16(&r->server_id));
	TRY(pext->g_uint16(&r->session_id));
	TRY(pext->g_uint16(&r->request_id));
	TRY(pext->g_uint16(&r->reserved));
	TRY(pext->g_uint32(&r->time_since_request));
	return pext->g_uint32(&r->time_to_complete_request);
}

static int aux_ext_push_aux_perf_mdb_success_v2(
	EXT_PUSH *pext, AUX_PERF_MDB_SUCCESS_V2 *r)
{
	TRY(pext->p_uint16(r->process_id));
	TRY(pext->p_uint16(r->client_id));
	TRY(pext->p_uint16(r->server_id));
	TRY(pext->p_uint16(r->session_id));
	TRY(pext->p_uint16(r->request_id));
	TRY(pext->p_uint16(r->reserved));
	TRY(pext->p_uint32(r->time_since_request));
	return pext->p_uint32(r->time_to_complete_request);
}

static int aux_ext_pull_aux_perf_gc_success(
	EXT_PULL *pext, AUX_PERF_GC_SUCCESS *r)
{
	TRY(pext->g_uint16(&r->client_id));
	TRY(pext->g_uint16(&r->server_id));
	TRY(pext->g_uint16(&r->session_id));
	TRY(pext->g_uint16(&r->reserved1));
	TRY(pext->g_uint32(&r->time_since_request));
	TRY(pext->g_uint32(&r->time_to_complete_request));
	TRY(pext->g_uint8(&r->request_operation));
	return pext->g_bytes(r->reserved2, 3);
}

static int aux_ext_push_aux_perf_gc_success(
	EXT_PUSH *pext, const AUX_PERF_GC_SUCCESS *r)
{
	TRY(pext->p_uint16(r->client_id));
	TRY(pext->p_uint16(r->server_id));
	TRY(pext->p_uint16(r->session_id));
	TRY(pext->p_uint16(r->reserved1));
	TRY(pext->p_uint32(r->time_since_request));
	TRY(pext->p_uint32(r->time_to_complete_request));
	TRY(pext->p_uint8(r->request_operation));
	return pext->p_bytes(r->reserved2, 3);
}

static int aux_ext_pull_aux_perf_gc_success_v2(
	EXT_PULL *pext, AUX_PERF_GC_SUCCESS_V2 *r)
{
	TRY(pext->g_uint16(&r->process_id));
	TRY(pext->g_uint16(&r->client_id));
	TRY(pext->g_uint16(&r->server_id));
	TRY(pext->g_uint16(&r->session_id));
	TRY(pext->g_uint32(&r->time_since_request));
	TRY(pext->g_uint32(&r->time_to_complete_request));
	TRY(pext->g_uint8(&r->request_operation));
	return pext->g_bytes(r->reserved, 3);
}

static int aux_ext_push_aux_perf_gc_success_v2(
	EXT_PUSH *pext, const AUX_PERF_GC_SUCCESS_V2 *r)
{
	TRY(pext->p_uint16(r->process_id));
	TRY(pext->p_uint16(r->client_id));
	TRY(pext->p_uint16(r->server_id));
	TRY(pext->p_uint16(r->session_id));
	TRY(pext->p_uint32(r->time_since_request));
	TRY(pext->p_uint32(r->time_to_complete_request));
	TRY(pext->p_uint8(r->request_operation));
	return pext->p_bytes(r->reserved, 3);
}

static int aux_ext_pull_aux_perf_failure(EXT_PULL *pext, AUX_PERF_FAILURE *r)
{
	TRY(pext->g_uint16(&r->client_id));
	TRY(pext->g_uint16(&r->server_id));
	TRY(pext->g_uint16(&r->session_id));
	TRY(pext->g_uint16(&r->request_id));
	TRY(pext->g_uint32(&r->time_since_request));
	TRY(pext->g_uint32(&r->time_to_fail_request));
	TRY(pext->g_uint32(&r->result_code));
	TRY(pext->g_uint8(&r->request_operation));
	return pext->g_bytes(r->reserved, 3);
}

static int aux_ext_push_aux_perf_failure(
	EXT_PUSH *pext, const AUX_PERF_FAILURE *r)
{
	TRY(pext->p_uint16(r->client_id));
	TRY(pext->p_uint16(r->server_id));
	TRY(pext->p_uint16(r->session_id));
	TRY(pext->p_uint16(r->request_id));
	TRY(pext->p_uint32(r->time_since_request));
	TRY(pext->p_uint32(r->time_to_fail_request));
	TRY(pext->p_uint32(r->result_code));
	TRY(pext->p_uint8(r->request_operation));
	return pext->p_bytes(r->reserved, 3);
}

static int aux_ext_pull_aux_perf_failure_v2(
	EXT_PULL *pext, AUX_PERF_FAILURE_V2 *r)
{
	TRY(pext->g_uint16(&r->process_id));
	TRY(pext->g_uint16(&r->client_id));
	TRY(pext->g_uint16(&r->server_id));
	TRY(pext->g_uint16(&r->session_id));
	TRY(pext->g_uint16(&r->request_id));
	TRY(pext->g_uint16(&r->reserved1));
	TRY(pext->g_uint32(&r->time_since_request));
	TRY(pext->g_uint32(&r->time_to_fail_request));
	TRY(pext->g_uint32(&r->result_code));
	TRY(pext->g_uint8(&r->request_operation));
	return pext->g_bytes(r->reserved2, 3);
}

static int aux_ext_push_aux_perf_failure_v2(
	EXT_PUSH *pext, const AUX_PERF_FAILURE_V2 *r)
{
	TRY(pext->p_uint16(r->process_id));
	TRY(pext->p_uint16(r->client_id));
	TRY(pext->p_uint16(r->server_id));
	TRY(pext->p_uint16(r->session_id));
	TRY(pext->p_uint16(r->request_id));
	TRY(pext->p_uint16(r->reserved1));
	TRY(pext->p_uint32(r->time_since_request));
	TRY(pext->p_uint32(r->time_to_fail_request));
	TRY(pext->p_uint32(r->result_code));
	TRY(pext->p_uint8(r->request_operation));
	return pext->p_bytes(r->reserved2, 3);
}

static int aux_ext_pull_aux_client_control(
	EXT_PULL *pext, AUX_CLIENT_CONTROL *r)
{
	TRY(pext->g_uint32(&r->enable_flags));
	return pext->g_uint32(&r->expiry_time);
}

static int aux_ext_push_aux_client_control(
	EXT_PUSH *pext, const AUX_CLIENT_CONTROL *r)
{
	TRY(pext->p_uint32(r->enable_flags));
	return pext->p_uint32(r->expiry_time);
}

static int aux_ext_pull_aux_osversioninfo(
	EXT_PULL *pext, AUX_OSVERSIONINFO *r)
{
	TRY(pext->g_uint32(&r->os_version_info_size));
	TRY(pext->g_uint32(&r->major_version));
	TRY(pext->g_uint32(&r->minor_version));
	TRY(pext->g_uint32(&r->build_number));
	TRY(pext->g_bytes(r->reserved1, 132));
	TRY(pext->g_uint16(&r->service_pack_major));
	TRY(pext->g_uint16(&r->service_pack_minor));
	return pext->g_uint32(&r->reserved2);
}

static int aux_ext_push_aux_osversioninfo(
	EXT_PUSH *pext, const AUX_OSVERSIONINFO *r)
{
	TRY(pext->p_uint32(r->os_version_info_size));
	TRY(pext->p_uint32(r->major_version));
	TRY(pext->p_uint32(r->minor_version));
	TRY(pext->p_uint32(r->build_number));
	TRY(pext->p_bytes(r->reserved1, 132));
	TRY(pext->p_uint16(r->service_pack_major));
	TRY(pext->p_uint16(r->service_pack_minor));
	return pext->p_uint32(r->reserved2);
}

static int aux_ext_pull_aux_exorginfo(EXT_PULL *pext, AUX_EXORGINFO *r)
{
	return pext->g_uint32(&r->org_flags);
}

static int aux_ext_push_aux_exorginfo(
	EXT_PUSH *pext, const AUX_EXORGINFO *r)
{
	return pext->p_uint32(r->org_flags);
}

static int aux_ext_pull_aux_perf_accountinfo(
	EXT_PULL *pext, AUX_PERF_ACCOUNTINFO *r)
{
	TRY(pext->g_uint16(&r->client_id));
	TRY(pext->g_uint16(&r->reserved));
	return pext->g_guid(&r->account);
}

static int aux_ext_push_aux_perf_accountinfo(
	EXT_PUSH *pext, const AUX_PERF_ACCOUNTINFO *r)
{
	TRY(pext->p_uint16(r->client_id));
	TRY(pext->p_uint16(r->reserved));
	return pext->p_guid(r->account);
}

static int aux_ext_pull_aux_endpoint_capabilities(
	EXT_PULL *pext, AUX_ENDPOINT_CAPABILITIES *r)
{
	return pext->g_uint32(&r->endpoint_capability_flag);
}

static int aux_ext_push_aux_endpoint_capabilities(
	EXT_PUSH *pext, const AUX_ENDPOINT_CAPABILITIES *r)
{
	return pext->p_uint32(r->endpoint_capability_flag);
}

static int aux_ext_pull_aux_client_connection_info(
	EXT_PULL *pext, AUX_CLIENT_CONNECTION_INFO *r)
{
	auto &ext = *pext;
	uint16_t offset_connection_context_info;
	uint32_t payload_offset = ext.m_offset;

	TRY(pext->g_guid(&r->connection_guid));
	TRY(pext->g_uint16(&offset_connection_context_info));
	TRY(pext->g_uint16(&r->reserved));
	TRY(pext->g_uint32(&r->connection_attempts));
	TRY(pext->g_uint32(&r->connection_flags));
	if (0 != offset_connection_context_info) {
		ext.m_offset = payload_offset + offset_connection_context_info - 4;
		TRY(pext->g_str(&r->connection_context_info));
	} else {
		r->connection_context_info = NULL;
	}
	return EXT_ERR_SUCCESS;
}

static int aux_ext_push_aux_client_connection_info(
	EXT_PUSH *pext, AUX_CLIENT_CONNECTION_INFO *r)
{
	TRY(pext->p_guid(r->connection_guid));
	uint16_t offset_connection_context_info = r->connection_context_info != nullptr ? 0 : 32;
	TRY(pext->p_uint16(offset_connection_context_info));
	TRY(pext->p_uint16(r->reserved));
	TRY(pext->p_uint32(r->connection_attempts));
	TRY(pext->p_uint32(r->connection_flags));
	if (r->connection_context_info != nullptr)
		TRY(pext->p_str(r->connection_context_info));
	return EXT_ERR_SUCCESS;
}

static int aux_ext_pull_aux_server_session_info(
	EXT_PULL *pext, AUX_SERVER_SESSION_INFO *r)
{
	auto &ext = *pext;
	uint16_t offset_server_session_context_info;
	uint32_t payload_offset = ext.m_offset;

	TRY(pext->g_uint16(&offset_server_session_context_info));
	if (0 != offset_server_session_context_info) {
		ext.m_offset = payload_offset + offset_server_session_context_info - 4;
		TRY(pext->g_str(&r->server_session_context_info));
	} else {
		r->server_session_context_info = NULL;
	}
	return EXT_ERR_SUCCESS;
}

static int aux_ext_push_aux_server_session_info(
	EXT_PUSH *pext, AUX_SERVER_SESSION_INFO *r)
{
	uint16_t offset_server_session_context_info = r->server_session_context_info == nullptr ? 0 : 6;
	TRY(pext->p_uint16(offset_server_session_context_info));
	if (r->server_session_context_info != nullptr)
		TRY(pext->p_str(r->server_session_context_info));
	return EXT_ERR_SUCCESS;
}

static int aux_ext_pull_aux_protocol_device_identification(
	EXT_PULL *pext, AUX_PROTOCOL_DEVICE_IDENTIFICATION *r)
{
	auto &ext = *pext;
	uint16_t device_manufacturer_offset;
	uint16_t device_model_offset;
	uint16_t device_serial_number_offset;
	uint16_t device_version_offset;
	uint16_t device_firmware_version_offset;
	uint32_t payload_offset = ext.m_offset;

	TRY(pext->g_uint16(&device_manufacturer_offset));
	TRY(pext->g_uint16(&device_model_offset));
	TRY(pext->g_uint16(&device_serial_number_offset));
	TRY(pext->g_uint16(&device_version_offset));
	TRY(pext->g_uint16(&device_firmware_version_offset));
	if (0 != device_manufacturer_offset) {
		ext.m_offset = payload_offset + device_manufacturer_offset - 4;
		TRY(pext->g_str(&r->device_manufacturer));
	} else {
		r->device_manufacturer = NULL;
	}
	if (0 != device_model_offset) {
		ext.m_offset = payload_offset + device_model_offset - 4;
		TRY(pext->g_str(&r->device_model));
	} else {
		r->device_model = NULL;
	}
	if (0 != device_serial_number_offset) {
		ext.m_offset = payload_offset + device_serial_number_offset - 4;
		TRY(pext->g_str(&r->device_serial_number));
	} else {
		r->device_serial_number = NULL;
	}
	if (0 != device_version_offset) {
		ext.m_offset = payload_offset + device_version_offset - 4;
		TRY(pext->g_str(&r->device_version));
	} else {
		r->device_version = NULL;
	}
	if (0 != device_firmware_version_offset) {
		ext.m_offset = payload_offset + device_firmware_version_offset - 4;
		TRY(pext->g_str(&r->device_firmware_version));
	} else {
		r->device_firmware_version = NULL;
	}
	return EXT_ERR_SUCCESS;
}

static int aux_ext_push_aux_protocol_device_identification(
	EXT_PUSH *pext, AUX_PROTOCOL_DEVICE_IDENTIFICATION *r)
{
	uint16_t device_manufacturer_offset;
	uint16_t device_manufacturer_size;
	uint16_t device_model_offset;
	uint16_t device_model_size;
	uint16_t device_serial_number_offset;
	uint16_t device_serial_number_size;
	uint16_t device_version_offset;
	uint16_t device_version_size;
	uint16_t device_firmware_version_offset;
	
	if (NULL != r->device_manufacturer) {
		device_manufacturer_offset = 14;
		device_manufacturer_size = strlen(r->device_manufacturer) + 1;
	} else {
		device_manufacturer_offset = 0;
		device_manufacturer_size = 0;
	}
	TRY(pext->p_uint16(device_manufacturer_offset));
	if (NULL != r->device_model) {
		device_model_offset = 14 + device_manufacturer_size;
		device_model_size = strlen(r->device_model) + 1;
	} else {
		device_model_offset = 0;
		device_model_size = 0;
	}						
	TRY(pext->p_uint16(device_model_offset));
	if (NULL != r->device_serial_number) {
		device_serial_number_offset = 14 + device_manufacturer_size +
										device_model_size;
		device_serial_number_size = strlen(r->device_serial_number) + 1;
	} else {
		device_serial_number_offset = 0;
		device_serial_number_size = 0;
	}
	TRY(pext->p_uint16(device_serial_number_offset));
	if (NULL != r->device_version) {
		device_version_offset = 14 + device_manufacturer_size +
								device_model_size + device_serial_number_size;
		device_version_size = strlen(r->device_version) + 1;
	} else {
		device_version_offset = 0;
		device_version_size = 0;
	}	
	TRY(pext->p_uint16(device_version_offset));
	if (NULL != r->device_firmware_version) {
		device_firmware_version_offset = 14 + device_manufacturer_size +
							device_model_size + device_serial_number_size +
							device_version_size;
	} else {
		device_firmware_version_offset = 0;
	}
	TRY(pext->p_uint16(device_firmware_version_offset));
	if (r->device_manufacturer != nullptr)
		TRY(pext->p_str(r->device_manufacturer));
	if (r->device_model != nullptr)
		TRY(pext->p_str(r->device_model));
	if (r->device_serial_number != nullptr)
		TRY(pext->p_str(r->device_serial_number));
	if (r->device_version != nullptr)
		TRY(pext->p_str(r->device_version));
	if (r->device_firmware_version != nullptr)
		TRY(pext->p_str(r->device_firmware_version));
	return EXT_ERR_SUCCESS;
}

static int aux_ext_pull_aux_header_type_union1(
	EXT_PULL *pext, uint8_t type, void **pppayload)
{
	switch (type) {
	case AUX_TYPE_PERF_REQUESTID:
		(*pppayload) = pext->anew<AUX_PERF_REQUESTID>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_requestid(pext, static_cast<AUX_PERF_REQUESTID *>(*pppayload));
	case AUX_TYPE_PERF_CLIENTINFO:
		(*pppayload) = pext->anew<AUX_PERF_CLIENTINFO>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_clientinfo(pext, static_cast<AUX_PERF_CLIENTINFO *>(*pppayload));
	case AUX_TYPE_PERF_SERVERINFO:
		(*pppayload) = pext->anew<AUX_PERF_SERVERINFO>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_serverinfo(pext, static_cast<AUX_PERF_SERVERINFO *>(*pppayload));
	case AUX_TYPE_PERF_SESSIONINFO:
		(*pppayload) = pext->anew<AUX_PERF_SESSIONINFO>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_sessioninfo(pext, static_cast<AUX_PERF_SESSIONINFO *>(*pppayload));
	case AUX_TYPE_PERF_DEFMDB_SUCCESS:
	case AUX_TYPE_PERF_BG_DEFMDB_SUCCESS:
	case AUX_TYPE_PERF_FG_DEFMDB_SUCCESS:
		(*pppayload) = pext->anew<AUX_PERF_DEFMDB_SUCCESS>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_defmdb_success(pext, static_cast<AUX_PERF_DEFMDB_SUCCESS *>(*pppayload));
	case AUX_TYPE_PERF_DEFGC_SUCCESS:
	case AUX_TYPE_PERF_BG_DEFGC_SUCCESS:
	case AUX_TYPE_PERF_FG_DEFGC_SUCCESS:
		(*pppayload) = pext->anew<AUX_PERF_DEFGC_SUCCESS>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_defgc_success(pext, static_cast<AUX_PERF_DEFGC_SUCCESS *>(*pppayload));
	case AUX_TYPE_PERF_MDB_SUCCESS:
	case AUX_TYPE_PERF_BG_MDB_SUCCESS:
	case AUX_TYPE_PERF_FG_MDB_SUCCESS:
		(*pppayload) = pext->anew<AUX_PERF_MDB_SUCCESS>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_mdb_success(pext, static_cast<AUX_PERF_MDB_SUCCESS *>(*pppayload));
	case AUX_TYPE_PERF_GC_SUCCESS:
	case AUX_TYPE_PERF_BG_GC_SUCCESS:
	case AUX_TYPE_PERF_FG_GC_SUCCESS:
		(*pppayload) = pext->anew<AUX_PERF_GC_SUCCESS>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_gc_success(pext, static_cast<AUX_PERF_GC_SUCCESS *>(*pppayload));
	case AUX_TYPE_PERF_FAILURE:
	case AUX_TYPE_PERF_BG_FAILURE:
	case AUX_TYPE_PERF_FG_FAILURE:
		(*pppayload) = pext->anew<AUX_PERF_FAILURE>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_failure(pext, static_cast<AUX_PERF_FAILURE *>(*pppayload));
	case AUX_TYPE_CLIENT_CONTROL:
		(*pppayload) = pext->anew<AUX_CLIENT_CONTROL>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_client_control(pext, static_cast<AUX_CLIENT_CONTROL *>(*pppayload));
	case AUX_TYPE_PERF_PROCESSINFO:
		(*pppayload) = pext->anew<AUX_PERF_PROCESSINFO>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_processinfo(pext, static_cast<AUX_PERF_PROCESSINFO *>(*pppayload));
	case AUX_TYPE_OSVERSIONINFO:
		(*pppayload) = pext->anew<AUX_OSVERSIONINFO>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_osversioninfo(pext, static_cast<AUX_OSVERSIONINFO *>(*pppayload));
	case AUX_TYPE_EXORGINFO:
		(*pppayload) = pext->anew<AUX_EXORGINFO>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_exorginfo(pext, static_cast<AUX_EXORGINFO *>(*pppayload));
	case AUX_TYPE_PERF_ACCOUNTINFO:
		(*pppayload) = pext->anew<AUX_PERF_ACCOUNTINFO>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_accountinfo(pext, static_cast<AUX_PERF_ACCOUNTINFO *>(*pppayload));
	case AUX_TYPE_ENDPOINT_CAPABILITIES:
		(*pppayload) = pext->anew<AUX_ENDPOINT_CAPABILITIES>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_endpoint_capabilities(pext, static_cast<AUX_ENDPOINT_CAPABILITIES *>(*pppayload));
	case AUX_TYPE_CLIENT_CONNECTION_INFO:
		(*pppayload) = pext->anew<AUX_CLIENT_CONNECTION_INFO>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_client_connection_info(pext, static_cast<AUX_CLIENT_CONNECTION_INFO *>(*pppayload));
	case AUX_TYPE_SERVER_SESSION_INFO:
		(*pppayload) = pext->anew<AUX_SERVER_SESSION_INFO>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_server_session_info(pext, static_cast<AUX_SERVER_SESSION_INFO *>(*pppayload));
	case AUX_TYPE_PROTOCOL_DEVICE_ID:
		(*pppayload) = pext->anew<AUX_PROTOCOL_DEVICE_IDENTIFICATION>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_protocol_device_identification(pext, static_cast<AUX_PROTOCOL_DEVICE_IDENTIFICATION *>(*pppayload));
	}
	(*pppayload) = pext->anew<DATA_BLOB>();
	if ((*pppayload) == nullptr)
		return EXT_ERR_ALLOC;
	return pext->g_blob(static_cast<DATA_BLOB *>(*pppayload));
}

static int aux_ext_push_aux_header_type_union1(
	EXT_PUSH *pext, uint8_t type, void *ppayload)
{
	switch (type) {
	case AUX_TYPE_PERF_REQUESTID:
		return aux_ext_push_aux_perf_requestid(pext, static_cast<AUX_PERF_REQUESTID *>(ppayload));
	case AUX_TYPE_PERF_CLIENTINFO:
		return aux_ext_push_aux_perf_clientinfo(pext, static_cast<AUX_PERF_CLIENTINFO *>(ppayload));
	case AUX_TYPE_PERF_SERVERINFO:
		return aux_ext_push_aux_perf_serverinfo(pext, static_cast<AUX_PERF_SERVERINFO *>(ppayload));
	case AUX_TYPE_PERF_SESSIONINFO:
		return aux_ext_push_aux_perf_sessioninfo(pext, static_cast<AUX_PERF_SESSIONINFO *>(ppayload));
	case AUX_TYPE_PERF_DEFMDB_SUCCESS:
	case AUX_TYPE_PERF_BG_DEFMDB_SUCCESS:
	case AUX_TYPE_PERF_FG_DEFMDB_SUCCESS:
		return aux_ext_push_aux_perf_defmdb_success(pext, static_cast<AUX_PERF_DEFMDB_SUCCESS *>(ppayload));
	case AUX_TYPE_PERF_DEFGC_SUCCESS:
	case AUX_TYPE_PERF_BG_DEFGC_SUCCESS:
	case AUX_TYPE_PERF_FG_DEFGC_SUCCESS:
		return aux_ext_push_aux_perf_defgc_success(pext, static_cast<AUX_PERF_DEFGC_SUCCESS *>(ppayload));
	case AUX_TYPE_PERF_MDB_SUCCESS:
	case AUX_TYPE_PERF_BG_MDB_SUCCESS:
	case AUX_TYPE_PERF_FG_MDB_SUCCESS:
		return aux_ext_push_aux_perf_mdb_success(pext, static_cast<AUX_PERF_MDB_SUCCESS *>(ppayload));
	case AUX_TYPE_PERF_GC_SUCCESS:
	case AUX_TYPE_PERF_BG_GC_SUCCESS:
	case AUX_TYPE_PERF_FG_GC_SUCCESS:
		return aux_ext_push_aux_perf_gc_success(pext, static_cast<AUX_PERF_GC_SUCCESS *>(ppayload));
	case AUX_TYPE_PERF_FAILURE:
	case AUX_TYPE_PERF_BG_FAILURE:
	case AUX_TYPE_PERF_FG_FAILURE:
		return aux_ext_push_aux_perf_failure(pext, static_cast<AUX_PERF_FAILURE *>(ppayload));
	case AUX_TYPE_CLIENT_CONTROL:
		return aux_ext_push_aux_client_control(pext, static_cast<AUX_CLIENT_CONTROL *>(ppayload));
	case AUX_TYPE_PERF_PROCESSINFO:
		return aux_ext_push_aux_perf_processinfo(pext, static_cast<AUX_PERF_PROCESSINFO *>(ppayload));
	case AUX_TYPE_OSVERSIONINFO:
		return aux_ext_push_aux_osversioninfo(pext, static_cast<AUX_OSVERSIONINFO *>(ppayload));
	case AUX_TYPE_EXORGINFO:
		return aux_ext_push_aux_exorginfo(pext, static_cast<AUX_EXORGINFO *>(ppayload));
	case AUX_TYPE_PERF_ACCOUNTINFO:
		return aux_ext_push_aux_perf_accountinfo(pext, static_cast<AUX_PERF_ACCOUNTINFO *>(ppayload));
	case AUX_TYPE_ENDPOINT_CAPABILITIES:
		return aux_ext_push_aux_endpoint_capabilities(pext, static_cast<AUX_ENDPOINT_CAPABILITIES *>(ppayload));
	case AUX_TYPE_CLIENT_CONNECTION_INFO:
		return aux_ext_push_aux_client_connection_info(pext, static_cast<AUX_CLIENT_CONNECTION_INFO *>(ppayload));
	case AUX_TYPE_SERVER_SESSION_INFO:
		return aux_ext_push_aux_server_session_info(pext, static_cast<AUX_SERVER_SESSION_INFO *>(ppayload));
	case AUX_TYPE_PROTOCOL_DEVICE_ID:
		return aux_ext_push_aux_protocol_device_identification(pext, static_cast<AUX_PROTOCOL_DEVICE_IDENTIFICATION *>(ppayload));
	}
	return pext->p_blob(*static_cast<DATA_BLOB *>(ppayload));
}

static int aux_ext_pull_aux_header_type_union2(
	EXT_PULL *pext, uint8_t type, void **pppayload)
{	
	switch (type) {
	case AUX_TYPE_PERF_SESSIONINFO:
		(*pppayload) = pext->anew<AUX_PERF_SESSIONINFO_V2>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_sessioninfo_v2(pext, static_cast<AUX_PERF_SESSIONINFO_V2 *>(*pppayload));
	case AUX_TYPE_PERF_MDB_SUCCESS:
	case AUX_TYPE_PERF_BG_MDB_SUCCESS:
	case AUX_TYPE_PERF_FG_MDB_SUCCESS:
		(*pppayload) = pext->anew<AUX_PERF_MDB_SUCCESS_V2>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_mdb_success_v2(pext, static_cast<AUX_PERF_MDB_SUCCESS_V2 *>(*pppayload));
	case AUX_TYPE_PERF_GC_SUCCESS:
	case AUX_TYPE_PERF_BG_GC_SUCCESS:
	case AUX_TYPE_PERF_FG_GC_SUCCESS:
		(*pppayload) = pext->anew<AUX_PERF_GC_SUCCESS_V2>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_gc_success_v2(pext, static_cast<AUX_PERF_GC_SUCCESS_V2 *>(*pppayload));
	case AUX_TYPE_PERF_FAILURE:
	case AUX_TYPE_PERF_BG_FAILURE:
	case AUX_TYPE_PERF_FG_FAILURE:
		(*pppayload) = pext->anew<AUX_PERF_FAILURE_V2>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_failure_v2(pext, static_cast<AUX_PERF_FAILURE_V2 *>(*pppayload));
	case AUX_TYPE_PERF_PROCESSINFO:
		(*pppayload) = pext->anew<AUX_PERF_PROCESSINFO>();
		if ((*pppayload) == nullptr)
			return EXT_ERR_ALLOC;
		return aux_ext_pull_aux_perf_processinfo(pext, static_cast<AUX_PERF_PROCESSINFO *>(*pppayload));
	}
	(*pppayload) = pext->anew<DATA_BLOB>();
	if ((*pppayload) == nullptr)
		return EXT_ERR_ALLOC;
	return pext->g_blob(static_cast<DATA_BLOB *>(*pppayload));
}

static int aux_ext_push_aux_header_type_union2(
	EXT_PUSH *pext, uint8_t type, void *ppayload)
{
	switch (type) {
	case AUX_TYPE_PERF_SESSIONINFO:
		return aux_ext_push_aux_perf_sessioninfo_v2(pext, static_cast<AUX_PERF_SESSIONINFO_V2 *>(ppayload));
	case AUX_TYPE_PERF_MDB_SUCCESS:
	case AUX_TYPE_PERF_BG_MDB_SUCCESS:
	case AUX_TYPE_PERF_FG_MDB_SUCCESS:
		return aux_ext_push_aux_perf_mdb_success_v2(pext, static_cast<AUX_PERF_MDB_SUCCESS_V2 *>(ppayload));
	case AUX_TYPE_PERF_GC_SUCCESS:
	case AUX_TYPE_PERF_FG_GC_SUCCESS:
	case AUX_TYPE_PERF_BG_GC_SUCCESS:
		return aux_ext_push_aux_perf_gc_success_v2(pext, static_cast<AUX_PERF_GC_SUCCESS_V2 *>(ppayload));
	case AUX_TYPE_PERF_FAILURE:
	case AUX_TYPE_PERF_BG_FAILURE:
	case AUX_TYPE_PERF_FG_FAILURE:
		return aux_ext_push_aux_perf_failure_v2(pext, static_cast<AUX_PERF_FAILURE_V2 *>(ppayload));
	case AUX_TYPE_PERF_PROCESSINFO:
		return aux_ext_push_aux_perf_processinfo(pext, static_cast<AUX_PERF_PROCESSINFO *>(ppayload));
	}
	return pext->p_blob(*static_cast<DATA_BLOB *>(ppayload));
}

static int aux_ext_pull_aux_header(EXT_PULL *pext, AUX_HEADER *r)
{
	auto &ext = *pext;
	uint16_t size;
	uint32_t offset = ext.m_offset;

	TRY(pext->g_uint16(&size));
	offset += size;
	TRY(pext->g_uint8(&r->version));
	TRY(pext->g_uint8(&r->type));
	switch (r->version) {
	case AUX_VERSION_1:
		TRY(aux_ext_pull_aux_header_type_union1(pext, r->type, &r->ppayload));
		break;
	case AUX_VERSION_2:
		TRY(aux_ext_pull_aux_header_type_union2(pext, r->type, &r->ppayload));
		break;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
	if (ext.m_offset > offset)
		return EXT_ERR_FORMAT;
	ext.m_offset = offset;
	return EXT_ERR_SUCCESS;
}


static int aux_ext_push_aux_header(EXT_PUSH *pext, AUX_HEADER *r)
{
	uint16_t size;
	EXT_PUSH subext;
	uint8_t tmp_buff[0x1008];
	uint8_t paddings[AUX_ALIGN_SIZE]{};
	
	if (!subext.init(tmp_buff, sizeof(tmp_buff), EXT_FLAG_UTF16))
		return EXT_ERR_ALLOC;
	switch (r->version) {
	case AUX_VERSION_1:
		TRY(aux_ext_push_aux_header_type_union1(&subext, r->type, r->ppayload));
		break;
	case AUX_VERSION_2:
		TRY(aux_ext_push_aux_header_type_union2(&subext, r->type, r->ppayload));
		break;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
	uint16_t actual_size = subext.m_offset + sizeof(uint16_t) + 2 * sizeof(uint8_t);
	size = (actual_size + (AUX_ALIGN_SIZE - 1)) & ~(AUX_ALIGN_SIZE - 1);
	TRY(pext->p_uint16(size));
	TRY(pext->p_uint8(r->version));
	TRY(pext->p_uint8(r->type));
	TRY(pext->p_bytes(subext.m_udata, subext.m_offset));
	return pext->p_bytes(paddings, size - actual_size);
}

int aux_ext_pull_aux_info(EXT_PULL *pext, AUX_INFO *r)
{
	auto &ext = *pext;
	EXT_PULL subext;
	uint8_t buff[0x1008];
	DOUBLE_LIST_NODE *pnode;
	uint32_t decompressed_len;
	RPC_HEADER_EXT rpc_header_ext;
	
	TRY(pext->g_rpc_header_ext(&rpc_header_ext));
	if (!(rpc_header_ext.flags & RHE_FLAG_LAST))
		return EXT_ERR_HEADER_FLAGS;
	r->rhe_version = rpc_header_ext.version;
	r->rhe_flags = rpc_header_ext.flags;
	double_list_init(&r->aux_list);
	if (0 != rpc_header_ext.size) {
		auto pdata = ext.m_udata + ext.m_offset;
		/* obfuscation case */
		if (rpc_header_ext.flags & RHE_FLAG_XORMAGIC)
			common_util_obfuscate_data(deconst(pdata), rpc_header_ext.size_actual);
		/* lzxpress case */
		if (rpc_header_ext.flags & RHE_FLAG_COMPRESSED) {
			decompressed_len = lzxpress_decompress(pdata,
				rpc_header_ext.size, buff, sizeof(buff));
			if (decompressed_len != rpc_header_ext.size_actual) {
				fprintf(stderr, "W-1098: lzxdecompress failed for client input (z=%u, exp=%u, got=%u)\n",
				        rpc_header_ext.size, rpc_header_ext.size_actual,
				        decompressed_len);
				return EXT_ERR_LZXPRESS;
			}
			pdata = buff;
		}
		subext.init(pdata, rpc_header_ext.size_actual, common_util_alloc, EXT_FLAG_UTF16);
		while (subext.m_offset < subext.m_data_size) {
			pnode = pext->anew<DOUBLE_LIST_NODE>();
			if (pnode == nullptr)
				return EXT_ERR_ALLOC;
			pnode->pdata = pext->anew<AUX_HEADER>();
			if (pnode->pdata == nullptr)
				return EXT_ERR_ALLOC;
			TRY(aux_ext_pull_aux_header(&subext, static_cast<AUX_HEADER *>(pnode->pdata)));
			double_list_append_as_tail(&r->aux_list, pnode);
		}
	}
	return EXT_ERR_SUCCESS;
}

int aux_ext_push_aux_info(EXT_PUSH *pext, AUX_INFO *r)
{
	EXT_PUSH subext;
	DOUBLE_LIST_NODE *pnode;
	uint8_t ext_buff[0x1008];
	uint8_t tmp_buff[0x1008];
	RPC_HEADER_EXT rpc_header_ext;


	if ((r->rhe_flags & RHE_FLAG_LAST) == 0)
		return EXT_ERR_HEADER_FLAGS;
	if (!subext.init(ext_buff, sizeof(ext_buff), EXT_FLAG_UTF16))
		return EXT_ERR_ALLOC;
	for (pnode=double_list_get_head(&r->aux_list); NULL!=pnode;
	     pnode = double_list_get_after(&r->aux_list, pnode))
		TRY(aux_ext_push_aux_header(&subext, static_cast<AUX_HEADER *>(pnode->pdata)));
	rpc_header_ext.version = r->rhe_version;
	rpc_header_ext.flags = r->rhe_flags;
	rpc_header_ext.size_actual = subext.m_offset;
	rpc_header_ext.size = rpc_header_ext.size_actual;
	if (rpc_header_ext.flags & RHE_FLAG_COMPRESSED) {
		if (rpc_header_ext.size_actual < MINIMUM_COMPRESS_SIZE) {
			rpc_header_ext.flags &= ~RHE_FLAG_COMPRESSED;
		} else {
			uint32_t compressed_len = lzxpress_compress(ext_buff, subext.m_offset, tmp_buff);
			if (compressed_len == 0 || compressed_len >= subext.m_offset) {
				/* if we can not get benefit from the
					compression, unmask the compress bit */
				rpc_header_ext.flags &= ~RHE_FLAG_COMPRESSED;
			} else {
				rpc_header_ext.size = compressed_len;
				memcpy(ext_buff, tmp_buff, compressed_len);
			}
		}
	}
	if (rpc_header_ext.flags & RHE_FLAG_XORMAGIC)
		rpc_header_ext.flags &= ~RHE_FLAG_XORMAGIC;
	TRY(pext->p_rpchdr(rpc_header_ext));
	return pext->p_bytes(ext_buff, rpc_header_ext.size);
}
