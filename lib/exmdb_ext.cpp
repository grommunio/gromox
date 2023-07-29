// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <poll.h>
#include <type_traits>
#include <unistd.h>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)

using namespace gromox;

void *(*exmdb_rpc_alloc)(size_t) = malloc;
void (*exmdb_rpc_free)(void *) = free;
template<typename T> T *cu_alloc()
{
	static_assert(std::is_trivially_destructible_v<T>);
	return static_cast<T *>(exmdb_rpc_alloc(sizeof(T)));
}
template<typename T> T *cu_alloc(size_t elem)
{
	static_assert(std::is_trivially_destructible_v<T>);
	return static_cast<T *>(exmdb_rpc_alloc(sizeof(T) * elem));
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_connect &d)
{
	TRY(x.g_str(&d.prefix));
	TRY(x.g_str(&d.remote_id));
	return x.g_bool(&d.b_private);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_connect &d)
{
	TRY(x.p_str(d.prefix));
	TRY(x.p_str(d.remote_id));
	return x.p_bool(d.b_private);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_listen_notification &d)
{
	return x.g_str(&d.remote_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_listen_notification &d)
{
	return x.p_str(d.remote_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_named_propids &d)
{
	TRY(x.g_bool(&d.b_create));
	d.ppropnames = cu_alloc<PROPNAME_ARRAY>();
	if (d.ppropnames == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_propname_a(d.ppropnames);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_named_propids &d)
{
	TRY(x.p_bool(d.b_create));
	return x.p_propname_a(*d.ppropnames);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_named_propnames &d)
{
	d.ppropids = cu_alloc<PROPID_ARRAY>();
	if (d.ppropids == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_propid_a(d.ppropids);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_named_propnames &d)
{
	return x.p_propid_a(*d.ppropids);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_mapping_guid &d)
{
	return x.g_uint16(&d.replid);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_mapping_guid &d)
{
	return x.p_uint16(d.replid);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_mapping_replid &d)
{
	return x.g_guid(&d.guid);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_mapping_replid &d)
{
	return x.p_guid(d.guid);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_store_properties &d)
{
	TRY(x.g_nlscp(&d.cpid));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_store_properties &d)
{
	TRY(x.p_uint32(d.cpid));
	return x.p_proptag_a(*d.pproptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_set_store_properties &d)
{
	TRY(x.g_nlscp(&d.cpid));
	d.ppropvals = cu_alloc<TPROPVAL_ARRAY>();
	if (d.ppropvals == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_tpropval_a(d.ppropvals);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_set_store_properties &d)
{
	TRY(x.p_uint32(d.cpid));
	return x.p_tpropval_a(*d.ppropvals);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_remove_store_properties &d)
{
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_remove_store_properties &d)
{
	return x.p_proptag_a(*d.pproptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_mbox_perm &d)
{
	return x.g_str(&d.username);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_mbox_perm &d)
{
	return x.p_str(d.username);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_folder_by_class &d)
{
	return x.g_str(&d.str_class);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_folder_by_class &d)
{
	return x.p_str(d.str_class);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_set_folder_by_class &d)
{
	TRY(x.g_uint64(&d.folder_id));
	return x.g_str(&d.str_class);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_set_folder_by_class &d)
{
	TRY(x.p_uint64(d.folder_id));
	return x.p_str(d.str_class);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_check_folder_id &d)
{
	return x.g_uint64(&d.folder_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_check_folder_id &d)
{
	return x.p_uint64(d.folder_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_check_folder_deleted &d)
{
	return x.g_uint64(&d.folder_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_check_folder_deleted &d)
{
	return x.p_uint64(d.folder_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_folder_by_name &d)
{
	TRY(x.g_uint64(&d.parent_id));
	return x.g_str(&d.str_name);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_folder_by_name &d)
{
	TRY(x.p_uint64(d.parent_id));
	return x.p_str(d.str_name);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_folder_perm &d)
{
	TRY(x.g_uint64(&d.folder_id));
	return x.g_str(&d.username);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_folder_perm &d)
{
	TRY(x.p_uint64(d.folder_id));
	return x.p_str(d.username);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_create_folder_by_properties &d)
{
	TRY(x.g_nlscp(&d.cpid));
	d.pproperties = cu_alloc<TPROPVAL_ARRAY>();
	if (d.pproperties == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_tpropval_a(d.pproperties);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_create_folder_by_properties &d)
{
	TRY(x.p_uint32(d.cpid));
	return x.p_tpropval_a(*d.pproperties);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_folder_all_proptags &d)
{
	return x.g_uint64(&d.folder_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_folder_all_proptags &d)
{
	return x.p_uint64(d.folder_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_folder_properties &d)
{
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_folder_properties &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	return x.p_proptag_a(*d.pproptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_set_folder_properties &d)
{
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	d.pproperties = cu_alloc<TPROPVAL_ARRAY>();
	if (d.pproperties == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_tpropval_a(d.pproperties);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_set_folder_properties &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	return x.p_tpropval_a(*d.pproperties);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_remove_folder_properties &d)
{
	TRY(x.g_uint64(&d.folder_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_remove_folder_properties &d)
{
	TRY(x.p_uint64(d.folder_id));
	return x.p_proptag_a(*d.pproptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_delete_folder &d)
{
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	return x.g_bool(&d.b_hard);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_delete_folder &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	return x.p_bool(d.b_hard);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_empty_folder &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == '\0')
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint32(&d.flags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_empty_folder &d)
{
	TRY(x.p_uint32(d.cpid));
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint32(d.flags);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_purge_softdelete &d)
{
	uint8_t b;
	TRY(x.g_uint8(&b));
	if (b == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint32(&d.del_flags));
	return x.g_uint64(&d.cutoff);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_purge_softdelete &d)
{
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_uint32(d.del_flags));
	return x.p_uint64(d.cutoff);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_check_folder_cycle &d)
{
	TRY(x.g_uint64(&d.src_fid));
	return x.g_uint64(&d.dst_fid);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_check_folder_cycle &d)
{
	TRY(x.p_uint64(d.src_fid));
	return x.p_uint64(d.dst_fid);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_copy_folder_internal &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.account_id));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_bool(&d.b_guest));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint64(&d.src_fid));
	TRY(x.g_bool(&d.b_normal));
	TRY(x.g_bool(&d.b_fai));
	TRY(x.g_bool(&d.b_sub));
	return x.g_uint64(&d.dst_fid);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_copy_folder_internal &d)
{
	TRY(x.p_uint32(d.account_id));
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_bool(d.b_guest));
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint64(d.src_fid));
	TRY(x.p_bool(d.b_normal));
	TRY(x.p_bool(d.b_fai));
	TRY(x.p_bool(d.b_sub));
	return x.p_uint64(d.dst_fid);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_search_criteria &d)
{
	return x.g_uint64(&d.folder_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_search_criteria &d)
{
	return x.p_uint64(d.folder_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_set_search_criteria &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint32(&d.search_flags));
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.prestriction = nullptr;
	} else {
		d.prestriction = cu_alloc<RESTRICTION>();
		if (d.prestriction == nullptr)
			return EXT_ERR_ALLOC;
		TRY(x.g_restriction(d.prestriction));
	}
	d.pfolder_ids = cu_alloc<LONGLONG_ARRAY>();
	if (d.pfolder_ids == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_uint64_a(d.pfolder_ids);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_set_search_criteria &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_uint32(d.search_flags));
	if (d.prestriction == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_restriction(*d.prestriction));
	}
	return x.p_uint64_a(*d.pfolder_ids);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_movecopy_message &d)
{
	TRY(x.g_uint32(&d.account_id));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint64(&d.message_id));
	TRY(x.g_uint64(&d.dst_fid));
	TRY(x.g_uint64(&d.dst_id));
	return x.g_bool(&d.b_move);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_movecopy_message &d)
{
	TRY(x.p_uint32(d.account_id));
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.message_id));
	TRY(x.p_uint64(d.dst_fid));
	TRY(x.p_uint64(d.dst_id));
	return x.p_bool(d.b_move);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_movecopy_messages &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.account_id));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_bool(&d.b_guest));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint64(&d.src_fid));
	TRY(x.g_uint64(&d.dst_fid));
	TRY(x.g_bool(&d.b_copy));
	d.pmessage_ids = cu_alloc<EID_ARRAY>();
	if (d.pmessage_ids == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_eid_a(d.pmessage_ids);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_movecopy_messages &d)
{
	TRY(x.p_uint32(d.account_id));
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_bool(d.b_guest));
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint64(d.src_fid));
	TRY(x.p_uint64(d.dst_fid));
	TRY(x.p_bool(d.b_copy));
	return x.p_eid_a(*d.pmessage_ids);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_movecopy_folder &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.account_id));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_bool(&d.b_guest));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint64(&d.src_pid));
	TRY(x.g_uint64(&d.src_fid));
	TRY(x.g_uint64(&d.dst_fid));
	TRY(x.g_str(&d.str_new));
	return x.g_bool(&d.b_copy);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_movecopy_folder &d)
{
	TRY(x.p_uint32(d.account_id));
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_bool(d.b_guest));
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint64(d.src_pid));
	TRY(x.p_uint64(d.src_fid));
	TRY(x.p_uint64(d.dst_fid));
	TRY(x.p_str(znul(d.str_new)));
	return x.p_bool(d.b_copy);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_delete_messages &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.account_id));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint64(&d.folder_id));
	d.pmessage_ids = cu_alloc<EID_ARRAY>();
	if (d.pmessage_ids == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_eid_a(d.pmessage_ids));
	return x.g_bool(&d.b_hard);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_delete_messages &d)
{
	TRY(x.p_uint32(d.account_id));
	TRY(x.p_uint32(d.cpid));
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_eid_a(*d.pmessage_ids));
	return x.p_bool(d.b_hard);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_message_brief &d)
{
	TRY(x.g_nlscp(&d.cpid));
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_message_brief &d)
{
	TRY(x.p_uint32(d.cpid));
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_sum_hierarchy &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	return x.g_bool(&d.b_depth);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_sum_hierarchy &d)
{
	TRY(x.p_uint64(d.folder_id));
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	return x.p_bool(d.b_depth);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_load_hierarchy_table &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint8(&d.table_flags));
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.prestriction = nullptr;
	} else {
		d.prestriction = cu_alloc<RESTRICTION>();
		if (d.prestriction == nullptr)
			return EXT_ERR_ALLOC;
		TRY(x.g_restriction(d.prestriction));
	}
	return EXT_ERR_SUCCESS;
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_load_hierarchy_table &d)
{
	TRY(x.p_uint64(d.folder_id));
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint8(d.table_flags));
	if (d.prestriction == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return x.p_restriction(*d.prestriction);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_sum_content &d)
{
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_bool(&d.b_fai));
	return x.g_bool(&d.b_deleted);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_sum_content &d)
{
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_bool(d.b_fai));
	return x.p_bool(d.b_deleted);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_load_content_table &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint8(&d.table_flags));
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.prestriction = nullptr;
	} else {
		d.prestriction = cu_alloc<RESTRICTION>();
		if (d.prestriction == nullptr)
			return EXT_ERR_ALLOC;
		TRY(x.g_restriction(d.prestriction));
	}
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.psorts = nullptr;
		return EXT_ERR_SUCCESS;
	}
	d.psorts = cu_alloc<SORTORDER_SET>();
	if (d.psorts == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_sortorder_set(d.psorts);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_load_content_table &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint8(d.table_flags));
	if (d.prestriction == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_restriction(*d.prestriction));
	}
	if (d.psorts == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return x.p_sortorder_set(*d.psorts);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_reload_content_table &d)
{
	return x.g_uint32(&d.table_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_reload_content_table &d)
{
	return x.p_uint32(d.table_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_load_perm_table_v1 &d)
{
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint8(&d.table_flags);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_load_permission_table &d)
{
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint32(&d.table_flags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_load_perm_table_v1 &d)
{
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint8(d.table_flags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_load_permission_table &d)
{
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint32(d.table_flags);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_load_rule_table &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint8(&d.table_flags));
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.prestriction = nullptr;
		return EXT_ERR_SUCCESS;
	}
	d.prestriction = cu_alloc<RESTRICTION>();
	if (d.prestriction == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_restriction(d.prestriction);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_load_rule_table &d)
{
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_uint8(d.table_flags));
	if (d.prestriction == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return x.p_restriction(*d.prestriction);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_unload_table &d)
{
	return x.g_uint32(&d.table_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_unload_table &d)
{
	return x.p_uint32(d.table_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_sum_table &d)
{
	return x.g_uint32(&d.table_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_sum_table &d)
{
	return x.p_uint32(d.table_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_query_table &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint32(&d.table_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_proptag_a(d.pproptags));
	TRY(x.g_uint32(&d.start_pos));
	return x.g_int32(&d.row_needed);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_query_table &d)
{
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint32(d.table_id));
	TRY(x.p_proptag_a(*d.pproptags));
	TRY(x.p_uint32(d.start_pos));
	return x.p_int32(d.row_needed);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_match_table &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint32(&d.table_id));
	TRY(x.g_bool(&d.b_forward));
	TRY(x.g_uint32(&d.start_pos));
	d.pres = cu_alloc<RESTRICTION>();
	if (d.pres == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_restriction(d.pres));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_match_table &d)
{
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint32(d.table_id));
	TRY(x.p_bool(d.b_forward));
	TRY(x.p_uint32(d.start_pos));
	TRY(x.p_restriction(*d.pres));
	return x.p_proptag_a(*d.pproptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_locate_table &d)
{
	TRY(x.g_uint32(&d.table_id));
	TRY(x.g_uint64(&d.inst_id));
	return x.g_uint32(&d.inst_num);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_locate_table &d)
{
	TRY(x.p_uint32(d.table_id));
	TRY(x.p_uint64(d.inst_id));
	return x.p_uint32(d.inst_num);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_read_table_row &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint32(&d.table_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_proptag_a(d.pproptags));
	TRY(x.g_uint64(&d.inst_id));
	return x.g_uint32(&d.inst_num);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_read_table_row &d)
{
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint32(d.table_id));
	TRY(x.p_proptag_a(*d.pproptags));
	TRY(x.p_uint64(d.inst_id));
	return x.p_uint32(d.inst_num);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_mark_table &d)
{
	TRY(x.g_uint32(&d.table_id));
	return x.g_uint32(&d.position);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_mark_table &d)
{
	TRY(x.p_uint32(d.table_id));
	return x.p_uint32(d.position);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_table_all_proptags &d)
{
	return x.g_uint32(&d.table_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_table_all_proptags &d)
{
	return x.p_uint32(d.table_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_expand_table &d)
{
	TRY(x.g_uint32(&d.table_id));
	return x.g_uint64(&d.inst_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_expand_table &d)
{
	TRY(x.p_uint32(d.table_id));
	return x.p_uint64(d.inst_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_collapse_table &d)
{
	TRY(x.g_uint32(&d.table_id));
	return x.g_uint64(&d.inst_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_collapse_table &d)
{
	TRY(x.p_uint32(d.table_id));
	return x.p_uint64(d.inst_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_store_table_state &d)
{
	TRY(x.g_uint32(&d.table_id));
	TRY(x.g_uint64(&d.inst_id));
	return x.g_uint32(&d.inst_num);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_store_table_state &d)
{
	TRY(x.p_uint32(d.table_id));
	TRY(x.p_uint64(d.inst_id));
	return x.p_uint32(d.inst_num);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_restore_table_state &d)
{
	TRY(x.g_uint32(&d.table_id));
	return x.g_uint32(&d.state_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_restore_table_state &d)
{
	TRY(x.p_uint32(d.table_id));
	return x.p_uint32(d.state_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_check_message &d)
{
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_check_message &d)
{
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_check_message_deleted &d)
{
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_check_message_deleted &d)
{
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_load_message_instance &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_bool(&d.b_new));
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_load_message_instance &d)
{
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_bool(d.b_new));
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_load_embedded_instance &d)
{
	TRY(x.g_bool(&d.b_new));
	return x.g_uint32(&d.attachment_instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_load_embedded_instance &d)
{
	TRY(x.p_bool(d.b_new));
	return x.p_uint32(d.attachment_instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_embedded_cn &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_embedded_cn &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_reload_message_instance &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_reload_message_instance &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_clear_message_instance &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_clear_message_instance &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_read_message_instance &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_read_message_instance &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_write_message_instance &d)
{
	TRY(x.g_uint32(&d.instance_id));
	d.pmsgctnt = cu_alloc<MESSAGE_CONTENT>();
	if (d.pmsgctnt == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_msgctnt(d.pmsgctnt));
	return x.g_bool(&d.b_force);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_write_message_instance &d)
{
	TRY(x.p_uint32(d.instance_id));
	TRY(x.p_msgctnt(*d.pmsgctnt));
	return x.p_bool(d.b_force);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_load_attachment_instance &d)
{
	TRY(x.g_uint32(&d.message_instance_id));
	return x.g_uint32(&d.attachment_num);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_load_attachment_instance &d)
{
	TRY(x.p_uint32(d.message_instance_id));
	return x.p_uint32(d.attachment_num);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_create_attachment_instance &d)
{
	return x.g_uint32(&d.message_instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_create_attachment_instance &d)
{
	return x.p_uint32(d.message_instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_read_attachment_instance &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_read_attachment_instance &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_write_attachment_instance &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.instance_id));
	d.pattctnt = cu_alloc<ATTACHMENT_CONTENT>();
	if (d.pattctnt == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_tpropval_a(&d.pattctnt->proplist));
	TRY(x.g_uint8(&tmp_byte));
	if (0 != tmp_byte) {
		d.pattctnt->pembedded = cu_alloc<MESSAGE_CONTENT>();
		if (d.pattctnt->pembedded == nullptr)
			return EXT_ERR_ALLOC;
		TRY(x.g_msgctnt(d.pattctnt->pembedded));
	} else {
		d.pattctnt->pembedded = nullptr;
	}
	return x.g_bool(&d.b_force);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_write_attachment_instance &d)
{
	TRY(x.p_uint32(d.instance_id));
	TRY(x.p_tpropval_a(d.pattctnt->proplist));
	if (d.pattctnt->pembedded == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_msgctnt(*d.pattctnt->pembedded));
	}
	return x.p_bool(d.b_force);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_delete_message_instance_attachment &d)
{
	TRY(x.g_uint32(&d.message_instance_id));
	return x.g_uint32(&d.attachment_num);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_delete_message_instance_attachment &d)
{
	TRY(x.p_uint32(d.message_instance_id));
	return x.p_uint32(d.attachment_num);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_flush_instance &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.instance_id));
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.account = nullptr;
		return EXT_ERR_SUCCESS;
	}
	return x.g_str(&d.account);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_flush_instance &d)
{
	TRY(x.p_uint32(d.instance_id));
	if (d.account == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return x.p_str(d.account);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_unload_instance &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_unload_instance &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_instance_all_proptags &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_instance_all_proptags &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_instance_properties &d)
{
	TRY(x.g_uint32(&d.size_limit));
	TRY(x.g_uint32(&d.instance_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_instance_properties &d)
{
	TRY(x.p_uint32(d.size_limit));
	TRY(x.p_uint32(d.instance_id));
	return x.p_proptag_a(*d.pproptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_set_instance_properties &d)
{
	TRY(x.g_uint32(&d.instance_id));
	d.pproperties = cu_alloc<TPROPVAL_ARRAY>();
	if (d.pproperties == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_tpropval_a(d.pproperties);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_set_instance_properties &d)
{
	TRY(x.p_uint32(d.instance_id));
	return x.p_tpropval_a(*d.pproperties);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_remove_instance_properties &d)
{
	TRY(x.g_uint32(&d.instance_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_remove_instance_properties &d)
{
	TRY(x.p_uint32(d.instance_id));
	return x.p_proptag_a(*d.pproptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_check_instance_cycle &d)
{
	TRY(x.g_uint32(&d.src_instance_id));
	return x.g_uint32(&d.dst_instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_check_instance_cycle &d)
{
	TRY(x.p_uint32(d.src_instance_id));
	return x.p_uint32(d.dst_instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_empty_message_instance_rcpts &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_empty_message_instance_rcpts &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_message_instance_rcpts_num &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_message_instance_rcpts_num &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_message_instance_rcpts_all_proptags &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_message_instance_rcpts_all_proptags &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_message_instance_rcpts &d)
{
	TRY(x.g_uint32(&d.instance_id));
	TRY(x.g_uint32(&d.row_id));
	return x.g_uint16(&d.need_count);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_message_instance_rcpts &d)
{
	TRY(x.p_uint32(d.instance_id));
	TRY(x.p_uint32(d.row_id));
	return x.p_uint16(d.need_count);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_update_message_instance_rcpts &d)
{
	TRY(x.g_uint32(&d.instance_id));
	d.pset = cu_alloc<TARRAY_SET>();
	if (d.pset == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_tarray_set(d.pset);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_update_message_instance_rcpts &d)
{
	TRY(x.p_uint32(d.instance_id));
	return x.p_tarray_set(*d.pset);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_copy_instance_rcpts &d)
{
	TRY(x.g_bool(&d.b_force));
	TRY(x.g_uint32(&d.src_instance_id));
	return x.g_uint32(&d.dst_instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_copy_instance_rcpts &d)
{
	TRY(x.p_bool(d.b_force));
	TRY(x.p_uint32(d.src_instance_id));
	return x.p_uint32(d.dst_instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_empty_message_instance_attachments &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_empty_message_instance_attachments &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_message_instance_attachments_num &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_message_instance_attachments_num &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_message_instance_attachment_table_all_proptags &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_message_instance_attachment_table_all_proptags &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_query_message_instance_attachment_table &d)
{
	TRY(x.g_uint32(&d.instance_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_proptag_a(d.pproptags));
	TRY(x.g_uint32(&d.start_pos));
	return x.g_int32(&d.row_needed);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_query_message_instance_attachment_table &d)
{
	TRY(x.p_uint32(d.instance_id));
	TRY(x.p_proptag_a(*d.pproptags));
	TRY(x.p_uint32(d.start_pos));
	return x.p_int32(d.row_needed);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_copy_instance_attachments &d)
{
	TRY(x.g_bool(&d.b_force));
	TRY(x.g_uint32(&d.src_instance_id));
	return x.g_uint32(&d.dst_instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_copy_instance_attachments &d)
{
	TRY(x.p_bool(d.b_force));
	TRY(x.p_uint32(d.src_instance_id));
	return x.p_uint32(d.dst_instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_set_message_instance_conflict &d)
{
	TRY(x.g_uint32(&d.instance_id));
	d.pmsgctnt = cu_alloc<MESSAGE_CONTENT>();
	if (d.pmsgctnt == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_msgctnt(d.pmsgctnt);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_set_message_instance_conflict &d)
{
	TRY(x.p_uint32(d.instance_id));
	return x.p_msgctnt(*d.pmsgctnt);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_message_rcpts &d)
{
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_message_rcpts &d)
{
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_message_properties &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint64(&d.message_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_message_properties &d)
{
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.message_id));
	return x.p_proptag_a(*d.pproptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_set_message_properties &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint64(&d.message_id));
	d.pproperties = cu_alloc<TPROPVAL_ARRAY>();
	if (d.pproperties == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_tpropval_a(d.pproperties);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_set_message_properties &d)
{
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.message_id));
	return x.p_tpropval_a(*d.pproperties);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_set_message_read_state &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint64(&d.message_id));
	return x.g_uint8(&d.mark_as_read);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_set_message_read_state &d)
{
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint64(d.message_id));
	return x.p_uint8(d.mark_as_read);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_remove_message_properties &d)
{
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint64(&d.message_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_remove_message_properties &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.message_id));
	return x.p_proptag_a(*d.pproptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_allocate_message_id &d)
{
	return x.g_uint64(&d.folder_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_allocate_message_id &d)
{
	return x.p_uint64(d.folder_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_message_group_id &d)
{
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_message_group_id &d)
{
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_set_message_group_id &d)
{
	TRY(x.g_uint64(&d.message_id));
	return x.g_uint32(&d.group_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_set_message_group_id &d)
{
	TRY(x.p_uint64(d.message_id));
	return x.p_uint32(d.group_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_save_change_indices &d)
{
	TRY(x.g_uint64(&d.message_id));
	TRY(x.g_uint64(&d.cn));
	d.pindices = cu_alloc<INDEX_ARRAY>();
	if (d.pindices == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_proptag_a(d.pindices));
	d.pungroup_proptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pungroup_proptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pungroup_proptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_save_change_indices &d)
{
	TRY(x.p_uint64(d.message_id));
	TRY(x.p_uint64(d.cn));
	TRY(x.p_proptag_a(*d.pindices));
	return x.p_proptag_a(*d.pungroup_proptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_change_indices &d)
{
	TRY(x.g_uint64(&d.message_id));
	return x.g_uint64(&d.cn);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_change_indices &d)
{
	TRY(x.p_uint64(d.message_id));
	return x.p_uint64(d.cn);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_mark_modified &d)
{
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_mark_modified &d)
{
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_try_mark_submit &d)
{
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_try_mark_submit &d)
{
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_clear_submit &d)
{
	TRY(x.g_uint64(&d.message_id));
	return x.g_bool(&d.b_unsent);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_clear_submit &d)
{
	TRY(x.p_uint64(d.message_id));
	return x.p_bool(d.b_unsent);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_link_message &d)
{
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_link_message &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_unlink_message &d)
{
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_unlink_message &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_rule_new_message &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_str(&d.account));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_rule_new_message &d)
{
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_str(d.account));
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_set_message_timer &d)
{
	TRY(x.g_uint64(&d.message_id));
	return x.g_uint32(&d.timer_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_set_message_timer &d)
{
	TRY(x.p_uint64(d.message_id));
	return x.p_uint32(d.timer_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_message_timer &d)
{
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_message_timer &d)
{
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_empty_folder_permission &d)
{
	return x.g_uint64(&d.folder_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_empty_folder_permission &d)
{
	return x.p_uint64(d.folder_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_update_folder_permission &d)
{
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_bool(&d.b_freebusy));
	TRY(x.g_uint16(&d.count));
	if (0 == d.count) {
		d.prow = nullptr;
		return EXT_ERR_SUCCESS;
	}
	d.prow = cu_alloc<PERMISSION_DATA>(d.count);
	if (d.prow == nullptr) {
		d.count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < d.count; ++i)
		TRY(x.g_permission_data(&d.prow[i]));
	return EXT_ERR_SUCCESS;
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_update_folder_permission &d)
{
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_bool(d.b_freebusy));
	TRY(x.p_uint16(d.count));
	for (size_t i = 0; i < d.count; ++i)
		TRY(x.p_permission_data(d.prow[i]));
	return EXT_ERR_SUCCESS;
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_empty_folder_rule &d)
{
	return x.g_uint64(&d.folder_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_empty_folder_rule &d)
{
	return x.p_uint64(d.folder_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_update_folder_rule &d)
{
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint16(&d.count));
	if (0 == d.count) {
		d.prow = nullptr;
		return EXT_ERR_SUCCESS;
	}
	d.prow = cu_alloc<RULE_DATA>(d.count);
	if (d.prow == nullptr) {
		d.count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < d.count; ++i)
		TRY(x.g_rule_data(&d.prow[i]));
	return EXT_ERR_SUCCESS;
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_update_folder_rule &d)
{
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_uint16(d.count));
	for (size_t i = 0; i < d.count; ++i)
		TRY(x.p_rule_data(d.prow[i]));
	return EXT_ERR_SUCCESS;
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_deliver_message &d)
{
	TRY(x.g_str(&d.from_address));
	TRY(x.g_str(&d.account));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint32(&d.dlflags));
	d.pmsg = cu_alloc<MESSAGE_CONTENT>();
	if (d.pmsg == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_msgctnt(d.pmsg));
	return x.g_str(&d.pdigest);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_deliver_message &d)
{
	TRY(x.p_str(d.from_address));
	TRY(x.p_str(d.account));
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint32(d.dlflags));
	TRY(x.p_msgctnt(*d.pmsg));
	return x.p_str(d.pdigest);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_write_message &d)
{
	TRY(x.g_str(&d.account));
	TRY(x.g_nlscp(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	d.pmsgctnt = cu_alloc<MESSAGE_CONTENT>();
	if (d.pmsgctnt == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_msgctnt(d.pmsgctnt);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_write_message &d)
{
	TRY(x.p_str(d.account));
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	return x.p_msgctnt(*d.pmsgctnt);
}
	
static pack_result exmdb_pull(EXT_PULL &x, exreq_read_message &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_nlscp(&d.cpid));
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_read_message &d)
{
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint32(d.cpid));
	return x.p_uint64(d.message_id);
}

static pack_result gcsr_failure(pack_result status, exreq_get_content_sync &d)
{
	delete d.pgiven;
	delete d.pseen;
	delete d.pseen_fai;
	delete d.pread;
	return status;
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_content_sync &d)
{
	BINARY tmp_bin;
	uint8_t tmp_byte;
	
	memset(&d, 0, sizeof(d));
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte != 0)
		TRY(x.g_str(&d.username));
	TRY(x.g_bin_ex(&tmp_bin));
	d.pgiven = new(std::nothrow) idset(false, REPL_TYPE_ID);
	if (d.pgiven == nullptr)
		return EXT_ERR_ALLOC;
	if (!d.pgiven->deserialize(tmp_bin)) {
		delete d.pgiven;
		return EXT_ERR_FORMAT;
	}
	auto status = x.g_uint8(&tmp_byte);
	if (status != EXT_ERR_SUCCESS)
		return gcsr_failure(status, d);
	if (0 != tmp_byte) {
		status = x.g_bin_ex(&tmp_bin);
		if (status != EXT_ERR_SUCCESS)
			return gcsr_failure(status, d);
		d.pseen = new(std::nothrow) idset(false, REPL_TYPE_ID);
		if (d.pseen == nullptr)
			return gcsr_failure(EXT_ERR_ALLOC, d);
		if (!d.pseen->deserialize(tmp_bin))
			return gcsr_failure(EXT_ERR_FORMAT, d);
	}
	status = x.g_uint8(&tmp_byte);
	if (status != EXT_ERR_SUCCESS)
		return gcsr_failure(status, d);
	if (0 != tmp_byte) {
		status = x.g_bin_ex(&tmp_bin);
		if (status != EXT_ERR_SUCCESS)
			return gcsr_failure(status, d);
		d.pseen_fai = new(std::nothrow) idset(false, REPL_TYPE_ID);
		if (d.pseen_fai == nullptr)
			return gcsr_failure(EXT_ERR_ALLOC, d);
		if (!d.pseen_fai->deserialize(tmp_bin))
			return gcsr_failure(EXT_ERR_FORMAT, d);
	}
	status = x.g_uint8(&tmp_byte);
	if (status != EXT_ERR_SUCCESS)
		return gcsr_failure(status, d);
	if (0 != tmp_byte) {
		status = x.g_bin_ex(&tmp_bin);
		if (status != EXT_ERR_SUCCESS)
			return gcsr_failure(status, d);
		d.pread = new(std::nothrow) idset(false, REPL_TYPE_ID);
		if (d.pread == nullptr)
			return gcsr_failure(EXT_ERR_ALLOC, d);
		if (!d.pread->deserialize(tmp_bin))
			return gcsr_failure(EXT_ERR_FORMAT, d);
	}
	status = x.g_nlscp(&d.cpid);
	if (status != EXT_ERR_SUCCESS)
		return gcsr_failure(status, d);
	status = x.g_uint8(&tmp_byte);
	if (status != EXT_ERR_SUCCESS)
		return gcsr_failure(status, d);
	if (0 != tmp_byte) {
		d.prestriction = cu_alloc<RESTRICTION>();
		if (d.prestriction == nullptr)
			return gcsr_failure(EXT_ERR_ALLOC, d);
		status = x.g_restriction(d.prestriction);
		if (status != EXT_ERR_SUCCESS)
			return gcsr_failure(status, d);
	}
	status = x.g_bool(&d.b_ordered);
	if (status != EXT_ERR_SUCCESS)
		return gcsr_failure(status, d);
	return EXT_ERR_SUCCESS;
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_content_sync &d)
{
	TRY(x.p_uint64(d.folder_id));
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	auto pbin = d.pgiven->serialize_replid();
	if (pbin == nullptr)
		return EXT_ERR_ALLOC;
	auto status = x.p_bin_ex(*pbin);
	if (EXT_ERR_SUCCESS != status) {
		rop_util_free_binary(pbin);
		return status;
	}
	rop_util_free_binary(pbin);
	if (d.pseen == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		pbin = d.pseen->serialize_replid();
		if (pbin == nullptr)
			return EXT_ERR_ALLOC;
		status = x.p_bin_ex(*pbin);
		if (EXT_ERR_SUCCESS != status) {
			rop_util_free_binary(pbin);
			return status;
		}
		rop_util_free_binary(pbin);
	}
	if (d.pseen_fai == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		pbin = d.pseen_fai->serialize_replid();
		if (pbin == nullptr)
			return EXT_ERR_ALLOC;
		status = x.p_bin_ex(*pbin);
		if (EXT_ERR_SUCCESS != status) {
			rop_util_free_binary(pbin);
			return status;
		}
		rop_util_free_binary(pbin);
	}
	if (d.pread == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		pbin = d.pread->serialize_replid();
		if (pbin == nullptr)
			return EXT_ERR_ALLOC;
		status = x.p_bin_ex(*pbin);
		if (EXT_ERR_SUCCESS != status) {
			rop_util_free_binary(pbin);
			return status;
		}
		rop_util_free_binary(pbin);
	}
	TRY(x.p_uint32(d.cpid));
	if (d.prestriction == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_restriction(*d.prestriction));
	}
	return x.p_bool(d.b_ordered);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_hierarchy_sync &d)
{
	BINARY tmp_bin;
	uint8_t tmp_byte;
	
	memset(&d, 0, sizeof(d));
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte != 0)
		TRY(x.g_str(&d.username));
	TRY(x.g_bin_ex(&tmp_bin));
	d.pgiven = new(std::nothrow) idset(false, REPL_TYPE_ID);
	if (d.pgiven == nullptr)
		return EXT_ERR_ALLOC;
	if (!d.pgiven->deserialize(tmp_bin)) {
		delete d.pgiven;
		return EXT_ERR_FORMAT;
	}
	auto status = x.g_uint8(&tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		delete d.pgiven;
		return status;
	}
	if (0 != tmp_byte) {
		status = x.g_bin_ex(&tmp_bin);
		if (EXT_ERR_SUCCESS != status) {
			delete d.pgiven;
			return status;
		}
		d.pseen = new(std::nothrow) idset(false, REPL_TYPE_ID);
		if (d.pseen == nullptr) {
			delete d.pgiven;
			return EXT_ERR_ALLOC;
		}
		if (!d.pseen->deserialize(tmp_bin)) {
			delete d.pseen;
			delete d.pgiven;
			return EXT_ERR_FORMAT;
		}
	}
	return EXT_ERR_SUCCESS;
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_hierarchy_sync &d)
{
	TRY(x.p_uint64(d.folder_id));
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	auto pbin = d.pgiven->serialize_replid();
	if (pbin == nullptr)
		return EXT_ERR_ALLOC;
	auto status = x.p_bin_ex(*pbin);
	if (EXT_ERR_SUCCESS != status) {
		rop_util_free_binary(pbin);
		return status;
	}
	rop_util_free_binary(pbin);
	if (d.pseen == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		pbin = d.pseen->serialize_replid();
		if (pbin == nullptr)
			return EXT_ERR_ALLOC;
		status = x.p_bin_ex(*pbin);
		if (EXT_ERR_SUCCESS != status) {
			rop_util_free_binary(pbin);
			return status;
		}
		rop_util_free_binary(pbin);
	}
	return EXT_ERR_SUCCESS;
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_allocate_ids &d)
{
	return x.g_uint32(&d.count);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_allocate_ids &d)
{
	return x.p_uint32(d.count);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_subscribe_notification &d)
{
	TRY(x.g_uint16(&d.notification_type));
	TRY(x.g_bool(&d.b_whole));
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_subscribe_notification &d)
{
	TRY(x.p_uint16(d.notification_type));
	TRY(x.p_bool(d.b_whole));
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_unsubscribe_notification &d)
{
	return x.g_uint32(&d.sub_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_unsubscribe_notification &d)
{
	return x.p_uint32(d.sub_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_transport_new_mail &d)
{
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint64(&d.message_id));
	TRY(x.g_uint32(&d.message_flags));
	return x.g_str(&d.pstr_class);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_transport_new_mail &d)
{
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_uint64(d.message_id));
	TRY(x.p_uint32(d.message_flags));
	return x.p_str(d.pstr_class);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_notify_new_mail &d)
{
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_notify_new_mail &d)
{
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_check_contact_address &d)
{
	return x.g_str(&d.paddress);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_check_contact_address &d)
{
	return x.p_str(d.paddress);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_get_public_folder_unread_count &d)
{
	TRY(x.g_str(&d.username));
	return x.g_uint64(&d.folder_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_get_public_folder_unread_count &d)
{
	TRY(x.p_str(d.username));
	return x.p_uint64(d.folder_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_store_eid_to_user &d)
{
	d.store_eid = cu_alloc<STORE_ENTRYID>();
	if (d.store_eid == nullptr)
		return pack_result::alloc;
	return x.g_store_eid(d.store_eid);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_store_eid_to_user &d)
{
	return x.p_store_eid(*d.store_eid);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_autoreply_tsquery &d)
{
	TRY(x.g_str(&d.peer));
	return x.g_uint64(&d.window);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_autoreply_tsquery &d)
{
	TRY(x.p_str(d.peer));
	return x.p_uint64(d.window);
}

static pack_result exmdb_pull(EXT_PULL &x, exreq_autoreply_tsupdate &d)
{
	return x.g_str(&d.peer);
}

static pack_result exmdb_push(EXT_PUSH &x, const exreq_autoreply_tsupdate &d)
{
	return x.p_str(d.peer);
}

#define RQ_WITH_ARGS \
	E(get_named_propids) \
	E(get_named_propnames) \
	E(get_mapping_guid) \
	E(get_mapping_replid) \
	E(get_store_properties) \
	E(set_store_properties) \
	E(remove_store_properties) \
	E(get_mbox_perm) \
	E(get_folder_by_class) \
	E(set_folder_by_class) \
	E(check_folder_id) \
	E(check_folder_deleted) \
	E(get_folder_by_name) \
	E(get_folder_perm) \
	E(create_folder_by_properties) \
	E(get_folder_all_proptags) \
	E(get_folder_properties) \
	E(set_folder_properties) \
	E(remove_folder_properties) \
	E(delete_folder) \
	E(empty_folder) \
	E(check_folder_cycle) \
	E(copy_folder_internal) \
	E(get_search_criteria) \
	E(set_search_criteria) \
	E(movecopy_message) \
	E(movecopy_messages) \
	E(movecopy_folder) \
	E(delete_messages) \
	E(get_message_brief) \
	E(sum_hierarchy) \
	E(load_hierarchy_table) \
	E(sum_content) \
	E(load_content_table) \
	E(reload_content_table) \
	E(load_perm_table_v1) \
	E(load_permission_table) \
	E(load_rule_table) \
	E(unload_table) \
	E(sum_table) \
	E(query_table) \
	E(match_table) \
	E(locate_table) \
	E(read_table_row) \
	E(mark_table) \
	E(get_table_all_proptags) \
	E(expand_table) \
	E(collapse_table) \
	E(store_table_state) \
	E(restore_table_state) \
	E(check_message) \
	E(check_message_deleted) \
	E(load_message_instance) \
	E(load_embedded_instance) \
	E(get_embedded_cn) \
	E(reload_message_instance) \
	E(clear_message_instance) \
	E(read_message_instance) \
	E(write_message_instance) \
	E(load_attachment_instance) \
	E(create_attachment_instance) \
	E(read_attachment_instance) \
	E(write_attachment_instance) \
	E(delete_message_instance_attachment) \
	E(flush_instance) \
	E(unload_instance) \
	E(get_instance_all_proptags) \
	E(get_instance_properties) \
	E(set_instance_properties) \
	E(remove_instance_properties) \
	E(check_instance_cycle) \
	E(empty_message_instance_rcpts) \
	E(get_message_instance_rcpts_num) \
	E(get_message_instance_rcpts_all_proptags) \
	E(get_message_instance_rcpts) \
	E(update_message_instance_rcpts) \
	E(copy_instance_rcpts) \
	E(empty_message_instance_attachments) \
	E(get_message_instance_attachments_num) \
	E(get_message_instance_attachment_table_all_proptags) \
	E(query_message_instance_attachment_table) \
	E(copy_instance_attachments) \
	E(set_message_instance_conflict) \
	E(get_message_rcpts) \
	E(get_message_properties) \
	E(set_message_properties) \
	E(set_message_read_state) \
	E(remove_message_properties) \
	E(allocate_message_id) \
	E(get_message_group_id) \
	E(set_message_group_id) \
	E(save_change_indices) \
	E(get_change_indices) \
	E(mark_modified) \
	E(try_mark_submit) \
	E(clear_submit) \
	E(link_message) \
	E(unlink_message) \
	E(rule_new_message) \
	E(set_message_timer) \
	E(get_message_timer) \
	E(empty_folder_permission) \
	E(update_folder_permission) \
	E(empty_folder_rule) \
	E(update_folder_rule) \
	E(deliver_message) \
	E(write_message) \
	E(read_message) \
	E(get_content_sync) \
	E(get_hierarchy_sync) \
	E(allocate_ids) \
	E(subscribe_notification) \
	E(unsubscribe_notification) \
	E(transport_new_mail) \
	E(check_contact_address) \
	E(get_public_folder_unread_count) \
	E(notify_new_mail) \
	E(store_eid_to_user) \
	E(purge_softdelete) \
	E(autoreply_tsquery) \
	E(autoreply_tsupdate)

/**
 * This uses *& because we do not know which request type we are going to get
 * (cf. exmdb_ext_pull_response).
 */
pack_result exmdb_ext_pull_request(const BINARY *pbin_in, exreq *&prequest)
{
	EXT_PULL ext_pull;
	uint8_t raw_call_id;
	
	ext_pull.init(pbin_in->pb, pbin_in->cb, exmdb_rpc_alloc, EXT_FLAG_WCOUNT);
	TRY(ext_pull.g_uint8(&raw_call_id));
	auto call_id = static_cast<exmdb_callid>(raw_call_id);
	if (call_id == exmdb_callid::connect) {
		auto r = cu_alloc<exreq_connect>();
		prequest = r;
		if (r == nullptr)
			return EXT_ERR_ALLOC;
		auto xret = exmdb_pull(ext_pull, *r);
		prequest->call_id = call_id;
		return xret;
	} else if (call_id == exmdb_callid::listen_notification) {
		auto r = cu_alloc<exreq_listen_notification>();
		prequest = r;
		if (r == nullptr)
			return EXT_ERR_ALLOC;
		auto xret = exmdb_pull(ext_pull, *r);
		prequest->call_id = call_id;
		return xret;
	}

	char *dir = nullptr;
	TRY(ext_pull.g_str(&dir));
	pack_result xret;
	switch (call_id) {
	case exmdb_callid::ping_store:
	case exmdb_callid::get_all_named_propids:
	case exmdb_callid::get_store_all_proptags:
	case exmdb_callid::get_folder_class_table:
	case exmdb_callid::allocate_cn:
	case exmdb_callid::vacuum:
	case exmdb_callid::unload_store:
	case exmdb_callid::purge_datafiles: {
		prequest = cu_alloc<exreq>();
		if (prequest == nullptr)
			return EXT_ERR_ALLOC;
		xret = EXT_ERR_SUCCESS;
		break;
	}
#define E(t) case exmdb_callid::t: { \
		auto r = cu_alloc<exreq_ ## t >(); \
		prequest = r; \
		if (r == nullptr) \
			return EXT_ERR_ALLOC; \
		xret = exmdb_pull(ext_pull, *r); \
		break; \
	}
	RQ_WITH_ARGS
#undef E
	default:
		return EXT_ERR_BAD_SWITCH;
	}
	prequest->call_id = call_id;
	prequest->dir = dir;
	return xret;
}

pack_result exmdb_ext_push_request(const exreq *prequest, BINARY *pbin_out)
{
	EXT_PUSH ext_push;
	
	if (!ext_push.init(nullptr, 0, EXT_FLAG_WCOUNT))
		return EXT_ERR_ALLOC;
	auto status = ext_push.advance(sizeof(uint32_t));
	if (status != EXT_ERR_SUCCESS)
		return status;
	status = ext_push.p_uint8(static_cast<uint8_t>(prequest->call_id));
	if (status != EXT_ERR_SUCCESS)
		return status;
	if (prequest->call_id == exmdb_callid::connect) {
		status = exmdb_push(ext_push, *static_cast<const exreq_connect *>(prequest));
	} else if (prequest->call_id == exmdb_callid::listen_notification) {
		status = exmdb_push(ext_push, *static_cast<const exreq_listen_notification *>(prequest));
	} else {
	status = ext_push.p_str(prequest->dir);
	if (status != EXT_ERR_SUCCESS)
		return status;
	switch (prequest->call_id) {
	case exmdb_callid::ping_store:
	case exmdb_callid::get_all_named_propids:
	case exmdb_callid::get_store_all_proptags:
	case exmdb_callid::get_folder_class_table:
	case exmdb_callid::allocate_cn:
	case exmdb_callid::vacuum:
	case exmdb_callid::unload_store:
	case exmdb_callid::purge_datafiles:
		status = EXT_ERR_SUCCESS;
		break;
#define E(t) case exmdb_callid::t: status = exmdb_push(ext_push, *static_cast<const exreq_ ## t *>(prequest)); break;
	RQ_WITH_ARGS
#undef E
	default:
		return EXT_ERR_BAD_SWITCH;
	}
	}
	if (status != EXT_ERR_SUCCESS)
		return status;
	pbin_out->cb = ext_push.m_offset;
	ext_push.m_offset = 0;
	status = ext_push.p_uint32(pbin_out->cb - sizeof(uint32_t));
	if (status != EXT_ERR_SUCCESS)
		return status;
	/* memory referenced by ext_push.data will be freed outside */
	pbin_out->pb = ext_push.release();
	return EXT_ERR_SUCCESS;
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_all_named_propids &d)
{
	return x.g_propid_a(&d.propids);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_all_named_propids &d)
{
	return x.p_propid_a(d.propids);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_named_propids &d)
{
	return x.g_propid_a(&d.propids);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_named_propids &d)
{
	return x.p_propid_a(d.propids);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_named_propnames &d)
{
	return x.g_propname_a(&d.propnames);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_named_propnames &d)
{
	return x.p_propname_a(d.propnames);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_mapping_guid &d)
{
	TRY(x.g_bool(&d.b_found));
	return x.g_guid(&d.guid);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_mapping_guid &d)
{
	TRY(x.p_bool(d.b_found));
	return x.p_guid(d.guid);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_mapping_replid &d)
{
	TRY(x.g_bool(&d.b_found));
	return x.g_uint16(&d.replid);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_mapping_replid &d)
{
	TRY(x.p_bool(d.b_found));
	return x.p_uint16(d.replid);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_store_all_proptags &d)
{
	return x.g_proptag_a(&d.proptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_store_all_proptags &d)
{
	return x.p_proptag_a(d.proptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_store_properties &d)
{
	return x.g_tpropval_a(&d.propvals);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_store_properties &d)
{
	return x.p_tpropval_a(d.propvals);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_set_store_properties &d)
{
	return x.g_problem_a(&d.problems);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_set_store_properties &d)
{
	return x.p_problem_a(d.problems);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_mbox_perm &d)
{
	return x.g_uint32(&d.permission);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_mbox_perm &d)
{
	return x.p_uint32(d.permission);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_folder_by_class &d)
{
	TRY(x.g_uint64(&d.id));
	return x.g_str(&d.str_explicit);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_folder_by_class &d)
{
	TRY(x.p_uint64(d.id));
	return x.p_str(d.str_explicit);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_set_folder_by_class &d)
{
	return x.g_bool(&d.b_result);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_set_folder_by_class &d)
{
	return x.p_bool(d.b_result);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_folder_class_table &d)
{
	return x.g_tarray_set(&d.table);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_folder_class_table &d)
{
	return x.p_tarray_set(d.table);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_check_folder_id &d)
{
	return x.g_bool(&d.b_exist);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_check_folder_id &d)
{
	return x.p_bool(d.b_exist);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_check_folder_deleted &d)
{
	return x.g_bool(&d.b_del);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_check_folder_deleted &d)
{
	return x.p_bool(d.b_del);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_folder_by_name &d)
{
	return x.g_uint64(&d.folder_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_folder_by_name &d)
{
	return x.p_uint64(d.folder_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_folder_perm &d)
{
	return x.g_uint32(&d.permission);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_folder_perm &d)
{
	return x.p_uint32(d.permission);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_create_folder_by_properties &d)
{
	return x.g_uint64(&d.folder_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_create_folder_by_properties &d)
{
	return x.p_uint64(d.folder_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_folder_all_proptags &d)
{
	return x.g_proptag_a(&d.proptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_folder_all_proptags &d)
{
	return x.p_proptag_a(d.proptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_folder_properties &d)
{
	return x.g_tpropval_a(&d.propvals);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_folder_properties &d)
{
	return x.p_tpropval_a(d.propvals);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_set_folder_properties &d)
{
	return x.g_problem_a(&d.problems);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_set_folder_properties &d)
{
	return x.p_problem_a(d.problems);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_delete_folder &d)
{
	return x.g_bool(&d.b_result);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_delete_folder &d)
{
	return x.p_bool(d.b_result);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_empty_folder &d)
{
	return x.g_bool(&d.b_partial);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_empty_folder &d)
{
	return x.p_bool(d.b_partial);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_check_folder_cycle &d)
{
	return x.g_bool(&d.b_cycle);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_check_folder_cycle &d)
{
	return x.p_bool(d.b_cycle);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_copy_folder_internal &d)
{
	TRY(x.g_bool(&d.b_collid));
	return x.g_bool(&d.b_partial);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_copy_folder_internal &d)
{
	TRY(x.p_bool(d.b_collid));
	return x.p_bool(d.b_partial);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_search_criteria &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.search_status));
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.prestriction = nullptr;
	} else {
		d.prestriction = cu_alloc<RESTRICTION>();
		if (d.prestriction == nullptr)
			return EXT_ERR_ALLOC;
		TRY(x.g_restriction(d.prestriction));
	}
	return x.g_uint64_a(&d.folder_ids);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_search_criteria &d)
{
	TRY(x.p_uint32(d.search_status));
	if (d.prestriction == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_restriction(*d.prestriction));
	}
	return x.p_uint64_a(d.folder_ids);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_set_search_criteria &d)
{
	return x.g_bool(&d.b_result);
}
	
static pack_result exmdb_push(EXT_PUSH &x, const exresp_set_search_criteria &d)
{
	return x.p_bool(d.b_result);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_movecopy_message &d)
{
	return x.g_bool(&d.b_result);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_movecopy_message &d)
{
	return x.p_bool(d.b_result);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_movecopy_messages &d)
{
	return x.g_bool(&d.b_partial);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_movecopy_messages &d)
{
	return x.p_bool(d.b_partial);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_movecopy_folder &d)
{
	TRY(x.g_bool(&d.b_exist));
	return x.g_bool(&d.b_partial);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_movecopy_folder &d)
{
	TRY(x.p_bool(d.b_exist));
	return x.p_bool(d.b_partial);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_delete_messages &d)
{
	return x.g_bool(&d.b_partial);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_delete_messages &d)
{
	return x.p_bool(d.b_partial);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_message_brief &d)
{
	uint8_t tmp_byte;
	
	auto status = x.g_uint8(&tmp_byte);
	if (status != EXT_ERR_SUCCESS || tmp_byte == 0) {
		d.pbrief = nullptr;
		return EXT_ERR_SUCCESS;
	}
	d.pbrief = cu_alloc<MESSAGE_CONTENT>();
	if (d.pbrief == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_msgctnt(d.pbrief);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_message_brief &d)
{
	if (d.pbrief == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return x.p_msgctnt(*d.pbrief);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_sum_hierarchy &d)
{
	return x.g_uint32(&d.count);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_sum_hierarchy &d)
{
	return x.p_uint32(d.count);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_load_hierarchy_table &d)
{
	TRY(x.g_uint32(&d.table_id));
	return x.g_uint32(&d.row_count);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_load_hierarchy_table &d)
{
	TRY(x.p_uint32(d.table_id));
	return x.p_uint32(d.row_count);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_sum_content &d)
{
	return x.g_uint32(&d.count);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_sum_content &d)
{
	return x.p_uint32(d.count);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_load_content_table &d)
{
	TRY(x.g_uint32(&d.table_id));
	return x.g_uint32(&d.row_count);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_load_content_table &d)
{
	TRY(x.p_uint32(d.table_id));
	return x.p_uint32(d.row_count);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_load_permission_table &d)
{
	TRY(x.g_uint32(&d.table_id));
	return x.g_uint32(&d.row_count);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_load_permission_table &d)
{
	TRY(x.p_uint32(d.table_id));
	return x.p_uint32(d.row_count);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_load_rule_table &d)
{
	TRY(x.g_uint32(&d.table_id));
	return x.g_uint32(&d.row_count);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_load_rule_table &d)
{
	TRY(x.p_uint32(d.table_id));
	return x.p_uint32(d.row_count);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_sum_table &d)
{
	return x.g_uint32(&d.rows);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_sum_table &d)
{
	return x.p_uint32(d.rows);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_query_table &d)
{
	return x.g_tarray_set(&d.set);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_query_table &d)
{
	return x.p_tarray_set(d.set);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_match_table &d)
{
	TRY(x.g_int32(&d.position));
	return x.g_tpropval_a(&d.propvals);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_match_table &d)
{
	TRY(x.p_int32(d.position));
	return x.p_tpropval_a(d.propvals);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_locate_table &d)
{
	TRY(x.g_int32(&d.position));
	return x.g_uint32(&d.row_type);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_locate_table &d)
{
	TRY(x.p_int32(d.position));
	return x.p_uint32(d.row_type);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_read_table_row &d)
{
	return x.g_tpropval_a(&d.propvals);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_read_table_row &d)
{
	return x.p_tpropval_a(d.propvals);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_mark_table &d)
{
	TRY(x.g_uint64(&d.inst_id));
	TRY(x.g_uint32(&d.inst_num));
	return x.g_uint32(&d.row_type);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_mark_table &d)
{
	TRY(x.p_uint64(d.inst_id));
	TRY(x.p_uint32(d.inst_num));
	return x.p_uint32(d.row_type);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_table_all_proptags &d)
{
	return x.g_proptag_a(&d.proptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_table_all_proptags &d)
{
	return x.p_proptag_a(d.proptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_expand_table &d)
{
	TRY(x.g_bool(&d.b_found));
	TRY(x.g_int32(&d.position));
	return x.g_uint32(&d.row_count);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_expand_table &d)
{
	TRY(x.p_bool(d.b_found));
	TRY(x.p_int32(d.position));
	return x.p_uint32(d.row_count);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_collapse_table &d)
{
	TRY(x.g_bool(&d.b_found));
	TRY(x.g_int32(&d.position));
	return x.g_uint32(&d.row_count);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_collapse_table &d)
{
	TRY(x.p_bool(d.b_found));
	TRY(x.p_int32(d.position));
	return x.p_uint32(d.row_count);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_store_table_state &d)
{
	return x.g_uint32(&d.state_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_store_table_state &d)
{
	return x.p_uint32(d.state_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_restore_table_state &d)
{
	return x.g_int32(&d.position);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_restore_table_state &d)
{
	return x.p_int32(d.position);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_check_message &d)
{
	return x.g_bool(&d.b_exist);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_check_message &d)
{
	return x.p_bool(d.b_exist);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_check_message_deleted &d)
{
	return x.g_bool(&d.b_del);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_check_message_deleted &d)
{
	return x.p_bool(d.b_del);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_load_message_instance &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_load_message_instance &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_load_embedded_instance &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_load_embedded_instance &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_embedded_cn &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.pcn = nullptr;
		return EXT_ERR_SUCCESS;
	}
	d.pcn = cu_alloc<uint64_t>();
	if (d.pcn == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_uint64(d.pcn);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_embedded_cn &d)
{
	if (d.pcn == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return x.p_uint64(*static_cast<uint64_t *>(d.pcn));
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_reload_message_instance &d)
{
	return x.g_bool(&d.b_result);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_reload_message_instance &d)
{
	return x.p_bool(d.b_result);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_read_message_instance &d)
{
	return x.g_msgctnt(&d.msgctnt);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_read_message_instance &d)
{
	return x.p_msgctnt(d.msgctnt);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_write_message_instance &d)
{
	TRY(x.g_proptag_a(&d.proptags));
	return x.g_problem_a(&d.problems);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_write_message_instance &d)
{
	TRY(x.p_proptag_a(d.proptags));
	return x.p_problem_a(d.problems);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_load_attachment_instance &d)
{
	return x.g_uint32(&d.instance_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_load_attachment_instance &d)
{
	return x.p_uint32(d.instance_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_create_attachment_instance &d)
{
	TRY(x.g_uint32(&d.instance_id));
	return x.g_uint32(&d.attachment_num);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_create_attachment_instance &d)
{
	TRY(x.p_uint32(d.instance_id));
	return x.p_uint32(d.attachment_num);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_read_attachment_instance &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_tpropval_a(&d.attctnt.proplist));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		d.attctnt.pembedded = nullptr;
		return EXT_ERR_SUCCESS;
	}
	d.attctnt.pembedded = cu_alloc<MESSAGE_CONTENT>();
	if (d.attctnt.pembedded == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_msgctnt(d.attctnt.pembedded);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_read_attachment_instance &d)
{
	TRY(x.p_tpropval_a(d.attctnt.proplist));
	if (d.attctnt.pembedded == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return x.p_msgctnt(*d.attctnt.pembedded);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_write_attachment_instance &d)
{
	return x.g_problem_a(&d.problems);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_write_attachment_instance &d)
{
	return x.p_problem_a(d.problems);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_flush_instance &d)
{
	return x.g_uint32(reinterpret_cast<uint32_t *>(&d.e_result));
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_flush_instance &d)
{
	return x.p_uint32(d.e_result);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_instance_all_proptags &d)
{
	return x.g_proptag_a(&d.proptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_instance_all_proptags &d)
{
	return x.p_proptag_a(d.proptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_instance_properties &d)
{
	return x.g_tpropval_a(&d.propvals);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_instance_properties &d)
{
	return x.p_tpropval_a(d.propvals);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_set_instance_properties &d)
{
	return x.g_problem_a(&d.problems);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_set_instance_properties &d)
{
	return x.p_problem_a(d.problems);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_remove_instance_properties &d)
{
	return x.g_problem_a(&d.problems);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_remove_instance_properties &d)
{
	return x.p_problem_a(d.problems);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_check_instance_cycle &d)
{
	return x.g_bool(&d.b_cycle);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_check_instance_cycle &d)
{
	return x.p_bool(d.b_cycle);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_message_instance_rcpts_num &d)
{
	return x.g_uint16(&d.num);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_message_instance_rcpts_num &d)
{
	return x.p_uint16(d.num);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_message_instance_rcpts_all_proptags &d)
{
	return x.g_proptag_a(&d.proptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_message_instance_rcpts_all_proptags &d)
{
	return x.p_proptag_a(d.proptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_message_instance_rcpts &d)
{
	return x.g_tarray_set(&d.set);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_message_instance_rcpts &d)
{
	return x.p_tarray_set(d.set);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_copy_instance_rcpts &d)
{
	return x.g_bool(&d.b_result);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_copy_instance_rcpts &d)
{
	return x.p_bool(d.b_result);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_message_instance_attachments_num &d)
{
	return x.g_uint16(&d.num);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_message_instance_attachments_num &d)
{
	return x.p_uint16(d.num);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_message_instance_attachment_table_all_proptags &d)
{
	return x.g_proptag_a(&d.proptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_message_instance_attachment_table_all_proptags &d)
{
	return x.p_proptag_a(d.proptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_query_message_instance_attachment_table &d)
{
	return x.g_tarray_set(&d.set);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_query_message_instance_attachment_table &d)
{
	return x.p_tarray_set(d.set);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_copy_instance_attachments &d)
{
	return x.g_bool(&d.b_result);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_copy_instance_attachments &d)
{
	return x.p_bool(d.b_result);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_message_rcpts &d)
{
	return x.g_tarray_set(&d.set);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_message_rcpts &d)
{
	return x.p_tarray_set(d.set);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_message_properties &d)
{
	return x.g_tpropval_a(&d.propvals);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_message_properties &d)
{
	return x.p_tpropval_a(d.propvals);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_set_message_properties &d)
{
	return x.g_problem_a(&d.problems);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_set_message_properties &d)
{
	return x.p_problem_a(d.problems);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_set_message_read_state &d)
{
	return x.g_uint64(&d.read_cn);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_set_message_read_state &d)
{
	return x.p_uint64(d.read_cn);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_allocate_message_id &d)
{
	return x.g_uint64(&d.message_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_allocate_message_id &d)
{
	return x.p_uint64(d.message_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_allocate_cn &d)
{
	return x.g_uint64(&d.cn);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_allocate_cn &d)
{
	return x.p_uint64(d.cn);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_message_group_id &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.pgroup_id = nullptr;
		return EXT_ERR_SUCCESS;
	}
	d.pgroup_id = cu_alloc<uint32_t>();
	if (d.pgroup_id == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_uint32(d.pgroup_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_message_group_id &d)
{
	if (d.pgroup_id == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return x.p_uint32(*d.pgroup_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_change_indices &d)
{
	TRY(x.g_proptag_a(&d.indices));
	return x.g_proptag_a(&d.ungroup_proptags);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_change_indices &d)
{
	TRY(x.p_proptag_a(d.indices));
	return x.p_proptag_a(d.ungroup_proptags);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_try_mark_submit &d)
{
	return x.g_bool(&d.b_marked);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_try_mark_submit &d)
{
	return x.p_bool(d.b_marked);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_link_message &d)
{
	return x.g_bool(&d.b_result);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_link_message &d)
{
	return x.p_bool(d.b_result);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_message_timer &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.ptimer_id = nullptr;
		return EXT_ERR_SUCCESS;
	}
	d.ptimer_id = cu_alloc<uint32_t>();
	if (d.ptimer_id == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_uint32(d.ptimer_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_message_timer &d)
{
	if (d.ptimer_id == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return x.p_uint32(*d.ptimer_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_update_folder_rule &d)
{
	return x.g_bool(&d.b_exceed);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_update_folder_rule &d)
{
	return x.p_bool(d.b_exceed);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_deliver_message &d)
{
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint64(&d.message_id));
	return x.g_uint32(&d.result);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_deliver_message &d)
{
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_uint64(d.message_id));
	return x.p_uint32(d.result);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_write_message &d)
{
	return x.g_uint32(reinterpret_cast<uint32_t *>(&d.e_result));
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_write_message &d)
{
	return x.p_uint32(d.e_result);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_read_message &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.pmsgctnt = nullptr;
		return EXT_ERR_SUCCESS;
	}
	d.pmsgctnt = cu_alloc<MESSAGE_CONTENT>();
	if (d.pmsgctnt == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_msgctnt(d.pmsgctnt);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_read_message &d)
{
	if (d.pmsgctnt == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return x.p_msgctnt(*d.pmsgctnt);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_content_sync &d)
{
	TRY(x.g_uint32(&d.fai_count));
	TRY(x.g_uint64(&d.fai_total));
	TRY(x.g_uint32(&d.normal_count));
	TRY(x.g_uint64(&d.normal_total));
	TRY(x.g_eid_a(&d.updated_mids));
	TRY(x.g_eid_a(&d.chg_mids));
	TRY(x.g_uint64(&d.last_cn));
	TRY(x.g_eid_a(&d.given_mids));
	TRY(x.g_eid_a(&d.deleted_mids));
	TRY(x.g_eid_a(&d.nolonger_mids));
	TRY(x.g_eid_a(&d.read_mids));
	TRY(x.g_eid_a(&d.unread_mids));
	return x.g_uint64(&d.last_readcn);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_content_sync &d)
{
	
	TRY(x.p_uint32(d.fai_count));
	TRY(x.p_uint64(d.fai_total));
	TRY(x.p_uint32(d.normal_count));
	TRY(x.p_uint64(d.normal_total));
	TRY(x.p_eid_a(d.updated_mids));
	TRY(x.p_eid_a(d.chg_mids));
	TRY(x.p_uint64(d.last_cn));
	TRY(x.p_eid_a(d.given_mids));
	TRY(x.p_eid_a(d.deleted_mids));
	TRY(x.p_eid_a(d.nolonger_mids));
	TRY(x.p_eid_a(d.read_mids));
	TRY(x.p_eid_a(d.unread_mids));
	return x.p_uint64(d.last_readcn);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_hierarchy_sync &d)
{
	TRY(x.g_uint32(&d.fldchgs.count));
	if (0 == d.fldchgs.count) {
		d.fldchgs.pfldchgs = nullptr;
	} else {
		d.fldchgs.pfldchgs = cu_alloc<TPROPVAL_ARRAY>(d.fldchgs.count);
		if (d.fldchgs.pfldchgs == nullptr) {
			d.fldchgs.count = 0;
			return EXT_ERR_ALLOC;
		}
		for (size_t i = 0; i < d.fldchgs.count; ++i)
			TRY(x.g_tpropval_a(&d.fldchgs.pfldchgs[i]));
	}
	TRY(x.g_uint64(&d.last_cn));
	TRY(x.g_eid_a(&d.given_fids));
	return x.g_eid_a(&d.deleted_fids);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_hierarchy_sync &d)
{
	TRY(x.p_uint32(d.fldchgs.count));
	for (size_t i = 0; i < d.fldchgs.count; ++i)
		TRY(x.p_tpropval_a(d.fldchgs.pfldchgs[i]));
	TRY(x.p_uint64(d.last_cn));
	TRY(x.p_eid_a(d.given_fids));
	return x.p_eid_a(d.deleted_fids);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_allocate_ids &d)
{
	return x.g_uint64(&d.begin_eid);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_allocate_ids &d)
{
	return x.p_uint64(d.begin_eid);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_subscribe_notification &d)
{
	return x.g_uint32(&d.sub_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_subscribe_notification &d)
{
	return x.p_uint32(d.sub_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_check_contact_address &d)
{
	return x.g_bool(&d.b_found);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_check_contact_address &d)
{
	return x.p_bool(d.b_found);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_get_public_folder_unread_count &d)
{
	return x.g_uint32(&d.count);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_get_public_folder_unread_count &d)
{
	return x.p_uint32(d.count);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_store_eid_to_user &d)
{
	TRY(x.g_str(&d.maildir));
	TRY(x.g_uint32(&d.user_id));
	return x.g_uint32(&d.domain_id);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_store_eid_to_user &d)
{
	TRY(x.p_str(d.maildir));
	TRY(x.p_uint32(d.user_id));
	return x.p_uint32(d.domain_id);
}

static pack_result exmdb_pull(EXT_PULL &x, exresp_autoreply_tsquery &d)
{
	return x.g_uint64(&d.tdiff);
}

static pack_result exmdb_push(EXT_PUSH &x, const exresp_autoreply_tsquery &d)
{
	return x.p_uint64(d.tdiff);
}

#define RSP_WITHOUT_ARGS \
	E(ping_store) \
	E(remove_store_properties) \
	E(remove_folder_properties) \
	E(reload_content_table) \
	E(unload_table) \
	E(clear_message_instance) \
	E(delete_message_instance_attachment) \
	E(unload_instance) \
	E(empty_message_instance_rcpts) \
	E(update_message_instance_rcpts) \
	E(empty_message_instance_attachments) \
	E(set_message_instance_conflict) \
	E(remove_message_properties) \
	E(set_message_group_id) \
	E(save_change_indices) \
	E(mark_modified) \
	E(clear_submit) \
	E(unlink_message) \
	E(rule_new_message) \
	E(set_message_timer) \
	E(empty_folder_permission) \
	E(update_folder_permission) \
	E(empty_folder_rule) \
	E(unsubscribe_notification) \
	E(transport_new_mail) \
	E(vacuum) \
	E(unload_store) \
	E(notify_new_mail) \
	E(purge_softdelete) \
	E(purge_datafiles) \
	E(autoreply_tsupdate)
#define RSP_WITH_ARGS \
	E(get_all_named_propids) \
	E(get_named_propids) \
	E(get_named_propnames) \
	E(get_mapping_guid) \
	E(get_mapping_replid) \
	E(get_store_all_proptags) \
	E(get_store_properties) \
	E(set_store_properties) \
	E(get_mbox_perm) \
	E(get_folder_by_class) \
	E(set_folder_by_class) \
	E(get_folder_class_table) \
	E(check_folder_id) \
	E(check_folder_deleted) \
	E(get_folder_by_name) \
	E(get_folder_perm) \
	E(create_folder_by_properties) \
	E(get_folder_all_proptags) \
	E(get_folder_properties) \
	E(set_folder_properties) \
	E(delete_folder) \
	E(empty_folder) \
	E(check_folder_cycle) \
	E(copy_folder_internal) \
	E(get_search_criteria) \
	E(set_search_criteria) \
	E(movecopy_message) \
	E(movecopy_messages) \
	E(movecopy_folder) \
	E(delete_messages) \
	E(get_message_brief) \
	E(sum_hierarchy) \
	E(load_hierarchy_table) \
	E(sum_content) \
	E(load_content_table) \
	E(load_perm_table_v1) \
	E(load_permission_table) \
	E(load_rule_table) \
	E(sum_table) \
	E(query_table) \
	E(match_table) \
	E(locate_table) \
	E(read_table_row) \
	E(mark_table) \
	E(get_table_all_proptags) \
	E(expand_table) \
	E(collapse_table) \
	E(store_table_state) \
	E(restore_table_state) \
	E(check_message) \
	E(check_message_deleted) \
	E(load_message_instance) \
	E(load_embedded_instance) \
	E(get_embedded_cn) \
	E(reload_message_instance) \
	E(read_message_instance) \
	E(write_message_instance) \
	E(load_attachment_instance) \
	E(create_attachment_instance) \
	E(read_attachment_instance) \
	E(write_attachment_instance) \
	E(flush_instance) \
	E(get_instance_all_proptags) \
	E(get_instance_properties) \
	E(set_instance_properties) \
	E(remove_instance_properties) \
	E(check_instance_cycle) \
	E(get_message_instance_rcpts_num) \
	E(get_message_instance_rcpts_all_proptags) \
	E(get_message_instance_rcpts) \
	E(copy_instance_rcpts) \
	E(get_message_instance_attachments_num) \
	E(get_message_instance_attachment_table_all_proptags) \
	E(query_message_instance_attachment_table) \
	E(copy_instance_attachments) \
	E(get_message_rcpts) \
	E(get_message_properties) \
	E(set_message_properties) \
	E(set_message_read_state) \
	E(allocate_message_id) \
	E(allocate_cn) \
	E(get_message_group_id) \
	E(get_change_indices) \
	E(try_mark_submit) \
	E(link_message) \
	E(get_message_timer) \
	E(update_folder_rule) \
	E(deliver_message) \
	E(write_message) \
	E(read_message) \
	E(get_content_sync) \
	E(get_hierarchy_sync) \
	E(allocate_ids) \
	E(subscribe_notification) \
	E(check_contact_address) \
	E(get_public_folder_unread_count) \
	E(store_eid_to_user) \
	E(autoreply_tsquery)

/* exmdb_callid::connect, exmdb_callid::listen_notification not included */
/*
 * This uses just *presponse, because the caller expects to receive the
 * same response type as the request type.
 */
pack_result exmdb_ext_pull_response(const BINARY *pbin_in, exresp *presponse)
{
	EXT_PULL ext_pull;
	
	ext_pull.init(pbin_in->pb, pbin_in->cb, exmdb_rpc_alloc, EXT_FLAG_WCOUNT);
	switch (presponse->call_id) {
#define E(t) case exmdb_callid::t:
	RSP_WITHOUT_ARGS
		return EXT_ERR_SUCCESS;
#undef E
#define E(t) case exmdb_callid::t: return exmdb_pull(ext_pull, *static_cast<exresp_ ## t *>(presponse));
	RSP_WITH_ARGS
#undef E
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

/* exmdb_callid::connect, exmdb_callid::listen_notification not included */
pack_result exmdb_ext_push_response(const exresp *presponse, BINARY *pbin_out)
{
	EXT_PUSH ext_push;
	
	if (!ext_push.init(nullptr, 0, EXT_FLAG_WCOUNT))
		return EXT_ERR_ALLOC;
	auto status = ext_push.p_uint8(static_cast<uint8_t>(exmdb_response::success));
	if (status != EXT_ERR_SUCCESS)
		return status;
	status = ext_push.advance(sizeof(uint32_t));
	if (status != EXT_ERR_SUCCESS)
		return status;

	switch (presponse->call_id) {
#define E(t) case exmdb_callid::t:
	RSP_WITHOUT_ARGS
		status = EXT_ERR_SUCCESS;
		break;
#undef E
#define E(t) case exmdb_callid::t: status = exmdb_push(ext_push, *static_cast<const exresp_ ## t *>(presponse)); break;
	RSP_WITH_ARGS
#undef E
	default:
		return EXT_ERR_BAD_SWITCH;
	}
	if (status != EXT_ERR_SUCCESS)
		return status;
	pbin_out->cb = ext_push.m_offset;
	ext_push.m_offset = 1;
	status = ext_push.p_uint32(pbin_out->cb - sizeof(uint32_t) - 1);
	if (status != EXT_ERR_SUCCESS)
		return status;
	/* memory referenced by ext_push.data will be freed outside */
	pbin_out->pb = ext_push.release();
	return EXT_ERR_SUCCESS;
}

pack_result exmdb_ext_pull_db_notify(const BINARY *pbin_in,
	DB_NOTIFY_DATAGRAM *pnotify)
{
	uint8_t tmp_byte;
	EXT_PULL ext_pull;
	
	ext_pull.init(pbin_in->pb, pbin_in->cb, exmdb_rpc_alloc, EXT_FLAG_WCOUNT);
	TRY(ext_pull.g_str(&pnotify->dir));
	TRY(ext_pull.g_bool(&pnotify->b_table));
	TRY(ext_pull.g_uint32_a(&pnotify->id_array));
	TRY(ext_pull.g_uint8(&tmp_byte));
	pnotify->db_notify.type = static_cast<db_notify_type>(tmp_byte);
	switch (pnotify->db_notify.type) {
	case db_notify_type::new_mail: {
		auto n = cu_alloc<DB_NOTIFY_NEW_MAIL>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->message_id));
		TRY(ext_pull.g_uint32(&n->message_flags));
		return ext_pull.g_str(const_cast<char **>(&n->pmessage_class));
	}
	case db_notify_type::folder_created: {
		auto n = cu_alloc<DB_NOTIFY_FOLDER_CREATED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->parent_id));
		return ext_pull.g_proptag_a(&n->proptags);
	}
	case db_notify_type::message_created: {
		auto n = cu_alloc<DB_NOTIFY_MESSAGE_CREATED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->message_id));
		return ext_pull.g_proptag_a(&n->proptags);
	}
	case db_notify_type::link_created: {
		auto n = cu_alloc<DB_NOTIFY_LINK_CREATED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->message_id));
		TRY(ext_pull.g_uint64(&n->parent_id));
		return ext_pull.g_proptag_a(&n->proptags);
	}
	case db_notify_type::folder_deleted: {
		auto n = cu_alloc<DB_NOTIFY_FOLDER_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		return ext_pull.g_uint64(&n->parent_id);
	}
	case db_notify_type::message_deleted: {
		auto n = cu_alloc<DB_NOTIFY_MESSAGE_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		return ext_pull.g_uint64(&n->message_id);
	}
	case db_notify_type::link_deleted: {
		auto n = cu_alloc<DB_NOTIFY_LINK_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->message_id));
		return ext_pull.g_uint64(&n->parent_id);
	}
	case db_notify_type::folder_modified: {
		auto n = cu_alloc<DB_NOTIFY_FOLDER_MODIFIED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint8(&tmp_byte));
		if (0 == tmp_byte) {
			n->ptotal = nullptr;
		} else {
			n->ptotal = cu_alloc<uint32_t>();
			if (n->ptotal == nullptr)
				return EXT_ERR_ALLOC;	
			TRY(ext_pull.g_uint32(n->ptotal));
		}
		TRY(ext_pull.g_uint8(&tmp_byte));
		if (0 == tmp_byte) {
			n->punread = nullptr;
		} else {
			n->punread = cu_alloc<uint32_t>();
			if (n->punread == nullptr)
				return EXT_ERR_ALLOC;	
			TRY(ext_pull.g_uint32(n->punread));
		}
		return ext_pull.g_proptag_a(&n->proptags);
	}
	case db_notify_type::message_modified: {
		auto n = cu_alloc<DB_NOTIFY_MESSAGE_MODIFIED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->message_id));
		return ext_pull.g_proptag_a(&n->proptags);
	}
	case db_notify_type::folder_moved:
	case db_notify_type::folder_copied: {
		auto n = cu_alloc<DB_NOTIFY_FOLDER_MVCP>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->parent_id));
		TRY(ext_pull.g_uint64(&n->old_folder_id));
		return ext_pull.g_uint64(&n->old_parent_id);
	}
	case db_notify_type::message_moved:
	case db_notify_type::message_copied: {
		auto n = cu_alloc<DB_NOTIFY_MESSAGE_MVCP>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->message_id));
		TRY(ext_pull.g_uint64(&n->old_folder_id));
		return ext_pull.g_uint64(&n->old_message_id);
	}
	case db_notify_type::search_completed: {
		auto n = cu_alloc<DB_NOTIFY_SEARCH_COMPLETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		return ext_pull.g_uint64(&n->folder_id);
	}
	case db_notify_type::hierarchy_table_changed:
	case db_notify_type::content_table_changed:
		return EXT_ERR_SUCCESS;
	case db_notify_type::hierarchy_table_row_added: {
		auto n = cu_alloc<DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->row_folder_id));
		return ext_pull.g_uint64(&n->after_folder_id);
	}
	case db_notify_type::content_table_row_added: {
		auto n = cu_alloc<DB_NOTIFY_CONTENT_TABLE_ROW_ADDED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->row_folder_id));
		TRY(ext_pull.g_uint64(&n->row_message_id));
		TRY(ext_pull.g_uint64(&n->row_instance));
		TRY(ext_pull.g_uint64(&n->after_folder_id));
		TRY(ext_pull.g_uint64(&n->after_row_id));
		return ext_pull.g_uint64(&n->after_instance);
	}
	case db_notify_type::hierarchy_table_row_deleted: {
		auto n = cu_alloc<DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		return ext_pull.g_uint64(&n->row_folder_id);
	}
	case db_notify_type::content_table_row_deleted: {
		auto n = cu_alloc<DB_NOTIFY_CONTENT_TABLE_ROW_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->row_folder_id));
		TRY(ext_pull.g_uint64(&n->row_message_id));
		return ext_pull.g_uint64(&n->row_instance);
	}
	case db_notify_type::hierarchy_table_row_modified: {
		auto n = cu_alloc<DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->row_folder_id));
		return ext_pull.g_uint64(&n->after_folder_id);
	}
	case db_notify_type::content_table_row_modified: {
		auto n = cu_alloc<DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->row_folder_id));
		TRY(ext_pull.g_uint64(&n->row_message_id));
		TRY(ext_pull.g_uint64(&n->row_instance));
		TRY(ext_pull.g_uint64(&n->after_folder_id));
		TRY(ext_pull.g_uint64(&n->after_row_id));
		return ext_pull.g_uint64(&n->after_instance);
	}
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

static pack_result exmdb_ext_push_db_notify2(EXT_PUSH &ext_push,
    const DB_NOTIFY_DATAGRAM *pnotify, BINARY *pbin_out)
{
	TRY(ext_push.advance(sizeof(uint32_t)));
	TRY(ext_push.p_str(pnotify->dir));
	TRY(ext_push.p_bool(pnotify->b_table));
	TRY(ext_push.p_uint32_a(pnotify->id_array));
	TRY(ext_push.p_uint8(static_cast<uint8_t>(pnotify->db_notify.type)));
	switch (pnotify->db_notify.type) {
	case db_notify_type::new_mail: {
		auto n = static_cast<const DB_NOTIFY_NEW_MAIL *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		TRY(ext_push.p_uint32(n->message_flags));
		TRY(ext_push.p_str(n->pmessage_class));
		break;
	}
	case db_notify_type::folder_created: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_CREATED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->parent_id));
		TRY(ext_push.p_proptag_a(n->proptags));
		break;
	}
	case db_notify_type::message_created: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_CREATED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		TRY(ext_push.p_proptag_a(n->proptags));
		break;
	}
	case db_notify_type::link_created: {
		auto n = static_cast<const DB_NOTIFY_LINK_CREATED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		TRY(ext_push.p_uint64(n->parent_id));
		TRY(ext_push.p_proptag_a(n->proptags));
		break;
	}
	case db_notify_type::folder_deleted: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_DELETED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->parent_id));
		break;
	}
	case db_notify_type::message_deleted: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_DELETED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		break;
	}
	case db_notify_type::link_deleted: {
		auto n = static_cast<const DB_NOTIFY_LINK_DELETED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		TRY(ext_push.p_uint64(n->parent_id));
		break;
	}
	case db_notify_type::folder_modified: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_MODIFIED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		if (n->ptotal != nullptr) {
			TRY(ext_push.p_uint8(1));
			TRY(ext_push.p_uint32(*n->ptotal));
		} else {
			TRY(ext_push.p_uint8(0));
		}
		if (n->punread != nullptr) {
			TRY(ext_push.p_uint8(1));
			TRY(ext_push.p_uint32(*n->punread));
		} else {
			TRY(ext_push.p_uint8(0));
		}
		TRY(ext_push.p_proptag_a(n->proptags));
		break;
	}
	case db_notify_type::message_modified: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_MODIFIED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		TRY(ext_push.p_proptag_a(n->proptags));
		break;
	}
	case db_notify_type::folder_moved:
	case db_notify_type::folder_copied: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_MVCP *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->parent_id));
		TRY(ext_push.p_uint64(n->old_folder_id));
		TRY(ext_push.p_uint64(n->old_parent_id));
		break;
	}
	case db_notify_type::message_moved:
	case db_notify_type::message_copied: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_MVCP *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		TRY(ext_push.p_uint64(n->old_folder_id));
		TRY(ext_push.p_uint64(n->old_message_id));
		break;
	}
	case db_notify_type::search_completed: {
		auto n = static_cast<const DB_NOTIFY_SEARCH_COMPLETED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		break;
	}
	case db_notify_type::hierarchy_table_changed:
	case db_notify_type::content_table_changed:
		break;
	case db_notify_type::hierarchy_table_row_added: {
		auto n = static_cast<const DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->row_folder_id));
		TRY(ext_push.p_uint64(n->after_folder_id));
		break;
	}
	case db_notify_type::content_table_row_added: {
		auto n = static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_ADDED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->row_folder_id));
		TRY(ext_push.p_uint64(n->row_message_id));
		TRY(ext_push.p_uint64(n->row_instance));
		TRY(ext_push.p_uint64(n->after_folder_id));
		TRY(ext_push.p_uint64(n->after_row_id));
		TRY(ext_push.p_uint64(n->after_instance));
		break;
	}
	case db_notify_type::hierarchy_table_row_deleted: {
		auto n = static_cast<const DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->row_folder_id));
		break;
	}
	case db_notify_type::content_table_row_deleted: {
		auto n = static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_DELETED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->row_folder_id));
		TRY(ext_push.p_uint64(n->row_message_id));
		TRY(ext_push.p_uint64(n->row_instance));
		break;
	}
	case db_notify_type::hierarchy_table_row_modified: {
		auto n = static_cast<const DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->row_folder_id));
		TRY(ext_push.p_uint64(n->after_folder_id));
		break;
	}
	case db_notify_type::content_table_row_modified: {
		auto n = static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->row_folder_id));
		TRY(ext_push.p_uint64(n->row_message_id));
		TRY(ext_push.p_uint64(n->row_instance));
		TRY(ext_push.p_uint64(n->after_folder_id));
		TRY(ext_push.p_uint64(n->after_row_id));
		TRY(ext_push.p_uint64(n->after_instance));
		break;
	}
	default:
		return EXT_ERR_BAD_SWITCH;
	}
	pbin_out->cb = ext_push.m_offset;
	ext_push.m_offset = 0;
	TRY(ext_push.p_uint32(pbin_out->cb - sizeof(uint32_t)));
	pbin_out->pb = ext_push.release();
	return EXT_ERR_SUCCESS;
}

pack_result exmdb_ext_push_db_notify(const DB_NOTIFY_DATAGRAM *pnotify,
	BINARY *pbin_out)
{
	EXT_PUSH ext_push;
	if (!ext_push.init(nullptr, 0, EXT_FLAG_WCOUNT))
		return EXT_ERR_ALLOC;
	return exmdb_ext_push_db_notify2(ext_push, pnotify, pbin_out);
}

const char *exmdb_rpc_strerror(exmdb_response v)
{
	switch (v) {
	case exmdb_response::access_deny: return "Access denied";
	case exmdb_response::max_reached: return "Server reached maximum number of connections";
	case exmdb_response::lack_memory: return "Out of memory";
	case exmdb_response::misconfig_prefix: return "Prefix is not served";
	case exmdb_response::misconfig_mode: return "Prefix has type mismatch";
	case exmdb_response::connect_incomplete: return "No prior CONNECT RPC made";
	case exmdb_response::pull_error: return "Invalid request/Server-side deserializing error";
	case exmdb_response::dispatch_error: return "Dispatch error";
	case exmdb_response::push_error: return "Server-side serialize error";
	default: break;
	}
	thread_local char xbuf[32];
	snprintf(xbuf, std::size(xbuf), "Unknown error %u", static_cast<unsigned int>(v));
	return xbuf;
}

BOOL exmdb_client_read_socket(int fd, BINARY &bin, long timeout_ms)
{
	uint32_t offset = 0;
	struct pollfd pfd;

	bin.cb = 0;
	bin.pb = nullptr;
	pfd.fd = fd;
	pfd.events = POLLIN | POLLPRI;

	while (true) {
		if (timeout_ms >= 0 && poll(&pfd, 1, timeout_ms) != 1) {
			exmdb_rpc_free(bin.pb);
			bin.pb = nullptr;
			return false;
		}

		if (bin.cb == 0) {
			uint8_t resp_buff[5];
			ssize_t read_len = read(fd, resp_buff, 5);
			if (read_len == 1) {
				bin.cb = 1;
				bin.pb = static_cast<uint8_t *>(exmdb_rpc_alloc(1));
				if (bin.pb == nullptr)
					return false;
				*bin.pb = resp_buff[0];
				return TRUE;
			} else if (read_len == 5) {
				bin.cb = le32p_to_cpu(resp_buff + 1) + 5;
				bin.pb = static_cast<uint8_t *>(exmdb_rpc_alloc(bin.cb));
				if (bin.pb == nullptr) {
					bin.cb = 0;
					return false;
				}
				memcpy(bin.pv, resp_buff, 5);
				offset = 5;
				if (offset == bin.cb)
					return TRUE;
				continue;
			} else {
				exmdb_rpc_free(bin.pb);
				bin.pb = nullptr;
				return false;
			}
		}
		ssize_t read_len = read(fd, bin.pb + offset, bin.cb - offset);
		if (read_len <= 0) {
			exmdb_rpc_free(bin.pb);
			bin.pb = nullptr;
			return false;
		}
		offset += read_len;
		if (offset == bin.cb)
			return TRUE;
	}
}

BOOL exmdb_client_write_socket(int fd, const BINARY &bin, long timeout_ms)
{
	uint32_t offset = 0;
	struct pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT | POLLWRBAND;

	while (true) {
		if (timeout_ms >= 0 && poll(&pfd, 1, timeout_ms) != 1)
			return false;
		ssize_t written_len = write(fd, bin.pb + offset, bin.cb - offset);
		if (written_len <= 0)
			return false;
		offset += written_len;
		if (offset == bin.cb)
			return TRUE;
	}
}
