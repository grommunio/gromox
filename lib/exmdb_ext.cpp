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
#include <gromox/scope.hpp>
#include <gromox/rop_util.hpp>
#define TRY(expr) do { int v = (expr); if (v != EXT_ERR_SUCCESS) return v; } while (false)

using namespace gromox;
using REQUEST_PAYLOAD = EXMDB_REQUEST_PAYLOAD;
using RESPONSE_PAYLOAD = EXMDB_RESPONSE_PAYLOAD;

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

static int exmdb_pull(EXT_PULL &x, EXREQ_CONNECT &d)
{
	TRY(x.g_str(&d.prefix));
	TRY(x.g_str(&d.remote_id));
	return x.g_bool(&d.b_private);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CONNECT &d)
{
	TRY(x.p_str(d.prefix));
	TRY(x.p_str(d.remote_id));
	return x.p_bool(d.b_private);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_LISTEN_NOTIFICATION &d)
{
	return x.g_str(&d.remote_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_LISTEN_NOTIFICATION &d)
{
	return x.p_str(d.remote_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_NAMED_PROPIDS &d)
{
	TRY(x.g_bool(&d.b_create));
	d.ppropnames = cu_alloc<PROPNAME_ARRAY>();
	if (d.ppropnames == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_propname_a(d.ppropnames);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_NAMED_PROPIDS &d)
{
	TRY(x.p_bool(d.b_create));
	return x.p_propname_a(*d.ppropnames);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_NAMED_PROPNAMES &d)
{
	d.ppropids = cu_alloc<PROPID_ARRAY>();
	if (d.ppropids == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_propid_a(d.ppropids);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_NAMED_PROPNAMES &d)
{
	return x.p_propid_a(*d.ppropids);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_MAPPING_GUID &d)
{
	return x.g_uint16(&d.replid);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_MAPPING_GUID &d)
{
	return x.p_uint16(d.replid);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_MAPPING_REPLID &d)
{
	return x.g_guid(&d.guid);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_MAPPING_REPLID &d)
{
	return x.p_guid(d.guid);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_STORE_PROPERTIES &d)
{
	TRY(x.g_uint32(&d.cpid));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_STORE_PROPERTIES &d)
{
	TRY(x.p_uint32(d.cpid));
	return x.p_proptag_a(*d.pproptags);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_SET_STORE_PROPERTIES &d)
{
	TRY(x.g_uint32(&d.cpid));
	d.ppropvals = cu_alloc<TPROPVAL_ARRAY>();
	if (d.ppropvals == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_tpropval_a(d.ppropvals);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_SET_STORE_PROPERTIES &d)
{
	TRY(x.p_uint32(d.cpid));
	return x.p_tpropval_a(*d.ppropvals);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_REMOVE_STORE_PROPERTIES &d)
{
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_REMOVE_STORE_PROPERTIES &d)
{
	return x.p_proptag_a(*d.pproptags);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_CHECK_MAILBOX_PERMISSION &d)
{
	return x.g_str(&d.username);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CHECK_MAILBOX_PERMISSION &d)
{
	return x.p_str(d.username);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_FOLDER_BY_CLASS &d)
{
	return x.g_str(&d.str_class);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_FOLDER_BY_CLASS &d)
{
	return x.p_str(d.str_class);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_SET_FOLDER_BY_CLASS &d)
{
	TRY(x.g_uint64(&d.folder_id));
	return x.g_str(&d.str_class);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_SET_FOLDER_BY_CLASS &d)
{
	TRY(x.p_uint64(d.folder_id));
	return x.p_str(d.str_class);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_CHECK_FOLDER_ID &d)
{
	return x.g_uint64(&d.folder_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CHECK_FOLDER_ID &d)
{
	return x.p_uint64(d.folder_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_QUERY_FOLDER_MESSAGES &d)
{
	return x.g_uint64(&d.folder_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_QUERY_FOLDER_MESSAGES &d)
{
	return x.p_uint64(d.folder_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_CHECK_FOLDER_DELETED &d)
{
	return x.g_uint64(&d.folder_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CHECK_FOLDER_DELETED &d)
{
	return x.p_uint64(d.folder_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_FOLDER_BY_NAME &d)
{
	TRY(x.g_uint64(&d.parent_id));
	return x.g_str(&d.str_name);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_FOLDER_BY_NAME &d)
{
	TRY(x.p_uint64(d.parent_id));
	return x.p_str(d.str_name);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_CHECK_FOLDER_PERMISSION &d)
{
	TRY(x.g_uint64(&d.folder_id));
	return x.g_str(&d.username);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CHECK_FOLDER_PERMISSION &d)
{
	TRY(x.p_uint64(d.folder_id));
	return x.p_str(d.username);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_CREATE_FOLDER_BY_PROPERTIES &d)
{
	TRY(x.g_uint32(&d.cpid));
	d.pproperties = cu_alloc<TPROPVAL_ARRAY>();
	if (d.pproperties == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_tpropval_a(d.pproperties);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CREATE_FOLDER_BY_PROPERTIES &d)
{
	TRY(x.p_uint32(d.cpid));
	return x.p_tpropval_a(*d.pproperties);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_FOLDER_ALL_PROPTAGS &d)
{
	return x.g_uint64(&d.folder_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_FOLDER_ALL_PROPTAGS &d)
{
	return x.p_uint64(d.folder_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_FOLDER_PROPERTIES &d)
{
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_FOLDER_PROPERTIES &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	return x.p_proptag_a(*d.pproptags);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_SET_FOLDER_PROPERTIES &d)
{
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	d.pproperties = cu_alloc<TPROPVAL_ARRAY>();
	if (d.pproperties == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_tpropval_a(d.pproperties);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_SET_FOLDER_PROPERTIES &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	return x.p_tpropval_a(*d.pproperties);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_REMOVE_FOLDER_PROPERTIES &d)
{
	TRY(x.g_uint64(&d.folder_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_REMOVE_FOLDER_PROPERTIES &d)
{
	TRY(x.p_uint64(d.folder_id));
	return x.p_proptag_a(*d.pproptags);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_DELETE_FOLDER &d)
{
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	return x.g_bool(&d.b_hard);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_DELETE_FOLDER &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	return x.p_bool(d.b_hard);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_EMPTY_FOLDER &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == '\0')
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_bool(&d.b_hard));
	TRY(x.g_bool(&d.b_normal));
	TRY(x.g_bool(&d.b_fai));
	return x.g_bool(&d.b_sub);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_EMPTY_FOLDER &d)
{
	TRY(x.p_uint32(d.cpid));
	if (d.username == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.username));
	}
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_bool(d.b_hard));
	TRY(x.p_bool(d.b_normal));
	TRY(x.p_bool(d.b_fai));
	return x.p_bool(d.b_sub);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_CHECK_FOLDER_CYCLE &d)
{
	TRY(x.g_uint64(&d.src_fid));
	return x.g_uint64(&d.dst_fid);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CHECK_FOLDER_CYCLE &d)
{
	TRY(x.p_uint64(d.src_fid));
	return x.p_uint64(d.dst_fid);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_COPY_FOLDER_INTERNAL &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.account_id));
	TRY(x.g_uint32(&d.cpid));
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_COPY_FOLDER_INTERNAL &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_SEARCH_CRITERIA &d)
{
	return x.g_uint64(&d.folder_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_SEARCH_CRITERIA &d)
{
	return x.p_uint64(d.folder_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_SET_SEARCH_CRITERIA &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.cpid));
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_SET_SEARCH_CRITERIA &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_MOVECOPY_MESSAGE &d)
{
	TRY(x.g_uint32(&d.account_id));
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint64(&d.message_id));
	TRY(x.g_uint64(&d.dst_fid));
	TRY(x.g_uint64(&d.dst_id));
	return x.g_bool(&d.b_move);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_MOVECOPY_MESSAGE &d)
{
	TRY(x.p_uint32(d.account_id));
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.message_id));
	TRY(x.p_uint64(d.dst_fid));
	TRY(x.p_uint64(d.dst_id));
	return x.p_bool(d.b_move);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_MOVECOPY_MESSAGES &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.account_id));
	TRY(x.g_uint32(&d.cpid));
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_MOVECOPY_MESSAGES &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_MOVECOPY_FOLDER &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.account_id));
	TRY(x.g_uint32(&d.cpid));
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_MOVECOPY_FOLDER &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_DELETE_MESSAGES &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.account_id));
	TRY(x.g_uint32(&d.cpid));
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_DELETE_MESSAGES &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_MESSAGE_BRIEF &d)
{
	TRY(x.g_uint32(&d.cpid));
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_MESSAGE_BRIEF &d)
{
	TRY(x.p_uint32(d.cpid));
	return x.p_uint64(d.message_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_SUM_HIERARCHY &d)
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_SUM_HIERARCHY &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_LOAD_HIERARCHY_TABLE &d)
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_LOAD_HIERARCHY_TABLE &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_SUM_CONTENT &d)
{
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_bool(&d.b_fai));
	return x.g_bool(&d.b_deleted);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_SUM_CONTENT &d)
{
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_bool(d.b_fai));
	return x.p_bool(d.b_deleted);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_LOAD_CONTENT_TABLE &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint32(&d.cpid));
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_LOAD_CONTENT_TABLE &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_RELOAD_CONTENT_TABLE &d)
{
	return x.g_uint32(&d.table_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_RELOAD_CONTENT_TABLE &d)
{
	return x.p_uint32(d.table_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_LOAD_PERMISSION_TABLE &d)
{
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint8(&d.table_flags);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_LOAD_PERMISSION_TABLE &d)
{
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint8(d.table_flags);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_LOAD_RULE_TABLE &d)
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_LOAD_RULE_TABLE &d)
{
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_uint8(d.table_flags));
	if (d.prestriction == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return x.p_restriction(*d.prestriction);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_UNLOAD_TABLE &d)
{
	return x.g_uint32(&d.table_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_UNLOAD_TABLE &d)
{
	return x.p_uint32(d.table_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_SUM_TABLE &d)
{
	return x.g_uint32(&d.table_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_SUM_TABLE &d)
{
	return x.p_uint32(d.table_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_QUERY_TABLE &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint32(&d.table_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_proptag_a(d.pproptags));
	TRY(x.g_uint32(&d.start_pos));
	return x.g_int32(&d.row_needed);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_QUERY_TABLE &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_MATCH_TABLE &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint32(&d.cpid));
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_MATCH_TABLE &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_LOCATE_TABLE &d)
{
	TRY(x.g_uint32(&d.table_id));
	TRY(x.g_uint64(&d.inst_id));
	return x.g_uint32(&d.inst_num);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_LOCATE_TABLE &d)
{
	TRY(x.p_uint32(d.table_id));
	TRY(x.p_uint64(d.inst_id));
	return x.p_uint32(d.inst_num);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_READ_TABLE_ROW &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint32(&d.table_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_proptag_a(d.pproptags));
	TRY(x.g_uint64(&d.inst_id));
	return x.g_uint32(&d.inst_num);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_READ_TABLE_ROW &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_MARK_TABLE &d)
{
	TRY(x.g_uint32(&d.table_id));
	return x.g_uint32(&d.position);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_MARK_TABLE &d)
{
	TRY(x.p_uint32(d.table_id));
	return x.p_uint32(d.position);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_TABLE_ALL_PROPTAGS &d)
{
	return x.g_uint32(&d.table_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_TABLE_ALL_PROPTAGS &d)
{
	return x.p_uint32(d.table_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_EXPAND_TABLE &d)
{
	TRY(x.g_uint32(&d.table_id));
	return x.g_uint64(&d.inst_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_EXPAND_TABLE &d)
{
	TRY(x.p_uint32(d.table_id));
	return x.p_uint64(d.inst_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_COLLAPSE_TABLE &d)
{
	TRY(x.g_uint32(&d.table_id));
	return x.g_uint64(&d.inst_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_COLLAPSE_TABLE &d)
{
	TRY(x.p_uint32(d.table_id));
	return x.p_uint64(d.inst_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_STORE_TABLE_STATE &d)
{
	TRY(x.g_uint32(&d.table_id));
	TRY(x.g_uint64(&d.inst_id));
	return x.g_uint32(&d.inst_num);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_STORE_TABLE_STATE &d)
{
	TRY(x.p_uint32(d.table_id));
	TRY(x.p_uint64(d.inst_id));
	return x.p_uint32(d.inst_num);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_RESTORE_TABLE_STATE &d)
{
	TRY(x.g_uint32(&d.table_id));
	return x.g_uint32(&d.state_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_RESTORE_TABLE_STATE &d)
{
	TRY(x.p_uint32(d.table_id));
	return x.p_uint32(d.state_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_CHECK_MESSAGE &d)
{
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CHECK_MESSAGE &d)
{
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint64(d.message_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_CHECK_MESSAGE_DELETED &d)
{
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CHECK_MESSAGE_DELETED &d)
{
	return x.p_uint64(d.message_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_LOAD_MESSAGE_INSTANCE &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_bool(&d.b_new));
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_LOAD_MESSAGE_INSTANCE &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_LOAD_EMBEDDED_INSTANCE &d)
{
	TRY(x.g_bool(&d.b_new));
	return x.g_uint32(&d.attachment_instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_LOAD_EMBEDDED_INSTANCE &d)
{
	TRY(x.p_bool(d.b_new));
	return x.p_uint32(d.attachment_instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_EMBEDDED_CN &d)
{
	return x.g_uint32(&d.instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_EMBEDDED_CN &d)
{
	return x.p_uint32(d.instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_RELOAD_MESSAGE_INSTANCE &d)
{
	return x.g_uint32(&d.instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_RELOAD_MESSAGE_INSTANCE &d)
{
	return x.p_uint32(d.instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_CLEAR_MESSAGE_INSTANCE &d)
{
	return x.g_uint32(&d.instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CLEAR_MESSAGE_INSTANCE &d)
{
	return x.p_uint32(d.instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_READ_MESSAGE_INSTANCE &d)
{
	return x.g_uint32(&d.instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_READ_MESSAGE_INSTANCE &d)
{
	return x.p_uint32(d.instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_WRITE_MESSAGE_INSTANCE &d)
{
	TRY(x.g_uint32(&d.instance_id));
	d.pmsgctnt = cu_alloc<MESSAGE_CONTENT>();
	if (d.pmsgctnt == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_msgctnt(d.pmsgctnt));
	return x.g_bool(&d.b_force);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_WRITE_MESSAGE_INSTANCE &d)
{
	TRY(x.p_uint32(d.instance_id));
	TRY(x.p_msgctnt(*d.pmsgctnt));
	return x.p_bool(d.b_force);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_LOAD_ATTACHMENT_INSTANCE &d)
{
	TRY(x.g_uint32(&d.message_instance_id));
	return x.g_uint32(&d.attachment_num);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_LOAD_ATTACHMENT_INSTANCE &d)
{
	TRY(x.p_uint32(d.message_instance_id));
	return x.p_uint32(d.attachment_num);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_CREATE_ATTACHMENT_INSTANCE &d)
{
	return x.g_uint32(&d.message_instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CREATE_ATTACHMENT_INSTANCE &d)
{
	return x.p_uint32(d.message_instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_READ_ATTACHMENT_INSTANCE &d)
{
	return x.g_uint32(&d.instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_READ_ATTACHMENT_INSTANCE &d)
{
	return x.p_uint32(d.instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_WRITE_ATTACHMENT_INSTANCE &d)
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_WRITE_ATTACHMENT_INSTANCE &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_DELETE_MESSAGE_INSTANCE_ATTACHMENT &d)
{
	TRY(x.g_uint32(&d.message_instance_id));
	return x.g_uint32(&d.attachment_num);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_DELETE_MESSAGE_INSTANCE_ATTACHMENT &d)
{
	TRY(x.p_uint32(d.message_instance_id));
	return x.p_uint32(d.attachment_num);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_FLUSH_INSTANCE &d)
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_FLUSH_INSTANCE &d)
{
	TRY(x.p_uint32(d.instance_id));
	if (d.account == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return x.p_str(d.account);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_UNLOAD_INSTANCE &d)
{
	return x.g_uint32(&d.instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_UNLOAD_INSTANCE &d)
{
	return x.p_uint32(d.instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_INSTANCE_ALL_PROPTAGS &d)
{
	return x.g_uint32(&d.instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_INSTANCE_ALL_PROPTAGS &d)
{
	return x.p_uint32(d.instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_INSTANCE_PROPERTIES &d)
{
	TRY(x.g_uint32(&d.size_limit));
	TRY(x.g_uint32(&d.instance_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_INSTANCE_PROPERTIES &d)
{
	TRY(x.p_uint32(d.size_limit));
	TRY(x.p_uint32(d.instance_id));
	return x.p_proptag_a(*d.pproptags);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_SET_INSTANCE_PROPERTIES &d)
{
	TRY(x.g_uint32(&d.instance_id));
	d.pproperties = cu_alloc<TPROPVAL_ARRAY>();
	if (d.pproperties == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_tpropval_a(d.pproperties);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_SET_INSTANCE_PROPERTIES &d)
{
	TRY(x.p_uint32(d.instance_id));
	return x.p_tpropval_a(*d.pproperties);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_REMOVE_INSTANCE_PROPERTIES &d)
{
	TRY(x.g_uint32(&d.instance_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_REMOVE_INSTANCE_PROPERTIES &d)
{
	TRY(x.p_uint32(d.instance_id));
	return x.p_proptag_a(*d.pproptags);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_CHECK_INSTANCE_CYCLE &d)
{
	TRY(x.g_uint32(&d.src_instance_id));
	return x.g_uint32(&d.dst_instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CHECK_INSTANCE_CYCLE &d)
{
	TRY(x.p_uint32(d.src_instance_id));
	return x.p_uint32(d.dst_instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_EMPTY_MESSAGE_INSTANCE_RCPTS &d)
{
	return x.g_uint32(&d.instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_EMPTY_MESSAGE_INSTANCE_RCPTS &d)
{
	return x.p_uint32(d.instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_MESSAGE_INSTANCE_RCPTS_NUM &d)
{
	return x.g_uint32(&d.instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_MESSAGE_INSTANCE_RCPTS_NUM &d)
{
	return x.p_uint32(d.instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS &d)
{
	return x.g_uint32(&d.instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS &d)
{
	return x.p_uint32(d.instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_MESSAGE_INSTANCE_RCPTS &d)
{
	TRY(x.g_uint32(&d.instance_id));
	TRY(x.g_uint32(&d.row_id));
	return x.g_uint16(&d.need_count);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_MESSAGE_INSTANCE_RCPTS &d)
{
	TRY(x.p_uint32(d.instance_id));
	TRY(x.p_uint32(d.row_id));
	return x.p_uint16(d.need_count);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_UPDATE_MESSAGE_INSTANCE_RCPTS &d)
{
	TRY(x.g_uint32(&d.instance_id));
	d.pset = cu_alloc<TARRAY_SET>();
	if (d.pset == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_tarray_set(d.pset);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_UPDATE_MESSAGE_INSTANCE_RCPTS &d)
{
	TRY(x.p_uint32(d.instance_id));
	return x.p_tarray_set(*d.pset);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_COPY_INSTANCE_RCPTS &d)
{
	TRY(x.g_bool(&d.b_force));
	TRY(x.g_uint32(&d.src_instance_id));
	return x.g_uint32(&d.dst_instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_COPY_INSTANCE_RCPTS &d)
{
	TRY(x.p_bool(d.b_force));
	TRY(x.p_uint32(d.src_instance_id));
	return x.p_uint32(d.dst_instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_EMPTY_MESSAGE_INSTANCE_ATTACHMENTS &d)
{
	return x.g_uint32(&d.instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_EMPTY_MESSAGE_INSTANCE_ATTACHMENTS &d)
{
	return x.p_uint32(d.instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM &d)
{
	return x.g_uint32(&d.instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM &d)
{
	return x.p_uint32(d.instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS &d)
{
	return x.g_uint32(&d.instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS &d)
{
	return x.p_uint32(d.instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE &d)
{
	TRY(x.g_uint32(&d.instance_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_proptag_a(d.pproptags));
	TRY(x.g_uint32(&d.start_pos));
	return x.g_int32(&d.row_needed);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE &d)
{
	TRY(x.p_uint32(d.instance_id));
	TRY(x.p_proptag_a(*d.pproptags));
	TRY(x.p_uint32(d.start_pos));
	return x.p_int32(d.row_needed);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_COPY_INSTANCE_ATTACHMENTS &d)
{
	TRY(x.g_bool(&d.b_force));
	TRY(x.g_uint32(&d.src_instance_id));
	return x.g_uint32(&d.dst_instance_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_COPY_INSTANCE_ATTACHMENTS &d)
{
	TRY(x.p_bool(d.b_force));
	TRY(x.p_uint32(d.src_instance_id));
	return x.p_uint32(d.dst_instance_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_SET_MESSAGE_INSTANCE_CONFLICT &d)
{
	TRY(x.g_uint32(&d.instance_id));
	d.pmsgctnt = cu_alloc<MESSAGE_CONTENT>();
	if (d.pmsgctnt == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_msgctnt(d.pmsgctnt);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_SET_MESSAGE_INSTANCE_CONFLICT &d)
{
	TRY(x.p_uint32(d.instance_id));
	return x.p_msgctnt(*d.pmsgctnt);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_MESSAGE_RCPTS &d)
{
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_MESSAGE_RCPTS &d)
{
	return x.p_uint64(d.message_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_MESSAGE_PROPERTIES &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint64(&d.message_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_MESSAGE_PROPERTIES &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_SET_MESSAGE_PROPERTIES &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint64(&d.message_id));
	d.pproperties = cu_alloc<TPROPVAL_ARRAY>();
	if (d.pproperties == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_tpropval_a(d.pproperties);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_SET_MESSAGE_PROPERTIES &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_SET_MESSAGE_READ_STATE &d)
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_SET_MESSAGE_READ_STATE &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_REMOVE_MESSAGE_PROPERTIES &d)
{
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint64(&d.message_id));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_proptag_a(d.pproptags);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_REMOVE_MESSAGE_PROPERTIES &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.message_id));
	return x.p_proptag_a(*d.pproptags);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_ALLOCATE_MESSAGE_ID &d)
{
	return x.g_uint64(&d.folder_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_ALLOCATE_MESSAGE_ID &d)
{
	return x.p_uint64(d.folder_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_MESSAGE_GROUP_ID &d)
{
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_MESSAGE_GROUP_ID &d)
{
	return x.p_uint64(d.message_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_SET_MESSAGE_GROUP_ID &d)
{
	TRY(x.g_uint64(&d.message_id));
	return x.g_uint32(&d.group_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_SET_MESSAGE_GROUP_ID &d)
{
	TRY(x.p_uint64(d.message_id));
	return x.p_uint32(d.group_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_SAVE_CHANGE_INDICES &d)
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_SAVE_CHANGE_INDICES &d)
{
	TRY(x.p_uint64(d.message_id));
	TRY(x.p_uint64(d.cn));
	TRY(x.p_proptag_a(*d.pindices));
	return x.p_proptag_a(*d.pungroup_proptags);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_CHANGE_INDICES &d)
{
	TRY(x.g_uint64(&d.message_id));
	return x.g_uint64(&d.cn);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_CHANGE_INDICES &d)
{
	TRY(x.p_uint64(d.message_id));
	return x.p_uint64(d.cn);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_MARK_MODIFIED &d)
{
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_MARK_MODIFIED &d)
{
	return x.p_uint64(d.message_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_TRY_MARK_SUBMIT &d)
{
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_TRY_MARK_SUBMIT &d)
{
	return x.p_uint64(d.message_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_CLEAR_SUBMIT &d)
{
	TRY(x.g_uint64(&d.message_id));
	return x.g_bool(&d.b_unsent);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CLEAR_SUBMIT &d)
{
	TRY(x.p_uint64(d.message_id));
	return x.p_bool(d.b_unsent);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_LINK_MESSAGE &d)
{
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_LINK_MESSAGE &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint64(d.message_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_UNLINK_MESSAGE &d)
{
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_UNLINK_MESSAGE &d)
{
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint64(d.message_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_RULE_NEW_MESSAGE &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_str(&d.account));
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_RULE_NEW_MESSAGE &d)
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

static int exmdb_pull(EXT_PULL &x, EXREQ_SET_MESSAGE_TIMER &d)
{
	TRY(x.g_uint64(&d.message_id));
	return x.g_uint32(&d.timer_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_SET_MESSAGE_TIMER &d)
{
	TRY(x.p_uint64(d.message_id));
	return x.p_uint32(d.timer_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_MESSAGE_TIMER &d)
{
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_MESSAGE_TIMER &d)
{
	return x.p_uint64(d.message_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_EMPTY_FOLDER_PERMISSION &d)
{
	return x.g_uint64(&d.folder_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_EMPTY_FOLDER_PERMISSION &d)
{
	return x.p_uint64(d.folder_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_UPDATE_FOLDER_PERMISSION &d)
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_UPDATE_FOLDER_PERMISSION &d)
{
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_bool(d.b_freebusy));
	TRY(x.p_uint16(d.count));
	for (size_t i = 0; i < d.count; ++i)
		TRY(x.p_permission_data(d.prow[i]));
	return EXT_ERR_SUCCESS;
}

static int exmdb_pull(EXT_PULL &x, EXREQ_EMPTY_FOLDER_RULE &d)
{
	return x.g_uint64(&d.folder_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_EMPTY_FOLDER_RULE &d)
{
	return x.p_uint64(d.folder_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_UPDATE_FOLDER_RULE &d)
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_UPDATE_FOLDER_RULE &d)
{
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_uint16(d.count));
	for (size_t i = 0; i < d.count; ++i)
		TRY(x.p_rule_data(d.prow[i]));
	return EXT_ERR_SUCCESS;
}

static int exmdb_pull(EXT_PULL &x, EXREQ_DELIVERY_MESSAGE &d)
{
	TRY(x.g_str(&d.from_address));
	TRY(x.g_str(&d.account));
	TRY(x.g_uint32(&d.cpid));
	d.pmsg = cu_alloc<MESSAGE_CONTENT>();
	if (d.pmsg == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_msgctnt(d.pmsg));
	return x.g_str(&d.pdigest);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_DELIVERY_MESSAGE &d)
{
	TRY(x.p_str(d.from_address));
	TRY(x.p_str(d.account));
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_msgctnt(*d.pmsg));
	return x.p_str(d.pdigest);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_WRITE_MESSAGE &d)
{
	TRY(x.g_str(&d.account));
	TRY(x.g_uint32(&d.cpid));
	TRY(x.g_uint64(&d.folder_id));
	d.pmsgctnt = cu_alloc<MESSAGE_CONTENT>();
	if (d.pmsgctnt == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_msgctnt(d.pmsgctnt);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_WRITE_MESSAGE &d)
{
	TRY(x.p_str(d.account));
	TRY(x.p_uint32(d.cpid));
	TRY(x.p_uint64(d.folder_id));
	return x.p_msgctnt(*d.pmsgctnt);
}
	
static int exmdb_pull(EXT_PULL &x, EXREQ_READ_MESSAGE &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.username = nullptr;
	else
		TRY(x.g_str(&d.username));
	TRY(x.g_uint32(&d.cpid));
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_READ_MESSAGE &d)
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

static int gcsr_failure(int status, EXREQ_GET_CONTENT_SYNC &d)
{
	delete d.pgiven;
	delete d.pseen;
	delete d.pseen_fai;
	delete d.pread;
	return status;
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_CONTENT_SYNC &d)
{
	int status;
	BINARY tmp_bin;
	uint8_t tmp_byte;
	
	memset(&d, 0, sizeof(d));
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte != 0)
		TRY(x.g_str(&d.username));
	TRY(x.g_exbin(&tmp_bin));
	d.pgiven = new(std::nothrow) idset(false, REPL_TYPE_ID);
	if (d.pgiven == nullptr)
		return EXT_ERR_ALLOC;
	if (!d.pgiven->deserialize(&tmp_bin)) {
		delete d.pgiven;
		return EXT_ERR_FORMAT;
	}
	status = x.g_uint8(&tmp_byte);
	if (status != EXT_ERR_SUCCESS)
		return gcsr_failure(status, d);
	if (0 != tmp_byte) {
		status = x.g_exbin(&tmp_bin);
		if (status != EXT_ERR_SUCCESS)
			return gcsr_failure(status, d);
		d.pseen = new(std::nothrow) idset(false, REPL_TYPE_ID);
		if (d.pseen == nullptr)
			return gcsr_failure(EXT_ERR_ALLOC, d);
		if (!d.pseen->deserialize(&tmp_bin))
			return gcsr_failure(EXT_ERR_FORMAT, d);
	}
	status = x.g_uint8(&tmp_byte);
	if (status != EXT_ERR_SUCCESS)
		return gcsr_failure(status, d);
	if (0 != tmp_byte) {
		status = x.g_exbin(&tmp_bin);
		if (status != EXT_ERR_SUCCESS)
			return gcsr_failure(status, d);
		d.pseen_fai = new(std::nothrow) idset(false, REPL_TYPE_ID);
		if (d.pseen_fai == nullptr)
			return gcsr_failure(EXT_ERR_ALLOC, d);
		if (!d.pseen_fai->deserialize(&tmp_bin))
			return gcsr_failure(EXT_ERR_FORMAT, d);
	}
	status = x.g_uint8(&tmp_byte);
	if (status != EXT_ERR_SUCCESS)
		return gcsr_failure(status, d);
	if (0 != tmp_byte) {
		status = x.g_exbin(&tmp_bin);
		if (status != EXT_ERR_SUCCESS)
			return gcsr_failure(status, d);
		d.pread = new(std::nothrow) idset(false, REPL_TYPE_ID);
		if (d.pread == nullptr)
			return gcsr_failure(EXT_ERR_ALLOC, d);
		if (!d.pread->deserialize(&tmp_bin))
			return gcsr_failure(EXT_ERR_FORMAT, d);
	}
	status = x.g_uint32(&d.cpid);
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

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_CONTENT_SYNC &d)
{
	int status;
	
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
	status = x.p_bin_ex(*pbin);
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

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_HIERARCHY_SYNC &d)
{
	int status;
	BINARY tmp_bin;
	uint8_t tmp_byte;
	
	memset(&d, 0, sizeof(d));
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint8(&tmp_byte));
	if (tmp_byte != 0)
		TRY(x.g_str(&d.username));
	TRY(x.g_exbin(&tmp_bin));
	d.pgiven = new(std::nothrow) idset(false, REPL_TYPE_ID);
	if (d.pgiven == nullptr)
		return EXT_ERR_ALLOC;
	if (!d.pgiven->deserialize(&tmp_bin)) {
		delete d.pgiven;
		return EXT_ERR_FORMAT;
	}
	status = x.g_uint8(&tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		delete d.pgiven;
		return status;
	}
	if (0 != tmp_byte) {
		status = x.g_exbin(&tmp_bin);
		if (EXT_ERR_SUCCESS != status) {
			delete d.pgiven;
			return status;
		}
		d.pseen = new(std::nothrow) idset(false, REPL_TYPE_ID);
		if (d.pseen == nullptr) {
			delete d.pgiven;
			return EXT_ERR_ALLOC;
		}
		if (!d.pseen->deserialize(&tmp_bin)) {
			delete d.pseen;
			delete d.pgiven;
			return EXT_ERR_FORMAT;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_HIERARCHY_SYNC &d)
{
	int status;
	
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
	status = x.p_bin_ex(*pbin);
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

static int exmdb_pull(EXT_PULL &x, EXREQ_ALLOCATE_IDS &d)
{
	return x.g_uint32(&d.count);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_ALLOCATE_IDS &d)
{
	return x.p_uint32(d.count);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_SUBSCRIBE_NOTIFICATION &d)
{
	TRY(x.g_uint16(&d.notificaton_type));
	TRY(x.g_bool(&d.b_whole));
	TRY(x.g_uint64(&d.folder_id));
	return x.g_uint64(&d.message_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_SUBSCRIBE_NOTIFICATION &d)
{
	TRY(x.p_uint16(d.notificaton_type));
	TRY(x.p_bool(d.b_whole));
	TRY(x.p_uint64(d.folder_id));
	return x.p_uint64(d.message_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_UNSUBSCRIBE_NOTIFICATION &d)
{
	return x.g_uint32(&d.sub_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_UNSUBSCRIBE_NOTIFICATION &d)
{
	return x.p_uint32(d.sub_id);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_TRANSPORT_NEW_MAIL &d)
{
	TRY(x.g_uint64(&d.folder_id));
	TRY(x.g_uint64(&d.message_id));
	TRY(x.g_uint32(&d.message_flags));
	return x.g_str(&d.pstr_class);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_TRANSPORT_NEW_MAIL &d)
{
	TRY(x.p_uint64(d.folder_id));
	TRY(x.p_uint64(d.message_id));
	TRY(x.p_uint32(d.message_flags));
	return x.p_str(d.pstr_class);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_CHECK_CONTACT_ADDRESS &d)
{
	return x.g_str(&d.paddress);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_CHECK_CONTACT_ADDRESS &d)
{
	return x.p_str(d.paddress);
}

static int exmdb_pull(EXT_PULL &x, EXREQ_GET_PUBLIC_FOLDER_UNREAD_COUNT &d)
{
	TRY(x.g_str(&d.username));
	return x.g_uint64(&d.folder_id);
}

static int exmdb_push(EXT_PUSH &x, const EXREQ_GET_PUBLIC_FOLDER_UNREAD_COUNT &d)
{
	TRY(x.p_str(d.username));
	return x.p_uint64(d.folder_id);
}

#define RQ_WITH_ARGS \
	E(get_named_propids) \
	E(get_named_propnames) \
	E(get_mapping_guid) \
	E(get_mapping_replid) \
	E(get_store_properties) \
	E(set_store_properties) \
	E(remove_store_properties) \
	E(check_mailbox_permission) \
	E(get_folder_by_class) \
	E(set_folder_by_class) \
	E(check_folder_id) \
	E(query_folder_messages) \
	E(check_folder_deleted) \
	E(get_folder_by_name) \
	E(check_folder_permission) \
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
	E(delivery_message) \
	E(write_message) \
	E(read_message) \
	E(get_content_sync) \
	E(get_hierarchy_sync) \
	E(allocate_ids) \
	E(subscribe_notification) \
	E(unsubscribe_notification) \
	E(transport_new_mail) \
	E(check_contact_address) \
	E(get_public_folder_unread_count)

int exmdb_ext_pull_request(const BINARY *pbin_in,
	EXMDB_REQUEST *prequest)
{
	EXT_PULL ext_pull;
	uint8_t call_id;
	
	ext_pull.init(pbin_in->pb, pbin_in->cb, exmdb_rpc_alloc, EXT_FLAG_WCOUNT);
	TRY(ext_pull.g_uint8(&call_id));
	prequest->call_id = static_cast<exmdb_callid>(call_id);
	if (prequest->call_id == exmdb_callid::connect)
		return exmdb_pull(ext_pull, prequest->payload.connect);
	else if (prequest->call_id == exmdb_callid::listen_notification)
		return exmdb_pull(ext_pull, prequest->payload.listen_notification);

	TRY(ext_pull.g_str(&prequest->dir));
	switch (prequest->call_id) {
	case exmdb_callid::ping_store:
	case exmdb_callid::get_all_named_propids:
	case exmdb_callid::get_store_all_proptags:
	case exmdb_callid::get_folder_class_table:
	case exmdb_callid::allocate_cn:
	case exmdb_callid::unload_store:
		return EXT_ERR_SUCCESS;
#define E(t) case exmdb_callid::t: return exmdb_pull(ext_pull, prequest->payload.t);
	RQ_WITH_ARGS
#undef E
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int exmdb_ext_push_request(const EXMDB_REQUEST *prequest,
	BINARY *pbin_out)
{
	int status;
	EXT_PUSH ext_push;
	
	if (!ext_push.init(nullptr, 0, EXT_FLAG_WCOUNT))
		return EXT_ERR_ALLOC;
	status = ext_push.advance(sizeof(uint32_t));
	if (status != EXT_ERR_SUCCESS)
		return status;
	status = ext_push.p_uint8(static_cast<uint8_t>(prequest->call_id));
	if (status != EXT_ERR_SUCCESS)
		return status;
	if (prequest->call_id == exmdb_callid::connect) {
		status = exmdb_push(ext_push, prequest->payload.connect);
	} else if (prequest->call_id == exmdb_callid::listen_notification) {
		status = exmdb_push(ext_push, prequest->payload.listen_notification);
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
	case exmdb_callid::unload_store:
		status = EXT_ERR_SUCCESS;
		break;
#define E(t) case exmdb_callid::t: status = exmdb_push(ext_push, prequest->payload.t); break;
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

static int exmdb_ext_pull_get_all_named_propids_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_propid_a(&ppayload->get_all_named_propids.propids);
}

static int exmdb_ext_push_get_all_named_propids_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_propid_a(ppayload->get_all_named_propids.propids);
}

static int exmdb_ext_pull_get_named_propids_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_propid_a(&ppayload->get_named_propids.propids);
}

static int exmdb_ext_push_get_named_propids_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_propid_a(ppayload->get_named_propids.propids);
}

static int exmdb_ext_pull_get_named_propnames_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_propname_a(&ppayload->get_named_propnames.propnames);
}

static int exmdb_ext_push_get_named_propnames_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_propname_a(ppayload->get_named_propnames.propnames);
}

static int exmdb_ext_pull_get_mapping_guid_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_bool(&ppayload->get_mapping_guid.b_found));
	return pext->g_guid(&ppayload->get_mapping_guid.guid);
}

static int exmdb_ext_push_get_mapping_guid_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_bool(ppayload->get_mapping_guid.b_found));
	return pext->p_guid(ppayload->get_mapping_guid.guid);
}

static int exmdb_ext_pull_get_mapping_replid_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_bool(&ppayload->get_mapping_replid.b_found));
	return pext->g_uint16(&ppayload->get_mapping_replid.replid);
}

static int exmdb_ext_push_get_mapping_replid_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_bool(ppayload->get_mapping_replid.b_found));
	return pext->p_uint16(ppayload->get_mapping_replid.replid);
}

static int exmdb_ext_pull_get_store_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_proptag_a(&ppayload->get_store_all_proptags.proptags);
}

static int exmdb_ext_push_get_store_all_proptags_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_proptag_a(ppayload->get_store_all_proptags.proptags);
}

static int exmdb_ext_pull_get_store_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_tpropval_a(&ppayload->get_store_properties.propvals);
}

static int exmdb_ext_push_get_store_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_tpropval_a(ppayload->get_store_properties.propvals);
}

static int exmdb_ext_pull_set_store_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_problem_a(&ppayload->set_store_properties.problems);
}

static int exmdb_ext_push_set_store_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_problem_a(ppayload->set_store_properties.problems);
}

static int exmdb_ext_pull_check_mailbox_permission_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(&ppayload->check_mailbox_permission.permission);
}

static int exmdb_ext_push_check_mailbox_permission_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->check_mailbox_permission.permission);
}

static int exmdb_ext_pull_get_folder_by_class_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_uint64(&ppayload->get_folder_by_class.id));
	return pext->g_str(&ppayload->get_folder_by_class.str_explicit);
}

static int exmdb_ext_push_get_folder_by_class_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_uint64(ppayload->get_folder_by_class.id));
	return pext->p_str(ppayload->get_folder_by_class.str_explicit);
}

static int exmdb_ext_pull_set_folder_by_class_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->set_folder_by_class.b_result);
}

static int exmdb_ext_push_set_folder_by_class_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->set_folder_by_class.b_result);
}

static int exmdb_ext_pull_get_folder_class_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_tarray_set(&ppayload->get_folder_class_table.table);
}

static int exmdb_ext_push_get_folder_class_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_tarray_set(ppayload->get_folder_class_table.table);
}

static int exmdb_ext_pull_check_folder_id_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->check_folder_id.b_exist);
}

static int exmdb_ext_push_check_folder_id_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->check_folder_id.b_exist);
}

static int exmdb_ext_pull_query_folder_messages_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_tarray_set(&ppayload->query_folder_messages.set);
}

static int exmdb_ext_push_query_folder_messages_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_tarray_set(ppayload->query_folder_messages.set);
}

static int exmdb_ext_pull_check_folder_deleted_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->check_folder_deleted.b_del);
}

static int exmdb_ext_push_check_folder_deleted_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->check_folder_deleted.b_del);
}

static int exmdb_ext_pull_get_folder_by_name_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint64(&ppayload->get_folder_by_name.folder_id);
}

static int exmdb_ext_push_get_folder_by_name_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint64(ppayload->get_folder_by_name.folder_id);
}

static int exmdb_ext_pull_check_folder_permission_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(&ppayload->check_folder_permission.permission);
}

static int exmdb_ext_push_check_folder_permission_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->check_folder_permission.permission);
}

static int exmdb_ext_pull_create_folder_by_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint64(&ppayload->create_folder_by_properties.folder_id);
}

static int exmdb_ext_push_create_folder_by_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint64(ppayload->create_folder_by_properties.folder_id);
}

static int exmdb_ext_pull_get_folder_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_proptag_a(&ppayload->get_folder_all_proptags.proptags);
}

static int exmdb_ext_push_get_folder_all_proptags_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_proptag_a(ppayload->get_folder_all_proptags.proptags);
}

static int exmdb_ext_pull_get_folder_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_tpropval_a(&ppayload->get_folder_properties.propvals);
}

static int exmdb_ext_push_get_folder_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_tpropval_a(ppayload->get_folder_properties.propvals);
}

static int exmdb_ext_pull_set_folder_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_problem_a(&ppayload->set_folder_properties.problems);
}

static int exmdb_ext_push_set_folder_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_problem_a(ppayload->set_folder_properties.problems);
}

static int exmdb_ext_pull_delete_folder_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->delete_folder.b_result);
}

static int exmdb_ext_push_delete_folder_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->delete_folder.b_result);
}

static int exmdb_ext_pull_empty_folder_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->empty_folder.b_partial);
}

static int exmdb_ext_push_empty_folder_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->empty_folder.b_partial);
}

static int exmdb_ext_pull_check_folder_cycle_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->check_folder_cycle.b_cycle);
}

static int exmdb_ext_push_check_folder_cycle_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->check_folder_cycle.b_cycle);
}

static int exmdb_ext_pull_copy_folder_internal_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_bool(&ppayload->copy_folder_internal.b_collid));
	return pext->g_bool(&ppayload->copy_folder_internal.b_partial);
}

static int exmdb_ext_push_copy_folder_internal_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_bool(ppayload->copy_folder_internal.b_collid));
	return pext->p_bool(ppayload->copy_folder_internal.b_partial);
}

static int exmdb_ext_pull_get_search_criteria_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(pext->g_uint32(&ppayload->get_search_criteria.search_status));
	TRY(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->get_search_criteria.prestriction = NULL;
	} else {
		ppayload->get_search_criteria.prestriction = cu_alloc<RESTRICTION>();
		if (ppayload->get_search_criteria.prestriction == nullptr)
			return EXT_ERR_ALLOC;
		TRY(pext->g_restriction(ppayload->get_search_criteria.prestriction));
	}
	return pext->g_uint64_a(&ppayload->get_search_criteria.folder_ids);
}

static int exmdb_ext_push_get_search_criteria_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_uint32(ppayload->get_search_criteria.search_status));
	if (NULL == ppayload->get_search_criteria.prestriction) {
		TRY(pext->p_uint8(0));
	} else {
		TRY(pext->p_uint8(1));
		TRY(pext->p_restriction(*ppayload->get_search_criteria.prestriction));
	}
	return pext->p_uint64_a(ppayload->get_search_criteria.folder_ids);
}

static int exmdb_ext_pull_set_search_criteria_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->set_search_criteria.b_result);
}
	
static int exmdb_ext_push_set_search_criteria_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->set_search_criteria.b_result);
}

static int exmdb_ext_pull_movecopy_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->movecopy_message.b_result);
}

static int exmdb_ext_push_movecopy_message_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->movecopy_message.b_result);
}

static int exmdb_ext_pull_movecopy_messages_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->movecopy_messages.b_partial);
}

static int exmdb_ext_push_movecopy_messages_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->movecopy_messages.b_partial);
}

static int exmdb_ext_pull_movecopy_folder_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_bool(&ppayload->movecopy_folder.b_exist));
	return pext->g_bool(&ppayload->movecopy_folder.b_partial);
}

static int exmdb_ext_push_movecopy_folder_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_bool(ppayload->movecopy_folder.b_exist));
	return pext->p_bool(ppayload->movecopy_folder.b_partial);
}

static int exmdb_ext_pull_delete_messages_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->delete_messages.b_partial);
}

static int exmdb_ext_push_delete_messages_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->delete_messages.b_partial);
}

static int exmdb_ext_pull_get_message_brief_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = pext->g_uint8(&tmp_byte);
	if (status != EXT_ERR_SUCCESS || tmp_byte == 0) {
		ppayload->get_message_brief.pbrief = NULL;
		return EXT_ERR_SUCCESS;
	}
	ppayload->get_message_brief.pbrief = cu_alloc<MESSAGE_CONTENT>();
	if (ppayload->get_message_brief.pbrief == nullptr)
		return EXT_ERR_ALLOC;
	return pext->g_msgctnt(ppayload->get_message_brief.pbrief);
}

static int exmdb_ext_push_get_message_brief_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (ppayload->get_message_brief.pbrief == nullptr)
		return pext->p_uint8(0);
	TRY(pext->p_uint8(1));
	return pext->p_msgctnt(*ppayload->get_message_brief.pbrief);
}

static int exmdb_ext_pull_sum_hierarchy_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(&ppayload->sum_hierarchy.count);
}

static int exmdb_ext_push_sum_hierarchy_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->sum_hierarchy.count);
}

static int exmdb_ext_pull_load_hierarchy_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_uint32(&ppayload->load_hierarchy_table.table_id));
	return pext->g_uint32(&ppayload->load_hierarchy_table.row_count);
}

static int exmdb_ext_push_load_hierarchy_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_uint32(ppayload->load_hierarchy_table.table_id));
	return pext->p_uint32(ppayload->load_hierarchy_table.row_count);
}

static int exmdb_ext_pull_sum_content_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(&ppayload->sum_content.count);
}

static int exmdb_ext_push_sum_content_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->sum_content.count);
}

static int exmdb_ext_pull_load_content_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_uint32(&ppayload->load_content_table.table_id));
	return pext->g_uint32(&ppayload->load_content_table.row_count);
}

static int exmdb_ext_push_load_content_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_uint32(ppayload->load_content_table.table_id));
	return pext->p_uint32(ppayload->load_content_table.row_count);
}

static int exmdb_ext_pull_load_permission_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_uint32(&ppayload->load_permission_table.table_id));
	return pext->g_uint32(&ppayload->load_permission_table.row_count);
}

static int exmdb_ext_push_load_permission_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_uint32(ppayload->load_permission_table.table_id));
	return pext->p_uint32(ppayload->load_permission_table.row_count);
}

static int exmdb_ext_pull_load_rule_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_uint32(&ppayload->load_rule_table.table_id));
	return pext->g_uint32(&ppayload->load_rule_table.row_count);
}

static int exmdb_ext_push_load_rule_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_uint32(ppayload->load_rule_table.table_id));
	return pext->p_uint32(ppayload->load_rule_table.row_count);
}

static int exmdb_ext_pull_sum_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(&ppayload->sum_table.rows);
}

static int exmdb_ext_push_sum_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->sum_table.rows);
}

static int exmdb_ext_pull_query_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_tarray_set(&ppayload->query_table.set);
}

static int exmdb_ext_push_query_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_tarray_set(ppayload->query_table.set);
}

static int exmdb_ext_pull_match_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_int32(&ppayload->match_table.position));
	return pext->g_tpropval_a(&ppayload->match_table.propvals);
}

static int exmdb_ext_push_match_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_int32(ppayload->match_table.position));
	return pext->p_tpropval_a(ppayload->match_table.propvals);
}

static int exmdb_ext_pull_locate_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_int32(&ppayload->locate_table.position));
	return pext->g_uint32(&ppayload->locate_table.row_type);
}

static int exmdb_ext_push_locate_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_int32(ppayload->locate_table.position));
	return pext->p_uint32(ppayload->locate_table.row_type);
}

static int exmdb_ext_pull_read_table_row_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_tpropval_a(&ppayload->read_table_row.propvals);
}

static int exmdb_ext_push_read_table_row_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_tpropval_a(ppayload->read_table_row.propvals);
}

static int exmdb_ext_pull_mark_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_uint64(&ppayload->mark_table.inst_id));
	TRY(pext->g_uint32(&ppayload->mark_table.inst_num));
	return pext->g_uint32(&ppayload->mark_table.row_type);
}

static int exmdb_ext_push_mark_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_uint64(ppayload->mark_table.inst_id));
	TRY(pext->p_uint32(ppayload->mark_table.inst_num));
	return pext->p_uint32(ppayload->mark_table.row_type);
}

static int exmdb_ext_pull_get_table_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_proptag_a(&ppayload->get_table_all_proptags.proptags);
}

static int exmdb_ext_push_get_table_all_proptags_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_proptag_a(ppayload->get_table_all_proptags.proptags);
}

static int exmdb_ext_pull_expand_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_bool(&ppayload->expand_table.b_found));
	TRY(pext->g_int32(&ppayload->expand_table.position));
	return pext->g_uint32(&ppayload->expand_table.row_count);
}

static int exmdb_ext_push_expand_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_bool(ppayload->expand_table.b_found));
	TRY(pext->p_int32(ppayload->expand_table.position));
	return pext->p_uint32(ppayload->expand_table.row_count);
}

static int exmdb_ext_pull_collapse_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_bool(&ppayload->collapse_table.b_found));
	TRY(pext->g_int32(&ppayload->collapse_table.position));
	return pext->g_uint32(&ppayload->collapse_table.row_count);
}

static int exmdb_ext_push_collapse_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_bool(ppayload->collapse_table.b_found));
	TRY(pext->p_int32(ppayload->collapse_table.position));
	return pext->p_uint32(ppayload->collapse_table.row_count);
}

static int exmdb_ext_pull_store_table_state_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(&ppayload->store_table_state.state_id);
}

static int exmdb_ext_push_store_table_state_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->store_table_state.state_id);
}

static int exmdb_ext_pull_restore_table_state_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_int32(&ppayload->restore_table_state.position);
}

static int exmdb_ext_push_restore_table_state_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_int32(ppayload->restore_table_state.position);
}

static int exmdb_ext_pull_check_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->check_message.b_exist);
}

static int exmdb_ext_push_check_message_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->check_message.b_exist);
}

static int exmdb_ext_pull_check_message_deleted_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->check_message_deleted.b_del);
}

static int exmdb_ext_push_check_message_deleted_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->check_message_deleted.b_del);
}

static int exmdb_ext_pull_load_message_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(&ppayload->load_message_instance.instance_id);
}

static int exmdb_ext_push_load_message_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->load_message_instance.instance_id);
}

static int exmdb_ext_pull_load_embedded_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(&ppayload->load_embedded_instance.instance_id);
}

static int exmdb_ext_push_load_embedded_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->load_embedded_instance.instance_id);
}

static int exmdb_ext_pull_get_embedded_cn_response(EXT_PULL *pext,
    RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->get_embedded_cn.pcn = nullptr;
		return EXT_ERR_SUCCESS;
	}
	ppayload->get_embedded_cn.pcn = cu_alloc<uint64_t>();
	if (ppayload->get_embedded_cn.pcn == nullptr)
		return EXT_ERR_ALLOC;
	return pext->g_uint64(ppayload->get_embedded_cn.pcn);
}

static int exmdb_ext_push_get_embedded_cn_response(EXT_PUSH *pext,
    const RESPONSE_PAYLOAD *ppayload)
{
	if (ppayload->get_embedded_cn.pcn == nullptr)
		return pext->p_uint8(0);
	TRY(pext->p_uint8(1));
	return pext->p_uint64(*static_cast<uint64_t *>(ppayload->get_embedded_cn.pcn));
}

static int exmdb_ext_pull_reload_message_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->reload_message_instance.b_result);
}

static int exmdb_ext_push_reload_message_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->reload_message_instance.b_result);
}

static int exmdb_ext_pull_read_message_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_msgctnt(&ppayload->read_message_instance.msgctnt);
}

static int exmdb_ext_push_read_message_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_msgctnt(ppayload->read_message_instance.msgctnt);
}

static int exmdb_ext_pull_write_message_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_proptag_a(&ppayload->write_message_instance.proptags));
	return pext->g_problem_a(&ppayload->write_message_instance.problems);
}

static int exmdb_ext_push_write_message_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_proptag_a(ppayload->write_message_instance.proptags));
	return pext->p_problem_a(ppayload->write_message_instance.problems);
}

static int exmdb_ext_pull_load_attachment_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(&ppayload->load_attachment_instance.instance_id);
}

static int exmdb_ext_push_load_attachment_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->load_attachment_instance.instance_id);
}

static int exmdb_ext_pull_create_attachment_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_uint32(&ppayload->create_attachment_instance.instance_id));
	return pext->g_uint32(&ppayload->create_attachment_instance.attachment_num);
}

static int exmdb_ext_push_create_attachment_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_uint32(ppayload->create_attachment_instance.instance_id));
	return pext->p_uint32(ppayload->create_attachment_instance.attachment_num);
}

static int exmdb_ext_pull_read_attachment_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(pext->g_tpropval_a(&ppayload->read_attachment_instance.attctnt.proplist));
	TRY(pext->g_uint8(&tmp_byte));
	if (tmp_byte == 0) {
		ppayload->read_attachment_instance.attctnt.pembedded = NULL;
		return EXT_ERR_SUCCESS;
	}
	ppayload->read_attachment_instance.attctnt.pembedded = cu_alloc<MESSAGE_CONTENT>();
	if (ppayload->read_attachment_instance.attctnt.pembedded == nullptr)
		return EXT_ERR_ALLOC;
	return pext->g_msgctnt(ppayload->read_attachment_instance.attctnt.pembedded);
}

static int exmdb_ext_push_read_attachment_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_tpropval_a(ppayload->read_attachment_instance.attctnt.proplist));
	if (ppayload->read_attachment_instance.attctnt.pembedded == nullptr)
		return pext->p_uint8(0);
	TRY(pext->p_uint8(1));
	return pext->p_msgctnt(*ppayload->read_attachment_instance.attctnt.pembedded);
}

static int exmdb_ext_pull_write_attachment_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_problem_a(&ppayload->write_attachment_instance.problems);
}

static int exmdb_ext_push_write_attachment_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_problem_a(ppayload->write_attachment_instance.problems);
}

static int exmdb_ext_pull_flush_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(reinterpret_cast<uint32_t *>(&ppayload->flush_instance.e_result));
}

static int exmdb_ext_push_flush_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->flush_instance.e_result);
}

static int exmdb_ext_pull_get_instance_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_proptag_a(&ppayload->get_instance_all_proptags.proptags);
}

static int exmdb_ext_push_get_instance_all_proptags_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_proptag_a(ppayload->get_instance_all_proptags.proptags);
}

static int exmdb_ext_pull_get_instance_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_tpropval_a(&ppayload->get_instance_properties.propvals);
}

static int exmdb_ext_push_get_instance_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_tpropval_a(ppayload->get_instance_properties.propvals);
}

static int exmdb_ext_pull_set_instance_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_problem_a(&ppayload->set_instance_properties.problems);
}

static int exmdb_ext_push_set_instance_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_problem_a(ppayload->set_instance_properties.problems);
}

static int exmdb_ext_pull_remove_instance_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_problem_a(&ppayload->remove_instance_properties.problems);
}

static int exmdb_ext_push_remove_instance_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_problem_a(ppayload->remove_instance_properties.problems);
}

static int exmdb_ext_pull_check_instance_cycle_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->check_instance_cycle.b_cycle);
}

static int exmdb_ext_push_check_instance_cycle_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->check_instance_cycle.b_cycle);
}

static int exmdb_ext_pull_get_message_instance_rcpts_num_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint16(&ppayload->get_message_instance_rcpts_num.num);
}

static int exmdb_ext_push_get_message_instance_rcpts_num_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint16(ppayload->get_message_instance_rcpts_num.num);
}

static int exmdb_ext_pull_get_message_instance_rcpts_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_proptag_a(&ppayload->get_message_instance_rcpts_all_proptags.proptags);
}

static int exmdb_ext_push_get_message_instance_rcpts_all_proptags_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_proptag_a(ppayload->get_message_instance_rcpts_all_proptags.proptags);
}

static int exmdb_ext_pull_get_message_instance_rcpts_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_tarray_set(&ppayload->get_message_instance_rcpts.set);
}

static int exmdb_ext_push_get_message_instance_rcpts_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_tarray_set(ppayload->get_message_instance_rcpts.set);
}

static int exmdb_ext_pull_copy_instance_rcpts_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->copy_instance_rcpts.b_result);
}

static int exmdb_ext_push_copy_instance_rcpts_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->copy_instance_rcpts.b_result);
}

static int exmdb_ext_pull_get_message_instance_attachments_num_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint16(&ppayload->get_message_instance_attachments_num.num);
}

static int exmdb_ext_push_get_message_instance_attachments_num_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint16(ppayload->get_message_instance_attachments_num.num);
}

static int exmdb_ext_pull_get_message_instance_attachment_table_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_proptag_a(&ppayload->get_message_instance_attachment_table_all_proptags.proptags);
}

static int exmdb_ext_push_get_message_instance_attachment_table_all_proptags_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_proptag_a(ppayload->get_message_instance_attachment_table_all_proptags.proptags);
}

static int exmdb_ext_pull_query_message_instance_attachment_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_tarray_set(&ppayload->query_message_instance_attachment_table.set);
}

static int exmdb_ext_push_query_message_instance_attachment_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_tarray_set(ppayload->query_message_instance_attachment_table.set);
}

static int exmdb_ext_pull_copy_instance_attachments_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->copy_instance_attachments.b_result);
}

static int exmdb_ext_push_copy_instance_attachments_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->copy_instance_attachments.b_result);
}

static int exmdb_ext_pull_get_message_rcpts_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_tarray_set(&ppayload->get_message_rcpts.set);
}

static int exmdb_ext_push_get_message_rcpts_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_tarray_set(ppayload->get_message_rcpts.set);
}

static int exmdb_ext_pull_get_message_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_tpropval_a(&ppayload->get_message_properties.propvals);
}

static int exmdb_ext_push_get_message_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_tpropval_a(ppayload->get_message_properties.propvals);
}

static int exmdb_ext_pull_set_message_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_problem_a(&ppayload->set_message_properties.problems);
}

static int exmdb_ext_push_set_message_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_problem_a(ppayload->set_message_properties.problems);
}

static int exmdb_ext_pull_set_message_read_state_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint64(&ppayload->set_message_read_state.read_cn);
}

static int exmdb_ext_push_set_message_read_state_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint64(ppayload->set_message_read_state.read_cn);
}

static int exmdb_ext_pull_allocate_message_id_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint64(&ppayload->allocate_message_id.message_id);
}

static int exmdb_ext_push_allocate_message_id_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint64(ppayload->allocate_message_id.message_id);
}

static int exmdb_ext_pull_allocate_cn_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint64(&ppayload->allocate_cn.cn);
}

static int exmdb_ext_push_allocate_cn_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint64(ppayload->allocate_cn.cn);
}

static int exmdb_ext_pull_get_message_group_id_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->get_message_group_id.pgroup_id = NULL;
		return EXT_ERR_SUCCESS;
	}
	ppayload->get_message_group_id.pgroup_id = cu_alloc<uint32_t>();
	if (ppayload->get_message_group_id.pgroup_id == nullptr)
		return EXT_ERR_ALLOC;
	return pext->g_uint32(ppayload->get_message_group_id.pgroup_id);
}

static int exmdb_ext_push_get_message_group_id_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (ppayload->get_message_group_id.pgroup_id == nullptr)
		return pext->p_uint8(0);
	TRY(pext->p_uint8(1));
	return pext->p_uint32(*ppayload->get_message_group_id.pgroup_id);
}

static int exmdb_ext_pull_get_change_indices_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_proptag_a(&ppayload->get_change_indices.indices));
	return pext->g_proptag_a(&ppayload->get_change_indices.ungroup_proptags);
}

static int exmdb_ext_push_get_change_indices_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_proptag_a(ppayload->get_change_indices.indices));
	return pext->p_proptag_a(ppayload->get_change_indices.ungroup_proptags);
}

static int exmdb_ext_pull_try_mark_submit_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->try_mark_submit.b_marked);
}

static int exmdb_ext_push_try_mark_submit_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->try_mark_submit.b_marked);
}

static int exmdb_ext_pull_link_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->link_message.b_result);
}

static int exmdb_ext_push_link_message_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->link_message.b_result);
}

static int exmdb_ext_pull_get_message_timer_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->get_message_timer.ptimer_id = NULL;
		return EXT_ERR_SUCCESS;
	}
	ppayload->get_message_timer.ptimer_id = cu_alloc<uint32_t>();
	if (ppayload->get_message_timer.ptimer_id == nullptr)
		return EXT_ERR_ALLOC;
	return pext->g_uint32(ppayload->get_message_timer.ptimer_id);
}

static int exmdb_ext_push_get_message_timer_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (ppayload->get_message_timer.ptimer_id == nullptr)
		return pext->p_uint8(0);
	TRY(pext->p_uint8(1));
	return pext->p_uint32(*ppayload->get_message_timer.ptimer_id);
}

static int exmdb_ext_pull_update_folder_rule_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->update_folder_rule.b_exceed);
}

static int exmdb_ext_push_update_folder_rule_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->update_folder_rule.b_exceed);
}

static int exmdb_ext_pull_delivery_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(&ppayload->delivery_message.result);
}

static int exmdb_ext_push_delivery_message_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->delivery_message.result);
}

static int exmdb_ext_pull_write_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(reinterpret_cast<uint32_t *>(&ppayload->write_message.e_result));
}

static int exmdb_ext_push_write_message_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->write_message.e_result);
}

static int exmdb_ext_pull_read_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->read_message.pmsgctnt = NULL;
		return EXT_ERR_SUCCESS;
	}
	ppayload->read_message.pmsgctnt = cu_alloc<MESSAGE_CONTENT>();
	if (ppayload->read_message.pmsgctnt == nullptr)
		return EXT_ERR_ALLOC;
	return pext->g_msgctnt(ppayload->read_message.pmsgctnt);
}

static int exmdb_ext_push_read_message_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (ppayload->read_message.pmsgctnt == nullptr)
		return pext->p_uint8(0);
	TRY(pext->p_uint8(1));
	return pext->p_msgctnt(*ppayload->read_message.pmsgctnt);
}

static int exmdb_ext_pull_get_content_sync_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_uint32(&ppayload->get_content_sync.fai_count));
	TRY(pext->g_uint64(&ppayload->get_content_sync.fai_total));
	TRY(pext->g_uint32(&ppayload->get_content_sync.normal_count));
	TRY(pext->g_uint64(&ppayload->get_content_sync.normal_total));
	TRY(pext->g_eid_a(&ppayload->get_content_sync.updated_mids));
	TRY(pext->g_eid_a(&ppayload->get_content_sync.chg_mids));
	TRY(pext->g_uint64(&ppayload->get_content_sync.last_cn));
	TRY(pext->g_eid_a(&ppayload->get_content_sync.given_mids));
	TRY(pext->g_eid_a(&ppayload->get_content_sync.deleted_mids));
	TRY(pext->g_eid_a(&ppayload->get_content_sync.nolonger_mids));
	TRY(pext->g_eid_a(&ppayload->get_content_sync.read_mids));
	TRY(pext->g_eid_a(&ppayload->get_content_sync.unread_mids));
	return pext->g_uint64(&ppayload->get_content_sync.last_readcn);
}

static int exmdb_ext_push_get_content_sync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	
	TRY(pext->p_uint32(ppayload->get_content_sync.fai_count));
	TRY(pext->p_uint64(ppayload->get_content_sync.fai_total));
	TRY(pext->p_uint32(ppayload->get_content_sync.normal_count));
	TRY(pext->p_uint64(ppayload->get_content_sync.normal_total));
	TRY(pext->p_eid_a(ppayload->get_content_sync.updated_mids));
	TRY(pext->p_eid_a(ppayload->get_content_sync.chg_mids));
	TRY(pext->p_uint64(ppayload->get_content_sync.last_cn));
	TRY(pext->p_eid_a(ppayload->get_content_sync.given_mids));
	TRY(pext->p_eid_a(ppayload->get_content_sync.deleted_mids));
	TRY(pext->p_eid_a(ppayload->get_content_sync.nolonger_mids));
	TRY(pext->p_eid_a(ppayload->get_content_sync.read_mids));
	TRY(pext->p_eid_a(ppayload->get_content_sync.unread_mids));
	return pext->p_uint64(ppayload->get_content_sync.last_readcn);
}

static int exmdb_ext_pull_get_hierarchy_sync_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->g_uint32(&ppayload->get_hierarchy_sync.fldchgs.count));
	if (0 == ppayload->get_hierarchy_sync.fldchgs.count) {
		ppayload->get_hierarchy_sync.fldchgs.pfldchgs = NULL;
	} else {
		ppayload->get_hierarchy_sync.fldchgs.pfldchgs = cu_alloc<TPROPVAL_ARRAY>(ppayload->get_hierarchy_sync.fldchgs.count);
		if (NULL == ppayload->get_hierarchy_sync.fldchgs.pfldchgs) {
			ppayload->get_hierarchy_sync.fldchgs.count = 0;
			return EXT_ERR_ALLOC;
		}
		for (size_t i = 0; i < ppayload->get_hierarchy_sync.fldchgs.count; ++i)
			TRY(pext->g_tpropval_a(&ppayload->get_hierarchy_sync.fldchgs.pfldchgs[i]));
	}
	TRY(pext->g_uint64(&ppayload->get_hierarchy_sync.last_cn));
	TRY(pext->g_eid_a(&ppayload->get_hierarchy_sync.given_fids));
	return pext->g_eid_a(&ppayload->get_hierarchy_sync.deleted_fids);
}

static int exmdb_ext_push_get_hierarchy_sync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	TRY(pext->p_uint32(ppayload->get_hierarchy_sync.fldchgs.count));
	for (size_t i = 0; i < ppayload->get_hierarchy_sync.fldchgs.count; ++i)
		TRY(pext->p_tpropval_a(ppayload->get_hierarchy_sync.fldchgs.pfldchgs[i]));
	TRY(pext->p_uint64(ppayload->get_hierarchy_sync.last_cn));
	TRY(pext->p_eid_a(ppayload->get_hierarchy_sync.given_fids));
	return pext->p_eid_a(ppayload->get_hierarchy_sync.deleted_fids);
}

static int exmdb_ext_pull_allocate_ids_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint64(&ppayload->allocate_ids.begin_eid);
}

static int exmdb_ext_push_allocate_ids_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint64(ppayload->allocate_ids.begin_eid);
}

static int exmdb_ext_pull_subscribe_notification_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(&ppayload->subscribe_notification.sub_id);
}

static int exmdb_ext_push_subscribe_notification_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->subscribe_notification.sub_id);
}

static int exmdb_ext_pull_check_contact_address_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_bool(&ppayload->check_contact_address.b_found);
}

static int exmdb_ext_push_check_contact_address_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_bool(ppayload->check_contact_address.b_found);
}

static int exmdb_ext_pull_get_public_folder_unread_count_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return pext->g_uint32(&ppayload->get_public_folder_unread_count.count);
}

static int exmdb_ext_push_get_public_folder_unread_count_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return pext->p_uint32(ppayload->get_public_folder_unread_count.count);
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
	E(unload_store)
#define RSP_WITH_ARGS \
	E(get_all_named_propids) \
	E(get_named_propids) \
	E(get_named_propnames) \
	E(get_mapping_guid) \
	E(get_mapping_replid) \
	E(get_store_all_proptags) \
	E(get_store_properties) \
	E(set_store_properties) \
	E(check_mailbox_permission) \
	E(get_folder_by_class) \
	E(set_folder_by_class) \
	E(get_folder_class_table) \
	E(check_folder_id) \
	E(query_folder_messages) \
	E(check_folder_deleted) \
	E(get_folder_by_name) \
	E(check_folder_permission) \
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
	E(delivery_message) \
	E(write_message) \
	E(read_message) \
	E(get_content_sync) \
	E(get_hierarchy_sync) \
	E(allocate_ids) \
	E(subscribe_notification) \
	E(check_contact_address) \
	E(get_public_folder_unread_count)

/* exmdb_callid::connect, exmdb_callid::listen_notification not included */
int exmdb_ext_pull_response(const BINARY *pbin_in,
	EXMDB_RESPONSE *presponse)
{
	EXT_PULL ext_pull;
	
	ext_pull.init(pbin_in->pb, pbin_in->cb, exmdb_rpc_alloc, EXT_FLAG_WCOUNT);
	switch (presponse->call_id) {
#define E(t) case exmdb_callid::t:
	RSP_WITHOUT_ARGS
		return EXT_ERR_SUCCESS;
#undef E
#define E(t) case exmdb_callid::t: return exmdb_ext_pull_ ## t ## _response(&ext_pull, &presponse->payload);
	RSP_WITH_ARGS
#undef E
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

/* exmdb_callid::connect, exmdb_callid::listen_notification not included */
int exmdb_ext_push_response(const EXMDB_RESPONSE *presponse,
	BINARY *pbin_out)
{
	int status;
	EXT_PUSH ext_push;
	
	if (!ext_push.init(nullptr, 0, EXT_FLAG_WCOUNT))
		return EXT_ERR_ALLOC;
	status = ext_push.p_uint8(static_cast<uint8_t>(exmdb_response::success));
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
#define E(t) case exmdb_callid::t: status = exmdb_ext_push_ ## t ## _response(&ext_push, &presponse->payload); break;
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

int exmdb_ext_pull_db_notify(const BINARY *pbin_in,
	DB_NOTIFY_DATAGRAM *pnotify)
{
	uint8_t tmp_byte;
	EXT_PULL ext_pull;
	
	ext_pull.init(pbin_in->pb, pbin_in->cb, exmdb_rpc_alloc, EXT_FLAG_WCOUNT);
	TRY(ext_pull.g_str(&pnotify->dir));
	TRY(ext_pull.g_bool(&pnotify->b_table));
	TRY(ext_pull.g_uint32_a(&pnotify->id_array));
	TRY(ext_pull.g_uint8(&pnotify->db_notify.type));
	switch (pnotify->db_notify.type) {
	case DB_NOTIFY_TYPE_NEW_MAIL: {
		auto n = cu_alloc<DB_NOTIFY_NEW_MAIL>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->message_id));
		TRY(ext_pull.g_uint32(&n->message_flags));
		return ext_pull.g_str(const_cast<char **>(&n->pmessage_class));
	}
	case DB_NOTIFY_TYPE_FOLDER_CREATED: {
		auto n = cu_alloc<DB_NOTIFY_FOLDER_CREATED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->parent_id));
		return ext_pull.g_proptag_a(&n->proptags);
	}
	case DB_NOTIFY_TYPE_MESSAGE_CREATED: {
		auto n = cu_alloc<DB_NOTIFY_MESSAGE_CREATED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->message_id));
		return ext_pull.g_proptag_a(&n->proptags);
	}
	case DB_NOTIFY_TYPE_LINK_CREATED: {
		auto n = cu_alloc<DB_NOTIFY_LINK_CREATED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->message_id));
		TRY(ext_pull.g_uint64(&n->parent_id));
		return ext_pull.g_proptag_a(&n->proptags);
	}
	case DB_NOTIFY_TYPE_FOLDER_DELETED: {
		auto n = cu_alloc<DB_NOTIFY_FOLDER_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		return ext_pull.g_uint64(&n->parent_id);
	}
	case DB_NOTIFY_TYPE_MESSAGE_DELETED: {
		auto n = cu_alloc<DB_NOTIFY_MESSAGE_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		return ext_pull.g_uint64(&n->message_id);
	}
	case DB_NOTIFY_TYPE_LINK_DELETED: {
		auto n = cu_alloc<DB_NOTIFY_LINK_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->message_id));
		return ext_pull.g_uint64(&n->parent_id);
	}
	case DB_NOTIFY_TYPE_FOLDER_MODIFIED: {
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
	case DB_NOTIFY_TYPE_MESSAGE_MODIFIED: {
		auto n = cu_alloc<DB_NOTIFY_MESSAGE_MODIFIED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->message_id));
		return ext_pull.g_proptag_a(&n->proptags);
	}
	case DB_NOTIFY_TYPE_FOLDER_MOVED:
	case DB_NOTIFY_TYPE_FOLDER_COPIED: {
		auto n = cu_alloc<DB_NOTIFY_FOLDER_MVCP>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->parent_id));
		TRY(ext_pull.g_uint64(&n->old_folder_id));
		return ext_pull.g_uint64(&n->old_parent_id);
	}
	case DB_NOTIFY_TYPE_MESSAGE_MOVED:
	case DB_NOTIFY_TYPE_MESSAGE_COPIED: {
		auto n = cu_alloc<DB_NOTIFY_MESSAGE_MVCP>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->folder_id));
		TRY(ext_pull.g_uint64(&n->message_id));
		TRY(ext_pull.g_uint64(&n->old_folder_id));
		return ext_pull.g_uint64(&n->old_message_id);
	}
	case DB_NOTIFY_TYPE_SEARCH_COMPLETED: {
		auto n = cu_alloc<DB_NOTIFY_SEARCH_COMPLETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		return ext_pull.g_uint64(&n->folder_id);
	}
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_CHANGED:
	case DB_NOTIFY_TYPE_CONTENT_TABLE_CHANGED:
		return EXT_ERR_SUCCESS;
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_ADDED: {
		auto n = cu_alloc<DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->row_folder_id));
		return ext_pull.g_uint64(&n->after_folder_id);
	}
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_ADDED: {
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
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_DELETED: {
		auto n = cu_alloc<DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		return ext_pull.g_uint64(&n->row_folder_id);
	}
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_DELETED: {
		auto n = cu_alloc<DB_NOTIFY_CONTENT_TABLE_ROW_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->row_folder_id));
		TRY(ext_pull.g_uint64(&n->row_message_id));
		return ext_pull.g_uint64(&n->row_instance);
	}
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_MODIFIED: {
		auto n = cu_alloc<DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_pull.g_uint64(&n->row_folder_id));
		return ext_pull.g_uint64(&n->after_folder_id);
	}
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_MODIFIED: {
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

static int exmdb_ext_push_db_notify2(EXT_PUSH &ext_push,
    const DB_NOTIFY_DATAGRAM *pnotify, BINARY *pbin_out)
{
	TRY(ext_push.advance(sizeof(uint32_t)));
	TRY(ext_push.p_str(pnotify->dir));
	TRY(ext_push.p_bool(pnotify->b_table));
	TRY(ext_push.p_uint32_a(pnotify->id_array));
	TRY(ext_push.p_uint8(pnotify->db_notify.type));
	switch (pnotify->db_notify.type) {
	case DB_NOTIFY_TYPE_NEW_MAIL: {
		auto n = static_cast<const DB_NOTIFY_NEW_MAIL *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		TRY(ext_push.p_uint32(n->message_flags));
		TRY(ext_push.p_str(n->pmessage_class));
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_CREATED: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_CREATED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->parent_id));
		TRY(ext_push.p_proptag_a(n->proptags));
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_CREATED: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_CREATED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		TRY(ext_push.p_proptag_a(n->proptags));
		break;
	}
	case DB_NOTIFY_TYPE_LINK_CREATED: {
		auto n = static_cast<const DB_NOTIFY_LINK_CREATED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		TRY(ext_push.p_uint64(n->parent_id));
		TRY(ext_push.p_proptag_a(n->proptags));
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_DELETED: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_DELETED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->parent_id));
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_DELETED: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_DELETED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		break;
	}
	case DB_NOTIFY_TYPE_LINK_DELETED: {
		auto n = static_cast<const DB_NOTIFY_LINK_DELETED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		TRY(ext_push.p_uint64(n->parent_id));
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_MODIFIED: {
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
	case DB_NOTIFY_TYPE_MESSAGE_MODIFIED: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_MODIFIED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		TRY(ext_push.p_proptag_a(n->proptags));
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_MOVED:
	case DB_NOTIFY_TYPE_FOLDER_COPIED: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_MVCP *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->parent_id));
		TRY(ext_push.p_uint64(n->old_folder_id));
		TRY(ext_push.p_uint64(n->old_parent_id));
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_MOVED:
	case DB_NOTIFY_TYPE_MESSAGE_COPIED: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_MVCP *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		TRY(ext_push.p_uint64(n->message_id));
		TRY(ext_push.p_uint64(n->old_folder_id));
		TRY(ext_push.p_uint64(n->old_message_id));
		break;
	}
	case DB_NOTIFY_TYPE_SEARCH_COMPLETED: {
		auto n = static_cast<const DB_NOTIFY_SEARCH_COMPLETED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->folder_id));
		break;
	}
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_CHANGED:
	case DB_NOTIFY_TYPE_CONTENT_TABLE_CHANGED:
		break;
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_ADDED: {
		auto n = static_cast<const DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->row_folder_id));
		TRY(ext_push.p_uint64(n->after_folder_id));
		break;
	}
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_ADDED: {
		auto n = static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_ADDED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->row_folder_id));
		TRY(ext_push.p_uint64(n->row_message_id));
		TRY(ext_push.p_uint64(n->row_instance));
		TRY(ext_push.p_uint64(n->after_folder_id));
		TRY(ext_push.p_uint64(n->after_row_id));
		TRY(ext_push.p_uint64(n->after_instance));
		break;
	}
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_DELETED: {
		auto n = static_cast<const DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->row_folder_id));
		break;
	}
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_DELETED: {
		auto n = static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_DELETED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->row_folder_id));
		TRY(ext_push.p_uint64(n->row_message_id));
		TRY(ext_push.p_uint64(n->row_instance));
		break;
	}
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_MODIFIED: {
		auto n = static_cast<const DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED *>(pnotify->db_notify.pdata);
		TRY(ext_push.p_uint64(n->row_folder_id));
		TRY(ext_push.p_uint64(n->after_folder_id));
		break;
	}
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_MODIFIED: {
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

int exmdb_ext_push_db_notify(const DB_NOTIFY_DATAGRAM *pnotify,
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
	case exmdb_response::max_reached: return "Maximum connections reached in server";
	case exmdb_response::lack_memory: return "mMximum connections reached in server";
	case exmdb_response::misconfig_prefix: return "Maximum connections reached in server";
	case exmdb_response::misconfig_mode: return "Maximum connections reached in server";
	case exmdb_response::connect_incomplete: return "No prior CONNECT RPC made";
	case exmdb_response::pull_error: return "Invalid request/Server-side deserializing error";
	case exmdb_response::dispatch_error: return "Dispatch error";
	case exmdb_response::push_error: return "Server-side serialize error";
	default: break;
	}
	thread_local char xbuf[32];
	snprintf(xbuf, GX_ARRAY_SIZE(xbuf), "Unknown error %u", static_cast<unsigned int>(v));
	return xbuf;
}

BOOL exmdb_client_read_socket(int fd, BINARY *bin, long timeout_ms)
{
	uint32_t offset = 0;
	struct pollfd pfd;

	bin->cb = 0;
	bin->pb = nullptr;
	pfd.fd = fd;
	pfd.events = POLLIN | POLLPRI;

	while (true) {
		if (timeout_ms >= 0 && poll(&pfd, 1, timeout_ms) != 1) {
			exmdb_rpc_free(bin->pb);
			bin->pb = nullptr;
			return false;
		}

		if (bin->cb == 0) {
			uint8_t resp_buff[5];
			ssize_t read_len = read(fd, resp_buff, 5);
			if (read_len == 1) {
				bin->cb = 1;
				bin->pb = static_cast<uint8_t *>(exmdb_rpc_alloc(1));
				if (bin->pb == nullptr)
					return false;
				*bin->pb = resp_buff[0];
				return TRUE;
			} else if (read_len == 5) {
				bin->cb = le32p_to_cpu(resp_buff + 1) + 5;
				bin->pb = static_cast<uint8_t *>(exmdb_rpc_alloc(bin->cb));
				if (bin->pb == nullptr) {
					bin->cb = 0;
					return false;
				}
				memcpy(bin->pv, resp_buff, 5);
				offset = 5;
				if (offset == bin->cb)
					return TRUE;
				continue;
			} else {
				return false;
			}
		}
		ssize_t read_len = read(fd, bin->pb + offset, bin->cb - offset);
		if (read_len <= 0) {
			exmdb_rpc_free(bin->pb);
			bin->pb = nullptr;
			return false;
		}
		offset += read_len;
		if (offset == bin->cb)
			return TRUE;
	}
}

BOOL exmdb_client_write_socket(int fd, const BINARY *bin, long timeout_ms)
{
	uint32_t offset = 0;
	struct pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT | POLLWRBAND;

	while (true) {
		if (timeout_ms >= 0 && poll(&pfd, 1, timeout_ms) != 1)
			return false;
		ssize_t written_len = write(fd, bin->pb + offset, bin->cb - offset);
		if (written_len <= 0)
			return false;
		offset += written_len;
		if (offset == bin->cb)
			return TRUE;
	}
}
