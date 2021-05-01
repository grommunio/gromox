#pragma once
#include <cstdint>
#include <gromox/ext_buffer.hpp>
#include "types.h"
#include "php.h"
#undef slprintf
#undef vslprintf
#undef snprintf
#undef vsnprintf
#undef vasprintf
#undef asprintf

using PULL_CTX = EXT_PULL;
using PUSH_CTX = EXT_PUSH;

extern void *ext_pack_alloc(size_t);
extern const struct EXT_BUFFER_MGT ext_buffer_mgt;

#define ext_pack_pull_init(c, d, s) ext_buffer_pull_init((c), (d), (s), ext_pack_alloc, EXT_FLAG_WCOUNT)
#define ext_pack_pull_advance(c, s) (ext_buffer_pull_advance((c), (s)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_uint8(c, v) (ext_buffer_pull_uint8((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_uint16(c, v) (ext_buffer_pull_uint16((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_uint32(c, v) (ext_buffer_pull_uint32((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_uint64(c, v) (ext_buffer_pull_uint64((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_float(c, v) (ext_buffer_pull_float((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_double(c, v) (ext_buffer_pull_double((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_bytes(c, v, z) (ext_buffer_pull_bytes((c), (v), (z)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_guid(c, v) (ext_buffer_pull_guid((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_string(c, v) (ext_buffer_pull_string((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_wstring(c, v) (ext_buffer_pull_wstring((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_binary(c, v) (ext_buffer_pull_binary((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_short_array(c, v) (ext_buffer_pull_short_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_long_array(c, v) (ext_buffer_pull_long_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_longlong_array(c, v) (ext_buffer_pull_longlong_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_binary_array(c, v) (ext_buffer_pull_binary_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_string_array(c, v) (ext_buffer_pull_string_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_guid_array(c, v) (ext_buffer_pull_guid_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_proptag_array(c, v) (ext_buffer_pull_proptag_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_restriction(c, v) (ext_buffer_pull_restriction((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_rule_actions(c, v) (ext_buffer_pull_rule_actions((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_tagged_propval(c, v) (ext_buffer_pull_tagged_propval((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_propval(c, v) (ext_buffer_pull_propval((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_property_name(c, v) (ext_buffer_pull_property_name((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_propname_array(c, v) (ext_buffer_pull_propname_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_propid_array(c, v) (ext_buffer_pull_propid_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_tpropval_array(c, v) (ext_buffer_pull_tpropval_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_tarray_set(c, v) (ext_buffer_pull_tarray_set((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_pull_oneoff_entryid(c, v) (ext_buffer_pull_oneoff_entryid((c), (v)) == EXT_ERR_SUCCESS)

zend_bool ext_pack_pull_permission_set(PULL_CTX *pctx, PERMISSION_SET *r);
zend_bool ext_pack_pull_state_array(PULL_CTX *pctx, STATE_ARRAY *r);
zend_bool ext_pack_pull_znotification_array(
	PULL_CTX *pctx, ZNOTIFICATION_ARRAY *r);

#define ext_pack_push_init(c) ((c)->init(nullptr, 0, EXT_FLAG_WCOUNT, &ext_buffer_mgt))
#define ext_pack_push_advance(c, v) ((c)->advance(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_bytes(c, v, z) ((c)->p_bytes((v), (z)) == EXT_ERR_SUCCESS)
#define ext_pack_push_uint8(c, v) ((c)->p_uint8(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_uint16(c, v) ((c)->p_uint16(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_int32(c, v) ((c)->p_int32(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_uint32(c, v) ((c)->p_uint32(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_uint64(c, v) ((c)->p_uint64(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_float(c, v) ((c)->p_float(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_double(c, v) ((c)->p_double(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_binary(c, v) ((c)->p_bin(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_guid(c, v) ((c)->p_guid(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_string(c, v) ((c)->p_str(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_wstring(c, v) ((c)->p_wstr(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_short_array(c, v) ((c)->p_uint16_a(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_long_array(c, v) ((c)->p_uint32_a(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_longlong_array(c, v) ((c)->p_uint64_a(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_binary_array(c, v) ((c)->p_bin_a(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_string_array(c, v) ((c)->p_str_a(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_guid_array(c, v) ((c)->p_guid_a(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_proptag_array(c, v) ((c)->p_proptag_a(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_restriction(c, v) ((c)->p_restriction(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_rule_actions(c, v) ((c)->p_rule_actions(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_tagged_propval(c, v) ((c)->p_tagged_pv(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_property_name(c, v) ((c)->p_propname(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_propname_array(c, v) ((c)->p_propname_a(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_propid_array(c, v) ((c)->p_propid_a(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_tpropval_array(c, v) ((c)->p_tpropval_a(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_tarray_set(c, v) ((c)->p_tarray_set(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_sort_order(c, v) ((c)->p_sort_order(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_sortorder_set(c, v) ((c)->p_sortorder_set(v) == EXT_ERR_SUCCESS)
#define ext_pack_push_oneoff_entryid(c, v) ((c)->p_oneoff_eid(v) == EXT_ERR_SUCCESS)
zend_bool ext_pack_push_permission_set(
	PUSH_CTX *pctx, const PERMISSION_SET *r);
zend_bool ext_pack_push_rule_data(
	PUSH_CTX *pctx, const RULE_DATA *r);
zend_bool ext_pack_push_rule_list(
	PUSH_CTX *pctx, const RULE_LIST *r);
zend_bool ext_pack_push_state_array(
	PUSH_CTX *pctx, const STATE_ARRAY *r);
