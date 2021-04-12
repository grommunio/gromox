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

#define ext_pack_push_init(c) ext_buffer_push_init((c), nullptr, 0, EXT_FLAG_WCOUNT, &ext_buffer_mgt)
#define ext_pack_push_free(c) ext_buffer_push_free(c)
#define ext_pack_push_advance(c, v) (ext_buffer_push_advance((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_bytes(c, v, z) (ext_buffer_push_bytes((c), (v), (z)) == EXT_ERR_SUCCESS)
#define ext_pack_push_uint8(c, v) (ext_buffer_push_uint8((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_uint16(c, v) (ext_buffer_push_uint16((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_int32(e, v) ext_pack_push_uint32((e), (v))
#define ext_pack_push_uint32(c, v) (ext_buffer_push_uint32((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_uint64(c, v) (ext_buffer_push_uint64((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_float(c, v) (ext_buffer_push_float((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_double(c, v) (ext_buffer_push_double((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_binary(c, v) (ext_buffer_push_binary((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_guid(c, v) (ext_buffer_push_guid((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_string(c, v) (ext_buffer_push_string((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_wstring(c, v) (ext_buffer_push_wstring((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_short_array(c, v) (ext_buffer_push_short_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_long_array(c, v) (ext_buffer_push_long_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_longlong_array(c, v) (ext_buffer_push_longlong_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_binary_array(c, v) (ext_buffer_push_binary_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_string_array(c, v) (ext_buffer_push_string_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_guid_array(c, v) (ext_buffer_push_guid_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_proptag_array(c, v) (ext_buffer_push_proptag_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_restriction(c, v) (ext_buffer_push_restriction((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_rule_actions(c, v) (ext_buffer_push_rule_actions((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_tagged_propval(c, v) (ext_buffer_push_tagged_propval((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_property_name(c, v) (ext_buffer_push_property_name((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_propname_array(c, v) (ext_buffer_push_propname_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_propid_array(c, v) (ext_buffer_push_propid_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_tpropval_array(c, v) (ext_buffer_push_tpropval_array((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_tarray_set(c, v) (ext_buffer_push_tarray_set((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_sort_order(c, v) (ext_buffer_push_sort_order((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_sortorder_set(c, v) (ext_buffer_push_sortorder_set((c), (v)) == EXT_ERR_SUCCESS)
#define ext_pack_push_oneoff_entryid(c, v) (ext_buffer_push_oneoff_entryid((c), (v)) == EXT_ERR_SUCCESS)
zend_bool ext_pack_push_permission_set(
	PUSH_CTX *pctx, const PERMISSION_SET *r);
zend_bool ext_pack_push_rule_data(
	PUSH_CTX *pctx, const RULE_DATA *r);
zend_bool ext_pack_push_rule_list(
	PUSH_CTX *pctx, const RULE_LIST *r);
zend_bool ext_pack_push_state_array(
	PUSH_CTX *pctx, const STATE_ARRAY *r);
