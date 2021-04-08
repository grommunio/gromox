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

inline void *ext_pack_pull_alloc(size_t z) { return emalloc(z); }

#define ext_pack_pull_init(c, d, s) ext_buffer_pull_init((c), (d), (s), ext_pack_pull_alloc, EXT_FLAG_WCOUNT)
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

zend_bool ext_pack_push_init(PUSH_CTX *pctx);

void ext_pack_push_free(PUSH_CTX *pctx);

zend_bool ext_pack_push_advance(PUSH_CTX *pctx, uint32_t size);
extern zend_bool ext_pack_push_bytes(PUSH_CTX *pctx, const void *pdata, uint32_t n);
zend_bool ext_pack_push_uint8(PUSH_CTX *pctx, uint8_t v);
zend_bool ext_pack_push_uint16(PUSH_CTX *pctx, uint16_t v);
#define ext_pack_push_int32(e, v) ext_pack_push_uint32((e), (v))
zend_bool ext_pack_push_uint32(PUSH_CTX *pctx, uint32_t v);
zend_bool ext_pack_push_uint64(PUSH_CTX *pctx, uint64_t v);

zend_bool ext_pack_push_float(PUSH_CTX *pctx, float v);

zend_bool ext_pack_push_double(PUSH_CTX *pctx, double v);

zend_bool ext_pack_push_binary(PUSH_CTX *pctx, const BINARY *r);

zend_bool ext_pack_push_guid(PUSH_CTX *pctx, const GUID *r);

zend_bool ext_pack_push_string(PUSH_CTX *pctx, const char *pstr);

zend_bool ext_pack_push_wstring(PUSH_CTX *pctx, const char *pstr);

zend_bool ext_pack_push_short_array(
	PUSH_CTX *pctx, const SHORT_ARRAY *r);

zend_bool ext_pack_push_long_array(
	PUSH_CTX *pctx, const LONG_ARRAY *r);

zend_bool ext_pack_push_longlong_array(
	PUSH_CTX *pctx, const LONGLONG_ARRAY *r);
zend_bool ext_pack_push_binary_array(
	PUSH_CTX *pctx, const BINARY_ARRAY *r);

zend_bool ext_pack_push_string_array(
	PUSH_CTX *pctx, const STRING_ARRAY *r);
zend_bool ext_pack_push_guid_array(
	PUSH_CTX *pctx, const GUID_ARRAY *r);

zend_bool ext_pack_push_proptag_array(
	PUSH_CTX *pctx, const PROPTAG_ARRAY *r);

zend_bool ext_pack_push_restriction(
	PUSH_CTX *pctx, const RESTRICTION *r);
zend_bool ext_pack_push_rule_actions(
	PUSH_CTX *pctx, const RULE_ACTIONS *r);

zend_bool ext_pack_push_tagged_propval(
	PUSH_CTX *pctx, const TAGGED_PROPVAL *r);
	
zend_bool ext_pack_push_property_name(
	PUSH_CTX *pctx, const PROPERTY_NAME *r);

zend_bool ext_pack_push_propname_array(
	PUSH_CTX *pctx, const PROPNAME_ARRAY *r);

zend_bool ext_pack_push_propid_array(
	PUSH_CTX *pctx, const PROPID_ARRAY *r);

zend_bool ext_pack_push_tpropval_array(
	PUSH_CTX *pctx, const TPROPVAL_ARRAY *r);

zend_bool ext_pack_push_tarray_set(
	PUSH_CTX *pctx, const TARRAY_SET *r);

zend_bool ext_pack_push_sort_order(
	PUSH_CTX *pctx, const SORT_ORDER *r);

zend_bool ext_pack_push_sortorder_set(
	PUSH_CTX *pctx, const SORTORDER_SET *r);

zend_bool ext_pack_push_permission_set(
	PUSH_CTX *pctx, const PERMISSION_SET *r);

zend_bool ext_pack_push_rule_data(
	PUSH_CTX *pctx, const RULE_DATA *r);

zend_bool ext_pack_push_rule_list(
	PUSH_CTX *pctx, const RULE_LIST *r);

zend_bool ext_pack_push_oneoff_entryid(
	PUSH_CTX *pctx, const ONEOFF_ENTRYID *r);
	
zend_bool ext_pack_push_state_array(
	PUSH_CTX *pctx, const STATE_ARRAY *r);
