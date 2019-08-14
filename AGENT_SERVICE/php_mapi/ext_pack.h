#ifndef _H_EXT_PACK_
#define _H_EXT_PACK_
#include "types.h"
#include "php.h"

typedef struct _PULL_CTX {
	const uint8_t *data;
	uint32_t data_size;
	uint32_t offset;
} PULL_CTX;

typedef struct _PUSH_CTX {
	uint8_t *data;
	uint32_t alloc_size;
	uint32_t offset;
} PUSH_CTX;


#define ext_pack_pull_bool	ext_pack_pull_uint8
#define ext_pack_pusg_bool	ext_pack_push_uint8

void ext_pack_pull_init(PULL_CTX *pctx,
	const uint8_t *pdata, uint32_t data_size);
	
zend_bool ext_pack_pull_advance(PULL_CTX *pctx, uint32_t size);

zend_bool ext_pack_pull_uint8(PULL_CTX *pctx, uint8_t *v);

zend_bool ext_pack_pull_uint16(PULL_CTX *pctx, uint16_t *v);

zend_bool ext_pack_pull_uint32(PULL_CTX *pctx, uint32_t *v);

zend_bool ext_pack_pull_int32(PULL_CTX *pctx, int32_t *v);

zend_bool ext_pack_pull_uint64(PULL_CTX *pctx, uint64_t *v);

zend_bool ext_pack_pull_float(PULL_CTX *pctx, float *v);

zend_bool ext_pack_pull_double(PULL_CTX *pctx, double *v);

zend_bool ext_pack_pull_bytes(PULL_CTX *pctx, uint8_t *data, uint32_t n);

zend_bool ext_pack_pull_guid(PULL_CTX *pctx, GUID *r);

zend_bool ext_pack_pull_string(PULL_CTX *pctx, char **ppstr);

zend_bool ext_pack_pull_wstring(PULL_CTX *pctx, char **ppstr);

zend_bool ext_pack_pull_binary(PULL_CTX *pctx, BINARY *r);

zend_bool ext_pack_pull_short_array(PULL_CTX *pctx, SHORT_ARRAY *r);

zend_bool ext_pack_pull_long_array(PULL_CTX *pctx, LONG_ARRAY *r);

zend_bool ext_pack_pull_longlong_array(PULL_CTX *pctx, LONGLONG_ARRAY *r);

zend_bool ext_pack_pull_binary_array(PULL_CTX *pctx, BINARY_ARRAY *r);

zend_bool ext_pack_pull_string_array(PULL_CTX *pctx, STRING_ARRAY *r);

zend_bool ext_pack_pull_wstring_array(PULL_CTX *pctx, STRING_ARRAY *r);

zend_bool ext_pack_pull_guid_array(PULL_CTX *pctx, GUID_ARRAY *r);

zend_bool ext_pack_pull_proptag_array(PULL_CTX *pctx, PROPTAG_ARRAY *r);

zend_bool ext_pack_pull_restriction(PULL_CTX *pctx, RESTRICTION *r);

zend_bool ext_pack_pull_svreid(PULL_CTX *pctx, SVREID *r);

zend_bool ext_pack_pull_rule_actions(PULL_CTX *pctx, RULE_ACTIONS *r);

zend_bool ext_pack_pull_tagged_propval(PULL_CTX *pctx, TAGGED_PROPVAL *r);

zend_bool ext_pack_pull_propval(PULL_CTX *pctx, uint16_t type, void **ppval);

zend_bool ext_pack_pull_property_name(PULL_CTX *pctx, PROPERTY_NAME *r);

zend_bool ext_pack_pull_propname_array(PULL_CTX *pctx, PROPNAME_ARRAY *r);

zend_bool ext_pack_pull_propid_array(PULL_CTX *pctx, PROPID_ARRAY *r);

zend_bool ext_pack_pull_tpropval_array(PULL_CTX *pctx, TPROPVAL_ARRAY *r);

zend_bool ext_pack_pull_tarray_set(PULL_CTX *pctx, TARRAY_SET *r);

zend_bool ext_pack_pull_sort_order(PULL_CTX *pctx, SORT_ORDER *r);

zend_bool ext_pack_pull_sortorder_set(PULL_CTX *pctx, SORTORDER_SET *r);

zend_bool ext_pack_pull_permission_set(PULL_CTX *pctx, PERMISSION_SET *r);

zend_bool ext_pack_pull_rule_data(PULL_CTX *pctx, RULE_DATA *r);

zend_bool ext_pacl_pull_rule_list(PULL_CTX *pctx, RULE_LIST *r);

zend_bool ext_pack_pull_oneoff_entryid(PULL_CTX *pctx, ONEOFF_ENTRYID *r);

zend_bool ext_pack_pull_state_array(PULL_CTX *pctx, STATE_ARRAY *r);

zend_bool ext_pack_pull_znotification_array(
	PULL_CTX *pctx, ZNOTIFICATION_ARRAY *r);

zend_bool ext_pack_push_init(PUSH_CTX *pctx);

void ext_pack_push_free(PUSH_CTX *pctx);

zend_bool ext_pack_push_advance(PUSH_CTX *pctx, uint32_t size);

zend_bool ext_pack_push_bytes(PUSH_CTX *pctx,
	const uint8_t *pdata, uint32_t n);

zend_bool ext_pack_push_uint8(PUSH_CTX *pctx, uint8_t v);

zend_bool ext_pack_push_int16(PUSH_CTX *pctx, int16_t v);

zend_bool ext_pack_push_uint16(PUSH_CTX *pctx, uint16_t v);

zend_bool ext_pack_push_int32(PUSH_CTX *pctx, int32_t v);

zend_bool ext_pack_push_uint32(PUSH_CTX *pctx, uint32_t v);

zend_bool ext_pack_push_int32(PUSH_CTX *pctx, int32_t v);

zend_bool ext_pack_push_int64(PUSH_CTX *pctx, int64_t v);

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

zend_bool ext_pack_push_slonglong_array(
	PUSH_CTX *pctx, const LONGLONG_ARRAY *r);

zend_bool ext_pack_push_binary_array(
	PUSH_CTX *pctx, const BINARY_ARRAY *r);

zend_bool ext_pack_push_string_array(
	PUSH_CTX *pctx, const STRING_ARRAY *r);

zend_bool ext_pack_push_wstring_array(
	PUSH_CTX *pctx, const STRING_ARRAY *r);

zend_bool ext_pack_push_guid_array(
	PUSH_CTX *pctx, const GUID_ARRAY *r);

zend_bool ext_pack_push_proptag_array(
	PUSH_CTX *pctx, const PROPTAG_ARRAY *r);

zend_bool ext_pack_push_restriction(
	PUSH_CTX *pctx, const RESTRICTION *r);

zend_bool ext_pack_push_svreid(
	PUSH_CTX *pctx, const SVREID *r);

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

zend_bool ext_pack_push_znotification_array(
	PUSH_CTX *pctx, const ZNOTIFICATION_ARRAY *r);

#endif /* _H_EXT_PACK_ */
