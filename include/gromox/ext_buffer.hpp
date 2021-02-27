#pragma once
#include <cstdint>
#include <gromox/mapi_types.hpp>
#include <gromox/element_data.hpp>

#define EXT_ERR_SUCCESS						0
#define EXT_ERR_FORMAT						1
#define EXT_ERR_BUFSIZE						2
#define EXT_ERR_ALLOC						3
#define EXT_ERR_BAD_SWITCH					4
#define EXT_ERR_CHARCNV						5
#define EXT_ERR_LZXPRESS					6
#define EXT_ERR_HEADER_FLAGS				7
#define EXT_ERR_HEADER_SIZE					8
#define EXT_ERR_RANGE						9
#define EXT_ERR_INVALID_OBJECT				10


#define EXT_FLAG_UTF16						0x00000001
#define EXT_FLAG_WCOUNT						0x00000002
#define EXT_FLAG_TBLLMT						0x00000004

typedef void* (*EXT_BUFFER_ALLOC)(size_t);

struct EXT_PULL {
	EXT_BUFFER_ALLOC alloc;
	template<typename T> inline T *anew() { return static_cast<T *>(alloc(sizeof(T))); }
	template<typename T> inline T *anew(size_t elem) { return static_cast<T *>(alloc(sizeof(T) * elem)); }
	union {
		const uint8_t *data;
		const char *cdata;
		const void *vdata;
	};
	uint32_t data_size;
	uint32_t offset;
	uint32_t flags;
};

struct EXT_PUSH {
	BOOL b_alloc;
	union {
		uint8_t *data;
		char *cdata;
		void *vdata;
	};
	uint32_t alloc_size;
	uint32_t offset;
	uint32_t flags;
};

/* bitmap RPC_HEADER_EXT flags */
#define RHE_FLAG_COMPRESSED							0x0001
#define RHE_FLAG_XORMAGIC							0x0002
#define RHE_FLAG_LAST								0x0004

struct RPC_HEADER_EXT {
	uint16_t version;
	uint16_t flags;
	uint16_t size;
	uint16_t size_actual;
};

extern void ext_buffer_pull_init(EXT_PULL *pext, const void *pdata,
	uint32_t data_size, EXT_BUFFER_ALLOC alloc, uint32_t flags);

void ext_buffer_pull_free(EXT_PULL *pext);

int ext_buffer_pull_advance(EXT_PULL *pext, uint32_t size);

int ext_buffer_pull_rpc_header_ext(EXT_PULL *pext, RPC_HEADER_EXT *r);

int ext_buffer_pull_int8(EXT_PULL *pext, int8_t *v);

int ext_buffer_pull_uint8(EXT_PULL *pext, uint8_t *v);

int ext_buffer_pull_int16(EXT_PULL *pext, int16_t *v);

int ext_buffer_pull_uint16(EXT_PULL *pext, uint16_t *v);

int ext_buffer_pull_int32(EXT_PULL *pext, int32_t *v);

int ext_buffer_pull_uint32(EXT_PULL *pext, uint32_t *v);

int ext_buffer_pull_int64(EXT_PULL *pext, int64_t *v);

int ext_buffer_pull_uint64(EXT_PULL *pext, uint64_t *v);

int ext_buffer_pull_float(EXT_PULL *pext, float *v);

int ext_buffer_pull_double(EXT_PULL *pext, double *v);

int ext_buffer_pull_bool(EXT_PULL *pext, BOOL *v);
extern int ext_buffer_pull_bytes(EXT_PULL *pext, void *data, uint32_t n);
int ext_buffer_pull_guid(EXT_PULL *pext, GUID *r);

int ext_buffer_pull_string(EXT_PULL *pext, char **ppstr);

int ext_buffer_pull_wstring(EXT_PULL *pext, char **ppstr);

int ext_buffer_pull_data_blob(EXT_PULL *pext, DATA_BLOB *pblob);

int ext_buffer_pull_binary(EXT_PULL *pext, BINARY *r);

int ext_buffer_pull_sbinary(EXT_PULL *pext, BINARY *r);

int ext_buffer_pull_exbinary(EXT_PULL *pext, BINARY *r);

int ext_buffer_pull_short_array(EXT_PULL *pext, SHORT_ARRAY *r);

int ext_buffer_pull_long_array(EXT_PULL *pext, LONG_ARRAY *r);

int ext_buffer_pull_longlong_array(EXT_PULL *pext, LONGLONG_ARRAY *r);

int ext_buffer_pull_slonglong_array(EXT_PULL *pext, LONGLONG_ARRAY *r);

int ext_buffer_pull_binary_array(EXT_PULL *pext, BINARY_ARRAY *r);

int ext_buffer_pull_string_array(EXT_PULL *pext, STRING_ARRAY *r);

int ext_buffer_pull_wstring_array(EXT_PULL *pext, STRING_ARRAY *r);

int ext_buffer_pull_guid_array(EXT_PULL *pext, GUID_ARRAY *r);

int ext_buffer_pull_proptag_array(EXT_PULL *pext, PROPTAG_ARRAY *r);

int ext_buffer_pull_restriction(EXT_PULL *pext, RESTRICTION *r);

int ext_buffer_pull_svreid(EXT_PULL *pext, SVREID *r);

int ext_buffer_pull_store_entryid(EXT_PULL *pext, STORE_ENTRYID *r);

int ext_buffer_pull_rule_actions(EXT_PULL *pext, RULE_ACTIONS *r);

int ext_buffer_pull_ext_rule_actions(EXT_PULL *pext, EXT_RULE_ACTIONS *r);

int ext_buffer_pull_namedproperty_information(
	EXT_PULL *pext, NAMEDPROPERTY_INFOMATION *r);

int ext_buffer_pull_long_term_id(EXT_PULL *pext, LONG_TERM_ID *r);
int ext_buffer_pull_long_term_id_rang(EXT_PULL *pext, LONG_TERM_ID_RANGE *r);

int ext_buffer_pull_typed_propval(EXT_PULL *pext, TYPED_PROPVAL *r);

int ext_buffer_pull_propval(EXT_PULL *pext, uint16_t type, void **ppval);

int ext_buffer_pull_tagged_propval(EXT_PULL *pext, TAGGED_PROPVAL *r);

int ext_buffer_pull_flagged_propval(EXT_PULL *pext,
	uint16_t type, FLAGGED_PROPVAL *r);

int ext_buffer_pull_property_row(EXT_PULL *pext,
	const PROPTAG_ARRAY *pcolumns, PROPERTY_ROW *r);
int ext_buffer_pull_property_name(EXT_PULL *pext, PROPERTY_NAME *r);

int ext_buffer_pull_propname_array(EXT_PULL *pext, PROPNAME_ARRAY *r);

int ext_buffer_pull_propid_array(EXT_PULL *pext, PROPID_ARRAY *r);

int ext_buffer_pull_tpropval_array(EXT_PULL *pext, TPROPVAL_ARRAY *r);

int ext_buffer_pull_tarray_set(EXT_PULL *pext, TARRAY_SET *r);

int ext_buffer_pull_problem_array(EXT_PULL *pext, PROBLEM_ARRAY *r);

int ext_buffer_pull_xid(EXT_PULL *pext, uint8_t size, XID *pxid);

int ext_buffer_pull_folder_entryid(EXT_PULL *pext, FOLDER_ENTRYID *r);

int ext_buffer_pull_message_entryid(EXT_PULL *pext, MESSAGE_ENTRYID *r);

int ext_buffer_pull_sort_order(EXT_PULL *pext, SORT_ORDER *r);

int ext_buffer_pull_sortorder_set(EXT_PULL *pext, SORTORDER_SET *r);
int ext_buffer_pull_recipient_row(EXT_PULL *pext,
	const PROPTAG_ARRAY *pproptags, RECIPIENT_ROW *r);
int ext_buffer_pull_modifyrecipient_row(EXT_PULL *pext,
	PROPTAG_ARRAY *pproptags, MODIFYRECIPIENT_ROW *r);
int ext_buffer_pull_permission_data(EXT_PULL *pext, PERMISSION_DATA *r);

int ext_buffer_pull_rule_data(EXT_PULL *pext, RULE_DATA *r);

int ext_buffer_pull_addressbook_entryid(
	EXT_PULL *pext, ADDRESSBOOK_ENTRYID *r);

int ext_buffer_pull_oneoff_entryid(EXT_PULL *pext, ONEOFF_ENTRYID *r);

int ext_buffer_pull_oneoff_array(EXT_PULL *pext, ONEOFF_ARRAY *r);
int ext_buffer_pull_eid_array(EXT_PULL *pext, EID_ARRAY *r);

int ext_buffer_pull_systemtime(EXT_PULL *pext, SYSTEMTIME *r);

int ext_buffer_pull_timezonestruct(EXT_PULL *pext, TIMEZONESTRUCT *r);

int ext_buffer_pull_timezonedefinition(EXT_PULL *pext, TIMEZONEDEFINITION *r);

int ext_buffer_pull_appointmentrecurrencepattern(
	EXT_PULL *pext, APPOINTMENTRECURRENCEPATTERN *r);

int ext_buffer_pull_globalobjectid(EXT_PULL *pext, GLOBALOBJECTID *r);

int ext_buffer_pull_message_content(EXT_PULL *pext, MESSAGE_CONTENT *pmsg);
extern BOOL ext_buffer_push_init(EXT_PUSH *pext, void *pdata,
	uint32_t alloc_size, uint32_t flags);
void ext_buffer_push_free(EXT_PUSH *pext);

int ext_buffer_push_advance(EXT_PUSH *pext, uint32_t size);

int ext_buffer_push_rpc_header_ext(EXT_PUSH *pext, const RPC_HEADER_EXT *r);

BOOL ext_buffer_push_check_overflow(EXT_PUSH *pext, uint32_t extra_size);
extern int ext_buffer_push_bytes(EXT_PUSH *pext, const void *pdata, uint32_t n);
int ext_buffer_push_int8(EXT_PUSH *pext, int8_t v);

int ext_buffer_push_uint8(EXT_PUSH *pext, uint8_t v);

int ext_buffer_push_int16(EXT_PUSH *pext, int16_t v);

int ext_buffer_push_uint16(EXT_PUSH *pext, uint16_t v);

int ext_buffer_push_int32(EXT_PUSH *pext, int32_t v);

int ext_buffer_push_uint32(EXT_PUSH *pext, uint32_t v);
int ext_buffer_push_uint64(EXT_PUSH *pext, uint64_t v);

int ext_buffer_push_float(EXT_PUSH *pext, float v);

int ext_buffer_push_double(EXT_PUSH *pext, double v);

int ext_buffer_push_bool(EXT_PUSH *pext, BOOL v);

int ext_buffer_push_data_blob(EXT_PUSH *pext, DATA_BLOB blob);

int ext_buffer_push_binary(EXT_PUSH *pext, const BINARY *r);

int ext_buffer_push_sbinary(EXT_PUSH *pext, const BINARY *r);

int ext_buffer_push_exbinary(EXT_PUSH *pext, const BINARY *r);

int ext_buffer_push_guid(EXT_PUSH *pext, const GUID *r);

int ext_buffer_push_string(EXT_PUSH *pext, const char *pstr);

int ext_buffer_push_wstring(EXT_PUSH *pext, const char *pstr);

int ext_buffer_push_short_array(EXT_PUSH *pext, const SHORT_ARRAY *r);

int ext_buffer_push_long_array(EXT_PUSH *pext, const LONG_ARRAY *r);

int ext_buffer_push_longlong_array(EXT_PUSH *pext, const LONGLONG_ARRAY *r);

int ext_buffer_push_slonglong_array(EXT_PUSH *pext, const LONGLONG_ARRAY *r);

int ext_buffer_push_binary_array(EXT_PUSH *pext, const BINARY_ARRAY *r);

int ext_buffer_push_string_array(EXT_PUSH *pext, const STRING_ARRAY *r);

int ext_buffer_push_wstring_array(EXT_PUSH *pext, const STRING_ARRAY *r);

int ext_buffer_push_guid_array(EXT_PUSH *pext, const GUID_ARRAY *r);

int ext_buffer_push_proptag_array(EXT_PUSH *pext, const PROPTAG_ARRAY *r);

int ext_buffer_push_restriction(EXT_PUSH *pext, const RESTRICTION *r);

int ext_buffer_push_svreid(EXT_PUSH *pext, const SVREID *r);

int ext_buffer_push_store_entryid(EXT_PUSH *pext, const STORE_ENTRYID *r);

int ext_buffer_push_rule_actions(EXT_PUSH *pext, const RULE_ACTIONS *r);
int ext_buffer_push_long_term_id(EXT_PUSH *pext, const LONG_TERM_ID *r);

int ext_buffer_push_long_term_id_array(
	EXT_PUSH *pext, const LONG_TERM_ID_ARRAY *r);
int ext_buffer_push_typed_propval(EXT_PUSH *pext, const TYPED_PROPVAL *r);

int ext_buffer_push_propval(EXT_PUSH *pext, uint16_t type, const void *pval);

int ext_buffer_push_tagged_propval(EXT_PUSH *pext, const TAGGED_PROPVAL *r);

int ext_buffer_push_flagged_propval(EXT_PUSH *pext,
	uint16_t type, const FLAGGED_PROPVAL *r);

int ext_buffer_push_property_row(EXT_PUSH *pext,
	const PROPTAG_ARRAY *pcolumns, const PROPERTY_ROW *r);
int ext_buffer_push_property_name(EXT_PUSH *pext, const PROPERTY_NAME *r);

int ext_buffer_push_propname_array(EXT_PUSH *pext, const PROPNAME_ARRAY *r);

int ext_buffer_push_propid_array(EXT_PUSH *pext, const PROPID_ARRAY *r);

int ext_buffer_push_tpropval_array(EXT_PUSH *pext, const TPROPVAL_ARRAY *r);

int ext_buffer_push_tarray_set(EXT_PUSH *pext, const TARRAY_SET *r);

int ext_buffer_push_problem_array(EXT_PUSH *pext, const PROBLEM_ARRAY *r);

int ext_buffer_push_xid(EXT_PUSH *pext, uint8_t size, const XID *pxid);

int ext_buffer_push_folder_entryid(EXT_PUSH *pext, const FOLDER_ENTRYID *r);

int ext_buffer_push_message_entryid(EXT_PUSH *pext, const MESSAGE_ENTRYID *r);

int ext_buffer_push_sort_order(EXT_PUSH *pext, const SORT_ORDER *r);

int ext_buffer_push_sortorder_set(EXT_PUSH *pext, const SORTORDER_SET *r);

int ext_buffer_push_typed_string(EXT_PUSH *pext, const TYPED_STRING *r);

int ext_buffer_push_recipient_row(EXT_PUSH *pext,
	const PROPTAG_ARRAY *pproptags, const RECIPIENT_ROW *r);

int ext_buffer_push_openrecipient_row(EXT_PUSH *pext,
	const PROPTAG_ARRAY *pproptags, const OPENRECIPIENT_ROW *r);
int ext_buffer_push_readrecipient_row(EXT_PUSH *pext,
	PROPTAG_ARRAY *pproptags, const READRECIPIENT_ROW *r);

int ext_buffer_push_permission_data(EXT_PUSH *pext, const PERMISSION_DATA *r);

int ext_buffer_push_rule_data(EXT_PUSH *pext, const RULE_DATA *r);

int ext_buffer_push_addressbook_entryid(
	EXT_PUSH *pext, const ADDRESSBOOK_ENTRYID *r);

int ext_buffer_push_oneoff_entryid(EXT_PUSH *pext,
	const ONEOFF_ENTRYID *r);
int ext_buffer_push_persistdata_array(
	EXT_PUSH *pext, const PERSISTDATA_ARRAY *r);

int ext_buffer_push_eid_array(EXT_PUSH *pext, const EID_ARRAY *r);

int ext_buffer_push_systemtime(EXT_PUSH *pext, const SYSTEMTIME *r);

int ext_buffer_push_timezonestruct(EXT_PUSH *pext, const TIMEZONESTRUCT *r);

int ext_buffer_push_timezonedefinition(
	EXT_PUSH *pext, const TIMEZONEDEFINITION *r);

int ext_buffer_push_appointmentrecurrencepattern(
	EXT_PUSH *pext, const APPOINTMENTRECURRENCEPATTERN *r);

int ext_buffer_push_globalobjectid(EXT_PUSH *pext, const GLOBALOBJECTID *r);

int ext_buffer_push_message_content(
	EXT_PUSH *pext, const MESSAGE_CONTENT *pmsg);
uint8_t *ext_buffer_push_release(EXT_PUSH *);
