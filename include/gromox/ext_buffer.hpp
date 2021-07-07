#pragma once
#include <cstddef>
#include <cstdint>
#include <gromox/common_types.hpp>
#include <gromox/mapidefs.h>

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

struct EXT_BUFFER_MGT {
	void *(*alloc)(size_t);
	void *(*realloc)(void *, size_t);
	void (*free)(void *);
};

struct EXT_PULL;
struct EXT_PUSH;
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

struct ADDRESSBOOK_ENTRYID;
struct APPOINTMENTRECURRENCEPATTERN;
struct EID_ARRAY;
struct EXT_RULE_ACTIONS;
struct FLAGGED_PROPVAL;
struct FOLDER_ENTRYID;
struct GLOBALOBJECTID;
struct LONG_TERM_ID;
struct LONG_TERM_ID_ARRAY;
struct LONG_TERM_ID_RANGE;
struct MESSAGE_CONTENT;
struct MESSAGE_ENTRYID;
struct MODIFYRECIPIENT_ROW;
struct NAMEDPROPERTY_INFOMATION;
struct OPENRECIPIENT_ROW;
struct PERMISSION_DATA;
struct PERSISTDATA_ARRAY;
struct PROBLEM_ARRAY;
struct PROPERTY_ROW;
struct READRECIPIENT_ROW;
struct RECIPIENT_ROW;
struct STORE_ENTRYID;
struct SYSTEMTIME;
struct TIMEZONEDEFINITION;
struct TIMEZONESTRUCT;
struct TYPED_PROPVAL;
struct TYPED_STRING;
struct XID;

extern void ext_buffer_pull_init(EXT_PULL *pext, const void *pdata,
	uint32_t data_size, EXT_BUFFER_ALLOC alloc, uint32_t flags);
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

struct EXT_PULL {
	EXT_BUFFER_ALLOC alloc{};
	inline void init(const void *d, uint32_t z, EXT_BUFFER_ALLOC a, uint32_t fl) { return ext_buffer_pull_init(this, d, z, a, fl); }
	inline int advance(uint32_t n) { return ext_buffer_pull_advance(this, n); }
	inline int g_rpc_header_ext(RPC_HEADER_EXT *r) { return ext_buffer_pull_rpc_header_ext(this, r); }
	inline int g_int8(int8_t *v) { return ext_buffer_pull_int8(this, v); }
	inline int g_uint8(uint8_t *v) { return ext_buffer_pull_uint8(this, v); }
	inline int g_int16(int16_t *v) { return ext_buffer_pull_int16(this, v); }
	inline int g_uint16(uint16_t *v) { return ext_buffer_pull_uint16(this, v); }
	inline int g_int32(int32_t *v) { return ext_buffer_pull_int32(this, v); }
	inline int g_uint32(uint32_t *v) { return ext_buffer_pull_uint32(this, v); }
	inline int g_int64(int64_t *v) { return ext_buffer_pull_int64(this, v); }
	inline int g_uint64(uint64_t *v) { return ext_buffer_pull_uint64(this, v); }
	inline int g_float(float *v) { return ext_buffer_pull_float(this, v); }
	inline int g_double(double *v) { return ext_buffer_pull_double(this, v); }
	inline int g_bool(BOOL *v) { return ext_buffer_pull_bool(this, v); }
	inline int g_bytes(void *d, uint32_t n) { return ext_buffer_pull_bytes(this, d, n); }
	inline int g_guid(GUID *r) { return ext_buffer_pull_guid(this, r); }
	inline int g_str(char **s) { return ext_buffer_pull_string(this, s); }
	inline int g_wstr(char **s) { return ext_buffer_pull_wstring(this, s); }
	inline int g_blob(DATA_BLOB *b) { return ext_buffer_pull_data_blob(this, b); }
	inline int g_bin(BINARY *r) { return ext_buffer_pull_binary(this, r); }
	inline int g_sbin(BINARY *r) { return ext_buffer_pull_sbinary(this, r); }
	inline int g_exbin(BINARY *r) { return ext_buffer_pull_exbinary(this, r); }
	inline int g_uint16_a(SHORT_ARRAY *r) { return ext_buffer_pull_short_array(this, r); }
	inline int g_uint32_a(LONG_ARRAY *r) { return ext_buffer_pull_long_array(this, r); }
	inline int g_uint64_a(LONGLONG_ARRAY *r) { return ext_buffer_pull_longlong_array(this, r); }
	inline int g_uint64_sa(LONGLONG_ARRAY *r) { return ext_buffer_pull_slonglong_array(this, r); }
	inline int g_bin_a(BINARY_ARRAY *r) { return ext_buffer_pull_binary_array(this, r); }
	inline int g_str_a(STRING_ARRAY *r) { return ext_buffer_pull_string_array(this, r); }
	inline int g_wstr_a(STRING_ARRAY *r) { return ext_buffer_pull_wstring_array(this, r); }
	inline int g_guid_a(GUID_ARRAY *r) { return ext_buffer_pull_guid_array(this, r); }
	inline int g_proptag_a(PROPTAG_ARRAY *r) { return ext_buffer_pull_proptag_array(this, r); }
	inline int g_restriction(RESTRICTION *r) { return ext_buffer_pull_restriction(this, r); }
	inline int g_svreid(SVREID *r) { return ext_buffer_pull_svreid(this, r); }
	inline int g_store_eid(STORE_ENTRYID *r) { return ext_buffer_pull_store_entryid(this, r); }
	inline int g_rule_actions(RULE_ACTIONS *r) { return ext_buffer_pull_rule_actions(this, r); }
	inline int g_ext_rule_actions(EXT_RULE_ACTIONS *r) { return ext_buffer_pull_ext_rule_actions(this, r); }
	inline int g_namedprop_info(NAMEDPROPERTY_INFOMATION *r) { return ext_buffer_pull_namedproperty_information(this, r); }
	inline int g_longterm(LONG_TERM_ID *r) { return ext_buffer_pull_long_term_id(this, r); }
	inline int g_longterm_rang(LONG_TERM_ID_RANGE *r) { return ext_buffer_pull_long_term_id_rang(this, r); }
	inline int g_typed_pv(TYPED_PROPVAL *r) { return ext_buffer_pull_typed_propval(this, r); }
	inline int g_propval(uint16_t type, void **v) { return ext_buffer_pull_propval(this, type, v); }
	inline int g_tagged_pv(TAGGED_PROPVAL *r) { return ext_buffer_pull_tagged_propval(this, r); }
	inline int g_flagged_pv(uint16_t type, FLAGGED_PROPVAL *r) { return ext_buffer_pull_flagged_propval(this, type, r); }
	inline int g_proprow(const PROPTAG_ARRAY *cols, PROPERTY_ROW *r) { return ext_buffer_pull_property_row(this, cols, r); }
	inline int g_propname(PROPERTY_NAME *r) { return ext_buffer_pull_property_name(this, r); }
	inline int g_propname_a(PROPNAME_ARRAY *r) { return ext_buffer_pull_propname_array(this, r); }
	inline int g_propid_a(PROPID_ARRAY *r) { return ext_buffer_pull_propid_array(this, r); }
	inline int g_tpropval_a(TPROPVAL_ARRAY *r) { return ext_buffer_pull_tpropval_array(this, r); }
	inline int g_tarray_set(TARRAY_SET *r) { return ext_buffer_pull_tarray_set(this, r); }
	inline int g_problem_a(PROBLEM_ARRAY *r) { return ext_buffer_pull_problem_array(this, r); }
	inline int g_xid(uint8_t size, XID *x) { return ext_buffer_pull_xid(this, size, x); }
	inline int g_folder_eid(FOLDER_ENTRYID *r) { return ext_buffer_pull_folder_entryid(this, r); }
	inline int g_msg_eid(MESSAGE_ENTRYID *r) { return ext_buffer_pull_message_entryid(this, r); }
	inline int g_sortorder(SORT_ORDER *r) { return ext_buffer_pull_sort_order(this, r); }
	inline int g_sortorder_set(SORTORDER_SET *r) { return ext_buffer_pull_sortorder_set(this, r); }
	inline int g_recipient_row(const PROPTAG_ARRAY *tags, RECIPIENT_ROW *r) { return ext_buffer_pull_recipient_row(this, tags, r); }
	inline int g_modrcpt_row(PROPTAG_ARRAY *tag, MODIFYRECIPIENT_ROW *r) { return ext_buffer_pull_modifyrecipient_row(this, tag, r); }
	inline int g_permission_data(PERMISSION_DATA *r) { return ext_buffer_pull_permission_data(this, r); }
	inline int g_rule_data(RULE_DATA *r) { return ext_buffer_pull_rule_data(this, r); }
	inline int g_abk_eid(ADDRESSBOOK_ENTRYID *r) { return ext_buffer_pull_addressbook_entryid(this, r); }
	inline int g_oneoff_eid(ONEOFF_ENTRYID *r) { return ext_buffer_pull_oneoff_entryid(this, r); }
	inline int g_oneoff_a(ONEOFF_ARRAY *r) { return ext_buffer_pull_oneoff_array(this, r); }
	inline int g_eid_a(EID_ARRAY *r) { return ext_buffer_pull_eid_array(this, r); }
	inline int g_systime(SYSTEMTIME *r) { return ext_buffer_pull_systemtime(this, r); }
	inline int g_tzstruct(TIMEZONESTRUCT *r) { return ext_buffer_pull_timezonestruct(this, r); }
	inline int g_tzdef(TIMEZONEDEFINITION *r) { return ext_buffer_pull_timezonedefinition(this, r); }
	inline int g_apptrecpat(APPOINTMENTRECURRENCEPATTERN *r) { return ext_buffer_pull_appointmentrecurrencepattern(this, r); }
	inline int g_goid(GLOBALOBJECTID *r) { return ext_buffer_pull_globalobjectid(this, r); }
	inline int g_msgctnt(MESSAGE_CONTENT *m) { return ext_buffer_pull_message_content(this, m); }

	template<typename T> inline T *anew() { return static_cast<T *>(alloc(sizeof(T))); }
	template<typename T> inline T *anew(size_t elem) { return static_cast<T *>(alloc(sizeof(T) * elem)); }
	union {
		const uint8_t *data, *udata;
		const char *cdata;
		const void *vdata = nullptr;
	};
	uint32_t data_size = 0, offset = 0, flags = 0;
};

struct EXT_PUSH {
	~EXT_PUSH();
	BOOL init(void *, uint32_t, uint32_t, const EXT_BUFFER_MGT * = nullptr);
	uint8_t *release();
	BOOL check_ovf(uint32_t);
	int advance(uint32_t);
	int p_bytes(const void *, uint32_t);
	int p_uint8(uint8_t);
	int p_int8(int8_t v) { return p_uint8(v); }
	int p_uint16(uint16_t);
	int p_int16(int16_t v) { return p_uint16(v); }
	int p_uint32(uint32_t);
	int p_int32(int32_t v) { return p_uint32(v); }
	int p_uint64(uint64_t);
	int p_int64(int64_t v) { return p_uint64(v); }
	int p_float(float);
	int p_double(double);
	int p_bool(BOOL);
	int p_blob(DATA_BLOB);
	int p_bin(const BINARY *);
	int p_bin_s(const BINARY *);
	int p_bin_ex(const BINARY *);
	int p_guid(const GUID *);
	int p_str(const char *);
	int p_wstr(const char *);
	int p_uint16_a(const SHORT_ARRAY *);
	int p_uint32_a(const LONG_ARRAY *);
	int p_uint64_a(const LONGLONG_ARRAY *);
	int p_uint64_sa(const LONGLONG_ARRAY *);
	int p_bin_a(const BINARY_ARRAY *);
	int p_str_a(const STRING_ARRAY *);
	int p_wstr_a(const STRING_ARRAY *);
	int p_guid_a(const GUID_ARRAY *);
	int p_proptag_a(const PROPTAG_ARRAY *);
	int p_restriction(const RESTRICTION *);
	int p_svreid(const SVREID *);
	int p_store_eid(const STORE_ENTRYID *);
	int p_rule_actions(const RULE_ACTIONS *);
	int p_longterm(const LONG_TERM_ID *);
	int p_longterm_a(const LONG_TERM_ID_ARRAY *);
	int p_propval(uint16_t, const void *);
	int p_tagged_pv(const TAGGED_PROPVAL *);
	int p_typed_pv(const TYPED_PROPVAL *);
	int p_flagged_pv(uint16_t, const FLAGGED_PROPVAL *);
	int p_proprow(const PROPTAG_ARRAY *, const PROPERTY_ROW *);
	int p_propname(const PROPERTY_NAME *);
	int p_propname_a(const PROPNAME_ARRAY *);
	int p_propid_a(const PROPID_ARRAY *);
	int p_tpropval_a(const TPROPVAL_ARRAY *);
	int p_tarray_set(const TARRAY_SET *);
	int p_problem_a(const PROBLEM_ARRAY *);
	int p_xid(uint8_t, const XID *);
	int p_folder_eid(const FOLDER_ENTRYID *);
	int p_msg_eid(const MESSAGE_ENTRYID *);
	int p_sortorder(const SORT_ORDER *);
	int p_sortorder_set(const SORTORDER_SET *);
	int p_typed_str(const TYPED_STRING *);
	int p_recipient_row(const PROPTAG_ARRAY *tags, const RECIPIENT_ROW *);
	int p_openrecipient_row(const PROPTAG_ARRAY *tags, const OPENRECIPIENT_ROW *);
	int p_readrecipient_row(const PROPTAG_ARRAY *tags, const READRECIPIENT_ROW *);
	int p_permission_data(const PERMISSION_DATA *);
	int p_rule_data(const RULE_DATA *);
	int p_abk_eid(const ADDRESSBOOK_ENTRYID *);
	int p_oneoff_eid(const ONEOFF_ENTRYID *);
	int p_persistdata_a(const PERSISTDATA_ARRAY *);
	int p_eid_a(const EID_ARRAY *);
	int p_systime(const SYSTEMTIME *);
	int p_tzstruct(const TIMEZONESTRUCT *);
	int p_tzdef(const TIMEZONEDEFINITION *);
	int p_apptrecpat(const APPOINTMENTRECURRENCEPATTERN *);
	int p_goid(const GLOBALOBJECTID *);
	int p_msgctnt(const MESSAGE_CONTENT *);
	int p_rpchdr(const RPC_HEADER_EXT *);

	BOOL b_alloc = false;
	union {
		uint8_t *data, *udata;
		char *cdata;
		void *vdata = nullptr;
	};
	uint32_t alloc_size = 0, offset = 0, flags = 0;
	EXT_BUFFER_MGT mgt{};
};
