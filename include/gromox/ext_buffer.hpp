#pragma once
#include <cstddef>
#include <cstdint>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>

enum {
	EXT_ERR_SUCCESS = 0,
	EXT_ERR_FAILURE,
	EXT_ERR_FORMAT,
	EXT_ERR_BUFSIZE,
	EXT_ERR_ALLOC,
	EXT_ERR_BAD_SWITCH,
	EXT_ERR_CHARCNV,
	EXT_ERR_LZXPRESS,
	EXT_ERR_HEADER_FLAGS,
	EXT_ERR_HEADER_SIZE,
	EXT_ERR_RANGE,
	EXT_ERR_INVALID_OBJECT,
	EXT_ERR_NDR64,
	EXT_ERR_PADDING,
	EXT_ERR_ARRAY_SIZE,
	EXT_ERR_IPV6ADDRESS,
	EXT_CTRL_SKIP,
};

/**
 * %EXT_FLAG_UTF16:	packed representation encodes wide strings as UTF-16
 * 			(else, UTF-8)
 * %EXT_FLAG_WCOUNT:	packed rep encodes certain array lengths as 32-bit
 * 			(else, 16-bit)
 * %EXT_FLAG_TBLLMT:	limit packed rep strings to 255 characters
 * 			(GetContentsTable / GetHierarchyTable)
 * %EXT_FLAG_ABK:	packed rep includes extra set/unset flags
 * %EXT_FLAG_ZCORE:	unpacked rep uses zcore types for rule element pointers
 *
 * The Exchange protocols use UTF-16, but the Gromox exmdb and zcore RPC
 * protocols use UTF-8. This may require using more than one context to process
 * certain chunks of data; for example, to parse zcreq_getpropvals you need a
 * ctx _without_ EXT_FLAG_UTF16, but to parse a oneoff entryid that may be
 * present inside that getpropval request, you need a ctx _with_
 * EXT_FLAG_UTF16.
 */
enum {
	EXT_FLAG_UTF16 = 1U << 0,
	EXT_FLAG_WCOUNT = 1U << 1,
	EXT_FLAG_TBLLMT = 1U << 2,
	EXT_FLAG_ABK = 1U << 3,
	EXT_FLAG_ZCORE = 1U << 4,
};

using EXT_BUFFER_ALLOC = void *(*)(size_t);

struct EXT_BUFFER_MGT {
	EXT_BUFFER_ALLOC alloc;
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

struct APPOINTMENT_RECUR_PAT;
struct EID_ARRAY;
struct EMSAB_ENTRYID;
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

struct EXT_PULL {
	EXT_BUFFER_ALLOC m_alloc{};
	void init(const void *, uint32_t, EXT_BUFFER_ALLOC, uint32_t) __attribute__((nonnull(4)));
	int advance(uint32_t);
	int g_rpc_header_ext(RPC_HEADER_EXT *);
	int g_uint8(uint8_t *);
	inline int g_int8(int8_t *v) { return g_uint8(reinterpret_cast<uint8_t *>(v)); }
	int g_uint16(uint16_t *);
	inline int g_int16(int16_t *v) { return g_uint16(reinterpret_cast<uint16_t *>(v)); }
	int g_uint32(uint32_t *);
	inline int g_int32(int32_t *v) { return g_uint32(reinterpret_cast<uint32_t *>(v)); }
	int g_uint64(uint64_t *);
	inline int g_int64(int64_t *v) { return g_uint64(reinterpret_cast<uint64_t *>(v)); }
	int g_float(float *);
	int g_double(double *);
	int g_bool(BOOL *);
	int g_bytes(void *, uint32_t) __attribute__((nonnull(2)));
	int g_guid(GUID *);
	inline int g_guid(FLATUID *v) { return g_bytes(v, sizeof(*v)); }
	int g_str(char **);
	int g_wstr(char **);
	int g_blob(DATA_BLOB *);
	int g_bin(BINARY *);
	int g_sbin(BINARY *);
	int g_bin_ex(BINARY *);
	int g_uint16_a(SHORT_ARRAY *);
	int g_uint32_a(LONG_ARRAY *);
	int g_uint64_a(LONGLONG_ARRAY *);
	int g_uint64_sa(LONGLONG_ARRAY *);
	int g_float_a(FLOAT_ARRAY *);
	int g_double_a(DOUBLE_ARRAY *);
	int g_bin_a(BINARY_ARRAY *);
	int g_str_a(STRING_ARRAY *);
	int g_wstr_a(STRING_ARRAY *);
	int g_guid_a(GUID_ARRAY *);
	int g_proptag_a(PROPTAG_ARRAY *);
	int g_proptag_a(LPROPTAG_ARRAY *);
	int g_restriction(RESTRICTION *);
	int g_svreid(SVREID *);
	int g_store_eid(STORE_ENTRYID *);
	int g_rule_actions(RULE_ACTIONS *);
	int g_ext_rule_actions(EXT_RULE_ACTIONS *);
	int g_namedprop_info(NAMEDPROPERTY_INFOMATION *);
	int g_longterm(LONG_TERM_ID *);
	int g_longterm_range(LONG_TERM_ID_RANGE *);
	int g_typed_pv(TYPED_PROPVAL *);
	int g_propval(uint16_t type, void **);
	int g_tagged_pv(TAGGED_PROPVAL *);
	int g_flagged_pv(uint16_t type, FLAGGED_PROPVAL *);
	int g_proprow(const PROPTAG_ARRAY *cols, PROPERTY_ROW *);
	int g_propname(PROPERTY_NAME *);
	int g_propname_a(PROPNAME_ARRAY *);
	int g_propid_a(PROPID_ARRAY *);
	int g_tpropval_a(TPROPVAL_ARRAY *);
	int g_tpropval_a(LTPROPVAL_ARRAY *);
	int g_tarray_set(TARRAY_SET *);
	int g_problem_a(PROBLEM_ARRAY *);
	int g_xid(uint8_t size, XID *);
	int g_folder_eid(FOLDER_ENTRYID *);
	int g_msg_eid(MESSAGE_ENTRYID *);
	int g_sortorder(SORT_ORDER *);
	int g_sortorder_set(SORTORDER_SET *);
	int g_recipient_row(const PROPTAG_ARRAY *tags, RECIPIENT_ROW *);
	int g_modrcpt_row(PROPTAG_ARRAY *tag, MODIFYRECIPIENT_ROW *);
	int g_permission_data(PERMISSION_DATA *);
	int g_rule_data(RULE_DATA *);
	int g_abk_eid(EMSAB_ENTRYID *);
	int g_oneoff_eid(ONEOFF_ENTRYID *);
	int g_flatentry_a(BINARY_ARRAY *);
	int g_eid_a(EID_ARRAY *);
	int g_systime(SYSTEMTIME *);
	int g_tzstruct(TIMEZONESTRUCT *);
	int g_tzdef(TIMEZONEDEFINITION *);
	int g_apptrecpat(APPOINTMENT_RECUR_PAT *);
	int g_goid(GLOBALOBJECTID *);
	int g_msgctnt(MESSAGE_CONTENT *);

	template<typename T> inline T *anew() { return static_cast<T *>(m_alloc(sizeof(T))); }
	template<typename T> inline T *anew(size_t elem) { return static_cast<T *>(m_alloc(sizeof(T) * elem)); }
	union {
		const uint8_t *m_udata;
		const char *m_cdata;
		const void *m_vdata = nullptr;
	};
	uint32_t m_data_size = 0, m_offset = 0, m_flags = 0;
};

struct EXT_PUSH {
	EXT_PUSH() = default;
	~EXT_PUSH();
	NOMOVE(EXT_PUSH);
	BOOL init(void *, uint32_t, uint32_t, const EXT_BUFFER_MGT * = nullptr);
	uint8_t *release();
	BOOL check_ovf(uint32_t);
	int advance(uint32_t);
	int p_bytes(const void *, uint32_t);
	int p_uint8(uint8_t);
	inline int p_int8(int8_t v) { return p_uint8(v); }
	int p_uint16(uint16_t);
	inline int p_int16(int16_t v) { return p_uint16(v); }
	int p_uint32(uint32_t);
	inline int p_int32(int32_t v) { return p_uint32(v); }
	int p_uint64(uint64_t);
	inline int p_int64(int64_t v) { return p_uint64(v); }
	int p_float(float);
	int p_double(double);
	int p_bool(BOOL);
	inline int p_blob(DATA_BLOB b) { return p_bytes(b.pv, b.cb); }
	int p_bin(const BINARY &);
	int p_bin_s(const BINARY &);
	int p_bin_ex(const BINARY &);
	int p_guid(const GUID &);
	inline int p_guid(const FLATUID &v) { return p_bytes(&v, sizeof(v)); }
	int p_str(const char *);
	int p_wstr(const char *);
	int p_uint16_a(const SHORT_ARRAY &);
	int p_uint32_a(const LONG_ARRAY &);
	int p_uint64_a(const LONGLONG_ARRAY &);
	int p_uint64_sa(const LONGLONG_ARRAY &);
	int p_float_a(const FLOAT_ARRAY &);
	int p_double_a(const DOUBLE_ARRAY &);
	int p_bin_a(const BINARY_ARRAY &);
	int p_str_a(const STRING_ARRAY &);
	int p_wstr_a(const STRING_ARRAY &);
	int p_guid_a(const GUID_ARRAY &);
	int p_proptag_a(const PROPTAG_ARRAY &);
	int p_proptag_a(const LPROPTAG_ARRAY &);
	int p_restriction(const RESTRICTION &);
	int p_svreid(const SVREID &);
	int p_store_eid(const STORE_ENTRYID &);
	int p_rule_actions(const RULE_ACTIONS &);
	int p_longterm(const LONG_TERM_ID &);
	int p_longterm_a(const LONG_TERM_ID_ARRAY &);
	int p_propval(uint16_t, const void *);
	int p_tagged_pv(const TAGGED_PROPVAL &);
	int p_typed_pv(const TYPED_PROPVAL &);
	int p_flagged_pv(uint16_t, const FLAGGED_PROPVAL &);
	int p_proprow(const PROPTAG_ARRAY &, const PROPERTY_ROW &);
	int p_proprow(const LPROPTAG_ARRAY &, const PROPERTY_ROW &);
	int p_propname(const PROPERTY_NAME &);
	int p_propname_a(const PROPNAME_ARRAY &);
	int p_propid_a(const PROPID_ARRAY &);
	int p_tpropval_a(const TPROPVAL_ARRAY &);
	int p_tpropval_a(const LTPROPVAL_ARRAY &);
	int p_tarray_set(const TARRAY_SET &);
	int p_problem_a(const PROBLEM_ARRAY &);
	int p_xid(const XID &);
	int p_folder_eid(const FOLDER_ENTRYID &);
	int p_msg_eid(const MESSAGE_ENTRYID &);
	int p_sortorder(const SORT_ORDER &);
	int p_sortorder_set(const SORTORDER_SET &);
	int p_typed_str(const TYPED_STRING &);
	int p_recipient_row(const PROPTAG_ARRAY &tags, const RECIPIENT_ROW &);
	int p_openrecipient_row(const PROPTAG_ARRAY &tags, const OPENRECIPIENT_ROW &);
	int p_readrecipient_row(const PROPTAG_ARRAY &tags, const READRECIPIENT_ROW &);
	int p_permission_data(const PERMISSION_DATA &);
	int p_rule_data(const RULE_DATA &);
	int p_abk_eid(const EMSAB_ENTRYID &);
	int p_oneoff_eid(const ONEOFF_ENTRYID &);
	int p_persistdata_a(const PERSISTDATA_ARRAY &);
	int p_eid_a(const EID_ARRAY &);
	int p_systime(const SYSTEMTIME &);
	int p_tzstruct(const TIMEZONESTRUCT &);
	int p_tzdef(const TIMEZONEDEFINITION &);
	int p_apptrecpat(const APPOINTMENT_RECUR_PAT &);
	int p_goid(const GLOBALOBJECTID &);
	int p_msgctnt(const MESSAGE_CONTENT &);
	int p_rpchdr(const RPC_HEADER_EXT &);

	BOOL b_alloc = false;
	union {
		uint8_t *m_udata;
		char *m_cdata;
		void *m_vdata = nullptr;
	};
	uint32_t m_alloc_size = 0, m_offset = 0, m_flags = 0;
	EXT_BUFFER_MGT m_mgt{};
};

extern bool emsab_to_parts(EXT_PULL &, char *type, size_t tsize, char *addr, size_t asize);
extern bool emsab_to_email(EXT_PULL &, ESSDN_TO_USERNAME, char *addr, size_t adsize);
extern bool oneoff_to_parts(EXT_PULL &, char *type, size_t tsize, char *addr, size_t asize);
