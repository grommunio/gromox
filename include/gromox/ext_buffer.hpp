#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>

enum class pack_result {
	success, ok = success, failure, format, bufsize, alloc, bad_switch,
	charconv, compress, header_flags, header_size, range, invalid_obj,
	ndr64, padding, array_size, ipv6addr, ctrl_skip, bad_callid,
};

/**
 * %EXT_FLAG_UTF16:	packed representation encodes wide strings as UTF-16
 * 			(else, UTF-8)
 * %EXT_FLAG_WCOUNT:	packed rep encodes certain array lengths as 32-bit
 * 			(else, 16-bit)
 * %EXT_FLAG_TBLLMT:	limit packed rep strings to 255 characters
 * 			(GetContentsTable / GetHierarchyTable)
 * %EXT_FLAG_ABK:	MH-NSP serialization mode
 * %EXT_FLAG_ZCORE:	unpacked rep uses zcore types for rule element pointers
 * %EXT_FLAG_DYNAMIC:   buffer is managed by EXT_PUSH [private flag]
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
	EXT_FLAG_DYNAMIC = 1U << 5,
};

using EXT_BUFFER_ALLOC = void *(*)(size_t);

struct  GX_EXPORT EXT_BUFFER_MGT {
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

struct  GX_EXPORT RPC_HEADER_EXT {
	uint16_t version;
	uint16_t flags;
	uint16_t size;
	uint16_t size_actual;
};

struct APPOINTMENT_RECUR_PAT;
struct EID_ARRAY;
struct EMSAB_ENTRYID_view;
struct EMSAB_ENTRYID;
struct EXT_RULE_ACTIONS;
struct FLAGGED_PROPVAL;
struct FOLDER_ENTRYID;
struct GLOBALOBJECTID;
struct LONG_TERM_ID;
struct LONG_TERM_ID_ARRAY;
struct LONG_TERM_ID_RANGE;
struct message_content;
using MESSAGE_CONTENT = message_content;
struct MESSAGE_ENTRYID;
struct MODIFYRECIPIENT_ROW;
struct NAMEDPROPERTY_INFO;
struct OPENRECIPIENT_ROW;
struct PERMISSION_DATA;
struct PERSISTDATA;
struct PROBLEM_ARRAY;
struct PROPERTY_ROW;
struct READRECIPIENT_ROW;
struct RECIPIENT_ROW;
struct RECURRENCE_PATTERN;
struct STORE_ENTRYID;
struct SYSTEMTIME;
struct TZDEF;
struct TZSTRUCT;
struct TYPED_PROPVAL;
struct TYPED_STRING;
struct XID;

struct GX_EXPORT EXT_PULL {
	EXT_BUFFER_ALLOC m_alloc{};
	void init(const void *, uint32_t, EXT_BUFFER_ALLOC, uint32_t);
	pack_result advance(uint32_t);
	pack_result g_rpc_header_ext(RPC_HEADER_EXT *);
	pack_result g_uint8(uint8_t *);
	pack_result g_int8(int8_t *v) { return g_uint8(reinterpret_cast<uint8_t *>(v)); }
	pack_result g_uint16(uint16_t *);
	pack_result g_int16(int16_t *v) { return g_uint16(reinterpret_cast<uint16_t *>(v)); }
	pack_result g_uint32(uint32_t *);
	pack_result g_int32(int32_t *v) { return g_uint32(reinterpret_cast<uint32_t *>(v)); }
	pack_result g_nlscp(cpid_t *v) { return g_uint32(reinterpret_cast<uint32_t *>(v)); }
	pack_result g_uint64(uint64_t *);
	pack_result g_int64(int64_t *v) { return g_uint64(reinterpret_cast<uint64_t *>(v)); }
	pack_result g_float(float *);
	pack_result g_double(double *);
	pack_result g_bool(BOOL *);
	pack_result g_bytes(void *, uint32_t) __attribute__((nonnull(2)));
	pack_result g_guid(GUID *);
	pack_result g_guid(FLATUID *v) { return g_bytes(v, sizeof(*v)); }
	pack_result g_str(char **);
	pack_result g_str(std::string *);
	pack_result g_wstr(char **);
	pack_result g_wstr(std::string *);
	pack_result g_blob(DATA_BLOB *);
	pack_result g_bin(BINARY *);
	pack_result g_bin(std::string *);
	pack_result g_sbin(BINARY *);
	pack_result g_bin_ex(BINARY *);
	pack_result g_uint16_an(SHORT_ARRAY *, uint32_t count);
	pack_result g_uint16_an(std::vector<uint16_t> *, size_t count);
	pack_result g_uint16_a(SHORT_ARRAY *);
	pack_result g_uint16_a(std::vector<uint16_t> *);
	pack_result g_uint32_an(LONG_ARRAY *, uint32_t count);
	pack_result g_uint32_an(std::vector<uint32_t> *, size_t count);
	pack_result g_uint32_a(LONG_ARRAY *);
	pack_result g_uint32_a(std::vector<uint32_t> *);
	pack_result g_uint64_an(LONGLONG_ARRAY *, uint32_t count);
	pack_result g_uint64_an(std::vector<uint64_t> *, size_t count);
	pack_result g_uint64_a(LONGLONG_ARRAY *);
	pack_result g_uint64_a(std::vector<uint64_t> *);
	pack_result g_uint64_sa(LONGLONG_ARRAY *);
	pack_result g_float_an(FLOAT_ARRAY *, uint32_t count);
	pack_result g_float_an(std::vector<float> *, size_t count);
	pack_result g_float_a(FLOAT_ARRAY *);
	pack_result g_float_a(std::vector<float> *);
	pack_result g_double_an(DOUBLE_ARRAY *, uint32_t count);
	pack_result g_double_an(std::vector<double> *, size_t count);
	pack_result g_double_a(DOUBLE_ARRAY *);
	pack_result g_double_a(std::vector<double> *);
	pack_result g_bin_a(BINARY_ARRAY *);
	pack_result g_str_a(STRING_ARRAY *);
	pack_result g_str_an(std::vector<std::string> *, size_t count);
	pack_result g_str_a(std::vector<std::string> *);
	pack_result g_wstr_a(STRING_ARRAY *);
	pack_result g_wstr_an(std::vector<std::string> *, size_t count);
	pack_result g_wstr_a(std::vector<std::string> *);
	pack_result g_guid_an(GUID_ARRAY *, uint32_t count);
	pack_result g_guid_an(std::vector<GUID> *, size_t count);
	pack_result g_guid_a(GUID_ARRAY *);
	pack_result g_guid_a(std::vector<GUID> *);
	pack_result g_proptag_a(PROPTAG_ARRAY *);
	pack_result g_proptag_a(std::vector<gromox::proptag_t> *);
	pack_result g_proptag_a(LPROPTAG_ARRAY *);
	pack_result g_restriction(RESTRICTION *);
	pack_result g_svreid(SVREID *);
	pack_result g_store_eid(STORE_ENTRYID *);
	pack_result g_rule_actions(RULE_ACTIONS *);
	pack_result g_ext_rule_actions(EXT_RULE_ACTIONS *);
	pack_result g_namedprop_info(NAMEDPROPERTY_INFO *);
	pack_result g_longterm(LONG_TERM_ID *);
	pack_result g_longterm_range(LONG_TERM_ID_RANGE *);
	pack_result g_typed_pv(TYPED_PROPVAL *);
	pack_result g_propval(uint16_t type, void **);
	pack_result g_tagged_pv(TAGGED_PROPVAL *);
	pack_result g_flagged_pv(uint16_t type, FLAGGED_PROPVAL *);
	pack_result g_proprow(const PROPTAG_ARRAY &cols, PROPERTY_ROW *);
	pack_result g_propname(PROPERTY_NAME *);
	pack_result g_propname_a(PROPNAME_ARRAY *);
	pack_result g_propid_a(PROPID_ARRAY *);
	pack_result g_tpropval_a(TPROPVAL_ARRAY *);
	pack_result g_tpropval_a(LTPROPVAL_ARRAY *);
	pack_result g_tarray_set(TARRAY_SET *);
	pack_result g_problem_a(PROBLEM_ARRAY *);
	pack_result g_xid(uint8_t size, XID *);
	pack_result g_folder_eid(FOLDER_ENTRYID *);
	pack_result g_msg_eid(MESSAGE_ENTRYID *);
	pack_result g_sortorder(SORT_ORDER *);
	pack_result g_sortorder_set(SORTORDER_SET *);
	pack_result g_recipient_row(const PROPTAG_ARRAY &tags, RECIPIENT_ROW *);
	pack_result g_modrcpt_row(const PROPTAG_ARRAY &tags, MODIFYRECIPIENT_ROW *);
	pack_result g_permission_data(PERMISSION_DATA *);
	pack_result g_rule_data(RULE_DATA *);
	pack_result g_abk_eid(EMSAB_ENTRYID *);
	pack_result g_oneoff_eid(ONEOFF_ENTRYID *);
	pack_result g_flatentry_a(BINARY_ARRAY *);
	pack_result g_eid_a(EID_ARRAY *);
	pack_result g_systime(SYSTEMTIME *);
	pack_result g_tzstruct(TZSTRUCT *);
	pack_result g_tzdef(TZDEF *);
	pack_result g_apptrecpat(APPOINTMENT_RECUR_PAT *);
	pack_result g_goid(GLOBALOBJECTID *);
	pack_result g_msgctnt(MESSAGE_CONTENT *);
	pack_result g_fb(freebusy_event *);
	pack_result g_fb_a(std::vector<freebusy_event> *);
	pack_result g_recpat(RECURRENCE_PATTERN *);

	template<typename T> inline T *anew()
	{
		static_assert(std::is_trivially_destructible_v<T> && std::is_trivially_copyable_v<T>);
		auto r = static_cast<T *>(m_alloc(sizeof(T)));
		if (r != nullptr)
			new(r) T;
		return r;
	}
	template<typename T> inline T *anew(size_t elem)
	{
		static_assert(std::is_trivially_destructible_v<T> && std::is_trivially_copyable_v<T>);
		auto r = static_cast<T *>(m_alloc(sizeof(T) * elem));
		if (r != nullptr)
			for (size_t i = 0; i < elem; ++i)
				new(r) T[i];
		return r;
	}
	union {
		const uint8_t *m_udata;
		const char *m_cdata;
		const void *m_vdata = nullptr;
	};
	uint32_t m_data_size = 0, m_offset = 0, m_flags = 0;
};

struct GX_EXPORT EXT_PUSH {
	EXT_PUSH() = default;
	~EXT_PUSH();
	NOMOVE(EXT_PUSH);
	BOOL init(void *, uint32_t, uint32_t, const EXT_BUFFER_MGT * = nullptr);
	uint8_t *release();
	BOOL check_ovf(uint32_t);
	pack_result advance(uint32_t);
	pack_result p_bytes(const void *, uint32_t);
	pack_result p_uint8(uint8_t);
	pack_result p_int8(int8_t v) { return p_uint8(v); }
	pack_result p_uint16(uint16_t);
	pack_result p_int16(int16_t v) { return p_uint16(v); }
	pack_result p_uint32(uint32_t);
	pack_result p_int32(int32_t v) { return p_uint32(v); }
	pack_result p_err32(ec_error_t v) { return p_uint32(static_cast<uint32_t>(v)); }
	pack_result p_uint64(uint64_t);
	pack_result p_int64(int64_t v) { return p_uint64(v); }
	pack_result p_float(float);
	pack_result p_double(double);
	pack_result p_bool(BOOL);
	pack_result p_blob(DATA_BLOB b) { return p_bytes(b.pv, b.cb); }
	pack_result p_bin(const BINARY &);
	pack_result p_bin(std::string_view);
	pack_result p_bin_s(const BINARY &);
	pack_result p_bin_ex(const BINARY &);
	pack_result p_guid(const GUID &);
	pack_result p_guid(const FLATUID &v) { return p_bytes(&v, sizeof(v)); }
	pack_result p_str(const char *);
	pack_result p_str(const std::string &s) { return p_str(s.c_str()); }
	pack_result p_wstr(const char *);
	pack_result p_uint16_a(const SHORT_ARRAY &);
	pack_result p_uint16_a(const std::vector<uint16_t> &);
	pack_result p_uint32_a(const LONG_ARRAY &);
	pack_result p_uint32_a(const std::vector<uint32_t> &);
	pack_result p_uint64_a(const LONGLONG_ARRAY &);
	pack_result p_uint64_a(const std::vector<uint64_t> &);
	pack_result p_uint64_sa(const LONGLONG_ARRAY &);
	pack_result p_float_a(const FLOAT_ARRAY &);
	pack_result p_float_a(const std::vector<float> &);
	pack_result p_double_a(const DOUBLE_ARRAY &);
	pack_result p_double_a(const std::vector<double> &);
	pack_result p_bin_a(const BINARY_ARRAY &);
	pack_result p_str_a(const STRING_ARRAY &);
	pack_result p_str_a(const std::vector<std::string> &);
	pack_result p_wstr_a(const STRING_ARRAY &);
	pack_result p_wstr_a(const std::vector<std::string> &);
	pack_result p_guid_a(const GUID_ARRAY &);
	pack_result p_guid_a(const std::vector<GUID> &);
	pack_result p_proptag_a(const PROPTAG_ARRAY &);
	pack_result p_proptag_a(std::span<const gromox::proptag_t>);
	pack_result p_proptag_a(const LPROPTAG_ARRAY &);
	pack_result p_restriction(const RESTRICTION &);
	pack_result p_svreid(const SVREID &);
	pack_result p_store_eid(const STORE_ENTRYID &);
	pack_result p_rule_actions(const RULE_ACTIONS &);
	pack_result p_longterm(const LONG_TERM_ID &);
	pack_result p_longterm_a(const LONG_TERM_ID_ARRAY &);
	pack_result p_propval(uint16_t, const void *);
	pack_result p_tagged_pv(const TAGGED_PROPVAL &);
	pack_result p_typed_pv(const TYPED_PROPVAL &);
	pack_result p_flagged_pv(uint32_t, const FLAGGED_PROPVAL &);
	pack_result p_proprow(const PROPTAG_ARRAY &, const PROPERTY_ROW &);
	pack_result p_proprow(const LPROPTAG_ARRAY &, const PROPERTY_ROW &);
	pack_result p_propname(const PROPERTY_NAME &);
	pack_result p_propname_a(const PROPNAME_ARRAY &);
	pack_result p_propid_a(const PROPID_ARRAY &);
	pack_result p_tpropval_a(const TPROPVAL_ARRAY &);
	pack_result p_tpropval_a(const LTPROPVAL_ARRAY &);
	pack_result p_tarray_set(const TARRAY_SET &);
	pack_result p_problem_a(const PROBLEM_ARRAY &);
	pack_result p_xid(const XID &);
	pack_result p_folder_eid(const FOLDER_ENTRYID &);
	pack_result p_msg_eid(const MESSAGE_ENTRYID &);
	pack_result p_sortorder(const SORT_ORDER &);
	pack_result p_sortorder_set(const SORTORDER_SET &);
	pack_result p_typed_str(const TYPED_STRING &);
	pack_result p_recipient_row(const PROPTAG_ARRAY &tags, const RECIPIENT_ROW &);
	pack_result p_openrecipient_row(const PROPTAG_ARRAY &tags, const OPENRECIPIENT_ROW &);
	pack_result p_readrecipient_row(const PROPTAG_ARRAY &tags, const READRECIPIENT_ROW &);
	pack_result p_permission_data(const PERMISSION_DATA &);
	pack_result p_rule_data(const RULE_DATA &);
	pack_result p_abk_eid(const EMSAB_ENTRYID_view &);
	pack_result p_oneoff_eid(const ONEOFF_ENTRYID_view &);
	pack_result p_persistdata_a(std::span<const PERSISTDATA>);
	pack_result p_eid_a(const EID_ARRAY &);
	pack_result p_systime(const SYSTEMTIME &);
	pack_result p_tzstruct(const TZSTRUCT &);
	pack_result p_tzdef(const TZDEF &);
	pack_result p_apptrecpat(const APPOINTMENT_RECUR_PAT &);
	pack_result p_goid(const GLOBALOBJECTID &);
	pack_result p_msgctnt(const MESSAGE_CONTENT &);
	pack_result p_rpchdr(const RPC_HEADER_EXT &);
	pack_result p_fbevent(const freebusy_event &);

	union {
		uint8_t *m_udata;
		char *m_cdata;
		void *m_vdata = nullptr;
	};
	uint32_t m_alloc_size = 0, m_offset = 0, m_flags = 0;
	EXT_BUFFER_MGT m_mgt{};
};

extern GX_EXPORT bool emsab_to_parts(EXT_PULL &, std::string &type, std::string &addr);
extern GX_EXPORT bool oneoff_to_parts(EXT_PULL &, std::string &type, std::string &addr);
