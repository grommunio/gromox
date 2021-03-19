#pragma once
#include <cstdint>

#define PROP_ID(x) ((x) >> 16)
#define PROP_TYPE(x) ((x) & 0xFFFF)
#define CHANGE_PROP_TYPE(tag, newtype) (((tag) & ~0xFFFF) | (newtype))
/*
 * x|y yields an unsigned result if either x or y are unsigned.
 * x<<y yields unsigned only if x is unsigned.
 * All the while | and << only make *sense* in an unsigned _context_ anyway
 * (i.e. the operator should have returned unsigned all the time)
 */
#define PROP_TAG(type, tag) ((((unsigned int)tag) << 16) | (type))
enum { /* MS-OAUT */
	PT_UNSPECIFIED = 0x0000, /* VT_EMPTY */
	PT_NULL = 0x0001, /* VT_NULL */
	PT_SHORT = 0x0002, /* VT_I2, PT_I2 */
	PT_LONG = 0x0003, /* VT_I4, PT_I4 */
	PT_FLOAT = 0x0004, /* VT_R4, PT_R4 */
	PT_DOUBLE = 0x0005, /* VT_R8, PT_R8 */
	PT_CURRENCY = 0x0006, /* VT_CY */
	PT_APPTIME = 0x0007, /* VT_DATE */
	PT_ERROR = 0x000A, /* VT_ERROR */
	PT_BOOLEAN = 0x000B, /* VT_BOOL */
	PT_OBJECT = 0x000D, /* VT_UNKNOWN */
	PT_I8 = 0x0014, /* VT_I8 */
	PT_STRING8 = 0x001E, /* VT_LPSTR */
	PT_UNICODE = 0x001F, /* VT_LPWSTR */
	PT_SYSTIME = 0x0040, /* VT_FILETIME */
	PT_CLSID = 0x0048, /* VT_CLSID */
	PT_SVREID = 0x00FB, /* MS-OXCDATA extension */
	PT_SRESTRICT = 0x00FD, /* edkmdb.h extension */
	PT_ACTIONS = 0x00FE, /* edkmdb.h extension */
	PT_BINARY = 0x0102,
	PT_MV_SHORT = 0x1002, /* PT_MV_I2 */
	PT_MV_LONG = 0x1003, /* PT_MV_I4 */
	PT_MV_FLOAT = 0x1004, /* PT_MV_R4 */
	PT_MV_DOUBLE = 0x1005, /* PT_MV_R8 */
	PT_MV_CURRENCY = 0x1006, /* PT_MV_CURRENCY */
	PT_MV_APPTIME = 0x1007, /* PT_MV_APPTIME */
	PT_MV_I8 = 0x1014,
	PT_MV_STRING8 = 0x101E,
	PT_MV_UNICODE = 0x101F,
	PT_MV_SYSTIME = 0x1040,
	PT_MV_CLSID = 0x1048,
	PT_MV_BINARY = 0x1102,
};

enum {
	MV_FLAG = 0x1000,
	MV_INSTANCE = 0x2000,
	MVI_FLAG = MV_FLAG | MV_INSTANCE,
};

enum {
	PR_BODY_A = PROP_TAG(PT_STRING8, 0x1000),
	PR_BODY_W = PROP_TAG(PT_UNICODE, 0x1000),
	PR_BODY = PR_BODY_W, /* pidTagBody */
	PR_HTML = PROP_TAG(PT_BINARY, 0x1013), /* pidTagHtml */
	PR_RTF_COMPRESSED = PROP_TAG(PT_BINARY, 0x1009), /* pidTagRtfCompressed */
};

enum bm_relop {
	BMR_EQZ = 0,
	BMR_NEZ,
};

enum {
	MNID_ID = 0,
	MNID_STRING = 1,
	KIND_NONE = 0xff,
};

enum relop {
	RELOP_LT = 0x00,
	RELOP_LE,
	RELOP_GT,
	RELOP_GE,
	RELOP_EQ,
	RELOP_NE,
	RELOP_RE,
	RELOP_MEMBER_OF_DL = 0x64,
};

enum res_type {
	RES_AND = 0x00,
	RES_OR = 0x01,
	RES_NOT = 0x02,
	RES_CONTENT = 0x03,
	RES_PROPERTY = 0x04,
	RES_PROPCOMPARE = 0x05,
	RES_BITMASK = 0x06,
	RES_SIZE = 0x07,
	RES_EXIST = 0x08,
	RES_SUBRESTRICTION = 0x09,
	RES_COMMENT = 0x0a,
	RES_COUNT = 0x0b,
	RES_NULL = 0xff,
};

enum {
	FL_FULLSTRING = 0,
	FL_SUBSTRING,
	FL_PREFIX,

	FL_IGNORECASE = 1 << 16,
	FL_IGNORENONSPACE = 1 << 17,
	FL_LOOSE = 1 << 18,
};

enum {
	MAXIMUM_SORT_COUNT = 8,
};

enum zaccess_type {
	ACCESS_TYPE_DENIED = 1,
	ACCESS_TYPE_GRANT = 2,
	ACCESS_TYPE_BOTH = 3,
};

enum {
	RIGHT_NORMAL = 0,
	RIGHT_NEW = 1U << 0,
	RIGHT_MODIFY = 1U << 1,
	RIGHT_DELETED = 1U << 2,
	RIGHT_AUTOUPDATE_DENIED = 1U << 3,
};

struct BINARY {
	uint32_t cb;
	union {
		uint8_t *pb;
		char *pc;
		void *pv;
	};
};

struct BINARY_ARRAY {
	union {
		uint32_t count, cvalues;
	};
	BINARY *pbin;
};

struct FLATUID {
	uint8_t ab[16];
};

struct FLATUID_ARRAY {
	uint32_t cvalues;
	FLATUID **ppguid;
};

struct GUID {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t clock_seq[2];
	uint8_t node[6];
};

struct GUID_ARRAY {
	uint32_t count;
	GUID *pguid;
};

struct LONG_ARRAY {
	union {
		uint32_t cvalues, count;
	};
	uint32_t *pl;
};

struct LONGLONG_ARRAY {
	union {
		uint32_t cvalues, count;
	};
	uint64_t *pll;
};

struct LPROPTAG_ARRAY {
	uint32_t cvalues;
	uint32_t *pproptag;
};

struct MESSAGE_STATE {
	BINARY source_key;
	uint32_t message_flags;
};

struct PERMISSION_ROW {
	uint32_t flags;
	BINARY entryid;
	uint32_t member_rights;
};

struct PERMISSION_SET {
	uint16_t count;
	PERMISSION_ROW *prows;
};

struct PROPERTY_NAME {
	uint8_t kind;
	GUID guid;
	uint32_t *plid;
	char *pname;
};

struct PROPID_ARRAY {
	uint16_t count;
	uint16_t *ppropid;
};

struct PROPNAME_ARRAY {
	uint16_t count;
	PROPERTY_NAME *ppropname;
};

struct PROPTAG_ARRAY {
	union {
		uint16_t cvalues, count;
	};
	uint32_t *pproptag;
};

struct SHORT_ARRAY {
	union {
		uint32_t cvalues, count;
	};
	uint16_t *ps;
};

struct SORT_ORDER {
	uint16_t type; /* pay attention to the 0x2000 bit */
	uint16_t propid;
	uint8_t table_sort;
};

struct SORTORDER_SET {
	uint16_t count;
	uint16_t ccategories;
	uint16_t cexpanded;
	SORT_ORDER *psort;
};

struct STATE_ARRAY {
	uint32_t count;
	MESSAGE_STATE *pstate;
};

struct STRING_ARRAY {
	union {
		uint32_t cvalues, count;
	};
	char **ppstr;
};

struct TAGGED_PROPVAL {
	uint32_t proptag;
	void *pvalue;
};

struct TPROPVAL_ARRAY {
	uint16_t count;
	TAGGED_PROPVAL *ppropval;
};

struct TARRAY_SET {
	uint32_t count;
	TPROPVAL_ARRAY **pparray;
};

struct RESTRICTION_AND_OR;
struct RESTRICTION_NOT;
struct RESTRICTION_CONTENT;
struct RESTRICTION_PROPERTY;
struct RESTRICTION_PROPCOMPARE;
struct RESTRICTION_BITMASK;
struct RESTRICTION_SIZE;
struct RESTRICTION_EXIST;
struct RESTRICTION_SUBOBJ;
struct RESTRICTION_COMMENT;
struct RESTRICTION_COUNT;

struct RESTRICTION {
	enum res_type rt;
	union {
		void *pres;
		RESTRICTION_AND_OR *andor;
		RESTRICTION_NOT *xnot;
		RESTRICTION_CONTENT *cont;
		RESTRICTION_PROPERTY *prop;
		RESTRICTION_PROPCOMPARE *pcmp;
		RESTRICTION_BITMASK *bm;
		RESTRICTION_SIZE *size;
		RESTRICTION_EXIST *exist;
		RESTRICTION_SUBOBJ *sub;
		RESTRICTION_COMMENT *comment;
		RESTRICTION_COUNT *count;
	};
};

struct RESTRICTION_AND_OR {
	uint32_t count;
	RESTRICTION *pres;
};

struct RESTRICTION_NOT {
	RESTRICTION res;
};

struct RESTRICTION_CONTENT {
	uint32_t fuzzy_level;
	uint32_t proptag;
	TAGGED_PROPVAL propval;
};

struct RESTRICTION_PROPERTY {
	enum relop relop;
	uint32_t proptag;
	TAGGED_PROPVAL propval;
};

struct RESTRICTION_PROPCOMPARE {
	enum relop relop;
	uint32_t proptag1;
	uint32_t proptag2;
};

struct RESTRICTION_BITMASK {
	enum bm_relop bitmask_relop;
	uint32_t proptag;
	uint32_t mask;
};

struct RESTRICTION_SIZE {
	enum relop relop;
	uint32_t proptag;
	uint32_t size;
};

struct RESTRICTION_EXIST {
	uint32_t proptag;
};

struct RESTRICTION_SUBOBJ {
	uint32_t subobject;
	RESTRICTION res;
};

struct RESTRICTION_COMMENT {
	uint8_t count;
	TAGGED_PROPVAL *ppropval;
	RESTRICTION *pres;
};

struct RESTRICTION_COUNT {
	uint32_t count;
	RESTRICTION sub_res;
};
