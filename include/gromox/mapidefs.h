#pragma once
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
enum {
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
	PT_OBJECT = 0x000D, /* VT_OBJECT */
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

enum {
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
