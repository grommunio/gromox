#pragma once
#define PROP_ID(x) ((x) >> 16)
#define PROP_TYPE(x) ((x) & 0xFFFF)
#define CHANGE_PROP_TYPE(tag, newtype) (((tag) & ~0xFFFF) | (newtype))
#define PROP_TAG(type, tag) (((tag) << 16) | (type))
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
	PT_CLSID = 0x0048, /* VT_CLSID */
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
	PT_MV_CLSID = 0x1048,
	PT_MV_BINARY = 0x1102,
};
