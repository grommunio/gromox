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
	PT_OBJECT = 0x000D, /* VT_OBJECT */
	PT_MV_SHORT = 0x1002, /* PT_MV_I2 */
	PT_MV_LONG = 0x1003, /* PT_MV_I4 */
};
