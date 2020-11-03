#pragma once
#define PROP_ID(x) ((x) >> 16)
#define PROP_TYPE(x) ((x) & 0xFFFF)
#define CHANGE_PROP_TYPE(tag, newtype) (((tag) & ~0xFFFF) | (newtype))
#define PROP_TAG(type, tag) (((tag) << 16) | (type))
enum {
	PT_UNSPECIFIED = 0x0000,
};
