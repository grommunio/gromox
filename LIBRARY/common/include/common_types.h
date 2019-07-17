#ifndef _H_COMMON_TYPES_
#define _H_COMMON_TYPES_
#include <stddef.h>
#include <stdint.h>

#ifndef BOOL
#define BOOL    int
#endif

#ifndef NULL
#define NULL    0
#endif

#ifndef TRUE
#define TRUE    0xFFFFFFFF
#endif

#ifndef FALSE
#define FALSE   0
#endif

typedef struct _GUID {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t clock_seq[2];
	uint8_t node[6];
} GUID;

typedef struct _DATA_BLOB {
	uint8_t *data;
	uint32_t length;
} DATA_BLOB;

#endif
