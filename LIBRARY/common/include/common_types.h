#pragma once
#ifdef __cplusplus
#	include <cstddef>
#	include <cstdint>
#else
#	include <stddef.h>
#	include <stdint.h>
#endif

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
	union {
		uint8_t *data;
		char *cdata;
		void *vdata;
	};
	uint32_t length;
} DATA_BLOB;
