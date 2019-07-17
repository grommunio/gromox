#ifndef _H_MACBINARY_
#define _H_MACBINARY_
#include "ext_buffer.h"
#include <stdint.h>
#include <time.h>

#define ORIGINAL_FLAG_ISALIAS				0x80
#define ORIGINAL_FLAG_ISINVISIBLE			0x40
#define ORIGINAL_FLAG_HASBUNDLE				0x20
#define ORIGINAL_FLAG_NAMELOCKED			0x10
#define ORIGINAL_FLAG_ISSTATIONERY			0x08
#define ORIGINAL_FLAG_HASCUSTOMICON			0x04
#define ORIGINAL_FLAG_RESERVED				0x02
#define ORIGINAL_FLAG_HASBEENINITED			0x01

#define FINDER_FLAG_HASNOINITS				0x80
#define FINDER_FLAG_ISSHARED				0x40
#define FINDER_FLAG_REQUIRESSWITCHLAUNCH	0x20
#define FINDER_FLAG_COLORRESERVED			0x10
#define FINDER_FLAG_COLIR_BIT3				0x08
#define FINDER_FLAG_COLIR_BIT2				0x04
#define FINDER_FLAG_COLIR_BIT1				0x02
#define FINDER_FLAG_ISONDESK				0x01

typedef struct _MACBINARY_HEADER {
	uint8_t old_version;
	char file_name[64];
	uint32_t type;
	uint32_t creator;
	uint8_t original_flags;
	uint8_t pad1;
	uint16_t point_v;
	uint16_t point_h;
	uint16_t folder_id;
	uint8_t protected_flag;
	uint8_t pad2;
	uint32_t data_len;
	uint32_t res_len;
	time_t creat_time;
	time_t modify_time;
	uint16_t comment_len;
	uint8_t finder_flags;
	uint32_t signature;
	char fd_script;
	char fd_xflags;
	uint8_t pads1[8];
	uint32_t total_unpacked;
	uint16_t xheader_len;
	uint8_t version;
	uint8_t mini_version;
	uint8_t pads2[2];
} MACBINARY_HEADER;

typedef struct _MACBINARY {
	MACBINARY_HEADER header;
	const uint8_t *pxheader;
	const uint8_t *pdata;
	const uint8_t *presource;
	const uint8_t *pcomment;
} MACBINARY;

#ifdef __cplusplus
extern "C" {
#endif

int macbinary_pull_binary(EXT_PULL *pext, MACBINARY *r);

int macbinary_push_binary(EXT_PUSH *pext, const MACBINARY *r);

#ifdef __cplusplus
}
#endif

#endif /* _H_MACBINARY_ */
