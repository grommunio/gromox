#ifndef _H_CRC32_
#define _H_CRC32_
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t crc32_calc_buffer(const uint8_t *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* _H_CRC32_ */
