#pragma once
#ifdef __cplusplus
#	include <cstddef>
#	include <cstdint>
#else
#	include <stddef.h>
#	include <stdint.h>
#endif

uint32_t crc32_calc_buffer(const uint8_t *buf, size_t size);
