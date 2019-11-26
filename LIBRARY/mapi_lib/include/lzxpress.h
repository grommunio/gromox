#ifndef _H_LZXPRESS_
#define _H_LZXPRESS_

#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

uint32_t lzxpress_compress(const uint8_t *uncompressed,
	uint32_t uncompressed_size, uint8_t *compressed);

uint32_t lzxpress_decompress(const uint8_t *input, uint32_t input_size,
	uint8_t *output, uint32_t max_output_size);

#ifdef __cplusplus
}
#endif

#endif /* _H_LZXPRESS_ */
