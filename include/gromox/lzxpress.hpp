#pragma once
#include <cstdint>
#include <gromox/defs.h>
extern GX_EXPORT uint32_t lzxpress_compress(const void *uncompressed, uint32_t uncompressed_size, void *compressed);
extern GX_EXPORT uint32_t lzxpress_decompress(const void *input, uint32_t input_size, void *output, uint32_t max_output_size);
