#pragma once
#include <cstdint>
#include <gromox/defs.h>
extern GX_EXPORT ssize_t lzxpress_compress(const void *, uint32_t, void *, uint32_t);
extern GX_EXPORT ssize_t lzxpress_decompress(const void *, uint32_t, void *, uint32_t);
