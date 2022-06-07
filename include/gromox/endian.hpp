#pragma once
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cstdint>
#include <cstring>
#ifdef HAVE_ENDIAN_H
#	include <endian.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
#	include <sys/endian.h>
#endif

#if (defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN) || \
    (defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN)
#	define cpu_to_le16(x) __builtin_bswap16(x)
#	define cpu_to_le32(x) __builtin_bswap32(x)
#	define cpu_to_le64(x) __builtin_bswap64(x)
#	define cpu_to_be16(x) ((uint16_t)(x))
#	define cpu_to_be32(x) ((uint32_t)(x))
#	define cpu_to_be64(x) ((uint64_t)(x))
#	define le16_to_cpu(x) __builtin_bswap16(x)
#	define le32_to_cpu(x) __builtin_bswap32(x)
#	define le64_to_cpu(x) __builtin_bswap64(x)
#	define be16_to_cpu(x) static_cast<uint16_t>(x)
#	define be32_to_cpu(x) static_cast<uint32_t>(x)
#	define be64_to_cpu(x) static_cast<uint64_t>(x)
#	define GX_BIG_ENDIAN 1
#else
#	define cpu_to_le16(x) (x)
#	define cpu_to_le32(x) (x)
#	define cpu_to_le64(x) (x)
#	define cpu_to_be16(x) __builtin_bswap16(x)
#	define cpu_to_be32(x) __builtin_bswap32(x)
#	define cpu_to_be64(x) __builtin_bswap64(x)
#	define le16_to_cpu(x) (x)
#	define le32_to_cpu(x) (x)
#	define le64_to_cpu(x) (x)
#	define be16_to_cpu(x) __builtin_bswap16(x)
#	define be32_to_cpu(x) __builtin_bswap32(x)
#	define be64_to_cpu(x) __builtin_bswap64(x)
#	define GX_BIG_ENDIAN 0
#endif

static inline uint16_t le16p_to_cpu(const void *p) { uint16_t v; memcpy(&v, p, sizeof(v)); return le16_to_cpu(v); }
static inline uint32_t le32p_to_cpu(const void *p) { uint32_t v; memcpy(&v, p, sizeof(v)); return le32_to_cpu(v); }
static inline uint64_t le64p_to_cpu(const void *p) { uint64_t v; memcpy(&v, p, sizeof(v)); return le64_to_cpu(v); }
static inline uint16_t be16p_to_cpu(const void *p) { uint16_t v; memcpy(&v, p, sizeof(v)); return be16_to_cpu(v); }
static inline uint32_t be32p_to_cpu(const void *p) { uint32_t v; memcpy(&v, p, sizeof(v)); return be32_to_cpu(v); }
static inline uint64_t be64p_to_cpu(const void *p) { uint64_t v; memcpy(&v, p, sizeof(v)); return be64_to_cpu(v); }
static inline void cpu_to_le16p(void *p, uint16_t v) { v = cpu_to_le16(v); memcpy(p, &v, sizeof(v)); }
static inline void cpu_to_le32p(void *p, uint32_t v) { v = cpu_to_le32(v); memcpy(p, &v, sizeof(v)); }
static inline void cpu_to_le64p(void *p, uint64_t v) { v = cpu_to_le64(v); memcpy(p, &v, sizeof(v)); }
static inline void cpu_to_be16p(void *p, uint16_t v) { v = cpu_to_be16(v); memcpy(p, &v, sizeof(v)); }
static inline void cpu_to_be32p(void *p, uint32_t v) { v = cpu_to_be32(v); memcpy(p, &v, sizeof(v)); }
static inline void cpu_to_be64p(void *p, uint64_t v) { v = cpu_to_be64(v); memcpy(p, &v, sizeof(v)); }
