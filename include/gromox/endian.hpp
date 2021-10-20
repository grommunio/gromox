#pragma once
#include <cstdint>
#include <cstring>
#include <gromox/defs.h>

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
