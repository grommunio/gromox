#pragma once
#include <cstddef>
#include <cstdint>
#ifndef BOOL
#if defined(__cplusplus) && defined(BOOLCHK)
struct GX_EXPORT BOOL {
	int v;
#if 0
	constexpr BOOL() noexcept = default;
	constexpr BOOL(int z) noexcept : m_bool_value{z} {}
	constexpr bool operator==(const BOOL &o) const noexcept { return m_bool_value == o.m_bool_value; }
	constexpr bool operator!=(const BOOL &o) const noexcept { return m_bool_value != o.m_bool_value; }
	constexpr bool operator!() const noexcept { return !m_bool_value; }
	constexpr operator bool() const noexcept { return m_bool_value; }
	constexpr operator int() const noexcept = delete;
#endif
};
inline bool operator==(const BOOL &a, const BOOL &b) { return a.v == b.v; }
inline bool operator!=(const BOOL &a, const BOOL &b) { return a.v != b.v; }
inline bool operator!(const BOOL &a) { return !a.v; }
static constexpr BOOL FALSE{0};
static constexpr BOOL TRUE{-1};
#else
#define BOOL    long
#define TRUE    (-1)
#define FALSE   0
#endif
#endif

#ifndef NULL
#define NULL    0
#endif
