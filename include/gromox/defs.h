#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#ifdef COMPILE_DIAG
#	include <cassert>
#	include <stdexcept>
#endif
#include <string>
#include <type_traits>
#include <gromox/mapierr.hpp>
#define SOCKET_TIMEOUT 60
namespace gromox {
#define arsizeof std::size
#define GX_ARRAY_SIZE arsizeof
}
#define GX_EXPORT __attribute__((visibility("default")))
#define NOMOVE(K) \
	K(K &&) noexcept = delete; \
	void operator=(K &&) noexcept = delete;

/*
 * The timezone column in the user database ought to be never empty. Having an
 * unusual fallback offset means that missing TZ problems will readily be
 * visible in UIs.
 */
#define GROMOX_FALLBACK_TIMEZONE "Pacific/Chatham"

enum gx_loglevel {
	LV_CRIT = 1,
	LV_ERR = 2,
	LV_WARN = 3,
	LV_NOTICE = 4,
	LV_INFO = 5,
	LV_DEBUG = 6,
};

enum {
	ULCLPART_SIZE = 65, /* localpart(64) plus \0 */
	UDOM_SIZE = 256, /* domain(255) plus \0 */
	UADDR_SIZE = 321, /* localpart(64) "@" domain \0 */

	/*
	 * The name of a namedprop can be at most 254 UTF-16 chars as per
	 * OXCPRPT v17 §4.1.1. Since Gromox operates in UTF-8, that's a few
	 * more octets. (TNEF uses a larger, 32-bit field.)
	 */
	GUIDSTR_SIZE = 37,
	NP_NAMEBUF_SIZE = 763,
	NP_STRBUF_SIZE = 36 + 11 + NP_NAMEBUF_SIZE, /* "GUID=<>,NAME=<>" */
};

enum cpid_t : uint32_t {
	CP_ACP = 0,
	CP_UTF16 = 1200,
	CP_WINUNICODE = CP_UTF16,
	CP_UTF16BE = 1201,
	CP_UTF32 = 12000,
	CP_UTF32BE = 12001,
	CP_ASCII = 20127,
	CP_UTF7 = 65000,
	CP_UTF8 = 65001,
};

extern GX_EXPORT const char *mapi_errname_r(unsigned int, char *, size_t);
extern GX_EXPORT const char *mapi_strerror(unsigned int);

template<typename T> constexpr T *deconst(const T *x) { return const_cast<T *>(x); }
#undef roundup /* you naughty glibc */
template<typename T> constexpr T roundup(T x, T y) { return (x + y - 1) / y * y; }
template<typename T, typename U> constexpr auto strange_roundup(T x, U y) -> decltype(x / y) { return (x / y + 1) * y; }
#define SR_GROW_ATTACHMENT_CONTENT 20U
#define SR_GROW_EID_ARRAY 100U
#define SR_GROW_PROPTAG_ARRAY 100U
#define SR_GROW_TAGGED_PROPVAL 100U
#define SR_GROW_TPROPVAL_ARRAY 100U

#ifdef COMPILE_DIAG
/* snprintf takes about 2.65x the time, but we get -Wformat-truncation diagnostics */
#define gx_strlcpy(dst, src, dsize) snprintf((dst), (dsize), "%s", (src))
#else
#define gx_strlcpy(dst, src, dsize) HX_strlcpy((dst), (src), (dsize))
#endif

#define ENVELOPE_FROM_NULL "no.envelope.from@invalid"
#define ENVELOPE_RCPT_NULL "no.envelope.rcpt@invalid"

static inline constexpr bool is_nameprop_id(unsigned int i) { return i >= 0x8000 && i <= 0xFFFE; }

namespace gromox {

static constexpr uint32_t SEQ_STAR = -1;

struct seq_node {
	using value_type = unsigned int;
	value_type min = SEQ_STAR, max = SEQ_STAR;
};

struct stdlib_delete {
	inline void operator()(void *x) const { free(x); }
};
template<typename T> static inline T *me_alloc() {
	static_assert(std::is_trivial_v<T> && std::is_trivially_destructible_v<T>);
	return static_cast<T *>(malloc(sizeof(T)));
}
template<typename T> static inline T *me_alloc(size_t elem) {
	static_assert(std::is_trivial_v<T> && std::is_trivially_destructible_v<T>);
	return static_cast<T *>(malloc(sizeof(T) * elem));
}
template<typename T> static inline T *re_alloc(void *x) {
	static_assert(std::is_trivial_v<T> && std::is_trivially_destructible_v<T>);
	return static_cast<T *>(realloc(x, sizeof(T)));
}
template<typename T> static inline T *re_alloc(void *x, size_t elem) {
	static_assert(std::is_trivial_v<T> && std::is_trivially_destructible_v<T>);
	return static_cast<T *>(realloc(x, sizeof(T) * elem));
}
static inline const char *snul(const std::string &s) { return s.size() != 0 ? s.c_str() : nullptr; }
static inline const char *znul(const char *s) { return s != nullptr ? s : ""; }

template<typename U, typename V> static int three_way_compare(U &&a, V &&b)
{
	return (a < b) ? -1 : (a == b) ? 0 : 1;
}

#if defined(COMPILE_DIAG) && !defined(__clang__)
struct errno_t {
	constexpr errno_t(int x) : m_value(x) {
#ifdef COVERITY
		assert(x >= 0);
#else
		if (x < 0)
			throw std::logic_error("errno_t value must be >=0");
#endif
	}
	constexpr operator int() const { return m_value; }
	constexpr operator bool() const = delete;
	constexpr void operator!() const = delete;
	private:
	int m_value = 0;
};
#else
using errno_t = int;
#endif

constexpr inline bool pvb_disabled(const void *z)
{
	return z == nullptr || *static_cast<const uint8_t *>(z) == 0;
}

constexpr inline bool pvb_enabled(const void *z)
{
	return z != nullptr && *static_cast<const uint8_t *>(z) != 0;
}

template<typename Container, typename U> void erase_first(Container &c, const U &value)
{
	for (auto i = c.begin(); i != c.end(); ++i) {
		if (*i == value) {
			c.erase(i);
			return;
		}
	}
}

template<typename Container, typename Pred> void erase_first_if(Container &c, Pred &&pred)
{
	for (auto i = c.begin(); i != c.end(); ++i) {
		if (pred(*i)) {
			c.erase(i);
			return;
		}
	}
}

}
