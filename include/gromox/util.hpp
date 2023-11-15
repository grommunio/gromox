#pragma once
#include <atomic>
#include <cstdint>
#include <ctime>
#include <memory>
#include <string>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/util.hpp>
#define FILE_BLOCK_SIZE 0x100
#define STREAM_BLOCK_SIZE 0x10000

#if defined(__OpenBSD__)
#include <pthread.h>
#include <pthread_np.h>
static inline int _pthread_setname_np(pthread_t thread, const char *name)
{
	pthread_set_name_np(thread, name);
	return 0;
}
#define pthread_setname_np _pthread_setname_np
#endif

enum {
	QP_MIME_HEADER = 1U << 0,
};

enum class mime_type {
	none, single, single_obj, multiple,
};

struct stream_block {
	DOUBLE_LIST_NODE list_node;
	char buf[STREAM_BLOCK_SIZE];
};

struct GX_EXPORT LIB_BUFFER {
	LIB_BUFFER(const char *n) : m_name(n) {}
	LIB_BUFFER(LIB_BUFFER &&) noexcept = delete;
	LIB_BUFFER(size_t size, size_t items, const char *name = nullptr, const char *hint = nullptr);
	LIB_BUFFER &operator=(LIB_BUFFER &&) noexcept;
	inline LIB_BUFFER *operator->() { return this; }
	void *get_raw();
	template<typename T> inline T *get()
	{
		auto p = get_raw();
		if (p == nullptr)
			return nullptr;
		return new(p) T;
	}
	void put_raw(void *);
	template<typename T> inline void put(T *i)
	{
		i->~T();
		put_raw(i);
	}

	std::atomic<size_t> allocated_num{0};
	size_t item_size = 0, max_items = 0;
	const char *m_name = nullptr, *m_hint = nullptr;
};

template<typename T> struct GX_EXPORT alloc_limiter : private LIB_BUFFER {
	constexpr alloc_limiter(const char *name) : LIB_BUFFER(name) {}
	constexpr alloc_limiter(size_t max, const char *name = nullptr, const char *hint = nullptr) :
		LIB_BUFFER(sizeof(T), max, name, hint) {}
	inline T *get() { return LIB_BUFFER::get<T>(); }
	inline void put(T *x) { LIB_BUFFER::put(x); }
	alloc_limiter<T> *operator->() { return this; }
	const LIB_BUFFER &internals() const { return *this; }
};

struct GX_EXPORT alloc_context {
	alloc_context() = default;
	NOMOVE(alloc_context);
	void *alloc(size_t z) try {
		auto p = std::make_unique<char[]>(z);
		m_ptrs.push_back(std::move(p));
		m_total_size += z;
		return m_ptrs.back().get();
	} catch (const std::bad_alloc &) {
		return nullptr;
	}
	size_t get_total() const { return m_total_size; }

	std::vector<std::unique_ptr<char[]>> m_ptrs;
	size_t m_total_size = 0;
};
using ALLOC_CONTEXT = alloc_context;

extern bool utf8_valid(const char *str);
BOOL utf8_truncate(char *str, int length);
void utf8_filter(char *string);
extern void wchar_to_utf8(uint32_t wchar, char *string);
const char* replace_iconv_charset(const char *charset);
extern GX_EXPORT BOOL string_to_utf8(const char *charset, const char *in_string, char *out_string, size_t out_len);
extern BOOL string_from_utf8(const char *charset, const char *in_string, char *out_string, size_t out_len);
extern ssize_t utf8_to_utf16le(const char *src, void *dst, size_t len);
extern BOOL utf16le_to_utf8(const void *src, size_t src_len, char *dst, size_t len);
char* search_string(const char *haystack, const char *needle, 
    size_t haystacklen);
extern GX_EXPORT const char *crypt_estar(const char *, const char *);
extern GX_EXPORT const char *crypt_wrapper(const char *);
int wildcard_match(const char *data, const char *mask, BOOL icase);
extern GX_EXPORT void randstring(char *out, size_t len, const char *pool = nullptr);
extern int encode64(const void *in, size_t inlen, char *out, size_t outmax, size_t *outlen);
extern int encode64_ex(const void *in, size_t inlen, char *out, size_t outmax, size_t *outlen);
#define decode64 decode64_ex
extern int decode64_ex(const char *in, size_t inlen, void *out, size_t outmax, size_t *outlen);
extern GX_EXPORT ssize_t qp_decode_ex(void *output, size_t out_len, const char *input, size_t length, unsigned int qp_flags = 0);
extern GX_EXPORT ssize_t qp_encode_ex(void *output, size_t outlen, const char *input, size_t length);
void encode_hex_int(int id, char *out);
int decode_hex_int(const char *in);
extern BOOL encode_hex_binary(const void *src, int srclen, char *dst, int dstlen);
extern BOOL decode_hex_binary(const char *src, void *dst, int dstlen);

namespace gromox {

/**
 * %HEX2BIN_EMPTY:	return empty string on unrecognized input character
 * %HEX2BIN_STOP:	return partial string on unrecognized input character
 * %HEX2BIN_ZERO:	treat unrecognized input characters as '0'
 * %HEX2BIN_SKIP:	skip over unrecognized input characters
 */
enum hex2bin_mode {
	HEX2BIN_EMPTY, HEX2BIN_STOP, HEX2BIN_ZERO, HEX2BIN_SKIP,
};

extern GX_EXPORT void *zalloc(size_t);
extern GX_EXPORT uint32_t rand();
extern GX_EXPORT bool parse_bool(const char *s);
extern GX_EXPORT std::string bin2cstr(const void *, size_t);
extern GX_EXPORT std::string bin2txt(const void *, size_t);
extern GX_EXPORT std::string bin2hex(const void *, size_t);
template<typename T> std::string bin2hex(const T &x) { return bin2hex(&x, sizeof(x)); }
extern GX_EXPORT std::string hex2bin(std::string_view, hex2bin_mode = HEX2BIN_EMPTY);
extern GX_EXPORT void rfc1123_dstring(char *, size_t, time_t = 0);
extern GX_EXPORT void rfc1123_dstring(char *, size_t, const struct tm &);
extern GX_EXPORT int setup_sigalrm();
extern GX_EXPORT size_t qp_encoded_size_estimate(const char *, size_t);
extern GX_EXPORT void safe_memset(void *, uint8_t, size_t);
extern GX_EXPORT unsigned int newline_size(const char *, size_t);
extern GX_EXPORT ec_error_t cu_validate_msgclass(const char *);
extern GX_EXPORT bool cpid_cstr_compatible(cpid_t);
extern GX_EXPORT bool cset_cstr_compatible(const char *);
extern GX_EXPORT size_t mb_to_utf8_len(const char *);
extern GX_EXPORT size_t utf8_to_mb_len(const char *);
extern GX_EXPORT size_t utf8_to_utf16_len(const char *);
inline size_t utf16_to_utf8_len(size_t z) { return z / 2 * 3 + 1; }
extern GX_EXPORT int iconv_validate();
extern GX_EXPORT const std::string *ianatz_to_tzdef(const char *, const char * = nullptr);
extern GX_EXPORT const std::string *wintz_to_tzdef(const char *, const char * = nullptr);
extern GX_EXPORT bool get_digest(const char *src, const char *tag, char *out, size_t outmax);
extern GX_EXPORT bool set_digest(char *src, size_t length, const char *tag, const char *v);
extern GX_EXPORT bool set_digest(char *src, size_t length, const char *tag, uint64_t v);
extern GX_EXPORT void mlog_init(const char *file, unsigned int level);
extern GX_EXPORT void mlog(unsigned int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
extern GX_EXPORT int pthread_create4(pthread_t *, std::nullptr_t, void *(*)(void *), void * = nullptr) noexcept;
extern GX_EXPORT int strtailcase(const char *h, const char *n);
extern GX_EXPORT void replace_unsafe_basename(char *);
extern GX_EXPORT size_t utf8_printable_prefix(const void *, size_t);
extern GX_EXPORT errno_t filedes_limit_bump(unsigned int);
extern GX_EXPORT uint64_t apptime_to_nttime_approx(double);

extern GX_EXPORT const uint8_t utf8_byte_num[256];

}
