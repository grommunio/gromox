#pragma once
#include <atomic>
#include <cstdint>
#include <cstring>
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

enum {
	QP_MIME_HEADER = 1U << 0,
};

enum class mime_type {
	none, single, single_obj, multiple,
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
	void clear() { m_ptrs.clear(); }

	std::vector<std::unique_ptr<char[]>> m_ptrs;
	size_t m_total_size = 0;
};
using ALLOC_CONTEXT = alloc_context;

extern GX_EXPORT bool utf8_valid(const char *str);
extern GX_EXPORT BOOL utf8_truncate(char *str, int length);
extern GX_EXPORT void utf8_filter(char *string);
extern GX_EXPORT void wchar_to_utf8(uint32_t wchar, char *string);
extern GX_EXPORT const char *replace_iconv_charset(const char *charset);
extern GX_EXPORT BOOL string_to_utf8(const char *charset, const char *in_string, char *out_string, size_t out_len);
extern GX_EXPORT BOOL string_from_utf8(const char *charset, const char *in_string, char *out_string, size_t out_len);
extern GX_EXPORT ssize_t utf8_to_utf16le(const char *src, void *dst, size_t len);
extern GX_EXPORT BOOL utf16le_to_utf8(const void *src, size_t src_len, char *dst, size_t len);
extern GX_EXPORT char *search_string(const char *haystack, const char *needle,
    size_t haystacklen);
extern GX_EXPORT int wildcard_match(const char *data, const char *mask, BOOL icase);
extern GX_EXPORT void randstring(char *out, size_t len, const char *pool = nullptr);
extern GX_EXPORT int encode64(const void *in, size_t inlen, char *out, size_t outmax, size_t *outlen);
extern GX_EXPORT int encode64_ex(const void *in, size_t inlen, char *out, size_t outmax, size_t *outlen);
#define decode64 decode64_ex
extern GX_EXPORT int decode64_ex(const char *in, size_t inlen, void *out, size_t outmax, size_t *outlen);
extern GX_EXPORT ssize_t qp_decode_ex(void *output, size_t out_len, const char *input, size_t length, unsigned int qp_flags = 0);
extern GX_EXPORT ssize_t qp_encode_ex(void *output, size_t outlen, const char *input, size_t length);
extern GX_EXPORT void encode_hex_int(int id, char *out);
extern GX_EXPORT int decode_hex_int(const char *in);
extern GX_EXPORT BOOL encode_hex_binary(const void *src, int srclen, char *dst, int dstlen);
extern GX_EXPORT BOOL decode_hex_binary(const char *src, void *dst, int dstlen);

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
extern GX_EXPORT size_t qp_encoded_size_estimate(const char *, size_t);
extern GX_EXPORT void safe_memset(void *, uint8_t, size_t);
extern GX_EXPORT unsigned int newline_size(const char *, size_t);
extern GX_EXPORT ec_error_t cu_validate_msgclass(const char *);
extern GX_EXPORT bool cpid_cstr_compatible(cpid_t);
extern GX_EXPORT bool cset_cstr_compatible(const char *);
extern GX_EXPORT int iconv_validate();
extern GX_EXPORT const std::string_view *ianatz_to_tzdef(const char *);
extern GX_EXPORT const std::string_view *wintz_to_tzdef(const char *);
extern GX_EXPORT bool get_digest(const char *src, const char *tag, char *out, size_t outmax);
extern GX_EXPORT bool set_digest(char *src, size_t length, const char *tag, const char *v);
extern GX_EXPORT bool set_digest(char *src, size_t length, const char *tag, uint64_t v);
extern GX_EXPORT void mlog_init(const char *ident, const char *file, unsigned int level, const char *user = nullptr);
extern GX_EXPORT void mlog(unsigned int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
extern GX_EXPORT int ssllog(const char *s, size_t len, void *);
extern GX_EXPORT int class_match_prefix(const char *h, const char *n);
extern GX_EXPORT int class_match_suffix(const char *h, const char *n);
extern GX_EXPORT void replace_unsafe_basename(char *);
extern GX_EXPORT size_t utf8_printable_prefix(const void *, size_t);
extern GX_EXPORT uint64_t apptime_to_nttime_approx(double);
extern GX_EXPORT std::string gx_utf8_to_punycode(const char *);
extern GX_EXPORT bool str_isascii(const char *);
extern GX_EXPORT bool str_isasciipr(const char *);
extern GX_EXPORT gromox::errno_t canonical_hostname(std::string &);

/* _xlen - exact length (chars); _len - allocation size, i.e. \0-terminated */
/* All the classic 8-bit charsets map to within the Unicode Basic Multilingual Plane */
static inline size_t mb_to_utf8_xlen(size_t z) { return 3 * z; }
static inline size_t mb_to_utf8_xlen(const char *s) { return mb_to_utf8_xlen(strlen(s)); }
static inline size_t mb_to_utf8_len(const char *s) { return mb_to_utf8_xlen(s) + 1; }
/*
 * Shift states... yuck. Anyway, if you look at all values of @utf32,
 * @isojp and @utf7, @utf32 is always largest, which means we need not
 * calculate max(utf32,utf7,isojp).
 */
// auto isojp = (z + 1) / 4 * 9 - 1 + (z - 3) % 4;
// auto utf7  = (z + 1) / 2 * 6 - (z % 2);
static inline size_t utf8_to_mb_xlen(size_t z) { return 4 * z + 4; }
static inline size_t utf8_to_mb_xlen(const char *s) { return utf8_to_mb_xlen(strlen(s)); }
static inline size_t utf8_to_mb_len(const char *s) { return utf8_to_mb_xlen(s) + 1; }
static inline size_t utf8_to_utf16_xlen(size_t z) { return 2 * z; }
static inline size_t utf8_to_utf16_len(size_t z) { return utf8_to_utf16_xlen(z) + 2; }
static inline size_t utf8_to_utf16_len(const char *s) { return utf8_to_utf16_xlen(strlen(s)) + 2; }
static inline size_t utf16_to_utf8_xlen(size_t z) { return z / 2 * 3 + 1; }
static inline size_t utf16_to_utf8_len(size_t z) { return utf16_to_utf8_xlen(z) + 1; }

extern GX_EXPORT const uint8_t utf8_byte_num[256];

}
