#pragma once
#include <atomic>
#include <cstdint>
#include <ctime>
#include <memory>
#include <string>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#define FILE_BLOCK_SIZE 0x100
#define FILE_ALLOC_SIZE (FILE_BLOCK_SIZE + sizeof(DOUBLE_LIST_NODE))

enum {
	QP_MIME_HEADER = 1U << 0,
};

struct GX_EXPORT LIB_BUFFER {
	LIB_BUFFER() = default;
	LIB_BUFFER(LIB_BUFFER &&) noexcept = delete;
	LIB_BUFFER(size_t size, size_t items);
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
};

BOOL utf8_check(const char *str);
extern GX_EXPORT bool utf8_count_codepoints(const char *str, size_t *numpoints);
extern GX_EXPORT bool utf16_count_codepoints(const char *str, size_t *numpoints);
BOOL utf8_truncate(char *str, int length);
void utf8_filter(char *string);
extern void wchar_to_utf8(uint32_t wchar, char *string);
const char* replace_iconv_charset(const char *charset);
BOOL string_to_utf8(const char *charset,
	const char *in_string, char *out_string);
extern BOOL string_from_utf8(const char *charset, const char *in_string, char *out_string, size_t out_len);
extern int utf8_to_utf16le(const char *src, void *dst, size_t len);
extern BOOL utf16le_to_utf8(const void *src, size_t src_len, char *dst, size_t len);
extern BOOL get_digest(const char *src, const char *tag, char *buff, size_t buff_len);
extern BOOL set_digest(char *src, size_t length, const char *tag, const char *value);
char* search_string(const char *haystack, const char *needle, 
    size_t haystacklen);
char* itvltoa(long interval, char *string);
char* bytetoa(uint64_t byte, char *string);
uint64_t atobyte(const char *string);
extern GX_EXPORT const char *crypt_wrapper(const char *);
int wildcard_match(const char *data, const char *mask, BOOL icase);
extern GX_EXPORT void randstring_k(char *out, int len, const char *pool);
void randstring(char *buff, int length);
extern int encode64(const void *in, size_t inlen, char *out, size_t outmax, size_t *outlen);
extern int encode64_ex(const void *in, size_t inlen, char *out, size_t outmax, size_t *outlen);
extern int decode64(const char *in, size_t inlen, void *out, size_t outmax, size_t *outlen);
extern int decode64_ex(const char *in, size_t inlen, void *out, size_t outmax, size_t *outlen);
extern GX_EXPORT size_t qp_decode(void *output, const char *input, size_t length, unsigned int qp_flags = 0);
extern GX_EXPORT ssize_t qp_decode_ex(void *output, size_t out_len, const char *input, size_t length);
extern GX_EXPORT ssize_t qp_encode_ex(void *output, size_t outlen, const char *input, size_t length);
void encode_hex_int(int id, char *out);
int decode_hex_int(const char *in);
extern BOOL encode_hex_binary(const void *src, int srclen, char *dst, int dstlen);
extern BOOL decode_hex_binary(const char *src, void *dst, int dstlen);
int uudecode(const char *in, size_t inlen, int *pmode,
	char *file_name, char *out, size_t *outlen);
int uuencode(int mode, const char *file_name, const char *in,
	size_t inlen, char *out, size_t outmax, size_t *outlen);
extern void debug_info(const char *format, ...);

namespace gromox {

extern GX_EXPORT long atoitvl(const char *);
extern GX_EXPORT bool parse_bool(const char *s);
extern GX_EXPORT std::string bin2hex(const void *, size_t);
template<typename T> std::string bin2hex(const T &x) { return bin2hex(&x, sizeof(x)); }
extern GX_EXPORT std::string hex2bin(const char *);
extern GX_EXPORT void rfc1123_dstring(char *, size_t, time_t = 0);
extern GX_EXPORT int setup_sigalrm();

}
