#pragma once
#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdbool.h>
#	include <stdint.h>
#endif
#include <gromox/common_types.hpp>

BOOL utf8_check(const char *str);

BOOL utf8_len(const char *str, int *plen);

BOOL utf8_truncate(char *str, int length);

void utf8_filter(char *string);
extern void wchar_to_utf8(uint32_t wchar, char *string);
const char* replace_iconv_charset(const char *charset);

BOOL string_to_utf8(const char *charset,
	const char *in_string, char *out_string);

BOOL string_from_utf8(const char *charset,
	const char *in_string, char *out_string);
extern int utf8_to_utf16le(const char *src, void *dst, size_t len);
extern BOOL utf16le_to_utf8(const void *src, size_t src_len, char *dst, size_t len);
extern BOOL get_digest(const char *src, const char *tag, char *buff, size_t buff_len);
extern BOOL set_digest(char *src, size_t length, const char *tag, const char *value);
extern BOOL add_digest(char *src, size_t length, const char *tag, const char *value);
void swap_string(char *dest, const char *src);

char* search_string(const char *haystack, const char *needle, 
    size_t haystacklen);
char* itoa(int value, char *string, int radix);

char* ltoa(long value, char *string, long radix);

#ifdef _STRCASESTR_
char *strcasestr(const char *s1, const char *s2);
#endif

char* itvltoa(long interval, char *string);

long atoitvl(const char *string);

char* bytetoa(uint64_t byte, char *string);

uint64_t atobyte(const char *string);

char* md5_crypt_wrapper(const char *pw);

int wildcard_match(const char *data, const char *mask, BOOL icase);
void randstring(char *buff, int length);
extern int encode64(const void *in, size_t inlen, char *out, size_t outmax, size_t *outlen);
extern int encode64_ex(const void *in, size_t inlen, char *out, size_t outmax, size_t *outlen);
extern int decode64(const char *in, size_t inlen, void *out, size_t *outlen);
extern int decode64_ex(const char *in, size_t inlen, void *out, size_t outmax, size_t *outlen);
extern int qp_decode(void *output, const char *input, size_t length);
extern int qp_decode_ex(void *output, size_t out_len, const char *input, size_t length);
extern int qp_encode_ex(void *output, size_t outlen, const char *input, size_t length);
void encode_hex_int(int id, char *out);

int decode_hex_int(const char *in);
extern BOOL encode_hex_binary(const void *src, int srclen, char *dst, int dstlen);
extern BOOL decode_hex_binary(const char *src, void *dst, int dstlen);
int uudecode(const char *in, size_t inlen, int *pmode,
	char *file_name, char *out, size_t *outlen);

int uuencode(int mode, const char *file_name, const char *in,
	size_t inlen, char *out, size_t outmax, size_t *outlen);
extern void debug_info(const char *format, ...);
extern bool parse_bool(const char *s);
