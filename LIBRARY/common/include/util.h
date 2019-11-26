#ifndef _H_UTIL_
#define _H_UTIL_

#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

BOOL utf8_check(const char *str);

BOOL utf8_len(const char *str, int *plen);

BOOL utf8_truncate(char *str, int length);

void utf8_filter(char *string);
extern void wchar_to_utf8(uint32_t wchar, uint8_t *string);
const char* replace_iconv_charset(const char *charset);

BOOL string_to_utf8(const char *charset,
	const char *in_string, char *out_string);

BOOL string_from_utf8(const char *charset,
	const char *in_string, char *out_string);

int utf8_to_utf16le(const char *src, char *dst, size_t len);

BOOL utf16le_to_utf8(const char *src,
	size_t src_len, char *dst, size_t len);

BOOL get_digest(const char *src, const char *tag, char *buff, size_t buff_len);

BOOL set_digest(char *src, size_t length, const char *tag, char *value);

BOOL add_digest(char *src, size_t length, const char *tag, char *value);

void remove_digest(char *src, const char *tag);

void swap_string(char *dest, const char *src);

char* search_string(const char *haystack, const char *needle, 
    size_t haystacklen);

void upper_string(char *string);

void lower_string(char *string);

void ltrim_string(char *string);

void rtrim_string(char *string);

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

int wildcard_hierarchy_match(const char *data, char seperator,
	const char *mask, BOOL icase);

void randstring(char *buff, int length);

int encode64(const char *_in, size_t inlen, char *_out,
	size_t outmax, size_t *outlen);

int encode64_ex(const char *_in, size_t inlen, char *_out, size_t outmax, 
    size_t *outlen);

int decode64(const char *in, size_t inlen, char *out, size_t *outlen);

int decode64_ex(const char *in, size_t inlen, char *out, size_t outmax,
	size_t *outlen);

int qp_decode(unsigned char* output, const char* input, size_t length);

int qp_decode_ex(unsigned char* output, size_t out_len, const char* input,
	size_t length);

int qp_encode_ex(unsigned char* output, size_t outlen, const char* input,
	size_t length);

void encode_hex_int(int id, char *out);

int decode_hex_int(const char *in);

BOOL encode_hex_binary(const char *src, int srclen, char *dst, int dstlen);

BOOL decode_hex_binary(const char *src, char *dst, int dstlen);

int uudecode(const char *in, size_t inlen, int *pmode,
	char *file_name, char *out, size_t *outlen);

int uuencode(int mode, const char *file_name, const char *in,
	size_t inlen, char *out, size_t outmax, size_t *outlen);

void debug_info(char *format, ...);

#ifdef __cplusplus
}
#endif


#endif
