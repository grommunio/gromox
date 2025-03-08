// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *	this file includes some utility functions that will be used by many 
 *	programs
 */
#if defined(HAVE_CONFIG_H)
#	include "config.h"
#endif
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iconv.h>
#include <random>
#include <unistd.h>
#include <json/reader.h>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/util.hpp>
#if defined(__linux__)
#	include <sys/random.h>
#endif

using namespace gromox;

namespace gromox {
const uint8_t utf8_byte_num[256] = {
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,6,6,0,0,
	/* 0x80-0xBF,0xFE,0xFF cannot start a sequence, hence 0 */
};
}

/* check for invalid UTF-8 */
bool utf8_valid(const char *str)
{
	int byte_num = 0;
	unsigned char ch;
	const char *ptr = str;

	if (str == nullptr)
		return FALSE;
	while (*ptr != '\0') {
		ch = (unsigned char)*ptr;
		if (byte_num == 0) {
			byte_num = utf8_byte_num[ch];
			if (byte_num == 0)
				return FALSE;
		}
		else {
			if ((ch & 0xC0) != 0x80)
				return FALSE;
		}
		byte_num --;
		ptr ++;
	}
	if (byte_num > 0)
		return FALSE;
	return TRUE;
}

BOOL utf8_truncate(char *str, int length)
{
	int len = 0;
	int clen = 0;
	char *ptr = str;
	
	clen = strlen(str);
	while (*ptr != '\0' && len < clen) {
		if (length == len) {
			*ptr = '\0';
			return TRUE;
		}
		auto byte_num = utf8_byte_num[static_cast<unsigned char>(*ptr)];
		if (byte_num == 0)
			return FALSE;
		ptr += byte_num;
		len ++;
	}
	return TRUE;
}

/* Strip invalid UTF-8 and replace by '?' */
void utf8_filter(char *string)  
{
	int m;
	int count_s = 0;
	int minus_s = 0;
	auto bytes = reinterpret_cast<unsigned char *>(string);
	unsigned char *end = bytes + strlen(string);
  
	while (bytes < end) {
		if (bytes[0] >= 0xF8) {
			if (minus_s) {
				m = count_s - minus_s + 1;
				memset((bytes-m), '?', m);
			}
			minus_s = 0;
			count_s = 0;
			bytes[0] = '?';
			bytes ++;
			continue;
		}
		if (bytes[0] <= 0x7F) {
			if (minus_s) {
				m = count_s - minus_s + 1;
				memset(bytes - m, '?', m);
			}
			minus_s = 0;  
			count_s = 0;
			if (bytes[0] == 0x09 || bytes[0] == 0x0A || bytes[0] == 0x0D ||
			    (bytes[0] >= 0x20 && bytes[0] <= 0x7E))
				/* do nothing */;
			else
				bytes[0] = '?';
			bytes ++;
			continue;
		}
		if ((bytes[0] & 0xF8) == 0xF0) {
			if (minus_s) {
				m = count_s - minus_s + 1;
				memset(bytes-m, '?', m);
			}
			count_s = 3;
			minus_s = 3;
			bytes ++;
			continue;
		}
		if ((bytes[0] & 0xF0) == 0xE0) {
			if (minus_s) {
				m = count_s - minus_s + 1;
				memset(bytes - m, '?', m);
			}
			count_s = 2;
			minus_s = 2;
			bytes ++;
			continue;
		}
		if ((bytes[0] & 0xE0) == 0xC0) {
			if (minus_s) {
				m = count_s - minus_s + 1;
				memset(bytes - m, '?', m);
			}
			count_s = 1;
			minus_s = 1;
			bytes ++;
			continue;
		}
		if ((bytes[0] & 0xC0) == 0x80) {
			if (minus_s)
				-- minus_s;
			else
				bytes[0] = '?';
			bytes ++;
			continue;
		}
		if (minus_s) {
			m = count_s - minus_s + 1;
			memset(bytes-m, '?', m);
		} else {
			bytes[0] = '?';
		}
        minus_s = 0;
        count_s = 0;
        bytes ++;
        continue;
    }
	if (minus_s) {
		m = count_s - minus_s + 1;
		memset(bytes - m, '?', m);
	}
}

void wchar_to_utf8(uint32_t wchar, char *zstring)
{
	auto string = reinterpret_cast<unsigned char *>(zstring);
	if (wchar < 0x7f) {
		string[0] = wchar;
		string[1] = '\0';
	} else if (wchar < 0x7ff) {
		string[0] = 192 + (wchar/64);
		string[1] = 128 + (wchar%64);
		string[2] = '\0';
	} else if (wchar < 0xffff) {
		string[0] = 224 + wchar/(64*64);
		string[1] = 128 + (wchar/64)%64;
		string[2] = 128 + wchar%64;
		string[3] = '\0';
	} else if (wchar < 0x1FFFFF) {
		string[0] = 240 + wchar/(64*64*64);
		string[1] = 128 + (wchar/(64*64))%64;
		string[2] = 128 + (wchar/64)%64;
		string[3] = 128 + wchar % 64;
		string[4] = '\0';
	} else if (wchar < 0x3FFFFFF) {
		string[0] = 248 + wchar/(64*64*64*64);
		string[1] = 128 + (wchar/(64*64*64))%64;
		string[2] = 128 + (wchar/(64*64))%64;
		string[3] = 128 + (wchar/64)%64;
		string[4] = 128 + wchar % 64;
		string[5] = '\0';
	} else if (wchar < 0x7FFFFFFF) {
		string[0] = 252 + wchar/(64*64*64*64*64);
		string[1] = 128 + (wchar/(64*64*64*64))%64;
		string[2] = 128 + (wchar/(64*64*64))%64;
		string[3] = 128 + (wchar/(64*64))%64;
		string[4] = 128 + (wchar/64)%64;
		string[5] = 128 + wchar % 64;
		string[6] = '\0';
	}
}

static bool have_jpms()
{
	auto cd = iconv_open("UTF-8", "iso-2022-jp-ms");
	if (cd == iconv_t(-1))
		return false;
	iconv_close(cd);
	return true;
}

/**
 * Upgrade charsets (e.g. gb2312 -> gbk) or outright replace uncommon strings.
 * This is used by either HTML/RTF readers trying to make sense of http-equiv
 * charset=, or to postprocess cpid_to_cset() results.
 *
 * Used by:
 * < string_mb_to_utf8 < oxcmail_parse_message_body
 * < html_string_to_utf8 [cpid_to_cset]
 */
const char* replace_iconv_charset(const char *charset)
{
	if (strcasecmp(charset, "gb2312") == 0)
		return "gbk";
	else if (strcasecmp(charset, "ksc_560") == 0 ||
	    strcasecmp(charset, "ks_c_5601") == 0 ||
	    strcasecmp(charset, "ks_c_5601-1987") == 0 ||
	    strcasecmp(charset, "csksc56011987") == 0)
		return "cp949";
	else if (strcasecmp(charset, "iso-2022-jp") == 0 && have_jpms())
		return "iso-2022-jp-ms";
	else if (strcasecmp(charset, "unicode-1-1-utf-7") == 0)
		return "utf-7";
	else if (strcasecmp(charset, "unicode") == 0)
		/*
		 * MSHTML 6: umlauts are HTML-entity-encoded
		 * MSHTML 9: umlauts are windows-1252 encoded
		 * MSHTML 11/Word 15: BOM mark at start (sometimes -
		 * this gets messed up when <html> is nested)
		 * Quite random. Just return something, it's impossible
		 * to get right all the time.
		 */
		return "utf-8";
	return charset;
}

BOOL string_mb_to_utf8(const char *charset, const char *in_string,
    char *out_string, size_t out_len)
{
	iconv_t conv_id;
	char *pin, *pout;
	char tmp_charset[64];
	
	if (0 == strcasecmp(charset, "UTF-8") ||
		0 == strcasecmp(charset, "ASCII") ||
		0 == strcasecmp(charset, "US-ASCII")) {
		gx_strlcpy(out_string, in_string, out_len);
		return TRUE;
	}
	cset_cstr_compatible(charset);
	auto length = strlen(in_string);
	if (0 == length) {
		if (out_len > 0)
			out_string[0] = '\0';
		return TRUE;
	}
	auto orig_outlen = out_len;
	if (out_len > 0)
		/* Leave room for \0 */
		--out_len;
	snprintf(tmp_charset, std::size(tmp_charset), "%s//IGNORE", replace_iconv_charset(charset));
	conv_id = iconv_open("UTF-8", tmp_charset);
	if (conv_id == iconv_t(-1)) {
		/* EINVAL could happen as a result of EMFILE... */
		mlog(LV_ERR, "E-2108: iconv_open %s: %s",
		        tmp_charset, strerror(errno));
		return FALSE;
	}
	pin = (char*)in_string;
	pout = out_string;
	auto in_len = length;
	if (iconv(conv_id, &pin, &in_len, &pout, &out_len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return FALSE;
	}
	iconv_close(conv_id);
	if (orig_outlen > 0)
		*pout = '\0';
	return TRUE;
}

BOOL string_utf8_to_mb(const char *charset, const char *in_string,
    char *out_string, size_t out_len)
{
	if (out_len == 0)
		return TRUE;
	if (0 == strcasecmp(charset, "UTF-8") ||
		0 == strcasecmp(charset, "ASCII") ||
		0 == strcasecmp(charset, "US-ASCII")) {
		gx_strlcpy(out_string, in_string, out_len);
		return TRUE;
	}
	
	auto length = strlen(in_string);
	if (0 == length) {
		out_string[0] = '\0';
		return TRUE;
	}
	
	auto orig_outlen = out_len;
	--out_len; /* Leave room for \0 */
	auto cs = replace_iconv_charset(charset);
	auto conv_id = iconv_open(cs, "UTF-8");
	if (conv_id == iconv_t(-1)) {
		mlog(LV_ERR, "E-2109: iconv_open %s: %s", cs, strerror(errno));
		return FALSE;
	}
	auto pin = const_cast<char *>(in_string);
	auto pout = out_string;
	auto in_len = length;
	if (iconv(conv_id, &pin, &in_len, &pout, &out_len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return FALSE;
	}
	iconv_close(conv_id);
	if (orig_outlen > 0)
		*pout = '\0';
	return TRUE;
}

ssize_t utf8_to_utf16le(const char *src, void *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id;

	len = std::min(len, static_cast<size_t>(SSIZE_MAX));
	conv_id = iconv_open("UTF-16LE", "UTF-8");
	if (conv_id == (iconv_t)-1) {
		mlog(LV_ERR, "E-2110: iconv_open: %s", strerror(errno));
		return -1;
	}
	auto pin  = deconst(src);
	auto pout = static_cast<char *>(dst);
	in_len = strlen(src) + 1;
	memset(dst, 0, len);
	out_len = len;
	if (iconv(conv_id, &pin, &in_len, &pout, &len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return -1;
	} else {
		iconv_close(conv_id);
		return out_len - len;
	}
}

BOOL utf16le_to_utf8(const void *src, size_t src_len, char *dst, size_t len)
{
	char *pin, *pout;
	iconv_t conv_id;
	
	conv_id = iconv_open("UTF-8", "UTF-16LE");
	if (conv_id == (iconv_t)-1) {
		mlog(LV_ERR, "E-2111: iconv_open: %s", strerror(errno));
		return false;
	}
	pin = (char*)src;
	pout = dst;
	memset(dst, 0, len);
	if (iconv(conv_id, &pin, &src_len, &pout, &len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return FALSE;
	} else {
		iconv_close(conv_id);
		return TRUE;
	}
}

/*
 *	search a substring in a string
 *	@param
 *		haystack [in]  string to be searched
 *		needle [in]	   substring to be found
 *		haystacklen	   maximum length of haystack
 *	@return
 *		pointer to first address of found substring
 */
char* search_string(const char *haystack, const char *needle,
	size_t haystacklen)
{
	if (*needle == '\0')	/* everything matches empty string */
	return (char *) haystack;
	size_t len = strlen(needle);
	if (len > haystacklen)
		return nullptr; /* can never find this */
	auto hend = haystack + haystacklen - len;
	for (auto p = const_cast<char *>(haystack); p <= hend; ++p)
		if (strncasecmp(p, needle, len) == 0)
			return (p);
	return NULL;
}

#define WILDS '*'  /* matches 0 or more characters (including spaces) */
#define WILDQ '?'  /* matches ecactly one character */

#define NOMATCH 0
#define MATCH (match+sofar)

int wildcard_match(const char *data, const char *mask, BOOL icase)
{
  const char *ma = mask, *na = data, *lsm = nullptr, *lsn = nullptr;
  int match = 1;
  int sofar = 0;

  /* null strings should never match */
	if (ma == nullptr || na == nullptr || *ma == '\0' || *na == '\0')
	return NOMATCH;
  /* find the end of each string */
  while (*(++mask));
  mask--;
  while (*(++data));
  data--;

  while (data >= na) {
	/* If the mask runs out of chars before the string, fall back on
	 * a wildcard or fail. */
	if (mask < ma) {
	  if (lsm) {
		data = --lsn;
		mask = lsm;
		if (data < na)
					lsm = nullptr;
		sofar = 0;
	  }
	  else
		return NOMATCH;
	}

	switch (*mask) {
	case WILDS:				   /* Matches anything */
	  do
		mask--;					   /* Zap redundant wilds */
	  while ((mask >= ma) && (*mask == WILDS));
	  lsm = mask;
	  lsn = data;
	  match += sofar;
	  sofar = 0;				/* Update fallback pos */
	  if (mask < ma)
		return MATCH;
	  continue;					/* Next char, please */
	case WILDQ:
	  mask--;
	  data--;
	  continue;					/* '?' always matches */
	}
	if (icase ? HX_toupper(*mask) == HX_toupper(*data) :
	(*mask == *data)) {		/* If matching char */
	  mask--;
	  data--;
	  sofar++;					/* Tally the match */
	  continue;					/* Next char, please */
	}
	if (lsm) {					/* To to fallback on '*' */
	  data = --lsn;
	  mask = lsm;
	  if (data < na)
				lsm = nullptr; /* Rewind to saved pos */
	  sofar = 0;
	  continue;					/* Next char, please */
	}
	return NOMATCH;				/* No fallback=No match */
  }
  while ((mask >= ma) && (*mask == WILDS))
	mask--;						   /* Zap leftover %s & *s */
  return (mask >= ma) ? NOMATCH : MATCH;   /* Start of both = match */
}

static constexpr char randstr_pool[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";

/**
 * @length:	the number of characters to produce
 */
void randstring(char *buff, size_t length, const char *string)
{	 
	if (length <= 0)
		return;
	if (string == nullptr || *string == '\0')
		string = randstr_pool;
	auto string_len = strlen(string);
	for (size_t i = 0; i < length; ++i)
		buff[i] = string[gromox::rand() % string_len];
	buff[length] = '\0';
}

#define OK	(0)
#define FAIL	(-1)
#define BUFOVER (-2)

static constexpr char base64tab[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static constexpr int8_t base64idx[] = {
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
	52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
	-1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
	15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
	-1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
	41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
};
#define basis_64 base64tab

/*
 * On success, 0 is returned and @out is NUL-terminated (@outlen does not count NUL).
 */
int encode64(const void *vin, size_t inlen, char *out,
    size_t outmax, size_t *outlen)
{
	auto in = static_cast<const unsigned char *>(vin);
	unsigned char oval;
	size_t olen;

	/* Will it fit? */
	olen = (inlen + 2) / 3 * 4;
	if (outlen)
	  *outlen = olen;
	if (olen >= outmax)
	  return BUFOVER;

	/* Do the work... */
	while (inlen >= 3) {
	  /* user provided max buffer size; make sure we don't go over it */
		*out++ = basis_64[in[0] >> 2];
		*out++ = basis_64[((in[0] << 4) & 0x30) | (in[1] >> 4)];
		*out++ = basis_64[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
		*out++ = basis_64[in[2] & 0x3f];
		in += 3;
		inlen -= 3;
	}
	if (inlen > 0) {
	  /* user provided max buffer size; make sure we don't go over it */
		*out++ = basis_64[in[0] >> 2];
		oval = (in[0] << 4) & 0x30;
		if (inlen > 1) oval |= in[1] >> 4;
		*out++ = basis_64[oval];
		*out++ = (inlen < 2) ? '=' : basis_64[(in[1] << 2) & 0x3c];
		*out++ = '=';
	}
	*out = '\0';
	return OK;
}

#define DW_EOL "\r\n"
#define MAXLINE	76
static char hextab[] = "0123456789ABCDEF";

/*
 * BASE64-encode with newlines.
 * On success, 0 is returned and @_out is NUL-terminated (@outlen does count NUL)
 */
int encode64_ex(const void *vin, size_t inlen, char *_out,
	size_t outmax, size_t *outlen)
{
	auto _in = static_cast<const uint8_t *>(vin);
	size_t inLen = inlen;
	size_t i;
	char* out = _out;
	size_t outsize = (inLen+2)/3*4;		/* 3:4 conversion ratio */
	size_t inpos  = 0;
	size_t outPos = 0;
	int c1, c2, c3;
	int lineLen = 0;
	const char* cp;
	
	if (_in == nullptr || _out == nullptr || outlen == nullptr)
		return -1;
	outsize += strlen(DW_EOL)*outsize/MAXLINE + 2;	/* Space for newlines and NUL */
	if (outsize >= outmax)
		return -1;
	/* Get three characters at a time and encode them. */
	for (i=0; i < inLen/3; ++i) {
		c1 = _in[inpos++] & 0xFF;
		c2 = _in[inpos++] & 0xFF;
		c3 = _in[inpos++] & 0xFF;
		out[outPos++] = base64tab[(c1 & 0xFC) >> 2];
		out[outPos++] = base64tab[((c1 & 0x03) << 4) | ((c2 & 0xF0) >> 4)];
		out[outPos++] = base64tab[((c2 & 0x0F) << 2) | ((c3 & 0xC0) >> 6)];
		out[outPos++] = base64tab[c3 & 0x3F];
		lineLen += 4;
		if (lineLen >= MAXLINE-3) {
			const char *cq = DW_EOL;
			out[outPos++] = *cq++;
			if (*cq != '\0')
				out[outPos++] = *cq;
			lineLen = 0;
		}
	}
	/* Encode the remaining one or two characters. */
	switch (inLen % 3) {
	case 0:
		cp = DW_EOL;
		out[outPos++] = *cp++;
		if (*cp != '\0')
			out[outPos++] = *cp;
		break;
	case 1:
		c1 = _in[inpos] & 0xFF;
		out[outPos++] = base64tab[(c1 & 0xFC) >> 2];
		out[outPos++] = base64tab[((c1 & 0x03) << 4)];
		out[outPos++] = '=';
		out[outPos++] = '=';
		cp = DW_EOL;
		out[outPos++] = *cp++;
		if (*cp != '\0')
			out[outPos++] = *cp;
		break;
	case 2:
		c1 = _in[inpos++] & 0xFF;
		c2 = _in[inpos] & 0xFF;
		out[outPos++] = base64tab[(c1 & 0xFC) >> 2];
		out[outPos++] = base64tab[((c1 & 0x03) << 4) | ((c2 & 0xF0) >> 4)];
		out[outPos++] = base64tab[((c2 & 0x0F) << 2)];
		out[outPos++] = '=';
		cp = DW_EOL;
		out[outPos++] = *cp++;
		if (*cp != '\0')
			out[outPos++] = *cp;
		break;
	}
	out[outPos] = 0;
	*outlen = outPos;
	return 0;
}

static inline bool isbase64(unsigned char c)
{
	return c < std::size(base64idx) && base64idx[c] != -1;
}

/*
 * On success, 0 is returned, @vout is NUL-terminated (@outlen does not count NUL)
 */
int decode64_ex(const char *_in, size_t inlen, void *vout,
	size_t outmax, size_t *outlen)
{
	auto out = static_cast<uint8_t *>(vout);
	size_t inLen = inlen;
	size_t outsize = inlen / 4 * 3;
	/* Get four input chars at a time and decode them. Ignore white space
	 * chars (CR, LF, SP, HT). If '=' is encountered, terminate input. If
	 * a char other than white space, base64 char, or '=' is encountered,
	 * flag an input error, but otherwise ignore the char.
	 */
	int is_err = 0;
	int is_endSeen = 0;
	int b1, b2, b3;
	int a1, a2, a3, a4;
	size_t inpos = 0;
	size_t outPos = 0;
	
	if (_in == nullptr || vout == nullptr || outlen == nullptr)
		return -1;
	if (outsize >= outmax) {
		*outlen = 0;
		return -1;
	}
	while (inpos < inLen) {
		a1 = a2 = a3 = a4 = 0;
		while (inpos < inLen) {
			a1 = _in[inpos++] & 0xFF;
			if (isbase64(a1)) {
				break;
			}
			else if (a1 == '=') {
				is_endSeen = 1;
				break;
			}
			else if (a1 != '\r' && a1 != '\n' && a1 != ' ' && a1 != '\t') {
				is_err = 1;
			}
		}
		while (inpos < inLen) {
			a2 = _in[inpos++] & 0xFF;
			if (isbase64(a2)) {
				break;
			}
			else if (a2 == '=') {
				is_endSeen = 1;
				break;
			}
			else if (a2 != '\r' && a2 != '\n' && a2 != ' ' && a2 != '\t') {
				is_err = 1;
			}
		}
		while (inpos < inLen) {
			a3 = _in[inpos++] & 0xFF;
			if (isbase64(a3)) {
				break;
			}
			else if (a3 == '=') {
				is_endSeen = 1;
				break;
			}
			else if (a3 != '\r' && a3 != '\n' && a3 != ' ' && a3 != '\t') {
				is_err = 1;
			}
		}
		while (inpos < inLen) {
			a4 = _in[inpos++] & 0xFF;
			if (isbase64(a4)) {
				break;
			}
			else if (a4 == '=') {
				is_endSeen = 1;
				break;
			}
			else if (a4 != '\r' && a4 != '\n' && a4 != ' ' && a4 != '\t') {
				is_err = 1;
			}
		}
		if (isbase64(a1) && isbase64(a2) && isbase64(a3) && isbase64(a4)) {
			a1 = base64idx[a1] & 0xFF;
			a2 = base64idx[a2] & 0xFF;
			a3 = base64idx[a3] & 0xFF;
			a4 = base64idx[a4] & 0xFF;
			b1 = ((a1 << 2) & 0xFC) | ((a2 >> 4) & 0x03);
			b2 = ((a2 << 4) & 0xF0) | ((a3 >> 2) & 0x0F);
			b3 = ((a3 << 6) & 0xC0) | ( a4		 & 0x3F);
			out[outPos++] = (char)b1;
			out[outPos++] = (char)b2;
			out[outPos++] = (char)b3;
		}
		else if (isbase64(a1) && isbase64(a2) && isbase64(a3) && a4 == '=') {
			a1 = base64idx[a1] & 0xFF;
			a2 = base64idx[a2] & 0xFF;
			a3 = base64idx[a3] & 0xFF;
			b1 = ((a1 << 2) & 0xFC) | ((a2 >> 4) & 0x03);
			b2 = ((a2 << 4) & 0xF0) | ((a3 >> 2) & 0x0F);
			out[outPos++] = (char)b1;
			out[outPos++] = (char)b2;
			break;
		}
		else if (isbase64(a1) && isbase64(a2) && a3 == '=' && a4 == '=') {
			a1 = base64idx[a1] & 0xFF;
			a2 = base64idx[a2] & 0xFF;
			b1 = ((a1 << 2) & 0xFC) | ((a2 >> 4) & 0x03);
			out[outPos++] = (char)b1;
			break;
		}
		else {
			break;
		}
		if (is_endSeen)
			break;
	} /* end while loop */
	out[outPos] = 0;
	*outlen = outPos;
	return (is_err) ? -1 : 0;
}

static inline bool qp_nonprintable(unsigned char c)
{
	return c < 32 || c == '=' || c >= 127;
}

namespace gromox {

void *zalloc(size_t z)
{
	return calloc(1, z);
}

size_t qp_encoded_size_estimate(const char *s, size_t n)
{
	size_t enc = n;
	for (; n-- > 0; ++s)
		if (qp_nonprintable(*s) && *s != '\t' && *s != '\n' && *s != '\r')
			enc += 2;
	return enc;
}

void replace_unsafe_basename(char *s)
{
	/* Replace chars with special meaning (sh, make) */
	for (; *s != '\0'; ++s) {
		auto safe = HX_isascii(*s) && (HX_isalnum(*s) ||
		            *s == '+' || *s == '-' || *s == '^' || *s == '_');
		if (!safe)
			*s = '_';
	}
}

}

/*
 * The resulting QP data is not suitable as encoded-words, only bodytext.
 */
ssize_t qp_encode_ex(void *voutput, size_t outlen, const char *input, size_t length)
{
	auto output = static_cast<uint8_t *>(voutput);
	size_t inpos, outpos, linelen;

	if (input == nullptr || output == nullptr)
		return -1;
	inpos  = 0;
	outpos = 0;
	linelen = 0;
	while (inpos < length) {
		auto ch = static_cast<unsigned char>(input[inpos++]);
		/* '.' at beginning of line (special meaning in SMTPs) */
		if (linelen == 0 && ch == '.') {
			if (outpos + 3 >= outlen)
				return -1;
			output[outpos++] = '=';
			output[outpos++] = hextab[(ch >> 4) & 0x0F];
			output[outpos++] = hextab[ch & 0x0F];
			linelen += 3;
		}
		/* "From" at beginning of line (special meaning in mbox) */
		else if (linelen == 0 && inpos + 2 < length && ch == 'F' &&
		    input[inpos] == 'r' && input[inpos+1] == 'o' &&
		    input[inpos+2] == 'm') {
			if (outpos + 3 >= outlen)
				return -1;
			output[outpos++] = '=';
			output[outpos++] = hextab[(ch >> 4) & 0x0F];
			output[outpos++] = hextab[ch & 0x0F];
			linelen += 3;
		}
		/* Normal printable char */
		else if ((62 <= ch && ch <= 126) || (33 <= ch && ch <= 60)) {
			if (outpos + 1 >= outlen)
				return -1;
			output[outpos++] = (char) ch;
			++linelen;
		}
		/* Space */
		else if (ch == ' ') {
			/* Space at end of line or end of input must be encoded */
			if (inpos >= length			  /* End of input? */
				|| (inpos < length-1	  /* End of line? */
					&& input[inpos	] == '\r' 
					&& input[inpos+1] == '\n') ) {
				if (outpos + 3 >= outlen)
					return -1;
				output[outpos++] = '=';
				output[outpos++] = '2';
				output[outpos++] = '0';
				linelen += 3;
			}
			else {
				if (outpos + 1 >= outlen)
					return -1;
				output[outpos++] = ' ';
				++linelen;
			}
		}
		/* Hard line break */
		else if (inpos < length && ch == '\r' && input[inpos] == '\n') {
			++inpos;
			if (outpos + 2 >= outlen)
				return -1;
			output[outpos++] = '\r';
			output[outpos++] = '\n';
			linelen = 0;
		} else if (qp_nonprintable(ch)) {
			if (outpos + 3 >= outlen)
				return -1;
			output[outpos++] = '=';
			output[outpos++] = hextab[(ch >> 4) & 0x0F];
			output[outpos++] = hextab[ch & 0x0F];
			linelen += 3;
		}
		/* Soft line break */
		if (linelen >= MAXLINE-3 && !(inpos < length-1 && 
			input[inpos] == '\r' && input[inpos+1] == '\n')) {
			if (outpos + 3 >= outlen)
				return -1;
			output[outpos++] = '=';
			output[outpos++] = '\r';
			output[outpos++] = '\n';
			linelen = 0;
		}
	}
	output[outpos] = 0;
	return outpos;
}

/*	qpdecode.c -- quoted-printable decoding routine
 *	Copyright (C) 2001-2003 Mark Weaver
 *	Written by Mark Weaver <mark@npsl.co.uk>
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public
 *	License as published by the Free Software Foundation; either
 *	version 2 of the License, or (at your option) any later version.
 *
 *	This library is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	Library General Public License for more details.
 *
 *	You should have received a copy of the GNU Library General Public
 *	License along with this library; if not, write to the
 *	Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 *	Boston, MA	02111-1307, USA.
 */



/* 'robust' QP decode accepts =3e as encouraged by the standard, although
 *	it is illegal to encode this way
 */
static const unsigned char hex_tab[256] = 
{
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
	0x0F, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x0A, 0x0B, 0x0C,
	0x0D, 0x0E, 0x0F, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10
};

static size_t qp_decode(void *voutput, const char *input, size_t length,
    unsigned int qp_flags)
{
	auto output = static_cast<uint8_t *>(voutput);
	bool mime_mode = qp_flags & QP_MIME_HEADER;
	size_t i, cnt = 0;
	for (i = 0; i < length; i++) {
		char c = input[i];
		switch (c) {
		case '=': {
			/* quoted char, process it */
			auto rem = length - i;
			if (rem >= 3 && HX_isxdigit(input[i+1]) &&
			    HX_isxdigit(input[i+2])) { /* OK, this is =HEX */
				output[cnt++] = (hex_tab[input[i+1] & 0xff] << 4) | 
					hex_tab[input[i+2] & 0xff];
				i +=2;
				break;
			}
			/* indicates 'soft-line break', implying ignore 
			   it & the following CR 
			*/
			if (rem > 1) {
				auto nl = newline_size(&input[i+1], rem - 1);
				if (nl > 0) {
					i += nl;
					break;
				}
			}
			/* just ignore it, it doesn't seem to be correctly quoting
			   anything (report an error/add a fussy mode?) 
			*/
			break;
		}
		case '_':
			if (mime_mode) {
				output[cnt++] = ' ';
				break;
			}
			[[fallthrough]];
		default:
			/* pass other characters through unmolested */
			output[cnt++] = c;
			break;
		}
	}
	output[cnt] = '\0';
	return cnt;
}

ssize_t qp_decode_ex(void *voutput, size_t out_len, const char *input,
    size_t length, unsigned int qp_flags)
{
	auto output = static_cast<uint8_t *>(voutput);
	int c;
	size_t i, cnt = 0;
	for (i = 0; i < length; i++) {

		c = input[i];

		switch (c) {
		case '=': {
			/* quoted char, process it */
			size_t rem = length - i;
			if (rem >= 3 && HX_isxdigit(input[i+1]) &&
			    HX_isxdigit(input[i+2])) { /* OK, this is =HEX */
				cnt++;
				i +=2;
				break;
			}
			/* indicates 'soft-line break', implying ignore 
			   it & the following CR 
			*/
			if (rem > 1) {
				auto nl = newline_size(&input[i+1], rem - 1);
				if (nl > 0) {
					i += nl;
					break;
				}
			}
			/* just ignore it, it doesn't seem to be correctly quoting
			   anything (report an error/add a fussy mode?) 
			*/
			break;
		}
		default:
			/* pass other characters through unmolested */
			cnt++;
			break;
		}
	}
	if (cnt >= out_len)
		return -1;
	return qp_decode(output, input, length, qp_flags);
}

void encode_hex_int(int id, char *out)
{
	static const char codes[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
							'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	char t_char;
	size_t i, j;
	
	for (i=0,j=0; i<sizeof(int); i++,j+=2) {
		t_char = (id >> i*8) & 0xFF;
		out[j+1] = codes[t_char&0x0f];
		out[j] = codes[(t_char&0xf0)>>4];
	}
	out[j] = '\0';
}

int decode_hex_int(const char *in)
{
	int retval;
	char t_buff[3];
	
	if (strlen(in) < 2 * sizeof(int))
		return 0;
	retval = 0;
	for (size_t i = 0; i < sizeof(int); ++i) {
		t_buff[0] = in[2*i];
		t_buff[1] = in[2*i+1];
		t_buff[2] = '\0';
		retval |= strtol(t_buff, NULL, 16) << i*8;
	}
	return retval;
}

BOOL encode_hex_binary(const void *vsrc, int srclen, char *dst, int dstlen)
{
	auto src = static_cast<const uint8_t *>(vsrc);
	static const char codes[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
							 '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	int i, j;
	char t_char;
	
	if (2 * srclen + 1 > dstlen)
		return FALSE;
	for (i=0,j=0; i<srclen; i++,j+=2) {
		t_char = src[i];
		dst[j + 1] = codes[t_char&0x0f];
		dst[j] = codes[(t_char&0xf0)>>4];
	}
	dst[j] = '\0';
	return TRUE;
}

BOOL decode_hex_binary(const char *src, void *vdst, int dstlen)
{
	auto dst = static_cast<uint8_t *>(vdst);
	char t_buff[3];
	int i, j, len;

	len = strlen(src);
	if (len / 2 > dstlen)
		return FALSE;
	for (i=0,j=0; i<len; i+=2,j++) {
		t_buff[0] = src[i];
		t_buff[1] = src[i+1];
		t_buff[2] = '\0';
		dst[j] = strtol(t_buff, NULL, 16);
	}
	if (j < dstlen)
		dst[j] = '\0';
	return TRUE;
}
