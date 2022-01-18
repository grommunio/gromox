// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
/*
 *	  Addr_kids, for parse the email addr
 */
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <unistd.h>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <vmime/mailbox.hpp>
#include <gromox/common_types.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>

using namespace gromox;

enum {
	SW_USUAL = 0,
	SW_SLASH,
	SW_DOT,
	SW_DOT_DOT,
	SW_QUOTED,
	SW_QUOTED_SECOND
};

static constexpr uint32_t g_uri_usual[] = {
    0xffffdbfe, /* 1111 1111 1111 1111  1101 1011 1111 1110 */

                /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
    0x7fff37d6, /* 0111 1111 1111 1111  0011 0111 1101 0110 */

                /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */

    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
};

void parse_email_addr(EMAIL_ADDR *e_addr, const char *email)
{
	parse_mime_addr(e_addr, email);
}

BOOL parse_uri(const char *uri_buff, char *parsed_uri)
{
	int tmp_len;
	const char *p;
	const char *uri_end;
	const char *args_start;
	int state, quoted_state;
    char c, ch, decoded, *u;
    
	decoded = '\0';
	quoted_state = SW_USUAL;
	state = SW_USUAL;
	p = uri_buff;
	uri_end = uri_buff + strlen(uri_buff);
	u = parsed_uri;
	args_start = NULL;
	ch = *p ++;
	while (p <= uri_end) {
		switch (state) {
		case SW_USUAL:
			if (g_uri_usual[ch >> 5] & (1U << (ch & 0x1f))) {
				*u++ = ch;
				ch = *p++;
				break;
			}
			switch (ch) {
			case '/':
				state = SW_SLASH;
				*u ++ = ch;
				break;
			case '%':
				quoted_state = state;
				state = SW_QUOTED;
				break;
			case '?':
				args_start = p;
				goto PARSE_ARGS;
			case '#':
				goto PARSE_DONE;
			default:
				*u ++ = ch;
				break;
			}
			ch = *p ++;
			break;
		case SW_SLASH:
			if (g_uri_usual[ch >> 5] & (1U << (ch & 0x1f))) {
				state = SW_USUAL;
				*u ++ = ch;
				ch = *p ++;
				break;
			}
			switch (ch) {
			case '/':
				/* merge slash */
				break;
			case '.':
				state = SW_DOT;
				*u ++ = ch;
				break;
			case '%':
				quoted_state = state;
				state = SW_QUOTED;
				break;
			case '?':
				args_start = p;
				goto PARSE_ARGS;
			case '#':
				goto PARSE_DONE;
			default:
				state = SW_USUAL;
				*u ++ = ch;
				break;
			}
			ch = *p ++;
			break;
		case SW_DOT:
			if (g_uri_usual[ch >> 5] & (1U << (ch & 0x1f))) {
				state = SW_USUAL;
				*u ++ = ch;
				ch = *p ++;
				break;
			}
			switch (ch) {
			case '/':
				state = SW_SLASH;
				u --;
				break;
			case '.':
				state = SW_DOT_DOT;
				*u ++ = ch;
				break;
			case '%':
				quoted_state = state;
				state = SW_QUOTED;
				break;
			case '?':
				args_start = p;
				goto PARSE_ARGS;
			case '#':
				goto PARSE_DONE;
			default:
				state = SW_USUAL;
				*u ++ = ch;
				break;
			}
			ch = *p ++;
			break;
		case SW_DOT_DOT:
			if (g_uri_usual[ch >> 5] & (1U << (ch & 0x1f))) {
				state = SW_USUAL;
				*u ++ = ch;
				ch = *p ++;
				break;
			}
			switch (ch) {
			case '/':
				state = SW_SLASH;
				u -= 5;
				for ( ;; ) {
					if (u < parsed_uri)
						return FALSE;
					if ('/' == *u) {
						u ++;
						break;
					}
					u --;
				}
				break;
			case '%':
				quoted_state = state;
				state = SW_QUOTED;
				break;
			case '?':
				args_start = p;
				goto PARSE_ARGS;
			case '#':
				goto PARSE_DONE;
			default:
				state = SW_USUAL;
				*u ++ = ch;
				break;
			}
			ch = *p ++;
			break;
		case SW_QUOTED:
			if (ch >= '0' && ch <= '9') {
				decoded = (uint8_t)(ch - '0');
				state = SW_QUOTED_SECOND;
				ch = *p ++;
				break;
			}
			c = (uint8_t)(ch | 0x20);
			if (c >= 'a' && c <= 'f') {
				decoded = (uint8_t)(c - 'a' + 10);
				state = SW_QUOTED_SECOND;
				ch = *p ++;
				break;
			}
			return FALSE;
		case SW_QUOTED_SECOND:
			if (ch >= '0' && ch <= '9') {
				ch = (uint8_t)((decoded << 4) + (ch - '0'));
				if ('%' == ch || '#' == ch) {
					state = SW_USUAL;
					*u ++ = ch;
					ch = *p ++;
					break;
				} else if ('\0' == ch) {
					return FALSE;
				}
				state = quoted_state;
				break;
			}

			c = (uint8_t)(ch | 0x20);
			if (c >= 'a' && c <= 'f') {
				ch = (uint8_t) ((decoded << 4) + (c - 'a') + 10);
				if ('?' == ch) {
					state = SW_USUAL;
					*u ++ = ch;
					ch = *p ++;
					break;

				}
				state = quoted_state;
				break;
			}
			return FALSE;
		}
	}
 PARSE_ARGS:
	while (p < uri_end) {
		if (*p ++ != '#')
			continue;
		tmp_len = p - args_start;
		memcpy(u, args_start, tmp_len);
		u += tmp_len;
        break;
    }
 PARSE_DONE:
	*u = '\0';
    return TRUE;
}

/*
 *	  parse email address in mime field into e_addr
 *	  @param
 *		  email	 [in]	  string contain the address
 *		  e_addr [out]	  for retrieving parsed address
 */
void parse_mime_addr(EMAIL_ADDR *e_addr, const char *input) try
{
	vmime::mailbox mb;
	mb.parse(input);

	gx_strlcpy(e_addr->display_name, mb.getName().getConvertedText("utf-8").c_str(), std::size(e_addr->display_name));
	auto &emp = mb.getEmail();
	gx_strlcpy(e_addr->local_part, emp.getLocalName().getConvertedText("utf-8").c_str(), std::size(e_addr->local_part));
	gx_strlcpy(e_addr->domain, emp.getDomainName().getConvertedText("utf-8").c_str(), std::size(e_addr->domain));
} catch (const std::bad_alloc &) {
	*e_addr = {};
}

/*
 *	  parse mime information from buffer into mime field
 *	  @param
 *		  in_buff [in]		buffer for passing the content of mime head
 *		  buff_len			length of buff_in
 *		  pmime_field [out] buffer for retrieving information of mime
 *	  @return
 *		  end of mime field information, including the last "\r\n", if the last
 *		  two byte in buff_in is "\r\n", it is also considered as a mime field 
 */
size_t parse_mime_field(const char *in_buff, size_t buff_len,
    MIME_FIELD *pmime_field) try
{
	BOOL meet_slash;
	
	if (buff_len > MIME_FIELD_LEN)
		buff_len = MIME_FIELD_LEN;
	/* parse the first line the get the field name and part of value*/
	auto tmp_ptr = in_buff;

	size_t i = 0, value_length = 0;
	while (*tmp_ptr != ':' && i < buff_len &&
		i <= MIME_NAME_LEN && *tmp_ptr != '\r'
		&& *tmp_ptr != '\n') {
		tmp_ptr ++; 
		i ++;
	}
	if (i == buff_len || i == MIME_NAME_LEN + 1 ||
	    *tmp_ptr == '\r' || *tmp_ptr == '\n')
		return 0;
	pmime_field->name.assign(in_buff, tmp_ptr - in_buff);
	tmp_ptr ++;	   /* skip ':' */
	i ++;
	while (i < buff_len && (' ' == *tmp_ptr || '\t' == *tmp_ptr)) { 
		tmp_ptr ++;	/* skip WSP */
		i ++;
	}
	if (i == buff_len)
		return 0;
	char field_value[MIME_FIELD_LEN];
	auto dest_ptr = field_value;
	while (true) {
		meet_slash = FALSE;
		while (i < buff_len && *tmp_ptr != '\r' && *tmp_ptr != '\n') {
			if (tmp_ptr[0] == '\\' && (tmp_ptr[1] == '\r' || tmp_ptr[1] == '\n')) {
				meet_slash = TRUE;
			} else {
				*dest_ptr++ = *tmp_ptr;
				value_length ++;
			}
			tmp_ptr ++;
			i ++;
		}
		if (i == buff_len) {
			if ('\r' == *tmp_ptr || '\n' == *tmp_ptr) {
				pmime_field->value.assign(field_value, value_length);
				return buff_len;
			}
			return 0;
		}
		if (*tmp_ptr == '\r') {
			++tmp_ptr;
			++i;
		}
		if (i == buff_len) {
			if (*tmp_ptr == '\n') {
				pmime_field->value.assign(field_value, value_length);
				return buff_len;
			}
			if (*tmp_ptr == ' ' || *tmp_ptr == '\t' || meet_slash)
				return 0;
			buff_len--;
		} else {
			if ('\n' == *tmp_ptr) {
				tmp_ptr ++;
				i ++;
			}
		}
		if (*tmp_ptr != ' ' && *tmp_ptr != '\t' && !meet_slash) {
			pmime_field->value.assign(field_value, value_length);
			return i;
		} else {
			while (i < buff_len && (' ' == *tmp_ptr || '\t' == *tmp_ptr)) {
				tmp_ptr ++; /* skip WSP */
				i ++;
			}
			if (i == buff_len)
				return 0;
			*dest_ptr++ = ' ';
			value_length ++;
		}
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2025: ENOMEM");
	return 0;
}

void parse_mime_encode_string(char *in_buff, long ibuff_len,
	ENCODE_STRING *pencode_string)
{
	assert(ibuff_len >= 0);
	size_t i = 0, buff_len = ibuff_len;
	
	memset(pencode_string, 0, sizeof(ENCODE_STRING));
	/* first ignore the ' ' in the buffer */
	for (i = 0; i < buff_len; ++i)
		if (in_buff[i] != ' ')
			break;
	if (i >= buff_len - 2) {
		strcpy(pencode_string->charset, "default");
		strcpy(pencode_string->encoding, "none");
		memcpy(pencode_string->title, in_buff + i, buff_len - i);
		pencode_string->title[buff_len - i] = '\0';
		return;
	}
	if (in_buff[i] != '=' || in_buff[i+1] != '?') {
		strcpy(pencode_string->charset, "default");
		strcpy(pencode_string->encoding, "none");
		auto title_len = std::max(buff_len, sizeof(pencode_string->title) - 1);
		memcpy(pencode_string->title, in_buff, title_len);
		pencode_string->title[title_len] = '\0';
		return;
	}
	auto charset_begin = i + 2;
	auto tmp_begin = charset_begin;
	for (i = tmp_begin; i<buff_len; ++i)
		if (in_buff[i] == '?')
			break;
	if (i >= buff_len - 1)
		return;
	/* copy charset to parsed structure */
	auto charset_len = i - charset_begin;
	if (charset_len > sizeof(pencode_string->charset) - 1)
		return;
	if (0 == charset_len) {
		strcpy(pencode_string->charset, "default");
	} else {	
		memcpy(pencode_string->charset, in_buff + charset_begin, charset_len);
		pencode_string->charset[charset_len] = '\0';
	}
	if ('b' == in_buff[i+1] || 'B' == in_buff[i+1]) {
		strcpy(pencode_string->encoding, "base64");
		tmp_begin = i + 2;
	} else if ('q' == in_buff[i+1] || 'Q' == in_buff[i+1]) {
		strcpy(pencode_string->encoding, "quoted-printable");
		tmp_begin = i + 2;
	} else {
		strcpy(pencode_string->encoding, "none");
		tmp_begin = i + 1;
	}
	if (tmp_begin >= buff_len)
		return;
	/* ignore the ? */
	if (in_buff[tmp_begin] == '?')
		tmp_begin ++;
	auto title_begin = tmp_begin;
	for (i = tmp_begin; i < buff_len; ++i)
		if (in_buff[i] == '?' && in_buff[i+1] == '=')
			break;
	auto title_len = i - title_begin;
	if (title_len > sizeof(pencode_string->title) - 1)
		title_len = sizeof(pencode_string->title) - 1;
	memcpy(pencode_string->title, in_buff + title_begin, title_len);
	pencode_string->title[title_len] = '\0';
}

/*
 *	this function parse the buffer containing the parameters in mime 
 *	field value
 *	@param
 *		in_buff [in]	buffer passed in
 *		buff_len		buffer length, normally should be less than 64K
 *		value [out]		buffer for retrieving the value
 *		val_len			length of value buffer
 *		pfile [in,out]	mem file to retrieving the parsing result of params
 */
void parse_field_value(const char *in_buff, long buff_len, char *value,
    long val_len, std::vector<kvpair> &pfile) try
{
	const char *ptr, *prev_section, *ptr_equal;
	int distance;
	int paratag_len = 0;
	int paraval_len = 0;
	char param_tag[MIME_FIELD_LEN];
	char param_value[MIME_FIELD_LEN];

	ptr = in_buff;
	prev_section = NULL;
	while ((ptr = static_cast<const char *>(memchr(ptr, ';', buff_len - (ptr - in_buff)))) != nullptr) {
		if (NULL == prev_section) {
			distance = ptr - in_buff;
			paratag_len = (val_len - 1 > distance)?distance:(val_len - 1);
			memcpy(value, in_buff, paratag_len);
			value[paratag_len] = '\0';
			HX_strrtrim(value);
			HX_strltrim(value);
		} else {
			ptr_equal = static_cast<const char *>(memchr(prev_section, '=', ptr - prev_section));
			if (NULL == ptr_equal) {
				paratag_len = ptr - prev_section;
				memcpy(param_tag, prev_section, paratag_len);
				paraval_len = 0;
			} else {
				paratag_len = ptr_equal - prev_section;
				memcpy(param_tag, prev_section, paratag_len);
				ptr_equal ++;
				paraval_len = ptr - ptr_equal;
				memcpy(param_value, ptr_equal, paraval_len);
			}
			param_tag[paratag_len] = '\0';
			param_value[paraval_len] = '\0';
			HX_strrtrim(param_tag);
			HX_strltrim(param_tag);
			HX_strrtrim(param_value);
			HX_strltrim(param_value);
			if (paratag_len != 0 || paraval_len != 0)
				pfile.emplace_back(MIME_FIELD{param_tag, param_value});
		}
		ptr ++;
		prev_section = ptr;
	}
	ptr = in_buff + buff_len;
	if (NULL == prev_section) {
		distance = ptr - in_buff;
		paratag_len = (val_len - 1 > distance)?distance:(val_len - 1);
		memcpy(value, in_buff, paratag_len);
		value[paratag_len] = '\0';
		HX_strrtrim(value);
		HX_strltrim(value);
		return;
	}
	ptr_equal = static_cast<const char *>(memchr(prev_section, '=', ptr - prev_section));
	if (NULL == ptr_equal) {
		paratag_len = ptr - prev_section;
		memcpy(param_tag, prev_section, paratag_len);
		paraval_len = 0;
	} else {
		paratag_len = ptr_equal - prev_section;
		memcpy(param_tag, prev_section, paratag_len);
		ptr_equal ++;
		paraval_len = ptr - ptr_equal;
		memcpy(param_value, ptr_equal, paraval_len);
	}
	param_tag[paratag_len] = '\0';
	param_value[paraval_len] = '\0';
	HX_strrtrim(param_tag);
	HX_strltrim(param_tag);
	HX_strrtrim(param_value);
	HX_strltrim(param_value);
	if (paratag_len != 0 || paraval_len != 0)
		pfile.emplace_back(MIME_FIELD{param_tag, param_value});
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1095: ENOMEM");
	return;
}

/*
 *	find URL of format scheme:hostname[:port]/dir in a buffer.	The
 *	buffer may contain pretty much anything; no errors are signaled.
 *	@param
 *		buf	[in]		buffer to be searched
 *		howmuch			buffer length
 *		count [out]		url length
 */
char* find_url(char *buf, size_t howmuch, int *count)
{
	char *s1, *s2;
	char tmp;

	for (s1=buf; howmuch>6; s1++) {
		switch (*s1) {
		case 'h':
		case 'H':
			if (strncasecmp(&s1[1], "ttp", 3) != 0)
				goto CONTINUE_LOOP;
			if (s1[4] != ':' && ((s1[4] != 's' && s1[4] != 'S') || s1[5] != ':'))
				goto CONTINUE_LOOP;
			break;
		case 'w':
		case 'W':
			if (strncasecmp(&s1[1], "ww.", 3) != 0)
				goto CONTINUE_LOOP;
			break;
		default:
			goto CONTINUE_LOOP;
		}
		for (s2=s1, *count=0; howmuch>0; s2++, (*count)++, howmuch--) {
			tmp = *s2;
			if (tmp < 32 || tmp >= 127 || tmp == ' ' ||
			    tmp == '!' || tmp == '"' || tmp == '\'' ||
			    tmp == '#' || tmp == '(' || tmp == ')' ||
			    tmp == ',' || tmp == '`' || tmp == '{' ||
			    tmp == '}' || tmp == '|' || tmp == '<' ||
			    tmp == '>')
				break;
		}
		return s1;
 CONTINUE_LOOP:
		howmuch --;
	}
	*count = 0;
	return NULL;
}

static const int Index_64[128] = {
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, 63,-1,-1,-1,
	52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
	-1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
	15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
	-1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
	41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
};

static const char B64Chars[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
  'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
  't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', '+', ','
};

/**
 * @u7:		input buffer (need not be \0-terminated)
 * @u7len:	number of bytes to read from @u8
 * @u8:		output buffer
 * @u8len:	size of output buffer
 *
 * On error, -1 is returned. On success, the number of bytes emitted to @u8,
 * not including the final \0 that is emitted.
 */
int mutf7_to_utf8(const char *u7, size_t u7len, char *u8, size_t u8len)
{
  char *u8end;
  int b, ch, k;

	auto p = u8;
  u8end = u8 + u8len - 1;

  for (; u7len&&p<u8end; u7++, u7len--)
  {
	if (*u7 == '&')
	{
	  u7++, u7len--;

	  if (u7len && *u7 == '-')
	  {
		*p++ = '&';
		continue;
	  }

	  ch = 0;
	  k = 10;
	  for (; u7len&&p<u8end; u7++, u7len--)
	  {
		if ((*u7 & 0x80) || (b = Index_64[(int)*u7]) == -1)
		  break;
		if (k > 0)
		{
		  ch |= b << k;
		  k -= 6;
		}
		else
		{
		  ch |= b >> (-k);
		  if (ch < 0x80)
		  {
			if (0x20 <= ch && ch < 0x7f)
			  /* Printable US-ASCII */
			  return -1;
			*p++ = ch;
		  }
		  else if (ch < 0x800)
		  {
			*p++ = 0xc0 | (ch >> 6);
			*p++ = 0x80 | (ch & 0x3f);
		  }
		  else
		  {
			*p++ = 0xe0 | (ch >> 12);
			*p++ = 0x80 | ((ch >> 6) & 0x3f);
			*p++ = 0x80 | (ch & 0x3f);
		  }
		  ch = (b << (16 + k)) & 0xffff;
		  k += 10;
		}
	  }
	  if (ch || k < 6)
		/* Non-zero or too many extra bits */
		return -1;
	  if (!u7len || *u7 != '-')
		/* BASE64 not properly terminated */
		return -1;
	  if (u7len > 2 && u7[1] == '&' && u7[2] != '-')
		/* Adjacent BASE64 sections */
		return -1;
	}
	else if (*u7 < 0x20 || *u7 >= 0x7f)
	  /* Not printable US-ASCII */
	  return -1;
	else
	  *p++ = *u7;
  }
  if (p >= u8end) {
	 return -1;
  }
  *p = '\0';
  return p - u8;
}

/**
 * @u8:		input buffer (need not be \0-terminated)
 * @u8len:	number of bytes to read from @u8
 * @u7:		output buffer
 * @u7len:	size of output buffer
 *
 * On error, -1 is returned. On success, the number of bytes emitted to @u7,
 * not including the final \0 that is emitted.
 */
int utf8_to_mutf7(const char *u8, size_t u8len, char *u7, size_t u7len)
{
  char *u7end;
  char *buf, *p;
	int ch, b = 0, k = 0;
  int base64 = 0;
	size_t n;

  /*
   * In the worst case we convert 2 chars to 7 chars. For example:
   * "\x10&\x10&..." -> "&ABA-&-&ABA-&-...".
   */
  p = buf = u7;

  u7end = u7 + u7len - 1;

  while (u8len&&p<u7end)
  {
	unsigned char c = *u8;

	if (c < 0x80)
	  ch = c, n = 0;
	else if (c < 0xc2)
	  return -1;
	else if (c < 0xe0)
	  ch = c & 0x1f, n = 1;
	else if (c < 0xf0)
	  ch = c & 0x0f, n = 2;
	else if (c < 0xf8)
	  ch = c & 0x07, n = 3;
	else if (c < 0xfc)
	  ch = c & 0x03, n = 4;
	else if (c < 0xfe)
	  ch = c & 0x01, n = 5;
	else
	  return -1;

	u8++, u8len--;
	if (n > u8len)
	  return -1;
	for (size_t i = 0; i < n; ++i) {
	  if ((u8[i] & 0xc0) != 0x80)
		return -1;
	  ch = (ch << 6) | (u8[i] & 0x3f);
	}
	if (n > 1 && !(ch >> (n * 5 + 1)))
	  return -1;
	u8 += n, u8len -= n;

	if (ch < 0x20 || ch >= 0x7f)
	{
	  if (!base64)
	  {
		*p++ = '&';
		base64 = 1;
		b = 0;
		k = 10;
	  }
	  if (ch & ~0xffff)
		ch = 0xfffe;
	  *p++ = B64Chars[b | ch >> k];
	  k -= 6;
	  for (; k >= 0; k -= 6)
		*p++ = B64Chars[(ch >> k) & 0x3f];
	  b = (ch << (-k)) & 0x3f;
	  k += 16;
	}
	else
	{
	  if (base64)
	  {
		if (k > 10)
		  *p++ = B64Chars[b];
		*p++ = '-';
		base64 = 0;
	  }
	  *p++ = ch;
	  if (ch == '&')
		*p++ = '-';
	}
  }

  if (u8len||p>=u7end)
  {
	return -1;
  }

  if (base64)
  {
	if (k > 10)
	  *p++ = B64Chars[b];
	*p++ = '-';
  }

  *p = '\0';
  return p - buf;
}

int parse_imap_args(char *cmdline, int cmdlen, char **argv, int argmax)
{
	int argc;
	char *ptr;
	int b_count = 0, s_count = 0;
	BOOL is_quoted;
	char *last_space;
	char *last_square;
	char *last_quote = nullptr;
	char *last_brace;
	char *last_bracket;

	cmdline[cmdlen++] = ' ';
	ptr = cmdline;
	/* Build the argv list */
	argc = 0;
	last_bracket = NULL;
	last_square = NULL;
	last_space = cmdline;
	is_quoted = FALSE;
	/*
	 * XXX: During splitting, both normal arguments and literals get
	 * converted to strings, and the distinction is lost.
	 *
	 * IMAP APPEND requires that the last argument be a message literal,
	 * but because of the above, normal strings can be passed to the gximap
	 * APPEND handler too. Moreover, the handler can no longer distinguish
	 * `* APPEND fld content` from `* APPEND fld datestring` and will
	 * create a message with datestring as content.
	 */
	while (ptr - cmdline < cmdlen && argc < argmax - 1) {
		/*
		 * After any memmove, we must immediately reevaluate *ptr,
		 * because we may have introduced the same kind of control char
		 * again.
		 */
		if (*ptr == '{' && last_quote == nullptr) {
			last_brace = static_cast<char *>(memchr(ptr + 1, '}', 16));
			if (last_brace != nullptr) {
				*last_brace = '\0';
				int length = strtol(ptr + 1, nullptr, 0);
				memmove(ptr, last_brace + 1, cmdline + cmdlen - 1 - last_brace);
				cmdlen -= last_brace + 1 - ptr;
				ptr += length;
				continue;
			} else {
				argv[0] = NULL;
				return -1;
			}
		}
		if ('\"' == *ptr) {
			memmove(ptr, ptr + 1, cmdline + cmdlen - ptr - 1);
			cmdlen --;
			if (last_quote == nullptr) {
				is_quoted = TRUE;
				last_quote = ptr;
				/* continue the lookp for the empty "" because of memmove */
				continue;
			}
			last_quote = nullptr;
		}
		if (*ptr == '[' && last_quote == nullptr) {
			if (NULL == last_square) {
				last_square = ptr;
				s_count = 0;
			} else {
				s_count ++;
			}
		}
		if (']' == *ptr && NULL != last_square) {
			if (s_count == 0)
				last_square = NULL;
			else
				s_count --;
		}
		if (*ptr == '(' && last_quote == nullptr) {
			if (NULL == last_bracket) {
				last_bracket = ptr;
				b_count = 0;
			} else {
				b_count ++;
			}
		}
		if (')' == *ptr && NULL != last_bracket) {
			if (b_count == 0)
				last_bracket = NULL;
			else
				b_count --;
		}
		if (*ptr == ' ' && last_quote == nullptr &&
			NULL == last_bracket && NULL == last_square) {
			/* ignore leading spaces */
			if (ptr == last_space && !is_quoted) {
				last_space ++;
			} else {
				argv[argc] = last_space;
				*ptr = '\0';
				if (!is_quoted && strcasecmp(argv[argc], "NIL") == 0)
					*argv[argc] = '\0';
				last_space = ptr + 1;
				argc ++;
				is_quoted = FALSE;
			}
		}
		ptr ++;
	}
	/* only one quote is found, error */
	if (last_quote != nullptr || last_bracket != nullptr || last_square != nullptr) {
		argv[0] = NULL;
		return -1;
	}
	argv[argc] = NULL;
	return argc;
}

time_t make_gmtime(struct tm *ptm)
{
	static tz::timezone_t sp;
	
	if (NULL == sp) {
		sp = tz::tzalloc("UTC");
		if (sp == nullptr)
			return 0;
	}
	return tz::mktime_z(sp, ptm);
}

void make_gmtm(time_t gm_time, struct tm *ptm)
{
	static tz::timezone_t sp;
	
	if (NULL == sp) {
		sp = tz::tzalloc("UTC");
		if (sp == nullptr)
			return;
	}
	tz::localtime_rz(sp, &gm_time, ptm);
}

BOOL parse_rfc822_timestamp(const char *str_time, time_t *ptime)
{
	int hour;
	int minute;
	int factor;
	int zone_len;
	time_t tmp_time;
	char tmp_buff[3];
	struct tm tmp_tm;
	const char *str_zone;
	
	memset(&tmp_tm, 0, sizeof(tmp_tm));
	while (HX_isspace(*str_time))
		++str_time;
	str_zone = strptime(str_time, "%a, %d %b %Y %H:%M:%S ", &tmp_tm);
	if (str_zone == nullptr)
		/* DOW is optional */
		str_zone = strptime(str_time, "%d %b %Y %H:%M:%S ", &tmp_tm);
	if (str_zone == nullptr)
		return FALSE;
	
	zone_len = strlen(str_zone);
	if (zone_len >= 5) {
		if (*str_zone == '-')
			factor = 1;
		else if (*str_zone == '+')
			factor = -1;
		else
			return FALSE;
		if (!HX_isdigit(str_zone[1]) || !HX_isdigit(str_zone[2]) ||
		    !HX_isdigit(str_zone[3]) || !HX_isdigit(str_zone[4]))
			return FALSE;

		tmp_buff[0] = str_zone[1];
		tmp_buff[1] = str_zone[2];
		tmp_buff[2] = '\0';
		hour = strtol(tmp_buff, nullptr, 0);
		if (hour < 0 || hour > 23)
			return FALSE;

		tmp_buff[0] = str_zone[3];
		tmp_buff[1] = str_zone[4];
		tmp_buff[2] = '\0';
		minute = strtol(tmp_buff, nullptr, 0);
		if (minute < 0 || minute > 59)
			return FALSE;
	} else if (1 == zone_len) {
		if ('A' <= str_zone[0] && 'J' > str_zone[0]) {
			factor = 1;
			hour = str_zone[0] - 'A' + 1;
			minute = 0;
		} else if ('J' < str_zone[0] && 'M' >= str_zone[0]) {
			factor = 1;
			hour = str_zone[0] - 'A';
			minute = 0;
		} else if ('N' <= str_zone[0] && 'Y' >= str_zone[0]) {
			factor = -1;
			hour = str_zone[0] - 'N' + 1;
			minute = 0;
		} else if ('Z' == str_zone[0]) {
			factor = 1;
			hour = 0;
			minute = 0;
		} else {
			return FALSE;
		}
	} else if (2 == zone_len || 3 == zone_len) {
		if (0 == strcmp("UT", str_zone) ||
			0 == strcmp("GMT", str_zone)) {
			factor = 1;
			hour = 0;
			minute = 0;
		} else if (0 == strcmp("EDT", str_zone)) {
			factor = 1;
			hour = 4;
			minute = 0;
		} else if (0 == strcmp("EST", str_zone) ||
			0 == strcmp("CDT", str_zone)) {
			factor = 1;
			hour = 5;
			minute = 0;
		} else if (0 == strcmp("CST", str_zone) ||
			0 == strcmp("MDT", str_zone)) {
			factor = 1;
			hour = 6;
			minute = 0;
		} else if (0 == strcmp("MST",  str_zone) ||
			0 == strcmp("PDT", str_zone)) {
			factor = 1;
			hour = 7;
			minute = 0;
		} else if (0 == strcmp("PST", str_zone)) {
			factor = 1;
			hour = 8;
			minute = 0;
		} else {
			return FALSE;
		}
	} else {
		return FALSE;
	}
	
	tmp_time = make_gmtime(&tmp_tm);
	tmp_time += factor*(60*60*hour + 60*minute);
	*ptime = tmp_time;
	return TRUE;
}

static BOOL encode_strings_to_utf8(const char *mime_string, char *out_string,
    size_t out_len)
{
	int i, buff_len;
	char last_charset[32];
	ENCODE_STRING encode_string;
	char temp_buff[MIME_FIELD_LEN];
	int last_pos, begin_pos, end_pos;
	size_t buff_offset, decode_len, tmp_len;
		
	buff_len = strlen(mime_string);
	auto in_buff = deconst(mime_string);
	begin_pos = -1;
	end_pos = -1;
	last_pos = 0;
	buff_offset = 0;
	last_charset[0] = '\0';
	for (i=0; i<buff_len-1; i++) {
		if (-1 == begin_pos && '=' == in_buff[i] && '?' == in_buff[i + 1]) {
			begin_pos = i;
			if (i > last_pos) {
				if (begin_pos - last_pos != -1 ||
				    in_buff[last_pos] != ' ')
					return FALSE;
				last_pos = i;
			}
		}
		if (end_pos == -1 && begin_pos != -1 && in_buff[i] == '?' &&
		    in_buff[i+1] == '=' && ((in_buff[i-1] != 'q' &&
		    in_buff[i-1] != 'Q' && in_buff[i-1] != 'b' &&
		    in_buff[i-1] != 'B') || in_buff[i-2] != '?'))
			end_pos = i + 1;
		if (-1 != begin_pos && -1 != end_pos) {
			parse_mime_encode_string(in_buff + begin_pos, 
				end_pos - begin_pos + 1, &encode_string);
			if ('\0' == last_charset[0]) {
				strcpy(last_charset, encode_string.charset);
			} else if (0 != strcasecmp(
				encode_string.charset, last_charset)) {
				return FALSE;
			}
			tmp_len = strlen(encode_string.title);
			if (0 == strcmp(encode_string.encoding, "base64")) {
				decode_len = 0;
				decode64(encode_string.title, tmp_len,
				         temp_buff + buff_offset,
				         std::size(temp_buff) - buff_offset, &decode_len);
				buff_offset += decode_len;
			} else if (0 == strcmp(encode_string.encoding,
				"quoted-printable")){
				auto xl = qp_decode_ex(temp_buff, std::size(temp_buff),
				          encode_string.title, tmp_len);
				if (xl < 0)
					return false;
				buff_offset += xl;
			} else {
				return FALSE;
			}
			last_pos = end_pos + 1;
			i = end_pos;
			begin_pos = -1;
			end_pos = -1;
			continue;
		}
	}
	if (i > last_pos)
		return FALSE;
	temp_buff[buff_offset] = '\0';
	if (!string_to_utf8(last_charset, temp_buff, out_string, out_len))
		return FALSE;	
	return utf8_valid(out_string);
}

BOOL mime_string_to_utf8(const char *charset, const char *mime_string,
    char *out_string, size_t out_len)
{
	size_t i;
	ENCODE_STRING encode_string;
	char temp_buff[MIME_FIELD_LEN];
	ssize_t begin_pos = -1, end_pos = -1;
	size_t offset, decode_len, tmp_len, last_pos = 0;
	auto buff_len = strlen(mime_string);
	auto in_buff = deconst(mime_string);
	auto out_buff = out_string;
	offset = 0;

	for (i = 0; buff_len > 0 && i < buff_len - 1 && offset < 2 * buff_len + 1; ++i) {
		if (-1 == begin_pos && '=' == in_buff[i] && '?' == in_buff[i + 1]) {
			begin_pos = i;
			if (i > last_pos) {
				memcpy(temp_buff, in_buff + last_pos, begin_pos - last_pos);
				temp_buff[begin_pos - last_pos] = '\0';
				HX_strltrim(temp_buff);
				if (!string_to_utf8(charset, temp_buff,
				    out_buff + offset, out_len - offset))
					return FALSE;
				offset += strlen(out_buff + offset);
				last_pos = i;
			}
		}
		if (end_pos == -1 && begin_pos != -1 && in_buff[i] == '?' &&
		    in_buff[i+1] == '=' && ((in_buff[i-1] != 'q' &&
		    in_buff[i-1] != 'Q' && in_buff[i-1] != 'b' &&
		    in_buff[i-1] != 'B') || in_buff[i-2] != '?'))
			end_pos = i + 1;
		if (-1 != begin_pos && -1 != end_pos) {
			parse_mime_encode_string(in_buff + begin_pos, 
				end_pos - begin_pos + 1, &encode_string);
			tmp_len = strlen(encode_string.title);
			if (0 == strcmp(encode_string.encoding, "base64")) {
				decode_len = 0;
				decode64(encode_string.title, tmp_len, temp_buff,
				         std::size(temp_buff), &decode_len);
				temp_buff[decode_len] = '\0';
				if (!string_to_utf8(encode_string.charset, temp_buff,
				    out_buff + offset, out_len - offset))
					return encode_strings_to_utf8(mime_string,
					       out_string, out_len);
			} else if (0 == strcmp(encode_string.encoding,
				"quoted-printable")){
				auto xl = qp_decode_ex(temp_buff, std::size(temp_buff),
				          encode_string.title, tmp_len, QP_MIME_HEADER);
				if (xl < 0)
					return false;
				decode_len = xl;
				temp_buff[decode_len] = '\0';
				if (!string_to_utf8(encode_string.charset, temp_buff,
				    out_buff + offset, out_len - offset))
					return encode_strings_to_utf8(mime_string,
					       out_string, out_len);
			} else {
				if (!string_to_utf8(charset, encode_string.title,
				    out_buff + offset, out_len - offset))
					return FALSE;
			}
			
			offset += strlen(out_buff + offset);
			
			last_pos = end_pos + 1;
			i = end_pos;
			begin_pos = -1;
			end_pos = -1;
			continue;
		}
	}
	if (i > last_pos || 1 == buff_len) {
		if (!string_to_utf8(charset, in_buff + last_pos,
		    out_buff + offset, out_len - offset))
			return FALSE;
		offset += strlen(out_buff + offset);
	} 
	out_buff[offset] = '\0';
	return utf8_valid(out_buff);
}

void enriched_to_html(const char *enriched_txt,
	char *html, int max_len)
{
	char *p;
	int len1;
	int offset;
	int nofill;
	int paramct, c;
	char token[62];
	
	paramct = 0;
	nofill = 0;
	auto len = strlen(enriched_txt);
	size_t i;
	for (i=0,offset=0; i<len&&offset<max_len-2; i++) {
		c = enriched_txt[i];
		if('<' == c) {
			i ++;
			if (i >= len)
				break;
			c = enriched_txt[i];
			if('<' == c) {
				if (offset + 4 >= max_len - 2)
					break;
				memcpy(html + offset, "&lt;", 4);
				offset += 4;
			} else {
				size_t j;
				for (j = 0, p = token; (c = enriched_txt[i+j]) != '\0' && c != '>'; ++j)
					if (j < sizeof(token) - 1)
						*p++ = HX_isupper(c) ? HX_tolower(c) : c;
				*p = '\0';
				if (c == '\0')
					break;
				if (0 == strcmp(token, "/param")) {
					paramct --;
					html[offset++] = '>';
					i += 6;
				} else if (paramct > 0) {
					len1 = strlen(token);
					if (offset + 8 + len1 >= max_len - 2)
						break;
					memcpy(html + offset, "&lt;", 4);
					offset += 4;
					memcpy(html + offset, token, len1);
					offset += len1;
					memcpy(html + offset, "&gt;", 4);
					offset += 4;
				} else {
					html[offset++] = '<';
					if (0 == strcmp(token, "nofill")) {
						nofill ++;
						if (offset + 3 >= max_len - 2)
							break;
						memcpy(html + offset, "pre", 3);
						offset += 3;
						i += 6;
					} else if (strcmp(token, "/nofill") == 0) {
						nofill --;
						if (offset + 4 >= max_len - 2)
							break;
						memcpy(html + offset, "/pre", 4);
						offset += 4;
						i += 7;
					} else if (strcmp(token, "bold") == 0) {
					   html[offset++] = 'b';
					   i += 4;
					} else if (strcmp(token, "/bold") == 0) {
						memcpy(html + offset, "/b", 2);
						offset += 2;
						i += 5;
					} else if(strcmp(token, "italic") == 0) {
						html[offset++] = 'i';
						i += 6;
					} else if (strcmp(token, "/italic") == 0) {
						memcpy(html + offset, "/i", 2);
						offset += 2;
						i += 7;
					} else if (strcmp(token, "fixed") == 0) {
						memcpy(html + offset, "tt", 2);
						offset += 2;
						i += 5;
					} else if (strcmp(token, "/fixed") == 0) {
						if (offset + 3 >= max_len - 2)
							break;
						memcpy(html + offset, "/tt", 3);
						offset += 3;
						i += 6;
					} else if (strcmp(token, "excerpt") == 0) {
						if (offset + 10 >= max_len - 2)
							break;
						memcpy(html + offset, "blockquote", 10);
						offset += 10;
						i += 7;
					} else if (strcmp(token, "/excerpt") == 0) {
						if (offset + 11 >= max_len - 2)
							break;
						memcpy(html + offset, "/blockquote", 11);
						offset += 11;
						i += 8;
					} else {
						len1 = strlen(token);
						if (offset + len1 >= max_len - 2)
							break;
						memcpy(html + offset, token, len1);
						offset += len1;
						i += len1;
						if(0 == strcmp(token, "param")) {
							paramct ++;
							html[offset++] = ' ';
							continue;
						}
					}
					html[offset++] = '>';
				}
			}
		} else if('>' == c) {
			if (offset + 4 >= max_len - 2)
				break;
			memcpy(html + offset, "&gt;", 4);
			offset += 4;
		} else if ('&' == c) {
			if (offset + 5 >= max_len - 2)
				break;
			memcpy(html + offset, "&amp;", 5);
			offset += 5;
		} else {
			if('\n' == c && nofill <= 0 && paramct <= 0) {
				size_t j;
				for (j=i+1; j<len; j++) {
					if ('\n' == enriched_txt[j]) {
						if (offset + 4 >= max_len - 2)
							break;
						memcpy(html + offset, "<br>", 4);
						offset += 4;
					} else {
						break;
					}
				}
				i = j - 1;
			}
			html[offset++] = c;
		}
	}
	html[offset++] = '\n';
	html[offset] = '\0';
}

static std::unique_ptr<char[]> htp_memdup(const void *src, size_t len)
{
	auto dst = std::make_unique<char[]>(len + 1);
	memcpy(dst.get(), src, len);
	dst[len] = '\0';
	return dst;
}

static int html_to_plain_boring(const void *inbuf, size_t len,
    std::string &outbuf) try
{
	enum class st { NONE, TAG, EXTRA, QUOTE, COMMENT } state = st::NONE;
	bool linebegin = true;
	char is_xml = 0, lc = 0;
	int depth = 0, in_q = 0;

	if (len == SIZE_MAX)
		--len;
	auto rbuf = htp_memdup(inbuf, len);
	auto buf = htp_memdup(inbuf, len);
	char c = buf[0];
	char *p = buf.get();
	char *rp = rbuf.get();
	for (size_t i = 0; i < len; ++i) {
		switch (c) {
		case '\0':
			break;
		case '<':
			if (in_q)
				break;
			if (HX_isspace(p[1]))
				goto REG_CHAR;
			if (state == st::NONE) {
				if (0 == strncasecmp(p, "<br>", 4) ||
					0 == strncasecmp(p, "</p>", 4)) {
					*(rp ++) = '\r';
					*(rp ++) = '\n';
					linebegin = true;
					i += 3;
					p += 3;
				} else if (0 == strncasecmp(p, "<style", 6)) {
					lc = 1;
					state = st::EXTRA;
					i += 6;
					p += 6;
				} else if (0 == strncasecmp(p, "<script", 7)) {
					lc = 2;
					state = st::EXTRA;
					i += 7;
					p += 7;
				} else {
					state = st::TAG;
				}
			} else if (state == st::TAG) {
				depth ++;
			} else if (state == st::EXTRA) {
				if (1 == lc && 0 == strncasecmp(p, "</style>", 8)) {
					state = st::NONE;
					i += 7;
					p += 7;
				} else if (2 == lc && 0 == strncasecmp(p, "</script>", 9)) {
					state = st::NONE;
					i += 8;
					p += 8;
				}
			}
			break;
		case '&':
			if (state == st::NONE) {
				if (0 == strncasecmp(p, "&quot;", 6)) {
					*(rp ++) = '"';
					i += 5;
					p += 5;
				} else if (0 == strncasecmp(p, "&amp;", 5)) {
					*(rp ++) = '&';
					i += 4;
					p += 4;
				} else if (0 == strncasecmp(p, "&lt;", 4)) {
					*(rp ++) = '<';
					i += 3;
					p += 3;
				} else if (0 == strncasecmp(p, "&gt;", 4)) {
					*(rp ++) = '>';
					i += 3;
					p += 3;
				} else if (0 == strncasecmp(p, "&nbsp;", 6)) {
					*(rp ++) = ' ';
					i += 5;
					p += 5;
				}
				linebegin = false;
			}
			break;
		case '(':
		case ')':
			if (state == st::NONE) {
				*(rp ++) = c;
				linebegin = false;
			}
			break;
		case '>':
			if (depth) {
				depth --;
				break;
			}
			if (in_q)
				break;
			switch (state) {
			case st::TAG:
				if (is_xml && p[-1] == '-')
					break;
				state = st::NONE;
				in_q = is_xml = 0;
				break;
			case st::EXTRA:
				break;
			case st::QUOTE:
				state = st::NONE;
				in_q = 0;
				break;
			case st::COMMENT:
				if (p >= buf.get() + 2 && p[-1] == '-' && p[-2] == '-') {
					state = st::NONE;
					in_q = 0;
				}
				break;
			default:
				*(rp ++) = c;
				linebegin = false;
				break;
			}
			break;
		case '"':
		case '\'':
			if (state == st::COMMENT) {
				/* Inside <!-- comment --> */
				break;
			} else if (state == st::NONE) {
				*(rp ++) = c;
				linebegin = false;
			}
			if (state != st::NONE && p != buf.get() &&
			    (state == st::TAG || p[-1] != '\\') && (!in_q || *p == in_q))
				in_q = in_q ? 0 : *p;
			break;
		case '!':
			/* JavaScript & Other HTML scripting languages */
			if (state == st::TAG && p[-1] == '<') {
				state = st::QUOTE;
				break;
			}
			if (state == st::NONE) {
				*(rp ++) = c;
				linebegin = false;
			}
			break;
		case '-':
			if (state == st::QUOTE && p >= buf.get() + 2 && p[-1] == '-' && p[-2] == '!')
				state = st::COMMENT;
			else
				goto REG_CHAR;
			break;
		case 'E':
		case 'e':
			/* !DOCTYPE exception */
			if (state == st::QUOTE && p > buf.get() + 6 &&
			    tolower(p[-6]) == 'd' && tolower(p[-5]) == 'o' &&
			    tolower(p[-4]) == 'c' && tolower(p[-3]) == 't' &&
			    tolower(p[-2]) == 'y' && tolower(p[-1]) == 'p') {
				state = st::TAG;
				break;
			}
			/* fall-through */
		default:
 REG_CHAR:
			if (state == st::NONE && (!HX_isspace(c) || !linebegin)) {
				*rp++ = c;
				linebegin = false;
			}
			break;
		}
		c = *(++ p);
	}
	if (rp < rbuf.get() + len)
		*rp = '\0';
	outbuf = rbuf.get();
	return 1;
} catch (...) {
	return -1;
}

int html_to_plain(const void *inbuf, size_t len, std::string &outbuf)
{
	auto ret = feed_w3m(inbuf, len, outbuf);
	if (ret >= 0)
		return CP_UTF8;
	ret = html_to_plain_boring(inbuf, len, outbuf);
	if (ret <= 0)
		return ret;
	return 1;
}

/*
 * Always outputs UTF-8. The caller must ensure that this is conveyed properly
 * (e.g. via PR_INTERNET_CPID=65001 [CP_UTF8]).
 */
char *plain_to_html(const char *rbuf)
{
	const char head[] =
		"<html><head><meta name=\"Generator\" content=\"gromox-texttohtml"
		"\">\r\n</head>\r\n<body>\r\n<pre>";
	const char footer[] = "</pre>\r\n</body>\r\n</html>";

	char *body = HX_strquote(rbuf, HXQUOTE_HTML, nullptr);
	if (body == nullptr)
		return nullptr;
	auto out = gromox::me_alloc<char>(strlen(head) + strlen(body) +
	           strlen(footer) + 1);
	if (out != nullptr) {
		strcpy(out, head);
		strcat(out, body);
		strcat(out, footer);
	}
	free(body);
	return out;
}
