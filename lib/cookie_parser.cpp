// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <gromox/cookie_parser.hpp>

namespace gromox {

static void cookie_parser_unencode(const char *src, char *dest)
{
	int code;
	const char *last;
	
	last = src + strlen(src);
	for (; src != last; src++, dest++) {
		if (*src == '+') {
			*dest = ' ';
		} else if (*src == '%') {
			if (sscanf(src+1, "%2x", &code) != 1)
				code = '?';
			*dest = code;
			src +=2;
		} else {
			*dest = *src;
		}
	}
	*dest = '\0';
}

cookie_jar cookie_parser_init(const char *cookie_string)
{
	int len;
	char *ptr;
	char *ptr1;
	char *ptoken;
	char *last_ptr;
	cookie_jar jar;
	char *decoded_string;
	
	len = strlen(cookie_string);
	decoded_string = (char*)malloc(len + 2);
	if (decoded_string == nullptr)
		return jar;
	cookie_parser_unencode(cookie_string, decoded_string);
	len = strlen(decoded_string);
	if (len > 0 && '\n' == decoded_string[len - 1]) {
		len --;
		decoded_string[len] = '\0';
	}
	
	if (len > 0) {
		decoded_string[len++] = ';';
		decoded_string[len] = '\0';
	}
	
	ptr = decoded_string;
	last_ptr = decoded_string;
	
	while ('\0' != *ptr) {
		if (';' == *ptr) {
			/* check if the ';' is only a character of the value */
			ptr1 = strchr(ptr + 1, ';');
			if (NULL != ptr1 && NULL == memchr(
				ptr + 1, '=', ptr1 - ptr - 1)) {
				ptr ++;
				continue;
			}
			*ptr = '\0';
			ptoken = strchr(last_ptr, '=');
			if (NULL != ptoken) {
				*ptoken++ = '\0';
				try {
					std::string pparam = ptoken;
					while (*last_ptr == ' ' && *last_ptr != '\0')
						last_ptr ++;
					if (*last_ptr != '\0')
						jar.emplace(last_ptr, std::move(pparam));
				} catch (...) {
				}
			}
			last_ptr = ptr + 1;
		}
		ptr ++;
	}
	
	free(decoded_string);
	return jar;
}

const char *cookie_parser_get(const cookie_jar &jar, const char *name)
{
	auto i = jar.find(name);
	return i != jar.cend() ? i->second.c_str() : nullptr;
}

}
