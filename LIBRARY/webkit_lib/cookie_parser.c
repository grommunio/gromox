// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include "cookie_parser.h"
#include <stdio.h>

static void cookie_parser_unencode(const char *src, char *dest);

COOKIE_PARSER* cookie_parser_init(const char *cookie_string)
{
	int len;
	char *ptr;
	char *ptr1;
	char *ptoken;
	char *pparam;
	char *last_ptr;
	ASSOC_ARRAY *parray;
	char *decoded_string;
	
	parray = assoc_array_init(sizeof(char*));
	if (NULL == parray) {
		return NULL;
	}
	len = strlen(cookie_string);
	decoded_string = (char*)malloc(len + 2);
	if (NULL == decoded_string) {
		assoc_array_free(parray);
		return NULL;
	}
	cookie_parser_unencode(cookie_string, decoded_string);
	len = strlen(decoded_string);
	if (len > 0 && '\n' == decoded_string[len - 1]) {
		len --;
		decoded_string[len] = '\0';
	}
	
	if (len > 0) {
		decoded_string[len] = ';';
		len ++;
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
				*ptoken = '\0';
				ptoken ++;
				pparam = strdup(ptoken);
				if (NULL != pparam) {
					while (' ' == *last_ptr && '\0' != *last_ptr) {
						last_ptr ++;
					}
					if ('\0' != *last_ptr) {
						assoc_array_assign(parray, last_ptr, &pparam);
					}
				}
			}
			last_ptr = ptr + 1;
		}
		ptr ++;
	}
	
	free(decoded_string);
	return parray;
}

const char* cookie_parser_get(COOKIE_PARSER *pparser, const char *name)
{
	char **ppvalue;
	
	ppvalue = (char**)assoc_array_get_by_key(pparser, name);
	if (NULL == ppvalue) {
		return NULL;
	}
	
	return *ppvalue;
}

size_t cookie_parser_num(COOKIE_PARSER *pparser)
{
	if (NULL == pparser) {
		return 0;
	}
	
	return assoc_array_get_elements_num(pparser);
}

static void cookie_parser_enum(const char *key, char **ppvalue)
{
	free(*ppvalue);
}

void cookie_parser_free(COOKIE_PARSER *pparser)
{
	assoc_array_foreach(pparser, (ASSOC_ARRAY_ENUM)cookie_parser_enum);
	assoc_array_free(pparser);
}

static void cookie_parser_unencode(const char *src, char *dest)
{
	int code;
	const char *last;
	
	last = src + strlen(src);
	for (; src != last; src++, dest++) {
		if (*src == '+') {
			*dest = ' ';
		} else if (*src == '%') {
			if (sscanf(src+1, "%2x", &code) != 1) {
				code = '?';
			}
			*dest = code;
			src +=2;
		} else {
			*dest = *src;
		}
	}
	*dest = '\0';
}
