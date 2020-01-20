#pragma once
#include "assoc_array.h"

#define COOKIE_PARSER			ASSOC_ARRAY

#ifdef __cplusplus
extern "C" {
#endif


COOKIE_PARSER* cookie_parser_init(const char *cookie_string);

const char* cookie_parser_get(COOKIE_PARSER *pparser, const char *name);

size_t cookie_parser_num(COOKIE_PARSER *pparser);

void cookie_parser_free(COOKIE_PARSER *pparser);


#ifdef __cplusplus
}
#endif
