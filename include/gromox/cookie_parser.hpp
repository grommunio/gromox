#pragma once
#include <gromox/assoc_array.hpp>
#define COOKIE_PARSER			ASSOC_ARRAY

COOKIE_PARSER* cookie_parser_init(const char *cookie_string);

const char* cookie_parser_get(COOKIE_PARSER *pparser, const char *name);
void cookie_parser_free(COOKIE_PARSER *pparser);
