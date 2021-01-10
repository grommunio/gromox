#pragma once
#include <map>
#include <string>
#include <gromox/defs.h>

using cookie_jar = std::map<std::string, std::string, std::less<>>;

extern GX_EXPORT cookie_jar cookie_parser_init(const char *cookie_string);
extern GX_EXPORT const char *cookie_parser_get(const cookie_jar &, const char *name);
