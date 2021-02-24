#pragma once
#include <map>
#include <string>
using cookie_jar = std::map<std::string, std::string, std::less<>>;
namespace gromox {
extern cookie_jar cookie_parser_init(const char *cookie_string);
extern const char *cookie_parser_get(const cookie_jar &jar, const char *name);
}
