#pragma once
#include <string_view>
#include <json/value.h>
#include <gromox/defs.h>
namespace gromox {
extern GX_EXPORT bool json_from_str(std::string_view, Json::Value &);
extern GX_EXPORT std::string json_to_str(const Json::Value &);
extern GX_EXPORT bool get_digest(const Json::Value &src, const char *tag, char *out, size_t outmax);
}
