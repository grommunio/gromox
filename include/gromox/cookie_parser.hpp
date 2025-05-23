#pragma once
#include <map>
#include <string>
#include <gromox/defs.h>

namespace gromox {

struct GX_EXPORT cookie_jar : public std::map<std::string, std::string, std::less<>> {
	ec_error_t add(std::string_view);
	const char *operator[](const char *name) const;
};

}
