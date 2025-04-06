#pragma once
#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <libHX/ctype_helper.h>

namespace gromox {

struct GX_EXPORT icasehash {
	inline size_t operator()(std::string s) const {
		std::transform(s.begin(), s.end(), s.begin(), HX_toupper);
		return std::hash<std::string>{}(std::move(s));
	}
};

struct GX_EXPORT icasecmp {
	inline bool operator()(const std::string &a, const std::string &b) const {
		return strcasecmp(a.c_str(), b.c_str()) == 0;
	}
};

}
