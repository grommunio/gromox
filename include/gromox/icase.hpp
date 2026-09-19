#pragma once
#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <libHX/ctype_helper.h>

namespace gromox {

struct GX_EXPORT icasehash {
	STATIC_IN_CXX23 inline size_t operator()(std::string s) CONST_BEFORE_CXX23 {
		std::transform(s.begin(), s.end(), s.begin(), HX_toupper);
		return std::hash<std::string>{}(std::move(s));
	}
};

struct GX_EXPORT icasecmp {
	STATIC_IN_CXX23 inline bool operator()(const std::string &a,
	    const std::string &b) CONST_BEFORE_CXX23
	{
		return strcasecmp(a.c_str(), b.c_str()) == 0;
	}
};

}
