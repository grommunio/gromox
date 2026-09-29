#pragma once
namespace gromox {
/* For use with unordered_map, to enable heterogenous lookup */
struct string_hash {
	using is_transparent = void;
	[[nodiscard]] STATIC_IN_CXX23 size_t operator()(const char *txt) CONST_BEFORE_CXX23
	{
		return std::hash<std::string_view>{}(txt);
	}
	[[nodiscard]] STATIC_IN_CXX23 size_t operator()(std::string_view txt) CONST_BEFORE_CXX23
	{
		return std::hash<std::string_view>{}(txt);
	}
	[[nodiscard]] STATIC_IN_CXX23 size_t operator()(const std::string &txt) CONST_BEFORE_CXX23
	{
		return std::hash<std::string>{}(txt);
	}
};
}
