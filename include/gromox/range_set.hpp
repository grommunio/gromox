#pragma once
#ifdef COMPILE_DIAG
#	include <cassert>
#	define GX_RANGE_NODE_ASSERT assert(low_value <= high_value)
#else
#	define GX_RANGE_NODE_ASSERT
#endif
#include <utility>
#include <vector>

namespace gromox {

template<typename T> struct GX_EXPORT range_node {
	constexpr range_node(const T &a, const T &b)
	    noexcept(noexcept(T{a}) && noexcept(T{b})) :
		low_value(a), high_value(b)
	{
		GX_RANGE_NODE_ASSERT;
	}
	constexpr range_node(T &&a, T &&b)
	    noexcept(noexcept(T{std::move(a)}) && noexcept(T{std::move(b)})) :
		low_value(std::move(a)), high_value(std::move(b))
	{
		GX_RANGE_NODE_ASSERT;
	}
#ifdef COMPILE_DIAG
	~range_node() { GX_RANGE_NODE_ASSERT; }
#endif
	constexpr inline bool contains(const T &i) const { return low_value <= i && i <= high_value; }
	T low_value, high_value;
};
#undef GX_RANGE_NODE_ASSERT

}
