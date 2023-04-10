#pragma once
#ifdef COMPILE_DIAG
#	include <cassert>
#	define GX_RANGE_NODE_ASSERT assert(lo <= hi)
#else
#	define GX_RANGE_NODE_ASSERT
#endif
#include <utility>
#include <vector>

namespace gromox {

template<typename T> struct GX_EXPORT range_node {
	constexpr range_node(const T &a, const T &b)
	    noexcept(noexcept(T{a}) && noexcept(T{b})) :
		lo(a), hi(b)
	{
		GX_RANGE_NODE_ASSERT;
	}
	constexpr range_node(T &&a, T &&b)
	    noexcept(noexcept(T{std::move(a)}) && noexcept(T{std::move(b)})) :
		lo(std::move(a)), hi(std::move(b))
	{
		GX_RANGE_NODE_ASSERT;
	}
#ifdef COMPILE_DIAG
	~range_node() { GX_RANGE_NODE_ASSERT; }
#endif
	constexpr inline bool contains(const T &i) const { return lo <= i && i <= hi; }
	T lo, hi;
};
#undef GX_RANGE_NODE_ASSERT

}
