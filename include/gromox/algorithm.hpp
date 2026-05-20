#pragma once
#include <algorithm>
#include <utility>

namespace gromox {

template<typename C, typename T> bool contains(const C &c, T &&v)
{
	return std::find(c.cbegin(), c.cend(), std::forward<T>(v)) != c.cend();
}

}
