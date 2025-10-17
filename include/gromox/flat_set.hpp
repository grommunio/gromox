#pragma once
#if __cplusplus >= 202300L
#include <flat_set>
namespace gromox {
template<typename T> using maybe_flat_set = std::flat_set<T>;
}
#else
#	include <set>
namespace gromox {
template<typename T> using maybe_flat_set = std::set<T>;
}
#endif
