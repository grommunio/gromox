#pragma once
#if __cplusplus >= 202000L
#include <version>
#ifdef __cpp_lib_flat_set
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
#endif
