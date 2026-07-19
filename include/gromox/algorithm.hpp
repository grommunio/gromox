#pragma once
#include <list>
#include <utility>

namespace gromox {

/**
 * Extract a bunch of elements from a std::list satisfying a predicate,
 * and return them in a new list.
 */
template<typename T, typename Pred> std::list<T>
splice_if(std::list<T> &src, Pred &&pred)
{
	std::list<T> dst;
	for (auto it = src.begin(); it != src.end(); ) {
		if (pred(*it)) {
			auto current = it++;
			dst.splice(dst.end(), src, current);
		} else {
			++it;
		}
	}
	return dst;
}

template<typename T, typename Pred> std::list<T>
splice_if(std::list<T> &&src, Pred &&pred)
{
	return splice_if(src, std::forward(pred));
}

}
