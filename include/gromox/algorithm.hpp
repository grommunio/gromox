#pragma once
#include <algorithm>
#include <list>
#include <utility>

namespace gromox {

void erase_first(auto &&cont, auto &&value)
{
	for (auto iter = cont.begin(); iter != cont.end(); ++iter) {
		if (*iter == value) {
			cont.erase(iter);
			return;
		}
	}
}

void erase_first_if(auto &&cont, auto &&pred)
{
	for (auto iter = cont.begin(); iter != cont.end(); ++iter) {
		if (pred(*iter)) {
			cont.erase(iter);
			return;
		}
	}
}

void pop_front(auto &&cont)
{
	cont.erase(cont.begin());
}

decltype(auto) pop_front_v(auto &&cont)
{
	auto v = std::move(cont.front());
	pop_front(cont);
	return v;
}

void sort_unique(auto &&cont)
{
	std::sort(cont.begin(), cont.end());
	cont.erase(std::unique(cont.begin(), cont.end()), cont.end());
}

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
