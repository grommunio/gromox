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

/*
 * std::ranges::contains is only available in C++23.
 * std::ranges also needs stdlib containers, but we still have
 * some legacy structs like EID_ARRAY that have only a minimal
 * iterator interface.
 */

template<typename T> decltype(auto) ct_find(auto &&cont, T &&val)
{
	return std::find(cont.begin(), cont.end(), std::forward<T>(val));
}

template<typename F> decltype(auto) ct_find_if(auto &&cont, F &&pred)
{
	return std::find_if(cont.begin(), cont.end(), std::forward<F>(pred));
}

template<typename T> bool ct_contains(auto &&cont, T &&val)
{
	return std::find(cont.begin(), cont.end(), std::forward<T>(val)) != cont.end();
}

/**
 * Determine the index of a value in a sequenced container, or, if not found,
 * one past the last.
 */
template<typename T> size_t ct_index(auto &&cont, T &&val)
{
	return std::distance(cont.begin(), std::find(cont.begin(),
	       cont.end(), std::forward<T>(val)));
}

template<typename F> size_t ct_index_if(auto &&cont, F &&pred)
{
	return std::distance(cont.begin(), std::find_if(cont.begin(),
	       cont.end(), std::forward<F>(pred)));
}

/**
 * Extract a bunch of elements from a std::list satisfying a predicate,
 * and return them in a new list.
 */
template<typename T> std::list<T> splice_if(std::list<T> &src, auto &&pred)
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

template<typename T> std::list<T> splice_if(std::list<T> &&src, auto &&pred)
{
	return splice_if(src, std::forward(pred));
}

}
