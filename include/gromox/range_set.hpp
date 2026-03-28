#pragma once
#ifdef COMPILE_DIAG
#	include <cassert>
#	define GX_RANGE_NODE_ASSERT assert(lo <= hi)
#else
#	define GX_RANGE_NODE_ASSERT
#endif
#include <algorithm>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>
#include <gromox/defs.h>

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
	constexpr inline size_t nelem() const { return hi - lo + 1; }
#endif
	constexpr inline bool contains(const T &i) const { return lo <= i && i <= hi; }
	T lo, hi;
};
#undef GX_RANGE_NODE_ASSERT

template<typename T> class GX_EXPORT range_set : private std::vector<gromox::range_node<T>> {
	private:
	using base = std::vector<gromox::range_node<T>>;

	public:
	using base::begin;
	using base::end;
	using base::cbegin;
	using base::cend;
	using base::front;
	using base::back;
	using base::empty;
	using base::size;
	using base::clear;
	using base::erase;

	/*
	 * Using the vector directly can void the invariant that the range_set
	 * is properly ordered. You've been warned.
	 */
	base &vec() { return *this; }

	void insert(T lo) { insert(lo, lo); }
	void insert(T lo, T hi) {
		if (lo > hi)
			return; /* Caller should swap on its own if so needed */
		/*
		 * The algorithm is left-merging: Adding the new range will
		 * occur such that the m_vec[0..i] is always invariant at every
		 * iteration.
		 *
		 * If nr={lo,hi} fills a gap between i->hi and
		 * (j=std::next(i))->lo precisely, then nr gets merged to i,
		 * and then we just deal with merging j into i afterwards.
		 */
		bool merge = false;
		auto i = begin();
		for (; i != end(); ++i) {
			bool left_gap  = hi < i->lo && i->lo - hi > 1;
			bool right_gap = lo > i->hi && lo - i->hi > 1;
			merge = !left_gap && !right_gap;
			if (merge) {
				i->lo = i->lo < lo ? i->lo : lo;
				i->hi = i->hi > hi ? i->hi : hi;
				break;
			}
			if (left_gap)
				break;
		}
		if (!merge) {
			/* newrange is non-adjacent non-overlapping. */
			base::emplace(i, lo, hi);
			return;
		}
		/*
		 * When a merge to @i happened, new adjacencies/overlaps could
		 * have formed. Because of the property that no left
		 * adjacencies could have been introduced (see above), we only
		 * need to check to the right of @i (in other words, @j), and
		 * also only on the high side.
		 */
		for (auto j = std::next(i); j != end(); j = base::erase(j)) {
			auto x = j->hi > i->hi && j->lo <= i->hi + 1;
			if (!x)
				break;
			i->hi = j->hi;
		}
	}

	void erase(T v)
	{
		for (auto i = begin(); i != end(); ++i) {
			if (v == i->lo && v == i->hi) {
				erase(i);
				return;
			} else if (v == i->lo) {
				++i->lo;
				return;
			} else if (v == i->hi) {
				--i->hi;
				return;
			} else if (v > i->lo && v < i->hi) {
				auto lo = i->lo;
				i->lo = v + 1;
				base::emplace(i, lo, v - 1);
				return;
			}
		}
	}

	bool contains(T v) const
	{
		auto i = std::lower_bound(cbegin(), cend(), v,
		         [&](const gromox::range_node<T> &rn, T vv) { return rn.hi < vv; });
		return i != cend() ? i->contains(v) : false;
	}

	/**
	 * Find next unused number e.
	 * @def: first valid regular number
	 * @ill: magic value for indicating "invalid/unused"
	 *
	 * There are two modes of operation.
	 *
	 * 1. e.g. for file descriptors where @ill < @def.
	 *
	 *      range_set<int> v; v.alloc_next_unused(0, -1);
	 *
	 *    Returns the next unused number e such that @def <= @e <= T_max.
	 *    Returns @ill when no free number is found.
	 *
	 * 2. for something like zcore handles where @ill >= @def.
	 *
	 *      range_set<uint32_t> v; v.alloc_next_unused(0, UINT32_MAX);
	 *
	 *    Returns the next unused number e such that @def <= @e < ill.
	 *    Returns @ill when no free number is found.
	 *
	 * Prerequisite: The set must not contain any number less than @def.
	 *
	 * If you cannot spare a value of T as the magic value, you have to use
	 * a T with a larger range, e.g. use range_set<uint32_t> if you want to
	 * hand out all 64K numbers from {0..UINT16_MAX}.
	 */
	T alloc_next_unused(T def, T ill)
	{
		if (empty()) {
			base::emplace(begin(), def, def);
			return def;
		} else if (def < front().lo) {
			insert(def);
			return def;
		}
		T n = front().hi;
		if (ill < def) {
			/* fd scenario */
			if (n >= std::numeric_limits<T>::max())
				return ill;
		} else {
			/* zcore handle scenario */
			if (n >= ill)
				return ill;
		}
		++n;
		insert(n);
		return n;
	}

#ifdef COMPILE_DIAG
	constexpr inline size_t nelem() const {
		size_t x = 0;
		for (const auto &i : *this)
			x += i.nelem();
		return x;
	}
#endif
};

using imap_seq_list = range_set<uint32_t>;

extern GX_EXPORT errno_t parse_imap_seq(imap_seq_list &out, const char *in);

}
