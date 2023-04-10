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

template<typename T> class GX_EXPORT range_set : private std::vector<gromox::range_node<T>> {
	private:
	using base = std::vector<gromox::range_node<T>>;

	public:
	using base::begin;
	using base::end;
	using base::front;
	using base::back;
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
			bool nr_is_before = hi + 1 < i->lo;
			bool i_is_after   = lo > i->hi + 1;
			merge = !i_is_after && !nr_is_before;
			if (merge) {
				i->lo = i->lo < lo ? i->lo : lo;
				i->hi = i->hi > hi ? i->hi : hi;
				break;
			}
			if (nr_is_before)
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
};

}
