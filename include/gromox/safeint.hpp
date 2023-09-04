#pragma once
#include <climits>
#include <cstdint>
#include <type_traits>

static inline uint32_t safe_add_u(uint64_t x, uint64_t y, int8_t *c = nullptr)
{
	bool cl1 = x > UINT64_MAX - y;
	x = cl1 ? UINT64_MAX : x + y;
	bool cl2 = x > UINT32_MAX;
	if (cl2)
		x = UINT32_MAX;
	if (c != nullptr)
		*c = cl1 || cl2;
	return x;
}

static inline uint32_t safe_add_s(uint64_t x, int64_t y, int8_t *c = nullptr)
{
	if (y >= 0)
		return safe_add_u(x, static_cast<uint64_t>(y), c);
	uint64_t yy = y == INT64_MIN ? static_cast<uint64_t>(INT64_MAX) + 1 : -y;
	int8_t clamped_low = -(x < yy);
	if (c != nullptr)
		*c = clamped_low;
	if (clamped_low)
		return 0;
	x -= yy;
	if (x <= UINT32_MAX)
		return x;
	if (c != nullptr)
		*c = 1;
	return UINT32_MAX;
}

namespace gromox {

#if __cpp_lib_integer_comparison_functions < 20202UL
template<typename A, typename B> constexpr bool cmp_less(A &&a, B &&b)
{
	if constexpr (std::is_signed_v<A> == std::is_signed_v<B>)
		return a <= b;
	else if constexpr (std::is_signed_v<A>)
		return a >= 0 && std::make_unsigned_t<A>(a) <= b;
	else
		return b >= 0 && a <= std::make_unsigned_t<B>(b);
}
template<typename A, typename B> constexpr bool cmp_less_equal(A &&a, B &&b)
{
	if constexpr (std::is_signed_v<A> == std::is_signed_v<B>)
		return a <= b;
	else if constexpr (std::is_signed_v<A>)
		return a >= 0 && std::make_unsigned_t<A>(a) <= b;
	else
		return b >= 0 && a <= std::make_unsigned_t<B>(b);
}
template<typename A, typename B> constexpr bool cmp_greater(A &&a, B &&b)
{
	if constexpr (std::is_signed_v<A> == std::is_signed_v<B>)
		return a > b;
	else if constexpr (std::is_signed_v<A>)
		return a >= 0 && std::make_unsigned_t<A>(a) > b;
	else
		return b >= 0 && a > std::make_unsigned_t<B>(b);
}
template<typename A, typename B> constexpr bool cmp_greater_equal(A &&a, B &&b)
{
	if constexpr (std::is_signed_v<A> == std::is_signed_v<B>)
		return a >= b;
	else if constexpr (std::is_signed_v<A>)
		return a >= 0 && std::make_unsigned_t<A>(a) >= b;
	else
		return b >= 0 && a >= std::make_unsigned_t<B>(b);
}
#else
using std::cmp_less;
using std::cmp_less_equal;
using std::cmp_greater;
using std::cmp_greater_equal;
#endif

}
