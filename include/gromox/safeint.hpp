#pragma once
#include <climits>
#include <cstdint>

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
