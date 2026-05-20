#pragma once

namespace ZZNDR_NS {

/*
 * You need to have either proc_common.h or svc_common.h included previously.
 * This is also why this file has a zz_ prefix so it sorts in include lists.
 */
template<typename T> T *ndr_stack_anew(unsigned int dir)
{
	static_assert(std::is_trivially_copyable_v<T> && std::is_trivially_destructible_v<T>);
	auto t = static_cast<T *>(ndr_stack_alloc(dir, sizeof(T)));
	if (t != nullptr)
		new(t) T;
	return t;
}

template<typename T> T *ndr_stack_anew(unsigned int dir, size_t elem)
{
	static_assert(std::is_trivially_copyable_v<T> && std::is_trivially_destructible_v<T>);
	auto t = static_cast<T *>(ndr_stack_alloc(dir, sizeof(T) * elem));
	if (t == nullptr)
		return nullptr;
	for (size_t i = 0; i < elem; ++i)
		new(&t[i]) T;
	return t;
}

}
