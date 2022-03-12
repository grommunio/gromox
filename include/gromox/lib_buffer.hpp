#pragma once
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <type_traits>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#define FILE_BLOCK_SIZE 0x100
#define FILE_ALLOC_SIZE (FILE_BLOCK_SIZE + sizeof(DOUBLE_LIST_NODE))
#define WSIZE           sizeof(void*)  /* word size (bytes) */

struct GX_EXPORT LIB_BUFFER {
	LIB_BUFFER(size_t size, size_t items, BOOL thr_safe);
	~LIB_BUFFER();
	NOMOVE(LIB_BUFFER);
	static std::unique_ptr<LIB_BUFFER> create(size_t item_size, size_t item_num, BOOL is_thread_safe);
	void *get_raw();
	template<typename T> inline T *get()
	{
		static_assert(std::is_trivially_constructible_v<T>);
		return static_cast<T *>(get_raw());
	}
	template<typename T> inline T *get_unconstructed() {
		static_assert(!std::is_trivially_constructible_v<T>);
		return static_cast<T *>(get_raw());
	}
	void put_raw(void *);
	template<typename T> inline void put(T *i)
	{
		static_assert(std::is_trivially_destructible_v<T>);
		put_raw(i);
	}
	inline void lib_buffer_put(void *i) { put_raw(i); }
	template<typename T> inline void destroy_and_put(T *i)
	{
		static_assert(!std::is_trivially_destructible_v<T>);
		i->~T();
		put_raw(i);
	}

	void *heap_list_head = nullptr, *free_list_head = nullptr, *cur_heap_head = nullptr;
	size_t free_list_size = 0, allocated_num = 0, item_size = 0, item_num = 0;
	BOOL is_thread_safe = false;
	std::mutex m_mutex;
};
