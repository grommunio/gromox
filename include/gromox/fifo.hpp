#pragma once
#include <gromox/lib_buffer.hpp>
#include <gromox/single_list.hpp>
#define EXTRA_FIFOITEM_SIZE sizeof(SINGLE_LIST)

struct GX_EXPORT FIFO {
	FIFO() = default;
	FIFO(LIB_BUFFER *, size_t data_size, size_t max_size);
	BOOL enqueue(void *);
	void *get_front();
	void dequeue();

	LIB_BUFFER *mbuf_pool = nullptr;
	SINGLE_LIST mlist{};
	size_t data_size = 0, cur_size = 0, max_size = 0;
};

LIB_BUFFER* fifo_allocator_init(size_t data_size, size_t max_size, BOOL thread_safe);
void fifo_allocator_free(LIB_BUFFER* pallocator);
