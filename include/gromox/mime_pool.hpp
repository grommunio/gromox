#pragma once
#include <memory>
#include <mutex>
#include <gromox/single_list.hpp>
#include <gromox/lib_buffer.hpp>
#include <gromox/mime.hpp>

struct MIME_POOL_NODE {
	SINGLE_LIST_NODE	node;
	MIME				mime;
	void*				pool;
};

struct GX_EXPORT MIME_POOL {
	MIME_POOL(MIME_POOL &&) = delete;
	MIME_POOL(size_t number, int ratio, BOOL thr_safe);
	~MIME_POOL();
	void operator=(MIME_POOL &&) = delete;

	SINGLE_LIST free_list{};
	BOOL thread_safe = false;
	std::mutex mutex;
	std::unique_ptr<MIME_POOL_NODE[]> pbegin;
	size_t number;
	LIB_BUFFER *allocator = nullptr;
};

extern GX_EXPORT std::unique_ptr<MIME_POOL> mime_pool_init(size_t number, int ratio, BOOL thread_safe);
MIME* mime_pool_get(MIME_POOL *pmime_pool);
void mime_pool_put(MIME *pmime);
