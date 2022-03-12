#pragma once
#include <memory>
#include <mutex>
#include <gromox/lib_buffer.hpp>
#include <gromox/mime.hpp>
#include <gromox/single_list.hpp>

struct MIME_POOL;
struct MIME_POOL_NODE {
	SINGLE_LIST_NODE	node;
	MIME				mime;
	MIME_POOL *pool;
};

struct GX_EXPORT MIME_POOL {
	MIME_POOL(size_t number, int ratio);
	~MIME_POOL();
	NOMOVE(MIME_POOL);

	static std::shared_ptr<MIME_POOL> create(size_t number, int ratio);
	MIME *get_mime();
	static void put_mime(MIME *);

	SINGLE_LIST free_list{};
	std::mutex mutex;
	std::unique_ptr<MIME_POOL_NODE[]> pbegin;
	size_t number = 0;
	std::unique_ptr<LIB_BUFFER> allocator;
};
