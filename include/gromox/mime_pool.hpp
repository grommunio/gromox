#pragma once
#include <list>
#include <memory>
#include <mutex>
#include <gromox/mime.hpp>
#include <gromox/single_list.hpp>
#include <gromox/util.hpp>

struct MIME_POOL;
struct MIME_POOL_NODE {
	MIME_POOL_NODE(LIB_BUFFER *b, MIME_POOL *p) : mime(b), pool(p) {}

	MIME mime;
	MIME_POOL *pool = nullptr;
};

/*
 * This should be modeled as resource_pool<MIME> instead. Current blocker is
 * that SIMPLE_TREE is not ready to manage non-trivial types as returned by
 * resource_pool<T>::get().
 */
struct GX_EXPORT MIME_POOL {
	MIME_POOL(size_t number, int ratio);

	static std::shared_ptr<MIME_POOL> create(size_t number, int ratio);
	MIME *get_mime();
	static void put_mime(MIME *);

	LIB_BUFFER allocator;
	std::list<MIME_POOL_NODE> pbegin;
	std::list<MIME_POOL_NODE *> free_list; /* references pbegin nodes */
	std::mutex mutex;
};
