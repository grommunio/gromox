// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <memory>
#include <mutex>
#include <libHX/defs.h>
#include <gromox/mime_pool.hpp>
#include <gromox/util.hpp>

using namespace gromox;

/*
 *	@param
 *		number			number of mimes
 *		ratio			proportion between mem file blocks and mime
 *						usually 4~256
 *	@return
 *		mime pool object
 */
MIME_POOL::MIME_POOL(size_t num, int ratio, const char *name, const char *hint) :
	allocator(name)
{
	auto pmime_pool = this;

	if (ratio < 4) {
		ratio = 4;
	} else if (ratio > 256) {
		ratio = 256;
	}
	pmime_pool->allocator = alloc_limiter<file_block>(num * ratio, name, hint);
	for (size_t i = 0; i < num; ++i) {
		pbegin.emplace_back(&pmime_pool->allocator, this);
		free_list.push_back(&pbegin.back());
	}
}

std::shared_ptr<MIME_POOL> MIME_POOL::create(size_t number, int ratio,
    const char *name, const char *hint) try
{
	return std::make_unique<MIME_POOL>(number, ratio, name, hint);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1546: ENOMEM");
	return nullptr;
}

/*
 *	get a mime from mime pool
 *	@param
 *		pmime_pool [in]				indicate the mime pool object
 *	@return
 *		mime object pointer
 */
MIME *MIME_POOL::get_mime()
{
	std::lock_guard lk(mutex);
	if (free_list.size() == 0)
		return nullptr;
	auto ptr = free_list.front();
	free_list.pop_front();
	return &ptr->mime;
}

/*
 *	release one mime object back into mime pool
 */
void MIME_POOL::put_mime(MIME *pmime)
{
#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime_pool]: NULL pointer in mime_pool_put");
		return;
	}
#endif
	auto pmime_node = containerof(pmime, MIME_POOL_NODE, mime);
	auto pmime_pool = pmime_node->pool;
#ifdef _DEBUG_UMTA
	if (NULL == pmime_pool) {
		debug_info("[mime_pool]: fatal error in mime_pool_put");
		return;
	}
#endif
	std::lock_guard lk(pmime_pool->mutex);
	pmime_pool->free_list.push_back(pmime_node);
}
