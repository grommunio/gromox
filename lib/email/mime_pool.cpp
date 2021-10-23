// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <memory>
#include <mutex>
#include <libHX/defs.h>
#include <gromox/util.hpp>
#include <gromox/mime_pool.hpp>

/*
 *	@param
 *		number			number of mimes
 *		ratio			proportion between mem file blocks and mime
 *						usually 4~256
 *	@return
 *		mime pool object
 */
MIME_POOL::MIME_POOL(size_t number, int ratio) :
	pbegin(std::make_unique<MIME_POOL_NODE[]>(number))
{
	auto pmime_pool = this;

	if (ratio < 4) {
		ratio = 4;
	} else if (ratio > 256) {
		ratio = 256;
	}
	pmime_pool->allocator = lib_buffer_init(FILE_ALLOC_SIZE, number * ratio, TRUE);
	if (NULL == pmime_pool->allocator) {
		throw std::bad_alloc();
	}
	single_list_init(&pmime_pool->free_list);
	for (size_t i = 0; i < number; ++i) {
		auto ptemp_mime = &pmime_pool->pbegin[i];
		ptemp_mime->node.pdata = ptemp_mime;
		ptemp_mime->pool = pmime_pool;
		mime_init(&ptemp_mime->mime, pmime_pool->allocator);
		single_list_append_as_tail(&pmime_pool->free_list, &ptemp_mime->node);
	}
	pmime_pool->number = number;
}

MIME_POOL::~MIME_POOL()
{
	auto pmime_pool = this;
	if (pmime_pool->number != single_list_get_nodes_num(&pmime_pool->free_list)) {
		debug_info("[mime_pool]: there's still some mimes unfree");
	}
	pmime_pool->number = 0;
	if (NULL != pmime_pool->pbegin) {
		for (size_t i = 0; i < pmime_pool->number; ++i)
			mime_free(&pmime_pool->pbegin[i].mime);
	}
	if (NULL != pmime_pool->allocator) {
		lib_buffer_free(pmime_pool->allocator);
	}
}

std::shared_ptr<MIME_POOL> MIME_POOL::create(size_t number, int ratio) try
{
	return std::make_unique<MIME_POOL>(number, ratio);
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1546: ENOMEM\n");
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
	auto pnode = single_list_pop_front(&free_list);
	if (NULL != pnode) {
		return &static_cast<MIME_POOL_NODE *>(pnode->pdata)->mime;
	}
	return NULL;
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
	single_list_append_as_tail(&pmime_pool->free_list, &pmime_node->node);
}
