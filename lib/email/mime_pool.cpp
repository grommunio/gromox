// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
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
MIME_POOL::MIME_POOL(size_t number, int ratio, BOOL ts) :
	thread_safe(ts), pbegin(std::make_unique<MIME_POOL_NODE[]>(number))
{
	auto pmime_pool = this;
	size_t i;
	MIME_POOL_NODE *ptemp_mime;

	if (ratio < 4) {
		ratio = 4;
	} else if (ratio > 256) {
		ratio = 256;
	}
	pmime_pool->allocator = lib_buffer_init(FILE_ALLOC_SIZE,
							number*ratio, thread_safe);
	if (NULL == pmime_pool->allocator) {
		throw std::bad_alloc();
	}
	single_list_init(&pmime_pool->free_list);
	for (i=0; i<number; i++) {
		ptemp_mime = &pmime_pool->pbegin[i];
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
	size_t i;
	MIME_POOL_NODE *pmime_node;

	if (pmime_pool->number != single_list_get_nodes_num(&pmime_pool->free_list)) {
		debug_info("[mime_pool]: there's still some mimes unfree");
	}
	pmime_pool->number = 0;
	if (NULL != pmime_pool->pbegin) {
		for (i=0; i<pmime_pool->number; i++) {
			pmime_node = &pmime_pool->pbegin[i];
			mime_free(&pmime_node->mime);
		}
	}
	if (NULL != pmime_pool->allocator) {
		lib_buffer_free(pmime_pool->allocator);
	}
}

std::shared_ptr<MIME_POOL>
MIME_POOL::create(size_t number, int ratio, BOOL thread_safe) try
{
	return std::make_unique<MIME_POOL>(number, ratio, thread_safe);
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
	auto pmime_pool = this;
	SINGLE_LIST_NODE *pnode;
	if (TRUE == pmime_pool->thread_safe) {
		pmime_pool->mutex.lock();
	}
	pnode = single_list_pop_front(&pmime_pool->free_list);
	if (TRUE == pmime_pool->thread_safe) {
		pmime_pool->mutex.unlock();
	}
	if (NULL != pnode) {
		return &((MIME_POOL_NODE*)(pnode->pdata))->mime;
	}
	return NULL;
}

/*
 *	release one mime object back into mime pool
 */
void MIME_POOL::put_mime(MIME *pmime)
{
	MIME_POOL *pmime_pool;

#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime_pool]: NULL pointer in mime_pool_put");
		return;
	}
#endif
	auto pmime_node = containerof(pmime, MIME_POOL_NODE, mime);
	pmime_pool = (MIME_POOL*)pmime_node->pool;
#ifdef _DEBUG_UMTA
	if (NULL == pmime_pool) {
		debug_info("[mime_pool]: fatal error in mime_pool_put");
		return;
	}
#endif
	if (TRUE == pmime_pool->thread_safe) {
		pmime_pool->mutex.lock();
    }
    single_list_append_as_tail(&pmime_pool->free_list, &pmime_node->node);
    if (TRUE == pmime_pool->thread_safe) {
		pmime_pool->mutex.unlock();
    }
    return;
}

