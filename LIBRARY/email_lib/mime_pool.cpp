// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/util.hpp>
#include <gromox/mime_pool.hpp>

/*
 *	mime pool's construct function
 *	@param
 *		number			number of mimes
 *		ratio			proportion between mem file blocks and mime
 *						usually 4~256
 *	@return
 *		mime pool object
 */
MIME_POOL* mime_pool_init(size_t number, int ratio, BOOL thread_safe)
{
	size_t i;
	MIME_POOL_NODE *ptemp_mime;

	auto pmime_pool = static_cast<MIME_POOL *>(malloc(sizeof(MIME_POOL)));
	if (NULL == pmime_pool) {
		debug_info("[mime_pool]: Failed to allocate MIME pool memory");
		return NULL;
	}
	pmime_pool->pbegin = static_cast<MIME_POOL_NODE *>(malloc(sizeof(MIME_POOL_NODE) * number));
	if (NULL == pmime_pool->pbegin) {
		debug_info("[mime_pool]: Failed to allocate MIME list");
		free(pmime_pool->pbegin);
		free(pmime_pool);
		return NULL;
	}
	if (ratio < 4) {
		ratio = 4;
	} else if (ratio > 256) {
		ratio = 256;
	}
	pmime_pool->allocator = lib_buffer_init(FILE_ALLOC_SIZE,
							number*ratio, thread_safe);
	if (NULL == pmime_pool->allocator) {
		debug_info("[mime_pool]: Failed to init file allocator");
		free(pmime_pool->pbegin);
		free(pmime_pool);
		return NULL;
	}
	single_list_init(&pmime_pool->free_list);
	for (i=0; i<number; i++) {
		ptemp_mime = pmime_pool->pbegin + i;
		ptemp_mime->node.pdata = ptemp_mime;
		ptemp_mime->pool = pmime_pool;
		mime_init(&ptemp_mime->mime, pmime_pool->allocator);
		single_list_append_as_tail(&pmime_pool->free_list, &ptemp_mime->node);
	}
	if (TRUE == thread_safe) {
		pthread_mutex_init(&pmime_pool->mutex, NULL);
	}
	pmime_pool->thread_safe = thread_safe;
	pmime_pool->number = number;
	return pmime_pool;
}

/*
 *	mime pool's destruct function
 *	@param
 *		pmime_pool [in]			indicate mime pool object to be freed
 */
void mime_pool_free(MIME_POOL *pmime_pool)
{
	size_t i;
	MIME_POOL_NODE *pmime_node;

#ifdef _DEBUG_UMTA
	if (NULL == pmime_pool) {
		debug_info("[mime_pool]: NULL pointer in mime_pool_free");
		return;
	}
#endif

	if (pmime_pool->number != single_list_get_nodes_num(&pmime_pool->free_list)) {
		debug_info("[mime_pool]: there's still some mimes unfree");
	}
	single_list_free(&pmime_pool->free_list);
	if (TRUE == pmime_pool->thread_safe) {
    	pthread_mutex_destroy(&pmime_pool->mutex);
    }
	pmime_pool->number = 0;
	if (NULL != pmime_pool->pbegin) {
		for (i=0; i<pmime_pool->number; i++) {
			pmime_node = pmime_pool->pbegin + i;
			mime_free(&pmime_node->mime);
		}
		free(pmime_pool->pbegin);
		pmime_pool->pbegin = NULL;
	}
	if (NULL != pmime_pool->allocator) {
		lib_buffer_free(pmime_pool->allocator);
		pmime_pool->allocator = NULL;
	}
    free(pmime_pool);
}

/*
 *	get a mime from mime pool
 *	@param
 *		pmime_pool [in]				indicate the mime pool object
 *	@return
 *		mime object pointer
 */
MIME* mime_pool_get(MIME_POOL *pmime_pool)
{
	SINGLE_LIST_NODE *pnode;

#ifdef _DEBUG_UMTA
	if (NULL == pmime_pool) {
		debug_info("[mime_pool]: NULL pointer in mime_pool_get");
		return NULL;
	}
#endif

	if (TRUE == pmime_pool->thread_safe) {
		pthread_mutex_lock(&pmime_pool->mutex);
	}
	pnode = single_list_get_from_head(&pmime_pool->free_list);
	if (TRUE == pmime_pool->thread_safe) {
		pthread_mutex_unlock(&pmime_pool->mutex);
	}
	if (NULL != pnode) {
		return &((MIME_POOL_NODE*)(pnode->pdata))->mime;
	}
	return NULL;
}

/*
 *	release one mime object back into mime pool
 *	@param
 *		pmime [in]				indicate the mime object 
 */
void mime_pool_put(MIME *pmime)
{
	MIME_POOL_NODE *pmime_node;
	MIME_POOL *pmime_pool;

#ifdef _DEBUG_UMTA
	if (NULL == pmime) {
		debug_info("[mime_pool]: NULL pointer in mime_pool_put");
		return;
	}
#endif

	pmime_node = (MIME_POOL_NODE*)((char*)pmime - 
					(long)(&((MIME_POOL_NODE*)0)->mime));
	pmime_pool = (MIME_POOL*)pmime_node->pool;
#ifdef _DEBUG_UMTA
	if (NULL == pmime_pool) {
		debug_info("[mime_pool]: fatal error in mime_pool_put");
		return;
	}
#endif
	if (TRUE == pmime_pool->thread_safe) {
        pthread_mutex_lock(&pmime_pool->mutex);
    }
    single_list_append_as_tail(&pmime_pool->free_list, &pmime_node->node);
    if (TRUE == pmime_pool->thread_safe) {
        pthread_mutex_unlock(&pmime_pool->mutex);
    }
    return;
}

