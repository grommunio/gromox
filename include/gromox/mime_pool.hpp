#pragma once
#include "single_list.h"
#include "lib_buffer.h"
#include <gromox/mime.hpp>
#include <pthread.h>

typedef struct _MIME_POOL_NODE {
	SINGLE_LIST_NODE	node;
	MIME				mime;
	void*				pool;
} MIME_POOL_NODE;

typedef struct _MIME_POOL{
	SINGLE_LIST		free_list;
	BOOL			thread_safe;
	pthread_mutex_t mutex;
	MIME_POOL_NODE	*pbegin;
	size_t			number;
	LIB_BUFFER		*allocator;
} MIME_POOL;

#ifdef __cplusplus
extern "C" {
#endif

MIME_POOL* mime_pool_init(size_t number, int ratio, BOOL thread_safe);

void mime_pool_free(MIME_POOL *pmime_pool);

MIME* mime_pool_get(MIME_POOL *pmime_pool);

void mime_pool_put(MIME *pmime);

#ifdef __cplusplus
}
#endif
