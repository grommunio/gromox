#ifndef _H_ARRAY_
#define _H_ARRAY_
#include "lib_buffer.h"
#include "single_list.h"

#define ARRAY_CACHEITEM_NUMBER  200000

typedef struct _ARRAY {
	LIB_BUFFER* mbuf_pool;
	SINGLE_LIST mlist;
	size_t data_size;
	size_t cur_size;
	void **cache_ptrs;
} ARRAY;

#ifdef __cplusplus
extern "C" {
#endif

void array_init(ARRAY* parray, LIB_BUFFER* pbuf_pool, size_t data_size);

void array_free(ARRAY* parray);

LIB_BUFFER* array_allocator_init(size_t data_size,
	size_t max_size, BOOL thread_safe);

void array_allocator_free(LIB_BUFFER* buf);

long array_append(ARRAY* parray, void* pdata);

void* array_get_item(ARRAY* parray, size_t index);

size_t array_get_capacity(ARRAY* parray);

void array_clear(ARRAY* parray);

#ifdef __cplusplus
}
#endif

#endif /*_H_ARRAY_ */

