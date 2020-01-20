#pragma once
#include "lib_buffer.h"
#include "double_list.h"

#define XARRAY_CACHEITEM_NUMBER  (16*1024)
#define XARRAY_HASHITEM_NUMBER   (4*1024)

typedef struct _XARRAY_UNIT {
	DOUBLE_LIST_NODE    node;
	DOUBLE_LIST_NODE    node_hash;
	int                 index;
	unsigned int        xtag;
} XARRAY_UNIT;

typedef struct _XARRAY {
    LIB_BUFFER*  mbuf_pool;
    DOUBLE_LIST  mlist;
    size_t       data_size;
    size_t       cur_size;
    void*        cache_ptrs[XARRAY_CACHEITEM_NUMBER];
	DOUBLE_LIST  hash_lists[XARRAY_HASHITEM_NUMBER];
} XARRAY;

#ifdef __cplusplus
extern "C" {
#endif

void xarray_init(XARRAY* pxarray, LIB_BUFFER* pbuf_pool, int data_size);

void xarray_free(XARRAY* pxarray);

LIB_BUFFER* xarray_allocator_init(int data_size, int max_size, BOOL thread_safe);

void xarray_allocator_free(LIB_BUFFER* buf);

int xarray_append(XARRAY* pxarray, void* pdata, unsigned int xtag);

void* xarray_get_item(XARRAY* pxarray, int index);

unsigned int xarray_get_xtag(XARRAY* pxarray, int index);

void* xarray_get_itemx(XARRAY* pxarray, unsigned int xtag);

int xarray_get_index(XARRAY* pxarray, unsigned int xtag);

void xarray_remove_item(XARRAY *pxarray, int index);

void xarray_remove_itemx(XARRAY *pxarray, unsigned int xtag);

int xarray_get_capacity(XARRAY* pxarray);

void xarray_clear(XARRAY* pxarray);

#ifdef __cplusplus
}
#endif
