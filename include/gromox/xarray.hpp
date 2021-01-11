#pragma once
#include <gromox/lib_buffer.hpp>
#include <gromox/double_list.hpp>
#define XARRAY_CACHEITEM_NUMBER  (16*1024)
#define XARRAY_HASHITEM_NUMBER   (4*1024)

struct XARRAY_UNIT {
	DOUBLE_LIST_NODE    node;
	DOUBLE_LIST_NODE    node_hash;
	int                 index;
	unsigned int        xtag;
};

struct XARRAY {
    LIB_BUFFER*  mbuf_pool;
    DOUBLE_LIST  mlist;
    size_t       data_size;
    size_t       cur_size;
    void*        cache_ptrs[XARRAY_CACHEITEM_NUMBER];
	DOUBLE_LIST  hash_lists[XARRAY_HASHITEM_NUMBER];
};

void xarray_init(XARRAY* pxarray, LIB_BUFFER* pbuf_pool, int data_size);

void xarray_free(XARRAY* pxarray);
extern GX_EXPORT LIB_BUFFER *xarray_allocator_init(int data_size, int max_size, bool thread_safe);
void xarray_allocator_free(LIB_BUFFER* buf);

int xarray_append(XARRAY* pxarray, void* pdata, unsigned int xtag);

void* xarray_get_item(XARRAY* pxarray, int index);
void* xarray_get_itemx(XARRAY* pxarray, unsigned int xtag);
int xarray_get_capacity(XARRAY* pxarray);

void xarray_clear(XARRAY* pxarray);
