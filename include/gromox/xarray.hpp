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

/* the extra memory ocupation for xarray node */
#define EXTRA_XARRAYNODE_SIZE sizeof(XARRAY_UNIT)

struct XARRAY {
    LIB_BUFFER*  mbuf_pool;
    DOUBLE_LIST  mlist;
    size_t       data_size;
    size_t       cur_size;
    void*        cache_ptrs[XARRAY_CACHEITEM_NUMBER];
	DOUBLE_LIST  hash_lists[XARRAY_HASHITEM_NUMBER];
};

extern GX_EXPORT void xarray_init(XARRAY *, LIB_BUFFER *pool, size_t data_size);
void xarray_free(XARRAY* pxarray);
int xarray_append(XARRAY* pxarray, void* pdata, unsigned int xtag);
extern GX_EXPORT void *xarray_get_item(XARRAY* pxarray, size_t index);
void* xarray_get_itemx(XARRAY* pxarray, unsigned int xtag);
extern size_t xarray_get_capacity(XARRAY *);
void xarray_clear(XARRAY* pxarray);
