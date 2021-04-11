// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/xarray.hpp>
#include <gromox/util.hpp>
#include <cstring>

/* the extra memory ocupation for xarray node */
#define EXTRA_XARRAYNODE_SIZE		 sizeof(XARRAY_UNIT)


/*
 *	init a xarray with the specified size of data and max capacity.
 *
 *	@param
 *		pxarray		[in]	the xarray that will be init
 *		pbuf_pool	[in]	the outside allocator that manage the 
 *							memory core
 *		data_size			the data elements size
 */
void xarray_init(XARRAY *pxarray, LIB_BUFFER *pbuf_pool, size_t data_size)
{
#ifdef _DEBUG_UMTA
	if (NULL == pxarray || NULL == pbuf_pool) {
		debug_info("[xarray]: NULL pointer found in xarray_init");
		return;
	}
#endif
	memset(pxarray, 0, sizeof(XARRAY));
	double_list_init(&pxarray->mlist);
	
	pxarray->mbuf_pool	 = pbuf_pool;
	pxarray->cur_size	 = 0;
	pxarray->data_size	 = data_size;
   
	if (data_size > lib_buffer_get_param(pbuf_pool, 
		MEM_ITEM_SIZE) - EXTRA_XARRAYNODE_SIZE) {
		debug_info("[xarray]: xarray_init warning: xarray data"
			" size larger than allocator item size");
	}
}

/*
 *	free the specified xarray
 *
 *	@param
 *		pxarray [in]	 the xarray object to free
 */

void xarray_free(XARRAY* pxarray)
{
#ifdef _DEBUG_UMTA
	if (NULL == pxarray) {
		debug_info("[xarray]: NULL pointer found in xarray_free");
		return;
	}
#endif
	xarray_clear(pxarray);
	double_list_free(&pxarray->mlist);
}


/*
 *	init a memory allocator with the specified requirement for the xarray
 *
 *	@param	
 *		data_size		the xarray data size
 *		max_size		the capacity of the xarray
 *		thread_safe		is the allocator thread safe?
 *
 *	@return
 *		the allocator pointer, NULL if fail
 */
LIB_BUFFER *xarray_allocator_init(size_t data_size, size_t max_size,
    bool thread_safe)
{
	return lib_buffer_init(data_size + EXTRA_XARRAYNODE_SIZE, 
	       max_size, thread_safe ? TRUE : false);
}


/*
 *	free the specified xarray allocator
 *
 *	@param	
 *		buf [in]	the specified allocator
 */
void xarray_allocator_free(LIB_BUFFER* buf)
{
	if (NULL == buf) {
		return;
	}

	lib_buffer_free(buf);
}
/*
 *	append the data into the specified xarray
 *
 *	@param
 *		pxarray [in]	the xarray that will 
 *						push the data onto
 *		pdata  [in]		pointer to the data
 *						that will be push on
 *		xtag			should be larger than 0
 *	@return
 *		<0				fail to append
 *		>=0				index of the item
 */
int xarray_append(XARRAY* pxarray, void* pdata, unsigned int xtag)
{
	int ret_index;
	XARRAY_UNIT *punit;

#ifdef _DEBUG_UMTA
	if (NULL == pxarray || NULL == pdata) {	   
		debug_info("[xarray]: NULL pointer found in xarray_append");
	}
#endif

	if (0 == xtag || NULL != xarray_get_itemx(pxarray, xtag)) {
		return -1;
	}

	punit = (XARRAY_UNIT*)lib_buffer_get(pxarray->mbuf_pool);
	if (NULL == punit) {
		return -1;
	}
	punit->node.pdata = punit;
	punit->node_hash.pdata = punit;
	punit->xtag =  xtag;
	void *pdata1 = reinterpret_cast<char *>(punit) + sizeof(XARRAY_UNIT);
	memcpy(pdata1, pdata, pxarray->data_size);

	double_list_append_as_tail(&pxarray->mlist, &punit->node);
	ret_index = pxarray->cur_size;
	pxarray->cur_size ++;
	/* cache the ptr in cache table */
	if (ret_index < XARRAY_CACHEITEM_NUMBER) {
		pxarray->cache_ptrs[ret_index] = pdata1;
	}
	punit->index = ret_index;

	double_list_append_as_tail(&pxarray->hash_lists[xtag%XARRAY_HASHITEM_NUMBER],
		&punit->node_hash);
	return ret_index;
}

/*
 *	get item from the specified xarray
 *	
 *	@param	
 *		pxarray [in]	 the specified xarray object
 *
 *	@return
 *		pointer to the item data
 */
void *xarray_get_item(XARRAY* pxarray, size_t index)
{
#ifdef _DEBUG_UMTA
	if (NULL == pxarray) {
		debug_info("[xarray]: NULL pointer found in xarray_get_item");
	}
#endif
	if (NULL == pxarray) {
		return NULL;
	}
	if (index + 1 > pxarray->cur_size || index < 0) {
		return NULL;
	}

	if (index < XARRAY_CACHEITEM_NUMBER) {
		return pxarray->cache_ptrs[index];
	}
	auto punit = reinterpret_cast<XARRAY_UNIT *>(static_cast<char *>(pxarray->cache_ptrs[XARRAY_CACHEITEM_NUMBER-1]) - sizeof(XARRAY_UNIT));
	auto pnode = &punit->node;
	for (size_t i = XARRAY_CACHEITEM_NUMBER; i <= index; ++i)
		pnode = double_list_get_after(&pxarray->mlist, pnode);
	return static_cast<char *>(pnode->pdata) + sizeof(XARRAY_UNIT);
}

/*
 *	get item from the specified xarray by xtag
 *	
 *	@param	
 *		pxarray [in]	 the specified xarray object
 *
 *	@return
 *		pointer to the item data
 */
void* xarray_get_itemx(XARRAY* pxarray, unsigned int xtag)
{
	DOUBLE_LIST_NODE   *pnode;
	XARRAY_UNIT *punit;
	DOUBLE_LIST		   *plist;
	
#ifdef _DEBUG_UMTA
	if (NULL == pxarray) {
		debug_info("[xarray]: NULL pointer found in xarray_get_itemx");
	}
#endif
	if (NULL == pxarray) {
		return NULL;
	}

	plist = &pxarray->hash_lists[xtag%XARRAY_HASHITEM_NUMBER];
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		punit = (XARRAY_UNIT*)pnode->pdata;
		if (xtag == punit->xtag) {
			return static_cast<char *>(pnode->pdata) + sizeof(XARRAY_UNIT);
		}
	}

	return NULL;

}

/*
 *	get items of xarray
 *
 *	@param	
 *		pxarray [in]	 the xarray object
 *
 *	@return
 *		number of items
 */
size_t xarray_get_capacity(XARRAY* pxarray)
{
#ifdef _DEBUG_UMTA
	if (NULL == pxarray) {
		debug_info("[xarray]: NULL pointer found in xarray_get_capacity");
		return 0;
	}
#endif
	return pxarray->cur_size;
}

/*
 *	clear the items in the xarray and free 
 *	the memory it allocates
 *
 *	@param
 *		pxarray [in]	 the cleared xarray
 */

void xarray_clear(XARRAY* pxarray)
{
	DOUBLE_LIST_NODE *pnode;
#ifdef _DEBUG_UMTA
	if (NULL == pxarray) {
		debug_info("[xarray]: NULL pointer found in xarray_clear");
	}
#endif
	while ((pnode = double_list_pop_front(&pxarray->mlist)) != nullptr)
		lib_buffer_put(pxarray->mbuf_pool, pnode->pdata);
	pxarray->cur_size = 0;
	memset(pxarray->cache_ptrs, 0, sizeof(pxarray->cache_ptrs));
	memset(pxarray->hash_lists, 0, sizeof(pxarray->hash_lists));
}

