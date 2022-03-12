// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstring>
#include <gromox/util.hpp>
#include <gromox/xarray.hpp>

/*
 *	init a xarray with the specified size of data and max capacity.
 *
 *	@param
 *		pxarray		[in]	the xarray that will be init
 *		pbuf_pool	[in]	the outside allocator that manage the 
 *							memory core
 *		data_size			the data elements size
 */
XARRAY::XARRAY(LIB_BUFFER *pbuf_pool, size_t dsize)
{
	auto pxarray = this;
#ifdef _DEBUG_UMTA
	if (pbuf_pool == nullptr) {
		debug_info("[xarray]: NULL pointer found in xarray_init");
		return;
	}
#endif
	double_list_init(&pxarray->mlist);
	pxarray->mbuf_pool	 = pbuf_pool;
	pxarray->data_size = dsize;
	if (dsize > pbuf_pool->item_size - EXTRA_XARRAYNODE_SIZE)
		debug_info("[xarray]: xarray_init warning: xarray data"
			" size larger than allocator item size");
}

XARRAY::~XARRAY()
{
	auto pxarray = this;
	pxarray->clear();
	double_list_free(&pxarray->mlist);
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
int XARRAY::append(void *pdata, unsigned int xtag)
{
	auto pxarray = this;
	int ret_index;
#ifdef _DEBUG_UMTA
	if (pdata == nullptr)
		debug_info("[xarray]: NULL pointer found in XARRAY::append");
#endif
	if (xtag == 0 || get_itemx(xtag))
		return -1;
	auto punit = pxarray->mbuf_pool->get<XARRAY_UNIT>();
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
void *XARRAY::get_item(size_t index)
{
	auto pxarray = this;
	if (index + 1 > pxarray->cur_size)
		return NULL;
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
void *XARRAY::get_itemx(unsigned int xtag)
{
	auto pxarray = this;
	DOUBLE_LIST_NODE   *pnode;
	XARRAY_UNIT *punit;
	DOUBLE_LIST		   *plist;
	
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
 *	clear the items in the xarray and free 
 *	the memory it allocates
 *
 *	@param
 *		pxarray [in]	 the cleared xarray
 */
void XARRAY::clear()
{
	auto pxarray = this;
	DOUBLE_LIST_NODE *pnode;
	while ((pnode = double_list_pop_front(&pxarray->mlist)) != nullptr)
		pxarray->mbuf_pool->put_raw(pnode->pdata);
	pxarray->cur_size = 0;
	memset(pxarray->cache_ptrs, 0, sizeof(pxarray->cache_ptrs));
	memset(pxarray->hash_lists, 0, sizeof(pxarray->hash_lists));
}

