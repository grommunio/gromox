/*
 *	A simple vstack implements using single linked list. The core will be 
 *	maintain outside the vstack, but the vstack will give black a node size
 *	memory every time you call pop, unless the vstack is empty.
 *
 */

#include "vstack.h"
#include "util.h"

/* the extra memory ocupation for vstack node */
#define EXTRA_VSTACKNODE_SIZE		 sizeof(SINGLE_LIST_NODE)


/*
 *	init a vstack with the specified size of data and max capacity.
 *
 *	@param
 *		pvstack		[in]	the vstack that will be init
 *		pbuf_pool	[in]	the outside allocator that manage the 
 *							memory core
 *		data_size			the data elements size
 *		max_size			the max capacity of this vstack
 */
void vstack_init(VSTACK* pvstack, LIB_BUFFER* pbuf_pool, size_t data_size,
	size_t max_size)
{
#ifdef _DEBUG_UMTA
	if (NULL == pvstack || NULL == pbuf_pool) {
		debug_info("[vstack]: vstack_init, param NULL");
		return;
	}
#endif
	single_list_init(&(pvstack->mlist));
	
	pvstack->mbuf_pool	 = pbuf_pool;
	pvstack->cur_size	 = 0;

	pvstack->data_size	 = data_size;
	pvstack->max_size	 = max_size;
	if (data_size > lib_buffer_get_param(pbuf_pool, 
		MEM_ITEM_SIZE) - EXTRA_VSTACKNODE_SIZE) {
		debug_info("[vstack]: vstack_init, warning!!!! vstack data"
			" size larger than allocator item size");
	}
	if (max_size > lib_buffer_get_param(pbuf_pool,
			MEM_ITEM_NUM)) {
		debug_info("[vstack]: vstack_init, warning!!!! vstack max "
			"capacity larger than allocator capacity");
	}
							
}

/*
 *	free the specified vstack
 *
 *	@param
 *		pvstack [in]	 the vstack object to free
 */

void vstack_free(VSTACK* pvstack)
{
#ifdef _DEBUG_UMTA
	if (NULL == pvstack) {
		debug_info("[vstack]: vstack_free, param NULL");
		return;
	}
#endif
	vstack_clear(pvstack);
	single_list_free(&pvstack->mlist);
}


/*
 *	init a memory allocator with the specified requirement for the vstack
 *
 *	@param	
 *		data_size		the vstack data size
 *		max_size		the capacity of the vstack
 *		thread_safe		is the allocator thread safe?
 *
 *	@return
 *		the allocator pointer, NULL if fail
 */
LIB_BUFFER* vstack_allocator_init(size_t data_size, size_t max_size, BOOL thread_safe)
{
	return lib_buffer_init(data_size + EXTRA_VSTACKNODE_SIZE, 
					max_size, thread_safe);
}


/*
 *	free the specified vstack allocator
 *
 *	@param	
 *		buf [in]	the specified allocator
 */
void vstack_allocator_free(LIB_BUFFER* buf)
{
#ifdef _DEBUG_UMTA
	if (NULL == buf) {
		debug_info("[vstack]: vstack_allocator_free, param NULL");
		return;
	}
#endif
	lib_buffer_free(buf);
}
/*
 *	push the data into the specified vstack
 *
 *	@param
 *		pvstack [in]	the vstack that will 
 *						push the data onto
 *		pdata  [in]		pointer to the data
 *						that will be push on
 *	@return
 *		TRUE		success
 *		FALSE		the vstack is full
 */
BOOL vstack_push(VSTACK* pvstack, void* pdata)
{
	SINGLE_LIST_NODE   *node = NULL;

#ifdef _DEBUG_UMTA
	if (NULL == pvstack || NULL == pdata) {
		debug_info("[vstack]: vstack_push, param NULL");
		return FALSE;
	}
#endif
	if (pvstack->cur_size >= pvstack->max_size) {
		return FALSE;
	}
	node = lib_buffer_get(pvstack->mbuf_pool);
	node->pdata = (char*)node + sizeof(SINGLE_LIST_NODE);
	memcpy(node->pdata, pdata, pvstack->data_size);

	single_list_insert_as_head(&pvstack->mlist, node);
	pvstack->cur_size += 1;
	return TRUE;
}

/*
 *	pop the top item from the specified vstack, and give
 *	back the data size of memory to the outside allocator
 *	
 *	@param	
 *		pvstack [in]	 the specified vstack object
 *
 *	@return
 *		TRUE		success
 *		FALSE		if the pvstack is NULL or the 
 *					vstack is empty
 */
BOOL vstack_pop(VSTACK* pvstack)
{
	SINGLE_LIST_NODE   *node = NULL;
	
#ifdef _DEBUG_UMTA
	if (NULL == pvstack) {
		debug_info("[vstack]: vstack_pop, param NULL");
		return FALSE;
	}
#endif
	if (pvstack->cur_size <= 0) {
		return FALSE;
	}
	node = single_list_get_from_head(&pvstack->mlist);
	lib_buffer_put(pvstack->mbuf_pool, node);
	pvstack->cur_size -= 1;
	return TRUE;
}

/*
 *	return a pointer that point to the data at the top 
 *	of the specified vstack.
 *
 *	@param
 *		pvstack [in]	 the vstack to get the data from
 *
 *	@return
 *		the pointer that pointer to the data at the top
 *		of the vstack
 *		NULL if the pvstack is NULL or the vstack is empty
 */
void* vstack_get_top(VSTACK* pvstack)
{
	SINGLE_LIST_NODE   *node = NULL;

#ifdef _DEBUG_UMTA
	if (NULL == pvstack) {
		debug_info("[vstack]: vstack_get_top, param NULL");
		return NULL;
	}
#endif
	if (pvstack->cur_size <= 0) {
		return NULL;
	}
	node = single_list_get_head(&pvstack->mlist);
	return node->pdata;
}

/*
 *	test if the specified vstack is empty
 *
 *	@param	
 *		pvstack [in]	 the tested vstack
 *
 *	@return
 *		TRUE		if the vstack is empty
 *		FALSE		otherwise
 */
BOOL vstack_is_empty(VSTACK* pvstack)
{
#ifdef _DEBUG_UMTA
	if (NULL == pvstack) {
		debug_info("[vstack]: vstack_is_empty, param NULL");
		return FALSE;
	}
#endif
	if (pvstack->cur_size == 0) {
		return TRUE;
	}
	return FALSE;
}

/*
 *	clear the items in the vstack and free 
 *	the memory it allocates
 *
 *	@param
 *		pvstack [in]	 the cleared vstack
 */

void vstack_clear(VSTACK* pvstack)
{
#ifdef _DEBUG_UMTA
	if (NULL == pvstack) {
		debug_info("[vstack]: vstack_clear, param NULL");
		return;
	}
#endif
	while (!vstack_is_empty(pvstack)) {
		vstack_pop(pvstack);
	}
	return;
}


