/*
 * A simple ip hash table data structure, which takes a string ip address as
 * the key. Remember the ip hash table is thread-unsafe!
 *
 * CAUTION!!!
 *		In multithread enviroment, we must consider mutual exclusion and 
 *		synchronized problems. 
 */
#include "common_types.h"
#include "int_hash.h"
#include "util.h"
#include <string.h>


static size_t g_num_of_collision = 0;
static size_t default_int_hash_function(int);


/*
 *	init a hash table with the specified property
 *
 *	@param	
 *		max_items	the capacity of the hash table
 *		item_size	the size of the value object
 *		fun [in]	the hash function which takes
 *					a string and generate a integer.
 *					If NULL, default hash function
 *					will be used.
 *
 *	@return		
 *		a pointer that point to the hash table object
 */
INT_HASH_TABLE* int_hash_init(size_t max_items, size_t item_size, PINT_HASH_FUNC fun)
{
	DOUBLE_LIST* p_map = NULL;
	PINT_HASH_TABLE	 table = NULL;
	size_t	i = 0;

	if (max_items <= 0 || item_size <= 0) {
		debug_info("[int_hash]: parameter is invalid");
		return NULL;
	}
	table = (PINT_HASH_TABLE)malloc(sizeof(INT_HASH_TABLE));
	if (NULL == table) {
		debug_info("[int_hash]: can not alloc hash table");
		return NULL;
	}
	table->entry_num = 8 * max_items;	/* we always allocate eight times 
										   entries of the max items 
										 */
	p_map = (DOUBLE_LIST*)malloc(sizeof(DOUBLE_LIST) * table->entry_num);
	
	if (NULL == p_map) {
		debug_info("[int_hash]: can not alloc hash map");
		free(table);
		return NULL;
	}
	memset(p_map, 0, sizeof(DOUBLE_LIST) * table->entry_num);

	double_list_init(&(table->iter_list));
	for (i = 0; i < table->entry_num; i++) {
		double_list_init(&(p_map[i]));
	}

	table->buf_pool = lib_buffer_init(sizeof(INT_HASH_ITEM) + item_size,
						max_items, FALSE);
	if (NULL == table->buf_pool) {
		debug_info("[int_hash]: int_hash_init, lib_buffer_init fail");
		free(table);
		free(p_map);
		return NULL;

	}
	if (NULL == fun) {
		table->hash_func = default_int_hash_function;
	} else {
		table->hash_func = fun;
	}
	table->hash_map		= p_map;
	table->capacity		= max_items;
	table->data_size	= item_size;
	table->item_num		= 0;
	
	return table;
}


/*
 *	release the specified hash table
 *
 *	@param	
 *		ptbl [in]	pointer to the hash table 
 */
void int_hash_free(INT_HASH_TABLE* ptbl)
{
	size_t	i = 0;

	if (NULL == ptbl) {
		return;
	}

	double_list_free(&(ptbl->iter_list));
	if (NULL != ptbl->hash_map) {
		for (i = 0; i < ptbl->entry_num; i++) {
			double_list_free(&(ptbl->hash_map[i]));
		}
		free(ptbl->hash_map);
	}

	if (NULL != ptbl->buf_pool) {
		lib_buffer_free(ptbl->buf_pool);
	}

	free(ptbl);
}


/*
 *	add the key and value into the hash table. user will not maintain
 *	the memory of value, the hash table will help you with it.
 *
 *	@param	
 *		ptbl [in]	pointer to the destination hash table
 *		key	 [in]	the key that map to the value. NOTE!, 
 *					we will ignore the second 'add' if 
 *					you add the same key into the hash 
 *					table twice.
 *		value[in]	the value that corresponding to the key
 *
 *	@return 
 *		 1	succeed
 *		-1	invalid parameter
 *		-2	the hash table is full
 *		-3	memory alloc fail
 *		-4	the key already exist	
 */
int int_hash_add(INT_HASH_TABLE* ptbl, int key, void *value)
{

	DOUBLE_LIST_NODE* next	= NULL;
	DOUBLE_LIST*	dlist	= NULL;

	void* list_node = NULL;
	INT_HASH_ITEM* item = NULL;
	size_t index = -1;
	
	if (NULL == ptbl || NULL == value) {
		debug_info("[int_hash]: int_hash_add, invalid parameter");
		return -1;
	}

	if (ptbl->item_num >= ptbl->capacity) {
		debug_info("[int_hash]: int_hash_add, the hash table is full");
		return -2;
	}
	
	list_node = lib_buffer_get(ptbl->buf_pool);

	if (NULL == list_node) {
		debug_info("[int_hash]: int_hash_add, lib_buffer_get fail");
		return -3;
	}

	index = ptbl->hash_func(key) % (ptbl->entry_num);

	item  = (INT_HASH_ITEM *)list_node;
	item->hash_key	= key;
	item->map_index = index;
	item->list_node.pdata = item;
	item->iter_node.pdata = item;

	memcpy((char*)list_node + sizeof(INT_HASH_ITEM), value, ptbl->data_size);

	dlist	= (DOUBLE_LIST*)&(ptbl->hash_map[index]);

	if (NULL == dlist->phead) {
		double_list_insert_as_head(dlist, &(item->list_node));
	} else {
		g_num_of_collision++;
		
		/* 
		 check if the key is already exist to avoid inserting
		 the same key twice.
		 */
		if (key == ((INT_HASH_ITEM*)dlist->phead->pdata)->hash_key) {
			debug_info("[int_hash]: int_hash_add, the key already exist");
			lib_buffer_put(ptbl->buf_pool, list_node);
			return -4;
		}
		next = dlist->phead->pnext;
		while (next != dlist->phead) 
		{
			if (key == ((INT_HASH_ITEM*)next->pdata)->hash_key) {
				debug_info("[int_hash]: int_hash_add, the key already exist");
				lib_buffer_put(ptbl->buf_pool, list_node);
				return -4;
			}
			next = next->pnext;
		}
		double_list_insert_as_head(dlist, &(item->list_node));
	}
	ptbl->item_num	+= 1;
	double_list_append_as_tail(&(ptbl->iter_list), &(item->iter_node));
	return 1;
}


/*
 *	query if the key is exist in the hash table and return the 
 *	corresponding value
 * 
 *	@param	
 *		ptbl [in]	pointer to the hash table
 *		key			the queried key
 *
 *	@return 
 *		the value that map the key, NULL if some error occurs
 */
void* int_hash_query(INT_HASH_TABLE* ptbl, int key)
{
	DOUBLE_LIST_NODE* next	= NULL;
	size_t	index = -1;
	void*	pdata = NULL;
	
#ifdef _DEBUG_UMTA
	if (NULL == ptbl) {
		debug_info("[int_hash]: int_hash_query, invalid param");
		return NULL;
	}
#endif
	index = ptbl->hash_func(key) % (ptbl->entry_num);

	if (NULL == ptbl->hash_map[index].phead) {
		return NULL;
	}

	next = ptbl->hash_map[index].phead;

	if (key == ((INT_HASH_ITEM*)next->pdata)->hash_key) {
		pdata = (char*)next->pdata + sizeof(INT_HASH_ITEM);
		return pdata;
	}
	next = next->pnext;

	while (next != ptbl->hash_map[index].phead) {
		if (key == ((INT_HASH_ITEM*)next->pdata)->hash_key)
		{
			pdata = (char*)next->pdata + sizeof(INT_HASH_ITEM);
			return pdata;
		}
		next = next->pnext;
	}
	return NULL;

}

/*
 *	remove the specified key form the hash table
 *	
 *	@param	
 *		ptbl [in]	pointer to the hash table
 *		key			the key that will be removed
 *
 *	@return	 
 *		 1		succeed
 *		-1		invalid parameter
 *		-2		the key does not exist
 */
int int_hash_remove(INT_HASH_TABLE* ptbl, int key)
{
	DOUBLE_LIST_NODE* next	= NULL;
	size_t index = -1;

#ifdef _DEBUG_UMTA
	if (NULL == ptbl) {
		debug_info("[int_hash]: int_hash_remove, invalid param");
		return -1;
	}
#endif
	index = ptbl->hash_func(key) % (ptbl->entry_num);
	if (NULL == ptbl->hash_map[index].phead) {
		return -2;
	}
	
	next = ptbl->hash_map[index].phead;
	if (key == ((INT_HASH_ITEM*)next->pdata)->hash_key)
		goto DONE;

	next = next->pnext;
	while (next != ptbl->hash_map[index].phead) {
		if (key == ((INT_HASH_ITEM*)next->pdata)->hash_key)
		{
			break;
		}
		next = next->pnext;
	}
	if (next == ptbl->hash_map[index].phead)
	{
		return -2;
	}

DONE:

	double_list_remove(&(ptbl->hash_map[index]), next);
	double_list_remove(&(ptbl->iter_list), 
				&(((INT_HASH_ITEM*)next->pdata)->iter_node));
	lib_buffer_put(ptbl->buf_pool, next->pdata);
	ptbl->item_num -= 1;
	return 1;
}

/*
 *	init the hash iterator of the specified hash table
 *
 *	@param	
 *		ptbl [in]	pointer to the hash table that we will iterator
 *
 *	@return		
 *		pointer to the hash iterator object, NULL if error occurs
 */
INT_HASH_ITER* int_hash_iter_init(INT_HASH_TABLE* ptbl)
{
	PINT_HASH_ITER iter = NULL;

#ifdef _DEBUG_UMTA
	if (NULL == ptbl) {
		debug_info("[int_hash]: int_hash_iter_init, invalid parameter");
		return NULL;
	}
#endif
	
	if (NULL == (iter = malloc(sizeof(INT_HASH_ITER)))) {
		debug_info("[int_hash]: can not alloc hash iter");
		return NULL;
	}
	
	iter->cur_node		= NULL;
	iter->iter_curr_pos = 0;
	iter->ptable		= ptbl;
	
	return iter;
}

/*
 *	release the specified hash iterator object
 *
 *	@param	
 *		piter [in]	pointer to the iterator that 
 *					will be released
 */
void int_hash_iter_free(INT_HASH_ITER *piter)
{
	if (NULL != piter) {
		free(piter);
	}
}


/*
 *	tell we begin to iterator the hash table
 *
 *	@param	
 *		piter [in]	pointer to the iterator, THE FOLLOWIN shows
 *		how to use the iterator
 *			
 *		[code]:
 *		for (piter=int_hash_iter_begin(piter); !int_hash_iter_done(piter)
 *			int_hash_iter_forward(piter)) {
 *			value = int_hash_iter_get_value(piter, NULL);
 *		}
 */
void int_hash_iter_begin(INT_HASH_ITER *piter)
{
	piter->cur_node = piter->ptable->iter_list.phead;
}

/*
 *	check if the iterator is finished
 *
 *	@param	
 *		piter [in]	pointer to the iterator object
 *
 *	@return 
 *		1		is finished
 *		0		not finished
 */
int int_hash_iter_done(INT_HASH_ITER *piter)
{
	return (piter->ptable->item_num <=
		piter->iter_curr_pos);
}

/*
 *	return the value of the current iterator position key can be NULL
 *	if we do not want to get the corresponding key
 *
 *	@param	
 *		piter [in]	pointer to the hash iterator object
 *		key	  [out] return the key of the current iterator position
 *
 *	@return		
 *		the value of the current iterator position, NULL if some error
 *		occurs
 */
void* int_hash_iter_get_value(INT_HASH_ITER *piter, int *key)
{
	void* pvalue   = NULL;

#ifdef _DEBUG_UMTA
	if (NULL == piter) {
		debug_info("[int_hash]: int_hash_iter_get_value, invalid param");
		return NULL;
	}
#endif
	pvalue = (char *)piter->cur_node->pdata + sizeof(INT_HASH_ITEM);
	
	if (NULL != key) {
		*key = ((INT_HASH_ITEM*)piter->cur_node->pdata)->hash_key;
	}
	return pvalue;
}


/*
 *	forward iterator by one item
 *
 *	@param	
 *		piter [in]	pointer to the hash iterator object
 *
 *	@return	 
 *		 1		succeed
 *		-1		invalid parameter
 */
int int_hash_iter_forward(INT_HASH_ITER *piter)
{
#ifdef _DEBUG_UMTA
	if (NULL == piter) {
		debug_info("[int_hash]: int_hash_iter_forward, invalid param");
		return -1;
	}
#endif
	if (NULL == piter->cur_node) {
		piter->cur_node = piter->ptable->iter_list.phead;
	} else {
		piter->cur_node = piter->cur_node->pnext;
	}
	piter->iter_curr_pos++; /* the last one may ++, too. */
	return 1;
}


/*
 *	remove the current item where the iterator at in the hash table
 *
 *	@param	
 *		piter [in]	pointer to the hash iterator object
 *
 *	@return	 
 *		 1		succeed
 *		-1		invalid parameter
 *		-2		the hash table is empty
 *		-3		the remove item does not exist
 */
int int_hash_iter_remove(INT_HASH_ITER *piter)
{
	DOUBLE_LIST* hash_map = NULL;
	DOUBLE_LIST_NODE* node= NULL;
	INT_HASH_ITEM* list_item  = NULL;

#ifdef _DEBUG_UMTA
	if (NULL == piter) {
		debug_info("[int_hash]: int_hash_iter_remove, invalid param");
		return -1;
	}
#endif
	hash_map = piter->ptable->hash_map;

	if (piter->ptable->item_num < 1) {
		debug_info("[int_hash]: the hash table is empty");
		return -2;
	}
	if (NULL == piter->cur_node) {
		debug_info("[int_hash]: the removed item does not exist");
		return -3;
	}
	node = piter->cur_node;
	if (piter->cur_node == piter->ptable->iter_list.phead ||
			piter->ptable->item_num <= 1) { 
		piter->cur_node = NULL;
	}
	else {
		piter->cur_node = piter->cur_node->pprev;
	}
	list_item = (INT_HASH_ITEM*)node->pdata;
	double_list_remove(&(hash_map[list_item->map_index]),
		&(list_item->list_node));
	double_list_remove(&(piter->ptable->iter_list), node);
	lib_buffer_put(piter->ptable->buf_pool, node->pdata);
	piter->ptable->item_num -= 1;
	piter->iter_curr_pos	-= 1;
	return 1;
	
}
/*
//////////////////////////////////////////////////////////////////
// WAINING!!!!!
// will not be used, nerver use it anyway!!!!!!!!!!!!!!!!!
//////////////////////////////////////////////////////////////////
int int_hash_iter_backward(IP_HASH_ITER *piter)
{
	if (NULL == piter) {
		debug_info("invalid param");
		return -1;
	}
	
	if (piter->ptable->item_num < 1) {
		debug_info("the hash table is empty");
		return -2;
	}
	if (piter->iter_curr_pos < 1) {
		piter->cur_node = NULL;
	} else {
		piter->cur_node = piter->cur_node->pprev;
		piter->iter_curr_pos	-= 1;
	}
	
	return 1;
}
*/


/*
 *	derived from hashpjw, Dragon Book P436
 */

static size_t default_int_hash_function(int key)
{
	key += (key << 12);
	key ^= (key >> 22);
	key += (key << 4);
	key ^= (key >> 9);
	key += (key << 10);
	key ^= (key >> 2);
	key += (key << 7);
	key ^= (key >> 12);
	return key;
}

