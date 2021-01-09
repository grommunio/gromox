// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 * A simple string hash table data structure
 */
#include "common_types.h"
#include "str_hash.h"
#include "util.h"
#include <cstring>

static size_t g_num_of_collision;

static size_t DJBHash(const char* str)
{
	size_t hash = 5381;
	size_t i	= 0;
	size_t len	= strlen(str);
	
	for(i = 0; i < len; str++, i++) {
		hash = ((hash << 5) + hash) + (*str);
	}
	return (hash & 0x7FFFFFFF);
}

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
STR_HASH_TABLE* str_hash_init(size_t max_items, size_t item_size, PSTR_HASH_FUNC fun)
{
	DOUBLE_LIST* p_map = NULL;
	PSTR_HASH_TABLE	 table = NULL;
	size_t	i = 0;

	if (max_items <= 0 || item_size <= 0) {
		debug_info("[str_hash]: str_hash_init, parameter is invalid");
		return NULL;
	}
	table = (PSTR_HASH_TABLE)malloc(sizeof(STR_HASH_TABLE));
	if (NULL == table) {
		debug_info("[str_hash]: can not alloc hash table");
		return NULL;
	}
	table->entry_num = 8 * max_items;	/* we always allocate eight times 
										   entries of the max items */
	p_map = (DOUBLE_LIST*)malloc(sizeof(DOUBLE_LIST) * table->entry_num);
	
	if (NULL == p_map) {
		debug_info("[str_hash]: can not alloc hash map");
		free(table);
		return NULL;
	}
	memset(p_map, 0, sizeof(DOUBLE_LIST) * table->entry_num);

	double_list_init(&(table->iter_list));
	for (i = 0; i < table->entry_num; i++) {
		double_list_init(&(p_map[i]));
	}

	table->buf_pool = lib_buffer_init(sizeof(STR_HASH_ITEM) + item_size, 
						max_items, FALSE);
	if (NULL == table->buf_pool) {
		debug_info("[str_hash]: str_hash_init, lib_buffer_init fail");
		free(table);
		free(p_map);
		return NULL;

	}
	if (NULL == fun) {
		table->hash_func = DJBHash;
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
void str_hash_free(STR_HASH_TABLE* ptbl)
{
	size_t	i = 0;

#ifdef _DEBUG_UMTA
	if (NULL == ptbl) {
		debug_info("[str_hash]: str_hash_free, param NULL");
		return;
	}
#endif
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
int str_hash_add(STR_HASH_TABLE *ptbl, const char *key, const void *value)
{
	DOUBLE_LIST_NODE* next	= NULL;
	DOUBLE_LIST*	dlist	= NULL;
	
	STR_HASH_ITEM* item = NULL;
	void* list_node = NULL;
	size_t index = -1;
	
#ifdef _DEBUG_UMTA 
	if (NULL == ptbl || NULL == key || NULL == value) {
		debug_info("[str_hash]: str_hash_add, param NULL");
		return -1;
	}
#endif
	if (ptbl->item_num >= ptbl->capacity) {
		return -2;
	}
	
	list_node = lib_buffer_get(ptbl->buf_pool);

	if (NULL == list_node) {
		debug_info("[str_hash]: str_hash_add, lib_buffer_get fail");
		return -3;
	}

	index = ptbl->hash_func(key) % (ptbl->entry_num);

	item  = (STR_HASH_ITEM *)list_node;

	item->map_index = index;
	item->list_node.pdata	= item;
	item->iter_node.pdata	= item;
	strncpy(item->key, key, MAX_KEY_LENGTH);

	memcpy((char*)list_node + sizeof(STR_HASH_ITEM), value, ptbl->data_size);

	dlist	= (DOUBLE_LIST*)&(ptbl->hash_map[index]);

	if (NULL == dlist->phead) {
		double_list_insert_as_head(dlist, &(item->list_node));
	} else {
		g_num_of_collision++;
		
		/* 
		 check if the key is already exist to avoid inserting
		 the same key twice.
		 */
		if (0 == strcmp(((STR_HASH_ITEM*)dlist->phead->pdata)->key, key)) {
			lib_buffer_put(ptbl->buf_pool, list_node);
			return -4;
		}
		
		next = dlist->phead->pnext;
		while (next != dlist->phead) {
			if (0 == strcmp(((STR_HASH_ITEM*)next->pdata)->key, key)) {
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
 *		key	 [in]	the queried key
 *
 *	@return 
 *		the value that map the key, NULL if some error occurs
 */
void* str_hash_query(STR_HASH_TABLE* ptbl, const char *key)
{
	DOUBLE_LIST_NODE* next	= NULL;
	size_t	index = -1;
	void*	pdata = NULL;
	
#ifdef _DEBUG_UMTA
	if (NULL == ptbl || NULL == key) {
		debug_info("[str_hash]: str_hash_query, param NULL");
		return NULL;
	}
#endif

	index = ptbl->hash_func(key) % (ptbl->entry_num);

	if (NULL == ptbl->hash_map[index].phead) {
		return NULL;
	}

	next = ptbl->hash_map[index].phead;

	if (0 == strcmp(key, ((STR_HASH_ITEM*)next->pdata)->key)) {
		pdata = (char*)next->pdata + sizeof(STR_HASH_ITEM);
		return pdata;
	}
	next = next->pnext;

	while (next != ptbl->hash_map[index].phead) {
		if (0 == strcmp(key, ((STR_HASH_ITEM*)next->pdata)->key)) {
			pdata = (char*)next->pdata + sizeof(STR_HASH_ITEM);
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
 *		key	 [in]	the key that will be removed
 *
 *	@return	 
 *		 1		succeed
 *		-1		invalid parameter
 *		-2		the key does not exist
 */
int str_hash_remove(STR_HASH_TABLE* ptbl, const char *key)
{
	DOUBLE_LIST_NODE* next	= NULL;
	size_t index = -1;
	
#ifdef _DEBUG_UMTA
	if (NULL == ptbl || NULL == key) {
		debug_info("[str_hash]: str_hash_remove, param NULL");
		return -1;
	}
#endif
	index = ptbl->hash_func(key) % (ptbl->entry_num);
	if (NULL == ptbl->hash_map[index].phead) {
		return -2;
	}
	
	next = ptbl->hash_map[index].phead;
	if (0 == strcmp(key, ((STR_HASH_ITEM*)next->pdata)->key))
		goto DONE;

	next = next->pnext;
	while (next != ptbl->hash_map[index].phead) {
		if (0 == strcmp(key, ((STR_HASH_ITEM*)next->pdata)->key)) {
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
				&(((STR_HASH_ITEM*)next->pdata)->iter_node));
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
STR_HASH_ITER* str_hash_iter_init(STR_HASH_TABLE* ptbl)
{
	PSTR_HASH_ITER iter = NULL;

#ifdef _DEBUG_UMTA
	if (NULL == ptbl) {
		debug_info("[str_hash]: str_hash_iter_init, param NULL");
		return NULL;
	}
#endif
	iter = static_cast<STR_HASH_ITER *>(malloc(sizeof(STR_HASH_ITER)));
	if (iter == nullptr) {
		debug_info("[str_hash]: can not alloc hash iter");
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
void str_hash_iter_free(STR_HASH_ITER *piter)
{
#ifdef _DEBUG_UMTA
	if (NULL == piter) {
		debug_info("[str_hash]: str_hash_iter_free, param NULL");
		return;
	}
#endif
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
 *		for (ip_hash_iter_begin(piter); !ip_hash_iter_done(piter)
 *			ip_hash_iter_forward(piter)) {
 *			value = ip_hash_iter_get_value(piter, NULL);
 *		}
 */
void str_hash_iter_begin(STR_HASH_ITER *piter)
{
#ifdef _DEBUG_UMTA
	if (NULL == piter) {	
		debug_info("[str_hash]: str_hash_iter_begin, param NULL");
		return;
	}
#endif
	piter->cur_node = 
		piter->ptable->iter_list.phead;
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
int str_hash_iter_done(STR_HASH_ITER *piter)
{
#ifdef _DEBUG_UMTA
	if (NULL == piter) {	
		debug_info("[str_hash]: str_hash_iter_done, param NULL");
		return 0;
	}
#endif
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
void* str_hash_iter_get_value(STR_HASH_ITER *piter, char *key)
{
	char*	pkey	 = NULL;
	void*	pvalue	 = NULL;

#ifdef _DEBUG_UMTA
	if (NULL == piter) {
		debug_info("[str_hash]: str_hash_iter_get_value, param NULL");
		return NULL;
	}
#endif
	pvalue = (char *)piter->cur_node->pdata +
		sizeof(STR_HASH_ITEM);
	
	if (NULL != key) {
		pkey = ((STR_HASH_ITEM*)piter->cur_node->pdata)->key;
		strcpy(key, pkey);
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
int str_hash_iter_forward(STR_HASH_ITER *piter)
{
#ifdef _DEBUG_UMTA
	if (NULL == piter) {
		debug_info("[str_hash]: str_hash_iter_forward, param NULL");
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
int str_hash_iter_remove(STR_HASH_ITER *piter)
{
	DOUBLE_LIST* hash_map	= NULL;
	DOUBLE_LIST_NODE* node	= NULL;
	STR_HASH_ITEM* list_item= NULL;

#ifdef _DEBUG_UMTA
	if (NULL == piter) {
		debug_info("[str_hash]: str_hash_iter_remove, param NULL");
		return -1;
	}
#endif
	hash_map = piter->ptable->hash_map;

	if (piter->ptable->item_num < 1) {
		return -2;
	}
	if (NULL == piter->cur_node) {
		return -3;
	}
	node	= piter->cur_node;
	if (piter->cur_node == piter->ptable->iter_list.phead ||
			piter->ptable->item_num <= 1) {
		piter->cur_node = NULL;
	} else {
		piter->cur_node = piter->cur_node->pprev;
	}
	list_item = (STR_HASH_ITEM*)node->pdata;
	double_list_remove(&(hash_map[list_item->map_index]), &(list_item->list_node));
	double_list_remove(&(piter->ptable->iter_list), node);
	lib_buffer_put(piter->ptable->buf_pool, node->pdata);
	piter->ptable->item_num -= 1;
	piter->iter_curr_pos	-= 1;
	return 1;
	
}
