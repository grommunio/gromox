// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 * A simple ip hash table data structure, which takes a string ip address as
 * the key. Remember the ip hash table is thread-unsafe!
 *
 * Caution:
 *		In multithread environment, we must consider mutual exclusion and 
 *		synchronized problems. 
 */
#include <cstddef>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/int_hash.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static size_t g_num_of_collision;
static constexpr auto inthashitem_al = roundup(sizeof(INT_HASH_ITEM), sizeof(std::max_align_t));

static unsigned int default_int_hash_function(unsigned int);


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
INT_HASH_TABLE::INT_HASH_TABLE(size_t max_items, size_t item_size)
{
	size_t	i = 0;

	if (max_items <= 0 || item_size <= 0)
		throw std::invalid_argument("[int_hash]: parameter is invalid");
	auto table = this;
	table->entry_num = 8 * max_items;	/* we always allocate eight times 
										   entries of the max items 
										 */
	hash_map = std::make_unique<DOUBLE_LIST[]>(table->entry_num);
	double_list_init(&(table->iter_list));
	for (i = 0; i < table->entry_num; i++) {
		double_list_init(&hash_map[i]);
	}
	table->buf_pool = LIB_BUFFER(inthashitem_al + item_size, max_items);
	table->capacity		= max_items;
	table->data_size	= item_size;
	table->item_num		= 0;
}

INT_HASH_TABLE::~INT_HASH_TABLE()
{
	auto ptbl = this;
	size_t	i = 0;

	double_list_free(&(ptbl->iter_list));
	if (NULL != ptbl->hash_map) {
		for (i = 0; i < ptbl->entry_num; i++) {
			double_list_free(&(ptbl->hash_map[i]));
		}
	}
}

std::unique_ptr<INT_HASH_TABLE>
INT_HASH_TABLE::create(size_t max_items, size_t item_size) try
{
	return std::make_unique<INT_HASH_TABLE>(max_items, item_size);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1548: ENOMEM");
	return nullptr;
} catch (const std::invalid_argument &e) {
	mlog(LV_ERR, "E-1549: %s", e.what());
	return nullptr;
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
int INT_HASH_TABLE::add(int key, void *value)
{
	auto ptbl = this;
	DOUBLE_LIST_NODE* next	= NULL;
	DOUBLE_LIST*	dlist	= NULL;
	size_t index = -1;
	
	if (value == nullptr) {
		debug_info("[int_hash]: int_hash_add, invalid parameter");
		return -1;
	}

	if (ptbl->item_num >= ptbl->capacity) {
		debug_info("[int_hash]: int_hash_add, the hash table is full");
		return -2;
	}
	auto list_node = ptbl->buf_pool->get<INT_HASH_ITEM>();
	if (NULL == list_node) {
		debug_info("[int_hash]: int_hash_add, lib_buffer_get fail");
		return -3;
	}

	index = default_int_hash_function(key) % ptbl->entry_num;
	auto item = list_node;
	item->hash_key	= key;
	item->map_index = index;
	item->list_node.pdata = item;
	item->iter_node.pdata = item;
	memcpy(reinterpret_cast<char *>(list_node) + inthashitem_al, value, ptbl->data_size);
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
			ptbl->buf_pool->put(list_node);
			return -4;
		}
		next = dlist->phead->pnext;
		while (next != dlist->phead) 
		{
			if (key == ((INT_HASH_ITEM*)next->pdata)->hash_key) {
				debug_info("[int_hash]: int_hash_add, the key already exist");
				ptbl->buf_pool->put(list_node);
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
void *INT_HASH_TABLE::query1(int key) const
{
	auto ptbl = this;
	DOUBLE_LIST_NODE* next	= NULL;
	size_t index = default_int_hash_function(key) % ptbl->entry_num;
	if (NULL == ptbl->hash_map[index].phead) {
		return NULL;
	}

	next = ptbl->hash_map[index].phead;

	if (key == ((INT_HASH_ITEM*)next->pdata)->hash_key) {
		return reinterpret_cast<char *>(next->pdata) + inthashitem_al;
	}
	next = next->pnext;

	while (next != ptbl->hash_map[index].phead) {
		if (key == ((INT_HASH_ITEM*)next->pdata)->hash_key)
		{
			return reinterpret_cast<char *>(next->pdata) + inthashitem_al;
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
int INT_HASH_TABLE::remove(int key)
{
	auto ptbl = this;
	DOUBLE_LIST_NODE* next	= NULL;
	size_t index = default_int_hash_function(key) % ptbl->entry_num;
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
	ptbl->buf_pool->put_raw(next->pdata);
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
INT_HASH_ITER *INT_HASH_TABLE::make_iter()
{
	auto ptbl = this;
	auto iter = gromox::me_alloc<INT_HASH_ITER>();
	if (iter == nullptr) {
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
 *		piter [in]	pointer to the iterator, THE FOLLOWING shows
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
	pvalue = reinterpret_cast<char *>(piter->cur_node->pdata) + inthashitem_al;
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
	DOUBLE_LIST_NODE* node= NULL;
	INT_HASH_ITEM* list_item  = NULL;

#ifdef _DEBUG_UMTA
	if (NULL == piter) {
		debug_info("[int_hash]: int_hash_iter_remove, invalid param");
		return -1;
	}
#endif
	auto hash_map = piter->ptable->hash_map.get();
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
	piter->ptable->buf_pool->put_raw(node->pdata);
	piter->ptable->item_num -= 1;
	piter->iter_curr_pos	-= 1;
	return 1;
	
}

/*
 *	derived from hashpjw, Dragon Book P436
 */
static unsigned int default_int_hash_function(unsigned int key)
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

