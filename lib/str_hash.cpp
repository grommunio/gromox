// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 * A simple string hash table data structure
 */
#include <cstddef>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <libHX/string.h>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/str_hash.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static size_t g_num_of_collision;
static constexpr auto strhashitem_al = roundup(sizeof(STR_HASH_ITEM), sizeof(std::max_align_t));

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
STR_HASH_TABLE::STR_HASH_TABLE(size_t max_items, size_t item_size, PSTR_HASH_FUNC fun)
{
	size_t	i = 0;

	if (max_items <= 0 || item_size <= 0)
		throw std::invalid_argument("[str_hash]: str_hash_init, parameter is invalid");
	auto table = this;
	table->entry_num = 8 * max_items;	/* we always allocate eight times 
										   entries of the max items */
	hash_map = std::make_unique<DOUBLE_LIST[]>(table->entry_num);
	memset(hash_map.get(), 0, sizeof(DOUBLE_LIST) * table->entry_num);
	double_list_init(&(table->iter_list));
	for (i = 0; i < table->entry_num; i++) {
		double_list_init(&hash_map[i]);
	}

	table->buf_pool = LIB_BUFFER(strhashitem_al + item_size, max_items);
	if (NULL == fun) {
		table->hash_func = DJBHash;
	} else {
		table->hash_func = fun;
	}
	table->capacity		= max_items;
	table->data_size	= item_size;
	table->item_num		= 0;
}

STR_HASH_TABLE::~STR_HASH_TABLE()
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

std::unique_ptr<STR_HASH_TABLE> STR_HASH_TABLE::create(size_t max_items,
    size_t item_size, PSTR_HASH_FUNC func) try
{
	return std::make_unique<STR_HASH_TABLE>(max_items, item_size, func);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1537: ENOMEM");
	return nullptr;
} catch (const std::invalid_argument &e) {
	mlog(LV_ERR, "E-1538: %s", e.what());
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
int STR_HASH_TABLE::add(const char *key, const void *value)
{
	auto ptbl = this;
	DOUBLE_LIST_NODE* next	= NULL;
	DOUBLE_LIST*	dlist	= NULL;
	size_t index = -1;
	
#ifdef _DEBUG_UMTA 
	if (NULL == ptbl || NULL == key || NULL == value) {
		mlog(LV_DEBUG, "str_hash: str_hash_add, param NULL");
		return -1;
	}
#endif
	if (ptbl->item_num >= ptbl->capacity) {
		return -2;
	}
	auto list_node = ptbl->buf_pool->get<STR_HASH_ITEM>();
	if (NULL == list_node) {
		mlog(LV_DEBUG, "str_hash: str_hash_add, lib_buffer_get fail");
		return -3;
	}

	index = ptbl->hash_func(key) % (ptbl->entry_num);
	auto item = list_node;
	item->map_index = index;
	item->list_node.pdata	= item;
	item->iter_node.pdata	= item;
	gx_strlcpy(item->key, key, gromox::arsizeof(item->key));
	memcpy(reinterpret_cast<char *>(list_node) + strhashitem_al, value, ptbl->data_size);
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
			ptbl->buf_pool->put(list_node);
			return -4;
		}
		
		next = dlist->phead->pnext;
		while (next != dlist->phead) {
			if (0 == strcmp(((STR_HASH_ITEM*)next->pdata)->key, key)) {
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
 *		key	 [in]	the queried key
 *
 *	@return 
 *		the value that map the key, NULL if some error occurs
 */
void *STR_HASH_TABLE::query1(const char *key) const
{
	auto ptbl = this;
	DOUBLE_LIST_NODE* next	= NULL;
	size_t	index = -1;
	
#ifdef _DEBUG_UMTA
	if (NULL == ptbl || NULL == key) {
		mlog(LV_DEBUG, "str_hash: str_hash_query, param NULL");
		return NULL;
	}
#endif

	index = ptbl->hash_func(key) % (ptbl->entry_num);

	if (NULL == ptbl->hash_map[index].phead) {
		return NULL;
	}

	next = ptbl->hash_map[index].phead;

	if (0 == strcmp(key, ((STR_HASH_ITEM*)next->pdata)->key)) {
		return reinterpret_cast<char *>(next->pdata) + strhashitem_al;
	}
	next = next->pnext;

	while (next != ptbl->hash_map[index].phead) {
		if (0 == strcmp(key, ((STR_HASH_ITEM*)next->pdata)->key)) {
			return reinterpret_cast<char *>(next->pdata) + strhashitem_al;
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
int STR_HASH_TABLE::remove(const char *key)
{
	auto ptbl = this;
	DOUBLE_LIST_NODE* next	= NULL;
	size_t index = -1;
	
#ifdef _DEBUG_UMTA
	if (NULL == ptbl || NULL == key) {
		mlog(LV_DEBUG, "str_hash: str_hash_remove, param NULL");
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
STR_HASH_ITER *STR_HASH_TABLE::make_iter()
{
	auto iter = gromox::me_alloc<STR_HASH_ITER>();
	if (iter == nullptr) {
		mlog(LV_DEBUG, "str_hash: can not alloc hash iter");
		return NULL;
	}
	
	iter->cur_node		= NULL;
	iter->iter_curr_pos = 0;
	iter->ptable = this;
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
		mlog(LV_DEBUG, "str_hash: str_hash_iter_free, param NULL");
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
 *		piter [in]	pointer to the iterator, THE FOLLOWING shows
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
		mlog(LV_DEBUG, "str_hash: str_hash_iter_begin, param NULL");
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
		mlog(LV_DEBUG, "str_hash: str_hash_iter_done, param NULL");
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
		mlog(LV_DEBUG, "str_hash: str_hash_iter_get_value, param NULL");
		return NULL;
	}
#endif
	pvalue = reinterpret_cast<char *>(piter->cur_node->pdata) + strhashitem_al;
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
		mlog(LV_DEBUG, "str_hash: str_hash_iter_forward, param NULL");
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
	DOUBLE_LIST_NODE* node	= NULL;
	STR_HASH_ITEM* list_item= NULL;

#ifdef _DEBUG_UMTA
	if (NULL == piter) {
		mlog(LV_DEBUG, "str_hash: str_hash_iter_remove, param NULL");
		return -1;
	}
#endif
	auto &hash_map = piter->ptable->hash_map;
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
	piter->ptable->buf_pool->put_raw(node->pdata);
	piter->ptable->item_num -= 1;
	piter->iter_curr_pos	-= 1;
	return 1;
	
}
