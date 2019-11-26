/*
 * A simple ip hash table data structure, which takes a string ip address as
 * the key. Remember the ip hash table is thread-unsafe!
 *
 * CAUTION!!!
 *		In multithread enviroment, we must consider mutual exclusion and 
 *		synchronized problems. 
 */
#include "common_types.h"
#include "ip4_hash.h"
#include "util.h"
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>	 /* for inet_addr only */

static size_t g_num_of_collision;

static size_t default_string_hash_function(const char *string);


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
IP4_HASH_TABLE* ip4_hash_init(size_t max_items, size_t item_size, PHASH_FUNC fun)
{
	DOUBLE_LIST* p_map = NULL;
	PIP4_HASH_TABLE	 table = NULL;
	size_t	i = 0;

	if (max_items <= 0 || item_size <= 0) {
		debug_info("[ip4_hash]: parameter is invalid");
		return NULL;
	}
	table = (PIP4_HASH_TABLE)malloc(sizeof(IP4_HASH_TABLE));
	if (NULL == table) {
		debug_info("[ip4_hash]: can not alloc hash table");
		return NULL;
	}
	table->entry_num = 8 * max_items;	/* we always allocate eight times 
										   entries of the max items 
										 */
	p_map = (DOUBLE_LIST*)malloc(sizeof(DOUBLE_LIST) * table->entry_num);
	
	if (NULL == p_map) {
		debug_info("[ip4_hash]: can not alloc hash map");
		free(table);
		return NULL;
	}
	memset(p_map, 0, sizeof(DOUBLE_LIST) * table->entry_num);

	double_list_init(&(table->iter_list));
	for (i = 0; i < table->entry_num; i++) {
		double_list_init(&(p_map[i]));
	}

	table->buf_pool = lib_buffer_init(sizeof(HASH_ITEM) + item_size, max_items,
						FALSE);
	if (NULL == table->buf_pool) {
		debug_info("[ip4_hash]: ip4_hash_init, lib_buffer_init fail");
		free(table);
		free(p_map);
		return NULL;

	}
	if (NULL == fun) {
		table->hash_func = default_string_hash_function;
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
void ip4_hash_free(IP4_HASH_TABLE* ptbl)
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
int ip4_hash_add(IP4_HASH_TABLE* ptbl, char *key, void *value)
{

	DOUBLE_LIST_NODE* next	= NULL;
	DOUBLE_LIST*	dlist	= NULL;

	void* list_node = NULL;
	HASH_ITEM* item = NULL;
	
	size_t index = -1, binary_ip_addr = 0;

#ifdef _DEBUG_UMTA
	if (NULL == ptbl || NULL == key || NULL == value) {
		debug_info("[ip4_hash]: ip4_hash_add, invalid parameter");
		return -1;
	}
#endif
	if (ptbl->item_num >= ptbl->capacity) {
		return -2;
	}
	
	binary_ip_addr = inet_addr(key);
	list_node = lib_buffer_get(ptbl->buf_pool);

	if (NULL == list_node) {
		debug_info("[ip4_hash]: ip4_hash_add, lib_buffer_get fail");
		return -3;
	}

	index = ptbl->hash_func(key) % (ptbl->entry_num);

	item  = (HASH_ITEM *)list_node;
	item->hash_key	= binary_ip_addr;
	item->map_index = index;
	item->list_node.pdata	= item;
	item->iter_node.pdata	= item;


	memcpy((char*)list_node + sizeof(HASH_ITEM), value, ptbl->data_size);

	dlist	= (DOUBLE_LIST*)&(ptbl->hash_map[index]);

	if (NULL == dlist->phead) {
		double_list_insert_as_head(dlist, &(item->list_node));
	} else {
		g_num_of_collision++;
		
		/* 
		 check if the key is already exist to avoid inserting
		 the same key twice.
		 */
		if (binary_ip_addr == ((HASH_ITEM*)dlist->phead->pdata)->hash_key) {
			lib_buffer_put(ptbl->buf_pool, list_node);
			return -4;
		}
		next = dlist->phead->pnext;
		while (next != dlist->phead) 
		{
			if (binary_ip_addr == ((HASH_ITEM*)next->pdata)->hash_key) {
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
void* ip4_hash_query(IP4_HASH_TABLE* ptbl, char *key)
{
	DOUBLE_LIST_NODE* next	= NULL;
	size_t binary_ip_addr	= 0;
	size_t	index = -1;
	void*	pdata = NULL;
#ifdef _DEBUG_UMTA
	if (NULL == ptbl || NULL == key) {
		debug_info("[ip4_hash]: ip4_hash_query, invalid param");
		return NULL;
	}
#endif
	binary_ip_addr = inet_addr(key);
	index = ptbl->hash_func(key) % (ptbl->entry_num);

	if (NULL == ptbl->hash_map[index].phead) {
		return NULL;
	}

	next = ptbl->hash_map[index].phead;

	if (binary_ip_addr == ((HASH_ITEM*)next->pdata)->hash_key) {
		pdata = (char*)next->pdata + sizeof(HASH_ITEM);
		return pdata;
	}
	next = next->pnext;

	while (next != ptbl->hash_map[index].phead) {
		if (binary_ip_addr == ((HASH_ITEM*)next->pdata)->hash_key)
		{
			pdata = (char*)next->pdata + sizeof(HASH_ITEM);
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
int ip4_hash_remove(IP4_HASH_TABLE* ptbl, char *key)
{
	DOUBLE_LIST_NODE* next	= NULL;
	size_t binary_ip_addr	= 0;
	size_t index = -1;
	
#ifdef _DEBUG_UMTA
	if (NULL == ptbl || NULL == key) {
		debug_info("[ip4_hash]: ip4_hash_remove, invalid param");
		return -1;
	}
#endif
	
	binary_ip_addr = inet_addr(key);

	index = ptbl->hash_func(key) % (ptbl->entry_num);
	if (NULL == ptbl->hash_map[index].phead) {
		return -2;
	}
	
	next = ptbl->hash_map[index].phead;
	if (binary_ip_addr == ((HASH_ITEM*)next->pdata)->hash_key)
		goto DONE;

	next = next->pnext;
	while (next != ptbl->hash_map[index].phead) {
		if (binary_ip_addr == ((HASH_ITEM*)next->pdata)->hash_key)
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
				&(((HASH_ITEM*)next->pdata)->iter_node)
	);
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
IP4_HASH_ITER* ip4_hash_iter_init(IP4_HASH_TABLE* ptbl)
{
	PIP4_HASH_ITER iter = NULL;

#ifdef _DEBUG_UMTA
	if (NULL == ptbl) {
		debug_info("[ip4_hash]: ip4_hash_iter_init, invalid parameter");
		return NULL;
	}
#endif
	if (NULL == (iter = malloc(sizeof(IP4_HASH_ITER)))) {
		debug_info("[ip4_hash]: can not alloc hash iter");
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
void ip4_hash_iter_free(IP4_HASH_ITER *piter)
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
 *		for (ip4_hash_iter_begin(piter); !ip4_hash_iter_done(piter)
 *			ip4_hash_iter_forward(piter)) {
 *			value = ip4_hash_iter_get_value(piter, NULL);
 *		}
 */
void ip4_hash_iter_begin(IP4_HASH_ITER *piter)
{
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
int ip4_hash_iter_done(IP4_HASH_ITER *piter)
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
void* ip4_hash_iter_get_value(IP4_HASH_ITER *piter, char *key)
{
	char*	ip_addr	 = NULL;
	struct	in_addr addr;
	void*	pvalue	 = NULL;

#ifdef _DEBUG_UMTA
	if (NULL == piter) {
		debug_info("[ip4_hash]: ip4_hash_iter_get_value, invalid param");
		return NULL;
	}
#endif
	pvalue = (char *)piter->cur_node->pdata +
		sizeof(HASH_ITEM);
	
	if (NULL != key) {
		addr.s_addr = ((HASH_ITEM*)piter->cur_node->pdata)->hash_key;
		ip_addr = inet_ntoa(addr);
		strcpy(key, ip_addr);
//		memcpy(key, ip_addr, strlen(ip_addr));
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
int ip4_hash_iter_forward(IP4_HASH_ITER *piter)
{
#ifdef _DEBUG_UMTA
	if (NULL == piter) {
		debug_info("[ip4_hash]: ip4_hash_iter_forward, invalid param");
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
int ip4_hash_iter_remove(IP4_HASH_ITER *piter)
{
	DOUBLE_LIST* hash_map = NULL;
	DOUBLE_LIST_NODE* node= NULL;
	HASH_ITEM* list_item  = NULL;

#ifdef _DEBUG_UMTA
	if (NULL == piter) {
		debug_info("[ip4_hash]: ip4_hash_iter_remove, invalid param");
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
			piter->ptable->item_num <= 1) 
		piter->cur_node = NULL;
	else
		piter->cur_node = piter->cur_node->pprev;
	
	list_item = (HASH_ITEM*)node->pdata;
	double_list_remove(&(hash_map[list_item->map_index]), &(list_item->list_node));
	double_list_remove(&(piter->ptable->iter_list), node);
	lib_buffer_put(piter->ptable->buf_pool, node->pdata);
	piter->ptable->item_num -= 1;
	piter->iter_curr_pos	-= 1;
	return 1;
	
}

/*
 *	derived from hashpjw, Dragon Book P436
 */

static size_t default_string_hash_function(const char *string)
{
	char *ptr = (char*)string;
	int hash = 0, len = 0;
	len = (int)strlen(string);

	for (hash = 0; len; len--, ptr++)
	// (31 * hash) will probably be optimized
	// to ((hash << 5) - hash) 
	hash = ((hash << 5) - hash) + *ptr;
 
	while (len-- > 0)
	{
		int g;
		hash = (hash << 4) + *ptr++;
		g = hash & 0xf0000000;
		if (g)
		hash = (hash ^ (g >> 24)) ^ g;
	}
	return hash & 07777777777;
}


