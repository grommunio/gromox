#pragma once
#include "lib_buffer.h"
#include "double_list.h"

typedef size_t (*PHASH_FUNC)(const char* key);

typedef struct _HASH_ITEM {
    size_t      hash_key;
    size_t      map_index;
    DOUBLE_LIST_NODE list_node; 
    DOUBLE_LIST_NODE iter_node;
} HASH_ITEM, *PHASH_ITEM;

typedef struct _IP4_HASH_TABLE {
    size_t      capacity;
    size_t      entry_num;
    size_t      data_size;
    size_t      item_num;
    DOUBLE_LIST iter_list;
    DOUBLE_LIST*    hash_map;
    LIB_BUFFER* buf_pool;
    PHASH_FUNC  hash_func;
} IP4_HASH_TABLE, *PIP4_HASH_TABLE;

typedef struct _IP4_HASH_ITER {
    DOUBLE_LIST_NODE* cur_node;
    size_t      iter_curr_pos;
    IP4_HASH_TABLE* ptable;
} IP4_HASH_ITER, *PIP4_HASH_ITER;

#ifdef __cplusplus
extern "C" {
#endif
/* 
 init a hash table with the specified max_items capacity and item_size
 of data size, the fun and a hash function which takes a string and 
 return a int, if the fun is NULL then a default hash function will
 be used
 */
IP4_HASH_TABLE* ip4_hash_init(size_t max_items, size_t item_size, PHASH_FUNC fun);

/* free the specified hash table */
void ip4_hash_free(IP4_HASH_TABLE* ptbl);

/* add the key and value into the specified hash table */
int ip4_hash_add(IP4_HASH_TABLE* ptbl, char *key, void *value);

/* query if the key is exist in the hash table */
void* ip4_hash_query(IP4_HASH_TABLE* ptbl, char *key);

/* remove the specified key from the hash table */
int ip4_hash_remove(IP4_HASH_TABLE* ptbl, char *key);

/* init a hash iterator object */
IP4_HASH_ITER* ip4_hash_iter_init(IP4_HASH_TABLE *ptbl);

/* free a hash iterator object */
void ip4_hash_iter_free(IP4_HASH_ITER *piter);

/* like C++ std list, this begin a hash iterator */
void ip4_hash_iter_begin(IP4_HASH_ITER *piter);

/* query if the iterator has reached the last item in hash table */
int ip4_hash_iter_done(IP4_HASH_ITER *piter);

/* return the data and key at the current iterator position */
void* ip4_hash_iter_get_value(IP4_HASH_ITER *piter, char* key);

/* remove the key at the current iterator position */
int ip4_hash_iter_remove(IP4_HASH_ITER *piter);

/* forward the iterator by one item */
int ip4_hash_iter_forward(IP4_HASH_ITER *piter);

#ifdef __cplusplus
}
#endif
