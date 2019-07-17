#ifndef _H_LONG_HASH_TABLE_
#define _H_LONG_HASH_TABLE_
#include "lib_buffer.h"
#include "double_list.h"

typedef size_t (*PLONG_HASH_FUNC)(long);

typedef struct _LONG_HASH_ITEM {
    long         hash_key;
    size_t      map_index;
    DOUBLE_LIST_NODE list_node; 
    DOUBLE_LIST_NODE iter_node;
} LONG_HASH_ITEM, *INT_PHASH_ITEM;

typedef struct _LONG_HASH_TABLE {
    size_t      capacity;
    size_t      entry_num;
    size_t      data_size;
    size_t      item_num;
    DOUBLE_LIST iter_list;
    DOUBLE_LIST*    hash_map;
    LIB_BUFFER* buf_pool;
    PLONG_HASH_FUNC  hash_func;
} LONG_HASH_TABLE, *PLONG_HASH_TABLE;

typedef struct _LONG_HASH_ITER {
    DOUBLE_LIST_NODE* cur_node;
    size_t      iter_curr_pos;
    LONG_HASH_TABLE* ptable;
} LONG_HASH_ITER, *PLONG_HASH_ITER;

#ifdef __cplusplus
extern "C" {
#endif
/* 
 init a hash table with the specified max_items capacity and item_size
 of data size, the fun and a hash function which takes a string and 
 return a int, if the fun is NULL then a default hash function will
 be used
 */
LONG_HASH_TABLE* long_hash_init(size_t max_items, size_t item_size, PLONG_HASH_FUNC fun);

/* free the specified hash table */
void long_hash_free(LONG_HASH_TABLE* ptbl);

/* add the key and value into the specified hash table */
int long_hash_add(LONG_HASH_TABLE* ptbl, long key, void *value);

/* query if the key is exist in the hash table */
void* long_hash_query(LONG_HASH_TABLE* ptbl, long key);

/* remove the specified key from the hash table */
int long_hash_remove(LONG_HASH_TABLE* ptbl, long key);

/* init a hash iterator object */
LONG_HASH_ITER* long_hash_iter_init(LONG_HASH_TABLE *ptbl);

/* free a hash iterator object */
void long_hash_iter_free(LONG_HASH_ITER *piter);

/* like C++ std list, this begin a hash iterator */
void long_hash_iter_begin(LONG_HASH_ITER *piter);

/* query if the iterator has reached the last item in hash table */
int long_hash_iter_done(LONG_HASH_ITER *piter);

/* return the data and key at the current iterator position */
void* long_hash_iter_get_value(LONG_HASH_ITER *piter, long *key);

/* remove the key at the current iterator position */
int long_hash_iter_remove(LONG_HASH_ITER *piter);

/* forward the iterator by one item */
int long_hash_iter_forward(LONG_HASH_ITER *piter);

#ifdef __cplusplus
}
#endif

#endif /* _H_LONG_HASH_TABLE_ */
