#ifndef _H_INT_HASH_TABLE_
#define _H_INT_HASH_TABLE_
#include "lib_buffer.h"
#include "double_list.h"

typedef size_t (*PINT_HASH_FUNC)(int);

typedef struct _INT_HASH_ITEM {
    int         hash_key;
    size_t      map_index;
    DOUBLE_LIST_NODE list_node; 
    DOUBLE_LIST_NODE iter_node;
} INT_HASH_ITEM, *INT_PHASH_ITEM;

typedef struct _INT_HASH_TABLE {
    size_t      capacity;
    size_t      entry_num;
    size_t      data_size;
    size_t      item_num;
    DOUBLE_LIST iter_list;
    DOUBLE_LIST*    hash_map;
    LIB_BUFFER* buf_pool;
    PINT_HASH_FUNC  hash_func;
} INT_HASH_TABLE, *PINT_HASH_TABLE;

typedef struct _INT_HASH_ITER {
    DOUBLE_LIST_NODE* cur_node;
    size_t      iter_curr_pos;
    INT_HASH_TABLE* ptable;
} INT_HASH_ITER, *PINT_HASH_ITER;

#ifdef __cplusplus
extern "C" {
#endif
/* 
 init a hash table with the specified max_items capacity and item_size
 of data size, the fun and a hash function which takes a string and 
 return a int, if the fun is NULL then a default hash function will
 be used
 */
INT_HASH_TABLE* int_hash_init(size_t max_items, size_t item_size, PINT_HASH_FUNC fun);

/* free the specified hash table */
void int_hash_free(INT_HASH_TABLE* ptbl);

/* add the key and value into the specified hash table */
int int_hash_add(INT_HASH_TABLE* ptbl, int key, void *value);

/* query if the key is exist in the hash table */
void* int_hash_query(INT_HASH_TABLE* ptbl, int key);

/* remove the specified key from the hash table */
int int_hash_remove(INT_HASH_TABLE* ptbl, int key);

/* init a hash iterator object */
INT_HASH_ITER* int_hash_iter_init(INT_HASH_TABLE *ptbl);

/* free a hash iterator object */
void int_hash_iter_free(INT_HASH_ITER *piter);

/* like C++ std list, this begin a hash iterator */
void int_hash_iter_begin(INT_HASH_ITER *piter);

/* query if the iterator has reached the last item in hash table */
int int_hash_iter_done(INT_HASH_ITER *piter);

/* return the data and key at the current iterator position */
void* int_hash_iter_get_value(INT_HASH_ITER *piter, int *key);

/* remove the key at the current iterator position */
int int_hash_iter_remove(INT_HASH_ITER *piter);

/* forward the iterator by one item */
int int_hash_iter_forward(INT_HASH_ITER *piter);

#ifdef __cplusplus
}
#endif

#endif /* _H_INT_HASH_TABLE_ */
