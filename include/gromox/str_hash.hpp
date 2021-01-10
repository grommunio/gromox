#pragma once
#include <gromox/lib_buffer.hpp>
#include <gromox/double_list.hpp>
#define MAX_KEY_LENGTH      512

typedef size_t (*PSTR_HASH_FUNC)(const char* key);

struct STR_HASH_ITEM {
    char        key[MAX_KEY_LENGTH];
    size_t      map_index;
    DOUBLE_LIST_NODE list_node; 
    DOUBLE_LIST_NODE iter_node;
};

struct STR_HASH_TABLE {
    size_t      capacity;
    size_t      entry_num;
    size_t      data_size;
    size_t      item_num;
    DOUBLE_LIST iter_list;
    DOUBLE_LIST*    hash_map;
    LIB_BUFFER* buf_pool;
    PSTR_HASH_FUNC  hash_func;
};

struct STR_HASH_ITER {
    DOUBLE_LIST_NODE* cur_node;
    size_t      iter_curr_pos;
    STR_HASH_TABLE* ptable;
};

/* 
 init a hash table with the specified max_items capacity and item_size
 of data size, the fun and a hash function which takes a string and 
 return a int, if the fun is NULL then a default hash function will
 be used
 */

STR_HASH_TABLE* str_hash_init(size_t max_items, size_t item_size, PSTR_HASH_FUNC fun);

/* free the specified hash table */
void str_hash_free(STR_HASH_TABLE* ptbl);

/* add the key and value into the specified hash table */
extern int str_hash_add(STR_HASH_TABLE *ptbl, const char *key, const void *value);

/* query if the key is exist in the hash table */
void* str_hash_query(STR_HASH_TABLE* ptbl, const char *key);

/* remove the specified key from the hash table */
int str_hash_remove(STR_HASH_TABLE* ptbl, const char *key);

/* init a hash iterator object */
STR_HASH_ITER* str_hash_iter_init(STR_HASH_TABLE *ptbl);

/* free a hash iterator object */
void str_hash_iter_free(STR_HASH_ITER *piter);

/* like C++ std list, this begin a hash iterator */
void str_hash_iter_begin(STR_HASH_ITER *piter);

/* query if the iterator has reached the last item in hash table */
int str_hash_iter_done(STR_HASH_ITER *piter);

/* return the data and key at the current iterator position */
void* str_hash_iter_get_value(STR_HASH_ITER *piter, char* key);

/* remove the key at the current iterator position */
int str_hash_iter_remove(STR_HASH_ITER *piter);

/* forward the iterator by one item */
int str_hash_iter_forward(STR_HASH_ITER *piter);
