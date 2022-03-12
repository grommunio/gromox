#pragma once
#include <memory>
#include <gromox/double_list.hpp>
#include <gromox/util.hpp>
#define MAX_KEY_LENGTH      512

using PSTR_HASH_FUNC = size_t (*)(const char *key);

struct STR_HASH_ITEM {
    char        key[MAX_KEY_LENGTH];
    size_t      map_index;
    DOUBLE_LIST_NODE list_node; 
    DOUBLE_LIST_NODE iter_node;
};

struct STR_HASH_ITER;

struct GX_EXPORT STR_HASH_TABLE {
	STR_HASH_TABLE(size_t max_items, size_t item_size, PSTR_HASH_FUNC);
	~STR_HASH_TABLE();
	NOMOVE(STR_HASH_TABLE);

	/*
	 * init a hash table with the specified max_items capacity and
	 * item_size of data size, the fun and a hash function which takes a
	 * string and return a int, if the fun is NULL then a default hash
	 * function will be used.
	 */
	static std::unique_ptr<STR_HASH_TABLE> create(size_t max_items, size_t item_size, PSTR_HASH_FUNC);
	/* add the key and value into the specified hash table */
	int add(const char *key, const void *value);
	/* query if the key is exist in the hash table */
	void *query1(const char *key) const;
	template<typename T> T *query(const char *key) const { return static_cast<T *>(query1(key)); }
	/* remove the specified key from the hash table */
	int remove(const char *key);
	/* init a hash iterator object */
	STR_HASH_ITER *make_iter();

	size_t capacity = 0, entry_num = 0, data_size = 0, item_num = 0;
	DOUBLE_LIST iter_list{};
	std::unique_ptr<DOUBLE_LIST[]> hash_map;
	LIB_BUFFER buf_pool;
	PSTR_HASH_FUNC hash_func;
};

struct STR_HASH_ITER {
    DOUBLE_LIST_NODE* cur_node;
    size_t      iter_curr_pos;
    STR_HASH_TABLE* ptable;
};

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
