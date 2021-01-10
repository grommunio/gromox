// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/assoc_array.hpp>
#define ASSOC_ARRAY_ENTRY_INIT		4096

#define ASSOC_ARRAY_ENTRY_STEP		16

ASSOC_ARRAY* assoc_array_init(size_t data_size)
{
	ASSOC_ARRAY *parray;

	parray = (ASSOC_ARRAY*)malloc(sizeof(ASSOC_ARRAY));
	if (NULL == parray) {
		return NULL;
	}
	parray->index_cache = static_cast<void **>(malloc(sizeof(void *) * ASSOC_ARRAY_ENTRY_INIT));
	if (NULL == parray->index_cache) {
		free(parray->index_cache);
		return NULL;
	}
	parray->capability = ASSOC_ARRAY_ENTRY_INIT;
	parray->entry_num = 0;

	parray->phash = str_hash_init(ASSOC_ARRAY_ENTRY_INIT,
						sizeof(size_t) + data_size, NULL);
	if (NULL == parray->phash) {
		free(parray->index_cache);
		free(parray);
		return NULL;
	}

	parray->data_size = data_size;
	return parray;

}

void assoc_array_free(ASSOC_ARRAY *parray)
{
	if (NULL == parray) {
		return;
	}

	if (NULL != parray->index_cache) {
		free(parray->index_cache);
		parray->index_cache = NULL;
	}

	if (NULL != parray->phash) {
		str_hash_free(parray->phash);
		parray->phash = NULL;
	}

	free(parray);
}

static BOOL assoc_array_enlarge(ASSOC_ARRAY *parray)
{
	void *ptr;
	size_t tmp_index;
	void **index_cache;
	STR_HASH_ITER *iter; 
	STR_HASH_TABLE *phash;
	size_t tmp_capability;
	char tmp_key[MAX_KEY_LENGTH];


	if (NULL == parray) {
		return FALSE;
	}
	tmp_capability = parray->capability * ASSOC_ARRAY_ENTRY_STEP;
	phash = str_hash_init(tmp_capability, parray->data_size, NULL);
	if (NULL == phash) {
		return FALSE;
	}
	index_cache = static_cast<void **>(malloc(sizeof(void *) * tmp_capability));
	if (NULL == index_cache) {
		str_hash_free(phash);
		return FALSE;
	}

	memset(index_cache, 0, sizeof(void*)*tmp_capability);

	iter = str_hash_iter_init(parray->phash);
	if (NULL == iter) {
		free(index_cache);
		str_hash_free(phash);
		return FALSE;
	}

	tmp_index = 0;
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		ptr = str_hash_iter_get_value(iter, tmp_key);
		str_hash_add(phash, tmp_key, ptr);
		ptr = str_hash_query(phash, tmp_key);
		if (NULL != ptr) {
			*reinterpret_cast<size_t *>(static_cast<char *>(ptr) + parray->data_size) = tmp_index;
			index_cache[tmp_index] = ptr;
		}
		tmp_index ++;
	}

	str_hash_iter_free(iter);

	free(parray->index_cache);
	parray->index_cache = index_cache;

	str_hash_free(parray->phash);
	parray->phash = phash;

	parray->capability = tmp_capability;
	return TRUE;
}

BOOL assoc_array_assign(ASSOC_ARRAY *parray, const char *key, void *value)
{
	void *ptr;

	if (NULL == parray || strlen(key) > MAX_KEY_LENGTH) {
		return FALSE;
	}
	
	ptr = str_hash_query(parray->phash, key);
	if (NULL != ptr) {
		memcpy(ptr, value, parray->data_size);
		return TRUE;
	}

	if (1 != str_hash_add(parray->phash, key, value)) {
		if (FALSE == assoc_array_enlarge(parray)) {
			return FALSE;
		}
		str_hash_add(parray->phash, key, value);
	}
	ptr = str_hash_query(parray->phash, key);
	if (NULL == ptr) {
		return FALSE;
	}

	parray->index_cache[parray->entry_num] = ptr;
	*reinterpret_cast<size_t *>(static_cast<char *>(ptr) + parray->data_size) = parray->entry_num;
	parray->entry_num ++;
	return TRUE;
}

void* assoc_array_get_by_key(ASSOC_ARRAY *parray, const char *key)
{
	if (NULL == parray) {
		return NULL;
	}
	return str_hash_query(parray->phash, (char*)key);
}

void assoc_array_foreach(ASSOC_ARRAY *parray, 
	ASSOC_ARRAY_ENUM enum_func)
{
	void *ptr;
	STR_HASH_ITER *iter; 
	char tmp_key[MAX_KEY_LENGTH];


	iter = str_hash_iter_init(parray->phash);
	if (NULL == iter) {
		return;
	}

	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		ptr = str_hash_iter_get_value(iter, tmp_key);
		enum_func(tmp_key, ptr);
	}

	str_hash_iter_free(iter);
}

