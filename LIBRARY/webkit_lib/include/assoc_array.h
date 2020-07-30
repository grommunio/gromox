#pragma once
#include "str_hash.h"


typedef struct _ASSOC_ARRAY {
	STR_HASH_TABLE	*phash;
	size_t			capability;
	size_t			data_size;
    size_t			entry_num;
	void			**index_cache;
} ASSOC_ARRAY;


typedef void (*ASSOC_ARRAY_ENUM)(const char *, void *);

#ifdef __cplusplus
extern "C" {
#endif

ASSOC_ARRAY* assoc_array_init(size_t data_size);

void assoc_array_free(ASSOC_ARRAY *parray);
extern BOOL assoc_array_assign(ASSOC_ARRAY *parray, const char *key, void *value);
void* assoc_array_get_by_key(ASSOC_ARRAY *parray, const char *key);

void* assoc_array_get_by_index(ASSOC_ARRAY *parray, size_t index);

size_t assoc_array_get_elements_num(ASSOC_ARRAY *parray);

void assoc_array_eliminate(ASSOC_ARRAY *parray, char *key);

void assoc_array_foreach(ASSOC_ARRAY *parray, 
	ASSOC_ARRAY_ENUM enum_func);


#ifdef __cplusplus
}
#endif
