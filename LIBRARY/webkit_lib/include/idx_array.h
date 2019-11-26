#ifndef _H_IDX_ARRAY_
#define _H_IDX_ARRAY_
#include "single_list.h"


typedef struct _IDX_ARRAY {
    SINGLE_LIST mlist;
    size_t      data_size;
    size_t      cur_size;
    void**      cache_ptrs;
} IDX_ARRAY;

#ifdef __cplusplus
extern "C" {
#endif

IDX_ARRAY* idx_array_init(size_t data_size);

void idx_array_free(IDX_ARRAY* pindex_array);

long idx_array_append(IDX_ARRAY* pindex_array, void* pdata);

void* idx_array_get_item(IDX_ARRAY* pindex_array, size_t index);
size_t idx_array_get_capacity(IDX_ARRAY *);

#ifdef __cplusplus
}
#endif

#endif /*_H_IDX_ARRAY_ */

