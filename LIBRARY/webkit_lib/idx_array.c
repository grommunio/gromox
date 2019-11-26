#include "idx_array.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>


#define IDX_ARRAY_CACHE_INIT		256

#define IDX_ARRAY_CACHE_STEP		16


IDX_ARRAY* idx_array_init(size_t data_size)
{
	IDX_ARRAY *parray;

	parray = (IDX_ARRAY*)malloc(sizeof(IDX_ARRAY));
	if (NULL == parray) {
		return NULL;
	}
    single_list_init(&(parray->mlist));
    parray->data_size = data_size;
    parray->cur_size = IDX_ARRAY_CACHE_INIT;
	parray->cache_ptrs = malloc(sizeof(void*)*IDX_ARRAY_CACHE_INIT);
	if (NULL == parray->cache_ptrs) {
		free(parray);
		return NULL;
	}
	return parray;
}


void idx_array_free(IDX_ARRAY* parray)
{
	SINGLE_LIST_NODE *pnode;

    if (NULL == parray) {
        return;
    }
	while ((pnode = single_list_get_from_head(&parray->mlist)) != NULL)
		free(pnode);
	single_list_free(&parray->mlist);
	free(parray->cache_ptrs);
	free(parray);
}


long idx_array_append(IDX_ARRAY* parray, void* pdata)
{
	void *tmp_ptr;
	size_t tmp_size;
    SINGLE_LIST_NODE *pnode;

    if (NULL == parray || NULL == pdata) {    
		return -1;
    }

	pnode = (SINGLE_LIST_NODE*)malloc(sizeof(SINGLE_LIST_NODE) +
				parray->data_size);

	if (NULL == pnode) {
		return -1;
	}

	pnode->pdata = (void*)pnode + sizeof(SINGLE_LIST_NODE);
    memcpy(pnode->pdata, pdata, parray->data_size);


	if (single_list_get_nodes_num(&parray->mlist) >= parray->cur_size) {
		tmp_size = IDX_ARRAY_CACHE_STEP * parray->cur_size;
		tmp_ptr = malloc(tmp_size);
		if (NULL == tmp_ptr) {
			free(pnode);
			return -1;
		}
		memset(tmp_ptr, 0, tmp_size);
		memcpy(tmp_ptr, parray->cache_ptrs, parray->cur_size);
		free(parray->cache_ptrs);
		parray->cache_ptrs = tmp_ptr;
		parray->cur_size = tmp_size;
	}
	tmp_size = single_list_get_nodes_num(&parray->mlist);
	parray->cache_ptrs[tmp_size] = pnode->pdata; 
	single_list_append_as_tail(&parray->mlist, pnode);
    return tmp_size;
}

void* idx_array_get_item(IDX_ARRAY* parray, size_t index)
{
	if (NULL == parray) {
		return NULL;
	}

    if (index >= parray->cur_size) {
		return NULL;
    }
    return parray->cache_ptrs[index];
}

size_t idx_array_get_capacity(IDX_ARRAY* parray)
{
    if (NULL == parray) {
        return 0;
    }

    return single_list_get_nodes_num(&parray->mlist);
}
