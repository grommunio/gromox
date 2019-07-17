#include "alloc_context.h"
#include <stdlib.h>

#define ALLOC_FRAME_SIZE					64*1024


void alloc_context_init(ALLOC_CONTEXT *pcontext)
{
	DOUBLE_LIST_NODE *pnode;
	
	/* init the ndr stack for ndr_pull and ndr_push */
	double_list_init(&pcontext->list);
	pcontext->offset = 0;
	pcontext->total = 0;
	pnode = (DOUBLE_LIST_NODE*)malloc(ALLOC_FRAME_SIZE);
	if (NULL != pnode) {
		pnode->pdata = (void*)pnode + sizeof(DOUBLE_LIST_NODE);
		double_list_append_as_tail(&pcontext->list, pnode);
	}
}

void* alloc_context_alloc(ALLOC_CONTEXT *pcontext, size_t size)
{
	void *ptr;
	DOUBLE_LIST_NODE *pnode;
	
	if (0 == double_list_get_nodes_num(&pcontext->list)) {
		return NULL;
	}
	if (size > ALLOC_FRAME_SIZE - sizeof(DOUBLE_LIST_NODE)) {
		pnode = malloc(size + sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			return NULL;
		}
		pnode->pdata = (void*)pnode + sizeof(DOUBLE_LIST_NODE);
		double_list_insert_as_head(&pcontext->list, pnode);
		pcontext->total += size;
		return pnode->pdata;
	} else {
		if (size > ALLOC_FRAME_SIZE - sizeof(DOUBLE_LIST_NODE) - pcontext->offset) {
			pnode = malloc(ALLOC_FRAME_SIZE);
			if (NULL == pnode) {
				return NULL;
			}
			pnode->pdata = (void*)pnode + sizeof(DOUBLE_LIST_NODE);
			double_list_append_as_tail(&pcontext->list, pnode);
			pcontext->offset = size;
			pcontext->total += size;
			return pnode->pdata;
		} else {
			pnode = double_list_get_tail(&pcontext->list);
			if (NULL == pnode) {
				return NULL;
			}
			ptr = pnode->pdata + pcontext->offset;
			pcontext->offset += size;
			pcontext->total += size;
			return ptr;
		}
	}
}

void alloc_context_free(ALLOC_CONTEXT *pcontext)
{
	DOUBLE_LIST_NODE *pnode;
	
	while (pnode=double_list_get_from_head(&pcontext->list)) {
		free(pnode);
	}
	double_list_free(&pcontext->list);
}

size_t alloc_context_get_total(ALLOC_CONTEXT *pcontext)
{
	return pcontext->total;
}
