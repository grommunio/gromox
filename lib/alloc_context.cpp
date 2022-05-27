// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstddef>
#include <cstdlib>
#include <gromox/alloc_context.hpp>
#include <gromox/defs.h>
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
		pnode->pdata = reinterpret_cast<char *>(pnode) + sizeof(DOUBLE_LIST_NODE);
		double_list_append_as_tail(&pcontext->list, pnode);
	}
}

void *ALLOC_CONTEXT::alloc(size_t size)
{
	auto pcontext = this;
	void *ptr;
	
	if (0 == double_list_get_nodes_num(&pcontext->list)) {
		return NULL;
	}
	static constexpr auto node_al = roundup(sizeof(DOUBLE_LIST_NODE), sizeof(std::max_align_t));
	auto size_al = roundup(size, sizeof(std::max_align_t));
	if (size > ALLOC_FRAME_SIZE - node_al) {
		auto pnode = static_cast<DOUBLE_LIST_NODE *>(malloc(node_al + size_al));
		if (NULL == pnode) {
			return NULL;
		}
		pnode->pdata = reinterpret_cast<char *>(pnode) + node_al;
		double_list_insert_as_head(&pcontext->list, pnode);
		pcontext->total += size_al;
		return pnode->pdata;
	}
	if (size > ALLOC_FRAME_SIZE - node_al - pcontext->offset) {
		auto pnode = static_cast<DOUBLE_LIST_NODE *>(malloc(ALLOC_FRAME_SIZE));
		if (NULL == pnode) {
			return NULL;
		}
		pnode->pdata = reinterpret_cast<char *>(pnode) + node_al;
		double_list_append_as_tail(&pcontext->list, pnode);
		pcontext->offset = size_al;
		pcontext->total += size_al;
		return pnode->pdata;
	}
	auto pnode = double_list_get_tail(&pcontext->list);
	if (NULL == pnode) {
		return NULL;
	}
	ptr = static_cast<char *>(pnode->pdata) + pcontext->offset;
	pcontext->offset += size_al;
	pcontext->total  += size_al;
	return ptr;
}

void alloc_context_free(ALLOC_CONTEXT *pcontext)
{
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(&pcontext->list)) != nullptr)
		free(pnode);
	double_list_free(&pcontext->list);
}

size_t ALLOC_CONTEXT::get_total() const
{
	auto pcontext = this;
	return pcontext->total;
}
