#pragma once
#include <gromox/double_list.hpp>

struct ALLOC_CONTEXT {
	DOUBLE_LIST list;
	int offset;
	size_t total;
};
using alloc_context = ALLOC_CONTEXT;

void alloc_context_init(ALLOC_CONTEXT *pcontext);
void* alloc_context_alloc(ALLOC_CONTEXT *pcontext, size_t size);
void alloc_context_free(ALLOC_CONTEXT *pcontext);
size_t alloc_context_get_total(ALLOC_CONTEXT *pcontext);
