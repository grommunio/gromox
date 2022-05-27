#pragma once
#include <gromox/double_list.hpp>

struct ALLOC_CONTEXT {
	void *alloc(size_t);
	size_t get_total() const;

	DOUBLE_LIST list;
	int offset;
	size_t total;
};
using alloc_context = ALLOC_CONTEXT;

void alloc_context_init(ALLOC_CONTEXT *pcontext);
void alloc_context_free(ALLOC_CONTEXT *pcontext);
