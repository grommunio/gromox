#pragma once
#include <gromox/double_list.hpp>

struct ALLOC_CONTEXT {
	ALLOC_CONTEXT();
	~ALLOC_CONTEXT();
	void *alloc(size_t);
	size_t get_total() const;

	DOUBLE_LIST list{};
	int offset = 0;
	size_t total = 0;
};
using alloc_context = ALLOC_CONTEXT;
