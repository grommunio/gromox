#pragma once
#include <gromox/array.hpp>

struct MSG_UNIT {
	SINGLE_LIST_NODE node;
	size_t size;
	char file_name[128];
	BOOL b_deleted;
};

#ifdef __cplusplus
extern "C" {
#endif

void units_allocator_init(size_t blocks);
extern int units_allocator_run(void);
extern int units_allocator_stop(void);
extern void units_allocator_free(void);
extern LIB_BUFFER *units_allocator_get_allocator(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
