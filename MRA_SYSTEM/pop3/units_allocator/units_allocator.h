#ifndef _H_UNIT_ALLOCATOR_
#define _H_UNIT_ALLOCATOR_
#include "array.h"

typedef struct _MSG_UNIT {
	SINGLE_LIST_NODE node;
	size_t size;
	char file_name[128];
	BOOL b_deleted;
} MSG_UNIT;

void units_allocator_init(size_t blocks);

int units_allocator_run();

int units_allocator_stop();

void units_allocator_free();

LIB_BUFFER* units_allocator_get_allocator();

#endif
