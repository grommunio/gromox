#pragma once
#include "lib_buffer.h"

void blocks_allocator_init(size_t blocks);
extern int blocks_allocator_run(void);
extern int blocks_allocator_stop(void);
extern void blocks_allocator_free(void);
LIB_BUFFER *blocks_allocator_get_allocator(void);
