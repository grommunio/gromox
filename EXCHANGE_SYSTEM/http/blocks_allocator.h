#ifndef _H_BLOCKS_ALLOCATOR_
#define _H_BLOCKS_ALLOCATOR_

#include "lib_buffer.h"

void blocks_allocator_init(size_t blocks);

int blocks_allocator_run();

int blocks_allocator_stop();

void blocks_allocator_free();

LIB_BUFFER* blocks_allocator_get_allocator();

#endif
