#pragma once
#include <gromox/lib_buffer.hpp>

void blocks_allocator_init(size_t blocks);
extern int blocks_allocator_run();
extern int blocks_allocator_stop();
extern void blocks_allocator_free();
extern LIB_BUFFER *blocks_allocator_get_allocator();
