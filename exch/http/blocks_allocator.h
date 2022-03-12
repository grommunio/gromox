#pragma once
#include <cstddef>

struct LIB_BUFFER;
void blocks_allocator_init(size_t blocks);
extern int blocks_allocator_run();
extern void blocks_allocator_stop();
extern LIB_BUFFER *blocks_allocator_get_allocator();
