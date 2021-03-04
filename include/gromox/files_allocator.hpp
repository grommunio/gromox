#pragma once
#include <gromox/lib_buffer.hpp>

void files_allocator_init(size_t blocks);
extern int files_allocator_run();
extern void files_allocator_stop();
extern void files_allocator_free();
extern LIB_BUFFER *files_allocator_get_allocator();
