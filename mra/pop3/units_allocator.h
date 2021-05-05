#pragma once

void units_allocator_init(size_t blocks);
extern int units_allocator_run();
extern int units_allocator_stop();
extern void units_allocator_free();
extern LIB_BUFFER *units_allocator_get_allocator();
