#ifndef _H_FILES_ALLOCATOR_
#define _H_FILES_ALLOCATOR_

#include "lib_buffer.h"

void files_allocator_init(size_t blocks);

int files_allocator_run();

int files_allocator_stop();

void files_allocator_free();

LIB_BUFFER* files_allocator_get_allocator();

#endif
