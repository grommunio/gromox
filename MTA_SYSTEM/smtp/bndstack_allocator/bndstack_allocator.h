#ifndef _H_BNDSTACK_ALLOCATOR_
#define _H_BNDSTACK_ALLOCATOR_

#include "lib_buffer.h"
#include "smtp_parser.h"

void bndstack_allocator_init(size_t items);

int bndstack_allocator_run();

int bndstack_allocator_stop();

void bndstack_allocator_free();

LIB_BUFFER* bndstack_allocator_get_allocator();

#endif
