#ifndef _H_BNDSTACK_ALLOCATOR_
#define _H_BNDSTACK_ALLOCATOR_

#include "lib_buffer.h"
#include "smtp_parser.h"

void bndstack_allocator_init(size_t items);
extern int bndstack_allocator_run(void);
extern int bndstack_allocator_stop(void);
extern void bndstack_allocator_free(void);
extern LIB_BUFFER *bndstack_allocator_get_allocator(void);

#endif
