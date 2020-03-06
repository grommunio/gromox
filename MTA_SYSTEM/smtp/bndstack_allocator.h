#pragma once
#include "lib_buffer.h"
#include "smtp_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

void bndstack_allocator_init(size_t items);
extern int bndstack_allocator_run(void);
extern int bndstack_allocator_stop(void);
extern void bndstack_allocator_free(void);
extern LIB_BUFFER *bndstack_allocator_get_allocator(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
