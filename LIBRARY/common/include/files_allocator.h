#pragma once
#include "lib_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

void files_allocator_init(size_t blocks);
extern int files_allocator_run(void);
extern void files_allocator_stop(void);
extern void files_allocator_free(void);
extern LIB_BUFFER *files_allocator_get_allocator(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
