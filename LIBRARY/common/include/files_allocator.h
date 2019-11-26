#ifndef _H_FILES_ALLOCATOR_
#define _H_FILES_ALLOCATOR_

#include "lib_buffer.h"

void files_allocator_init(size_t blocks);
extern int files_allocator_run(void);
extern void files_allocator_stop(void);
extern void files_allocator_free(void);
extern LIB_BUFFER *files_allocator_get_allocator(void);

#endif
