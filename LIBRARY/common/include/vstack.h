#ifndef _H_VSTACK_
#define _H_VSTACK_
#include "lib_buffer.h"
#include "single_list.h"

typedef struct _VSTACK {
    LIB_BUFFER* mbuf_pool;
    SINGLE_LIST mlist;
    size_t      data_size;
    size_t      cur_size;
    size_t      max_size;
} VSTACK, *PVSTACK;

#ifdef __cplusplus
extern "C" {
#endif

void vstack_init(VSTACK* pvstack, LIB_BUFFER* pbuf_pool, size_t data_size, 
    size_t max_size);

void vstack_free(VSTACK* pvstack);

LIB_BUFFER* vstack_allocator_init(size_t data_size, size_t max_size, BOOL thread_safe);

void vstack_allocator_free(LIB_BUFFER* buf);

BOOL vstack_push(VSTACK* pvstack, void* pdata);

BOOL vstack_pop(VSTACK* pvstack);

void *vstack_get_top(VSTACK* pvstack);

BOOL vstack_is_empty(VSTACK* pvstack);

void vstack_clear(VSTACK* pvstack);

#ifdef __cplusplus
}
#endif

#endif /*_H_VSTACK_ */

