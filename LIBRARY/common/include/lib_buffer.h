#ifndef _H_LIB_BUFFER_
#define _H_LIB_BUFFER_

#ifdef __cplusplus
#	include <cstdlib>
#	include <cstring>
#else
#	include <stdlib.h>
#	include <string.h>
#endif
#include "common_types.h"
#include <pthread.h>
#define WSIZE           sizeof(void*)  /* word size (bytes) */

typedef enum _PARAM_TYPE {
    FREE_LIST_SIZE,
    ALLOCATED_NUM,
    MEM_ITEM_SIZE,
    MEM_ITEM_NUM
} PARAM_TYPE;

typedef struct _LIB_BUFFER {
    void*   heap_list_head;
    void*   free_list_head;
    void*   cur_heap_head;
    size_t  free_list_size;
    size_t  allocated_num;
    size_t  item_size;
    size_t  item_num;
    BOOL    is_thread_safe;
    pthread_mutex_t m_mutex;
} LIB_BUFFER, *PLIB_BUFFER;


#ifdef __cplusplus
extern "C" {
#endif

LIB_BUFFER* lib_buffer_init(size_t item_size, size_t item_num, BOOL is_thread_safe);

void lib_buffer_free(PLIB_BUFFER m_buf);

void* lib_buffer_get(PLIB_BUFFER m_buf);

void lib_buffer_put(PLIB_BUFFER m_buf, void *item);

size_t lib_buffer_get_param(LIB_BUFFER* m_buf, PARAM_TYPE type);

#ifdef __cplusplus
}
#endif

#endif /* _H_LIB_BUFFER_ */

