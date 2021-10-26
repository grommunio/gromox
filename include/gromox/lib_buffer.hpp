#pragma once
#include <cstdlib>
#include <cstring>
#include <type_traits>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <pthread.h>
#define FILE_BLOCK_SIZE 0x100
#define FILE_ALLOC_SIZE (FILE_BLOCK_SIZE + sizeof(DOUBLE_LIST_NODE))
#define WSIZE           sizeof(void*)  /* word size (bytes) */

enum PARAM_TYPE {
    FREE_LIST_SIZE,
    ALLOCATED_NUM,
    MEM_ITEM_SIZE,
    MEM_ITEM_NUM
};

struct LIB_BUFFER {
    void*   heap_list_head;
    void*   free_list_head;
    void*   cur_heap_head;
    size_t  free_list_size;
    size_t  allocated_num;
    size_t  item_size;
    size_t  item_num;
    BOOL    is_thread_safe;
    pthread_mutex_t m_mutex;
};

LIB_BUFFER* lib_buffer_init(size_t item_size, size_t item_num, BOOL is_thread_safe);
extern GX_EXPORT void lib_buffer_free(LIB_BUFFER *);
extern GX_EXPORT void *lib_buffer_get1(LIB_BUFFER *);
template<typename T> T *lib_buffer_get(LIB_BUFFER *b)
{
	static_assert(std::is_trivially_constructible_v<T> && std::is_trivially_destructible_v<T>);
	return static_cast<T *>(lib_buffer_get1(b));
}
template<typename T> T *lib_buffer_get_u(LIB_BUFFER *b)
{
	return static_cast<T *>(lib_buffer_get1(b));
}
extern GX_EXPORT void lib_buffer_put(LIB_BUFFER *, void *item);
size_t lib_buffer_get_param(LIB_BUFFER* m_buf, PARAM_TYPE type);
