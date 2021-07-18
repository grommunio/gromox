// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  blocks allocator is a memory pool for stream
 */
#include <gromox/common_types.hpp>
#include <gromox/stream.hpp>
#include "blocks_allocator.h"

static size_t g_blocks_num;
static LIB_BUFFER *g_allocator;

void blocks_allocator_init(size_t blocks)
{
    g_blocks_num = blocks;
}

int blocks_allocator_run() 
{
    g_allocator = lib_buffer_init(STREAM_ALLOC_SIZE, g_blocks_num, TRUE);
    if (NULL == g_allocator) {
        return -1;
    }
    return 0;
}

int blocks_allocator_stop()
{
    if (NULL == g_allocator) {
        return 0;
    }
    lib_buffer_free(g_allocator);
	g_allocator = nullptr;
    return 0;
}

void blocks_allocator_free()
{
    g_blocks_num = 0;
}

LIB_BUFFER* blocks_allocator_get_allocator()
{
    return g_allocator;
}

