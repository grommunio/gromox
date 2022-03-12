// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  blocks allocator is a memory pool for stream
 */
#include <memory>
#include <gromox/common_types.hpp>
#include <gromox/stream.hpp>
#include <gromox/util.hpp>
#include "blocks_allocator.h"

static size_t g_blocks_num;
static std::unique_ptr<LIB_BUFFER> g_allocator;

void blocks_allocator_init(size_t blocks)
{
    g_blocks_num = blocks;
}

int blocks_allocator_run() 
{
	g_allocator = LIB_BUFFER::create(STREAM_ALLOC_SIZE, g_blocks_num);
    if (NULL == g_allocator) {
        return -1;
    }
    return 0;
}

void blocks_allocator_stop()
{
	g_allocator.reset();
    g_blocks_num = 0;
}

LIB_BUFFER* blocks_allocator_get_allocator()
{
	return g_allocator.get();
}
