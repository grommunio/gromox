// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  blocks allocator is a memory pool for stream
 */
#include <gromox/common_types.hpp>
#include <gromox/stream.hpp>
#include <gromox/util.hpp>
#include "blocks_allocator.h"

static size_t g_blocks_num;
static LIB_BUFFER g_allocator;

void blocks_allocator_init(size_t blocks)
{
    g_blocks_num = blocks;
}

int blocks_allocator_run() 
{
	g_allocator = LIB_BUFFER(STREAM_ALLOC_SIZE, g_blocks_num);
    return 0;
}

LIB_BUFFER* blocks_allocator_get_allocator()
{
	return g_allocator.get();
}
