/*
 *	blocks allocator is a memory pool for stream
 */
#include "common_types.h"
#include "stream.h"
#include "blocks_allocator.h"

static size_t g_blocks_num;
static LIB_BUFFER *g_allocator;

/*
 *	blocks allocator's construct function
 *	@param
 *		blocks	indicate the number of 
 */
void blocks_allocator_init(size_t blocks)
{
	g_blocks_num = blocks;
}

/*
 *	run the blocks allocator
 *	@return
 *		-1	fail to reserve memory
 *		 0	OK
 */
int blocks_allocator_run() 
{
	g_allocator = lib_buffer_init(STREAM_ALLOC_SIZE, g_blocks_num, TRUE);
	if (NULL == g_allocator) {
		return -1;
	}
	return 0;
}

/*
 *	stop the blocks allocator
 *	@return
 *		-1	fail to stop
 *		 0	OK
 */
int blocks_allocator_stop()
{
	if (NULL == g_allocator) {
		return 0;
	}
	lib_buffer_free(g_allocator);
	g_allocator = 0;
	return 0;
}

/*
 *	blocks allocator's destruct function
 */
void blocks_allocator_free()
{
	g_blocks_num = 0;
}

/*
 *	get the blocks allocator's allocator
 */
LIB_BUFFER* blocks_allocator_get_allocator()
{
	return g_allocator;
}

