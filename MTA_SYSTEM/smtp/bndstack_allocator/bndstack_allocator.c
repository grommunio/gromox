/*
 *	 stack files allocator is a memory pool for bdn stack
 */
#include "common_types.h"
#include "vstack.h"
#include "bndstack_allocator.h"

static size_t g_item_num;
static LIB_BUFFER *g_allocator;

/*
 *	  stack allocator's construct function
 *	  @param
 *		  items	   indicate the number of 
 */
void bndstack_allocator_init(size_t items)
{
	g_item_num = items;
}

/*
 *	  run the stack allocator
 *	  @return
 *		  -1	fail to reserve memory
 *		   0	OK
 */
int bndstack_allocator_run()
{
	g_allocator = vstack_allocator_init(sizeof(BOUNDARY_STRING), g_item_num, TRUE);
	if (NULL == g_allocator) {
		return -1;
	}
	return 0;
}

/*
 *	  stop the stack allocator
 *	  @return
 *		   0	OK
 */
int bndstack_allocator_stop()
{
	if (NULL == g_allocator) {
		return 0;
	}
	lib_buffer_free(g_allocator);
	g_allocator = NULL;
	return 0;
}

/*
 *	  stack allocator's destruct function
 */
void bndstack_allocator_free()
{
	g_item_num = 0;
}

/*
 *	  get the stack allocator's allocator
 */
LIB_BUFFER* bndstack_allocator_get_allocator()
{
	return g_allocator;
}

