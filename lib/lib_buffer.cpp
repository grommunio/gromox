// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <gromox/defs.h>
#include <gromox/lib_buffer.hpp>
#include <gromox/util.hpp>

static constexpr auto wsize_al = roundup(WSIZE, sizeof(std::max_align_t));

/*
 *	init a buffer pool with specified item size and number
 *
 *	@param	
 *		item_size	the size of the elemenet buffer size
 *		item_num	the number of element buffer
 *
 *	@return			
 *		pointer to LIB_BUFFER	structure
 *		NULL if error happened
 */
LIB_BUFFER::LIB_BUFFER(size_t isize, size_t inum, BOOL thrsafe)
{
	void*	head_listp		= NULL;
	
	if (isize <= 0 || inum <= 0)
		throw std::invalid_argument("[lib_buffer]: lib_buffer_init, invalid parameter");
	auto item_size_al = roundup(isize, sizeof(std::max_align_t));
	head_listp = malloc((item_size_al + wsize_al) * inum);
	if (head_listp == nullptr) {
		struct bad_alloc2 : public std::bad_alloc {
			virtual const char *what() const noexcept {
				return "[lib_buffer]: lib_buffer_init, malloc head_listp fail";
			}
		};
		throw bad_alloc2();
	}

	memset(head_listp, 0, (item_size_al + wsize_al) * inum);
	auto lib_buffer = this;
	lib_buffer->heap_list_head	= head_listp;
	lib_buffer->cur_heap_head	= head_listp;

	lib_buffer->free_list_head	= NULL;
	lib_buffer->free_list_size	= 0;
	lib_buffer->allocated_num	= 0;
	lib_buffer->item_size = isize;
	lib_buffer->item_num = inum;
	lib_buffer->is_thread_safe = thrsafe;
}

std::unique_ptr<LIB_BUFFER> LIB_BUFFER::create(size_t isize,
    size_t inum, BOOL is_thread_safe) try
{
	if (isize <= 0 || inum <= 0) {
		debug_info("[lib_buffer]: lib_buffer_init, invalid parameter");
		return NULL;
	}
	return std::make_unique<LIB_BUFFER>(isize, inum, is_thread_safe);
} catch (const std::bad_alloc &e) {
	fprintf(stderr, "E-1658: ENOMEM\n");
	debug_info(e.what());
	return nullptr;
} catch (const std::invalid_argument &e) {
	fprintf(stderr, "E-1669: EINVAL: %s\n", e.what());
	debug_info(e.what());
	return nullptr;
}

/*
 *	free a buffer pool
 *	
 *	@param	
 *		m_buf [in]	the buffer pool to release
 *
 */
LIB_BUFFER::~LIB_BUFFER()
{
	auto m_buf = this;
	free(m_buf->heap_list_head);
}

/*
 *	allocate a buffer from the specified buffer pool the buffer size
 *	is determined when lib_buffer_init
 *
 *	@param	
 *		m_buf [in]	the buffer pool where to allocate the buffer
 *
 *	@return		
 *		the pointer to the new allocated buffer NULL if we allocate
 *		more buffers than specified in lib_buffer_init.
 */
void *LIB_BUFFER::get_raw()
{
	auto m_buf = this;
	void	*ret_buf	= NULL;
	char	*phead		= NULL;

	std::unique_lock tlock(m_buf->m_mutex, std::defer_lock_t{});
	if (m_buf->is_thread_safe)
		tlock.lock();
	auto item_size_al = roundup(m_buf->item_size, sizeof(std::max_align_t));
	if (m_buf->free_list_size > 0) {
		phead	= (char *)m_buf->free_list_head;
		ret_buf = m_buf->free_list_head;
		memcpy(&phead, phead + item_size_al, sizeof(void *));
#ifdef _DEBUG_UMTA
		/* check memory */
		memset(ret_buf + item_size_al, 0, sizeof(void *));
#endif

		m_buf->free_list_head  = phead;
		m_buf->free_list_size -= 1;
		m_buf->allocated_num  += 1;
		return ret_buf;
	} 
	
	if (m_buf->allocated_num >= m_buf->item_num) {
		debug_info("[lib_buffer]: the total allocated buffer num"
			" is larger than the initializing");
		return NULL;
	}

	phead	= (char*)m_buf->cur_heap_head;
	ret_buf = m_buf->cur_heap_head;
	memset(phead + item_size_al, 0, sizeof(void *));
	phead  += item_size_al + wsize_al;
	m_buf->cur_heap_head	= phead;
	m_buf->allocated_num	+= 1;
	return ret_buf;
}
/*
 *	return the buffer to the buffer pool
 *
 *	@param	
 *		m_buf [in]	the buffer pool
 *		item  [in]	the buffer to return
 *
 */
void LIB_BUFFER::put_raw(void *item)
{
	auto m_buf = this;
	char *pcur_item = NULL;
#ifdef _DEBUG_UMTA
	void *pzero;
#endif
	if (item == nullptr)
		return;
	pcur_item	= (char *)item;
	auto item_size_al = roundup(m_buf->item_size, sizeof(std::max_align_t));
	memset(pcur_item, 0, item_size_al);
#ifdef _DEBUG_UMTA
	/* memory check */
	memcpy(&pzero, pcur_item + item_size_al, sizeof(void *));
	if (pzero != 0) {
		debug_info("[lib_buffer]: lib_buffer memory dump");
	}
#endif

	std::unique_lock tlock(m_buf->m_mutex, std::defer_lock_t{});
	if (m_buf->is_thread_safe)
		tlock.lock();
	memcpy(pcur_item + item_size_al, &m_buf->free_list_head, sizeof(void *));
	m_buf->free_list_head = item;
	m_buf->free_list_size += 1;
	m_buf->allocated_num  -= 1;
}
