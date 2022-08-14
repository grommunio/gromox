// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/* 
 *	  stream is specified for smtp protocol
 */
#include <cassert>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <libHX/defs.h>
#include <gromox/common_types.hpp>
#include <gromox/stream.hpp>
#include <gromox/util.hpp>

#define CR			0x100
#define LF			0x101


enum {
	STREAM_EOM_WAITING = 0,
	STREAM_EOM_CRLF,
	STREAM_EOM_CRORLF,
};

static void stream_free(STREAM *);
static BOOL stream_append_node(STREAM *pstream); 

STREAM::STREAM(alloc_limiter<stream_block> *palloc) :
	allocator(palloc)
{
	auto pstream = this;
	BOOL bappend;
#ifdef _DEBUG_UMTA
	if (palloc == nullptr)
		throw std::invalid_parameter("[stream]: stream_init, param NULL");
#endif
	double_list_init(&pstream->list);

#ifdef _DEBUG_UMTA
	if (palloc->item_size - sizeof(DOUBLE_LIST_NODE) < STREAM_BLOCK_SIZE)
		throw std::invalid_parameter("[stream]: item size in stream allocator is too "
					"small in stream_init");
#endif
	/* allocate the first node in initialization */
	bappend = stream_append_node(pstream);
	if (!bappend) {
		debug_info("[stream]: Failed to allocate first node in stream_init");
		throw std::bad_alloc();
	}
	pstream->pnode_rd = pstream->pnode_wr;
}

STREAM::STREAM(const STREAM &o) :
	pnode_rd(o.pnode_rd), pnode_wr(o.pnode_wr), line_result(o.line_result),
	eom_result(o.eom_result), rd_block_pos(o.rd_block_pos),
	wr_block_pos(o.wr_block_pos), rd_total_pos(o.rd_total_pos),
	wr_total_pos(o.wr_total_pos), last_eom_parse(o.last_eom_parse),
	block_line_parse(o.block_line_parse), block_line_pos(o.block_line_pos),
	allocator(o.allocator), list(o.list), is_clone(true)
{}

STREAM &STREAM::operator=(STREAM &&o)
{
	stream_free(this);
	xcopy(o);
	o.allocator = nullptr;
	double_list_init(&o.list);
	double_list_free(&o.list);
	return *this;
}

void STREAM::xcopy(const STREAM &o)
{
	pnode_rd = o.pnode_rd;
	pnode_wr = o.pnode_wr;
	line_result = o.line_result;
	eom_result = o.eom_result;
	rd_block_pos = o.rd_block_pos;
	wr_block_pos = o.wr_block_pos;
	rd_total_pos = o.rd_total_pos;
	wr_total_pos = o.wr_total_pos;
	last_eom_parse = o.last_eom_parse;
	block_line_parse = o.block_line_parse;
	block_line_pos = o.block_line_pos;
	allocator = o.allocator;
	list = o.list;
}

/*
 *	  retrieve pointer of the line following the read pointer
 *	  @param
 *		  pstream [in]	  indicate the stream object
 *		  pbuff [out]	  for saving the line string pointer
 *	  @return		  
 *		  size of line, not include the token '\r' or '\n' 
 */
unsigned int STREAM::readline(char **ppline)
{
	auto pstream = this;
	unsigned int distance;

#ifdef _DEBUG_UMTA
	if (ppline == nullptr) {
		debug_info("[stream]: stream_readline, param NULL");
		return 0;
	}
#endif
	if (has_newline() != STREAM_LINE_AVAILABLE)
		return 0;
	distance = pstream->block_line_pos - pstream->rd_block_pos;
	*ppline = (char*)pstream->pnode_rd->pdata + pstream->rd_block_pos;
	pstream->rd_block_pos = pstream->block_line_parse;
	pstream->rd_total_pos = pstream->block_line_parse;
	pstream->line_result = STREAM_LINE_UNAVAILABLE;
	return distance;
}


/*
 *	  try to parse and mark a new line in stream
 *	  @param
 *		  pstream [in]	  indicate the stream object
 */
void STREAM::try_mark_line()
{
	auto pstream = this;
	int i, end;
	char temp1, temp2;
	DOUBLE_LIST_NODE *pnode;

	auto lr = has_newline();
	if (lr == STREAM_LINE_AVAILABLE || lr == STREAM_LINE_FAIL)
		return;
	if (pstream->block_line_parse == STREAM_BLOCK_SIZE) {
		pstream->line_result = STREAM_LINE_FAIL;
		return;
	}
	pnode = double_list_get_head(&pstream->list);
	/* lines should not overflow in the first block */
	if (pstream->pnode_rd != pnode) {
		pstream->line_result = STREAM_LINE_FAIL;
		return;
	}
	if (pnode == pstream->pnode_wr) {
		end = pstream->wr_block_pos;
	} else {
		end = STREAM_BLOCK_SIZE;
	}
	
	
	for (i=pstream->block_line_parse; i<end; i++) {
		temp1 = *((char*)pnode->pdata + i);
		switch (temp1) {
		case '\r':
			if(i > STREAM_BLOCK_SIZE - 2) {
				pstream->line_result = STREAM_LINE_FAIL;
				return;
			}
			temp2 = *((char*)pnode->pdata + i + 1);
			if (temp2 == '\n') {
				pstream->block_line_parse = i + 2;
				pstream->block_line_pos = i;
			} else {
				pstream->block_line_parse = i + 1;
				pstream->block_line_pos = i;
			}
			pstream->line_result = STREAM_LINE_AVAILABLE;
			return;
		case '\n':
			if (i > STREAM_BLOCK_SIZE - 2) {
				pstream->line_result = STREAM_LINE_FAIL;
				return;
			}
			pstream->block_line_parse = i + 1;
			pstream->block_line_pos = i;
			pstream->line_result = STREAM_LINE_AVAILABLE;
			return;
		}
	}
	
	pstream->block_line_parse = i;
	if (i == STREAM_BLOCK_SIZE) {
		pstream->line_result = STREAM_LINE_FAIL;
	}
}

/*
 *	  reset the stream object into the initial state
 *	  @param
 *		  pstream [in]	  indicate the stream object
 */
void STREAM::clear()
{
	auto pstream = this;
	DOUBLE_LIST_NODE *pnode, *phead;
#ifdef _DEBUG_UMTA
	if (allocator == nullptr)
		return;
#endif
	phead = double_list_get_head(&pstream->list);
	if (phead == nullptr)
		goto CLEAR_RETRUN;
	pnode = double_list_get_tail(&pstream->list);
	if (1 == double_list_get_nodes_num(&pstream->list)) {
		goto CLEAR_RETRUN;
	}
	while (true) {
		if (pnode != phead) {
			double_list_remove(&pstream->list, pnode);
		} else {
			break;
		}
		pstream->allocator->put(containerof(pnode, stream_block, list_node));
		pnode = double_list_get_tail(&pstream->list);
	}

 CLEAR_RETRUN:
	pstream->wr_block_pos		  = 0;
	pstream->wr_total_pos		  = 0;
	pstream->rd_block_pos		  = 0;
	pstream->rd_total_pos		  = 0;
	pstream->last_eom_parse		  = 0;
	pstream->block_line_pos		  = 0;
	pstream->block_line_parse	  = 0;
	pstream->line_result		  = 0;
	pstream->eom_result			  = 0;
	pstream->pnode_wr			  = phead;
	pstream->pnode_rd			  = phead;
}

STREAM::~STREAM()
{
	if (!is_clone)
		stream_free(this);
}

void stream_free(STREAM *pstream)
{
	DOUBLE_LIST_NODE *phead;
#ifdef _DEBUG_UMTA
	if (NULL == pstream || NULL == pstream->allocator) {
		return;
	}
#endif
	pstream->clear();
	phead = double_list_pop_front(&pstream->list);
	if (phead != nullptr)
		pstream->allocator->put(containerof(phead, stream_block, list_node));
	pstream->allocator = NULL;
	double_list_free(&pstream->list);
}

/*
 *	Append one block in stream list. Caution: This function should be invoked
 *	when the last block is fully written. a new block is needed.
 *	  @param
 *		  pstream [in]	  indicate the stream object
 *	  @return
 *		  TRUE	  success
 *		  FALSE	   fail
 */
static BOOL stream_append_node(STREAM *pstream)
{
	DOUBLE_LIST_NODE *pnode;
#ifdef _DEBUG_UMTA
	if (NULL == pstream) {
		return FALSE;
	}
#endif
	if (pstream->pnode_wr != double_list_get_tail(&pstream->list)) {
		pnode = double_list_get_after(&pstream->list,
			pstream->pnode_wr);
	} else {
		auto blk = pstream->allocator->get();
		if (blk == nullptr)
			return FALSE;
		pnode = &blk->list_node;
		pnode->pdata = (char*)pnode + sizeof(DOUBLE_LIST_NODE);
		double_list_append_as_tail(&pstream->list, pnode);
	}
	pstream->pnode_wr = pnode;
	pstream->wr_block_pos = 0;
	return TRUE;
}

/*
 *	  get a buffer in stream for writing
 *	  @param
 *		  pstream [in]	  indicate the stream object
 *		  psize [in,out]  for retrieving the size of buffer
 *	  @return			  address of buffer	   
 */
void *STREAM::get_write_buf(unsigned int *psize)
{
	auto pstream = this;
#ifdef _DEBUG_UMTA
	if (psize == nullptr) {
		debug_info("[stream]: stream_get_wrbuf, param NULL");
		return NULL;
	}
#endif
	if (pstream->wr_block_pos == STREAM_BLOCK_SIZE) {
		*psize = 0;
		return NULL;
	}
	if (*psize > STREAM_BLOCK_SIZE - pstream->wr_block_pos) {
		*psize = STREAM_BLOCK_SIZE - pstream->wr_block_pos;
	}
	return (char*)pstream->pnode_wr->pdata + pstream->wr_block_pos;
}

/*
 *	  forward the writing pointer
 *	  @param
 *		  pstream [in]	  indicate the stream object
 *		  offset		  forward offset
 *	  @return
 *		  offset actual made
 */
unsigned int STREAM::fwd_write_ptr(unsigned int offset)
{
	auto pstream = this;
#ifdef _DEBUG_UMTA
	if(offset + pstream->wr_block_pos > STREAM_BLOCK_SIZE) {
		debug_info("[stream]: offset is larger than block size in " 
				   "stream_forward_writing_ptr");
		return 0;
	}
#endif
	pstream->wr_block_pos += offset;
	pstream->wr_total_pos += offset;
	if(pstream->wr_block_pos == STREAM_BLOCK_SIZE) {
		stream_append_node(pstream);
	}
	return offset;
}

/*
 *	Backtrack the writing pointer. Caution: The backward writing pointer will
 *	truncate the stream total length.
 *	  @param
 *		  pstream [in]	  indicate the stream object
 *		  offset		  Backward offset. Caution: The offset must be smaller
 *					  than one block size.
 *	  @return
 *		  offset actual made
 */
unsigned int STREAM::rewind_write_ptr(unsigned int offset)
{
	auto pstream = this;
	if (offset > pstream->wr_total_pos)
		offset = pstream->wr_total_pos;
	if (offset > STREAM_BLOCK_SIZE)
		offset = STREAM_BLOCK_SIZE;
	if (offset > pstream->wr_block_pos) {
		pstream->pnode_wr = double_list_get_before(&pstream->list,
												   pstream->pnode_wr);
		assert(pstream->pnode_wr != nullptr);
		pstream->wr_block_pos = STREAM_BLOCK_SIZE - 
								(offset - pstream->wr_block_pos);
	} else {
		pstream->wr_block_pos -= offset;
	}
	pstream->wr_total_pos -= offset;
	if (pstream->wr_total_pos < pstream->rd_total_pos) {
		pstream->rd_block_pos = pstream->wr_block_pos;
		pstream->rd_total_pos = pstream->wr_total_pos;
		pstream->pnode_rd = pstream->pnode_wr;
	}
	if (pstream->block_line_parse > pstream->wr_total_pos) {
		pstream->block_line_parse = pstream->wr_total_pos;
		pstream->block_line_pos = pstream->wr_total_pos;
	}
	return offset;
}

/*
 *	  backward the reading pointer.
 *	  @param
 *		  pstream [in]	  indicate the stream object
 *		  offset		  Backward offset. Caution: The offset must be smaller
 *					  than one block size.
 *	  @return
 *		  offset actual made
 */
unsigned int STREAM::rewind_read_ptr(unsigned int offset)
{
	auto pstream = this;
	if (offset > pstream->rd_total_pos)
		offset = pstream->rd_total_pos;
	if (offset > STREAM_BLOCK_SIZE)
		offset = STREAM_BLOCK_SIZE;
	if (offset > pstream->rd_block_pos) {
		pstream->pnode_rd = double_list_get_before(&pstream->list,
												   pstream->pnode_rd);
		assert(pstream->pnode_rd != nullptr);
		pstream->rd_block_pos = STREAM_BLOCK_SIZE - 
								(offset - pstream->rd_block_pos);
	} else {
		pstream->rd_block_pos -= offset;
	}
	pstream->rd_total_pos -= offset;
	if (pstream->block_line_pos > pstream->rd_total_pos) {
		pstream->block_line_parse = pstream->rd_total_pos;
		pstream->block_line_pos = pstream->rd_total_pos;
	}
	return offset;
}

/*
 *	  get a buffer in stream for reading, read pointer is also forwarded
 *	  @param
 *		  pstream [in]	  indicate the stream object
 *		  psize			  for retrieving the size of buffer
 *	  @return
 *		  the address of buffer
 */
void *STREAM::get_read_buf(unsigned int *psize)
{
	auto pstream = this;
	char *ret_ptr;
#ifdef _DEBUG_UMTA
	if (psize == nullptr) {
		debug_info("[stream]: stream_get_rdbuf, param NULL");
		return NULL;
	}
#endif
	if (pstream->pnode_wr != pstream->pnode_rd) {
		ret_ptr = (char*)pstream->pnode_rd->pdata + pstream->rd_block_pos;
		if (*psize >= STREAM_BLOCK_SIZE - pstream->rd_block_pos) {
			*psize = STREAM_BLOCK_SIZE - pstream->rd_block_pos;
			pstream->rd_block_pos = 0;
			pstream->pnode_rd = double_list_get_after(&pstream->list, 
								pstream->pnode_rd);
		} else {
			pstream->rd_block_pos += *psize;
		}
		pstream->rd_total_pos += *psize;
		return ret_ptr;
	}
	if (pstream->rd_block_pos == pstream->wr_block_pos) {
		*psize = 0;
		return NULL;
	} else if (pstream->wr_block_pos - pstream->rd_block_pos < *psize) {
		*psize = pstream->wr_block_pos - pstream->rd_block_pos;
		ret_ptr = (char*)pstream->pnode_rd->pdata + pstream->rd_block_pos;
		pstream->rd_block_pos = pstream->wr_block_pos;
		pstream->rd_total_pos = pstream->wr_total_pos;
	} else {
		ret_ptr = (char*)pstream->pnode_rd->pdata + pstream->rd_block_pos;
		pstream->rd_block_pos += *psize;
		pstream->rd_total_pos += *psize;
	}
	return ret_ptr;
}

/*
 *	  backward the reading pointer after the last line, which is parsed by 
 *	  stream_try_mark_line
 *	  @param
 *		  pstream [in]	  indicate the stream object
 */
void STREAM::reset_reading()
{
	auto pstream = this;
	pstream->pnode_rd = double_list_get_head(&pstream->list);
	pstream->rd_block_pos = 0;
	pstream->rd_total_pos = 0;
}

/*
 *	copy a line from the stream into the pbuff, a line is identify by the 
 *	trailing '\r' or '\n' or '\r\n', if there is a leading '\n' at the 
 *	beginning of the stream, we will skip it.
 *
 *	@param
 *		pstream [in]		the stream
 *		pbuff	[in]		copy the line into the buffer
 *		psize	[in/out]	the size of the buffer, the length
 *							of the line not including the '\r'
 *							or '\n'
 *
 *	@return
 *		STREAM_COPY_OK		ok, get a line
 *		STREAM_COPY_PART	the line is longer than the buffer size,
 *							copy unfinished line into buffer
 *		STREAM_COPY_TERM	meet the stream end but does not meet
 *							the '\r' or '\n', in this case, we copy
 *							the unterminated line into the pbuff
 *		STREAM_COPY_END		like EOF in ASCI-C std read or write file
 */
int STREAM::copyline(char *pbuff, unsigned int *psize)
{
	auto pstream = this;
	int i, end, actual_size;
	int buf_size, state = 0;
	DOUBLE_LIST_NODE *pnode;
	char tmp;

#ifdef _DEBUG_UMTA
	if (pbuff == nullptr || psize == nullptr) {
		debug_info("[stream]: stream_copyline, param NULL");
		return STREAM_COPY_ERROR;
	}

	if (*psize <= 0 ) {
		*psize = 0;
		return STREAM_COPY_ERROR;
	}
#endif
	

	/* 
	if the read pointer has reached the end of the stream, return 
	immediately 
	*/
	if (pstream->rd_total_pos >= pstream->wr_total_pos) {
		*psize	= 0;
		return STREAM_COPY_END;
	}

	/* skip the '\n' at the beginning of the stream */
	if (0 == pstream->rd_total_pos && *((char*)pstream->pnode_rd->pdata)
				== '\n') {
		debug_info("[stream]: skip \\n at the leading position of the stream "
				"in stream_copyline");
		pstream->rd_block_pos	= 1;
		pstream->rd_total_pos	= 1;
	}


	buf_size = *psize;
	buf_size --;  /* reserve last byte for '\0' */
	
	/* if the read node is the last node of the mem file */
	if (pstream->pnode_rd == pstream->pnode_wr) {
		end = pstream->wr_total_pos%STREAM_BLOCK_SIZE;
		pnode = pstream->pnode_rd;
		for (i=pstream->rd_block_pos; i<end; i++) {
			tmp = *((char*)pnode->pdata + i);
			if (tmp == '\n') {
				state = LF;
				break;
			}
			if (tmp == '\r') {
				state = CR;
				break;
			}
		}

		actual_size = i - pstream->rd_block_pos;
		if (actual_size > buf_size) {
			actual_size = buf_size;
			*psize = actual_size;
			memcpy(pbuff, (char*)pnode->pdata + pstream->rd_block_pos,
				actual_size);
			pbuff[actual_size] = '\0';
			pstream->rd_block_pos += actual_size;
			pstream->rd_total_pos += actual_size;
			return STREAM_COPY_PART;
		}
		*psize = actual_size;
		memcpy(pbuff, (char*)pnode->pdata + pstream->rd_block_pos, actual_size);
		pbuff[actual_size] = '\0';

		/* if the end of the stream is not terminated with \r\n */
		if (i == end) {
			pstream->rd_block_pos = end;
			pstream->rd_total_pos = pstream->wr_total_pos;
			return STREAM_COPY_TERM;
		}
		
		if (state == LF || i + 1 == end) {
			pstream->rd_block_pos += actual_size + 1;
			pstream->rd_total_pos += actual_size + 1;
			return STREAM_COPY_OK;
		}

		if (*((char*)pnode->pdata + i + 1) == '\n') {
			pstream->rd_block_pos += actual_size + 2;
			pstream->rd_total_pos += actual_size + 2;
		} else {
			pstream->rd_block_pos += actual_size + 1;
			pstream->rd_total_pos += actual_size + 1;
		}
		return STREAM_COPY_OK;
	}

	pnode = pstream->pnode_rd;
	for (i = pstream->rd_block_pos; i < STREAM_BLOCK_SIZE; i++) {
		tmp = *((char *)pnode->pdata + i);
		if (tmp == '\n') {
			state = LF;
			break;
		}
		if (tmp == '\r') {
			state = CR;
			break;
		}
	}
	if (i != STREAM_BLOCK_SIZE) {
		actual_size = i - pstream->rd_block_pos;
		if (actual_size > buf_size) {
			actual_size = buf_size;
			*psize = actual_size;
			memcpy(pbuff, (char *)pnode->pdata + pstream->rd_block_pos,
				actual_size);
			pbuff[actual_size] = '\0';
			pstream->rd_block_pos += actual_size;
			pstream->rd_total_pos += actual_size;
			return STREAM_COPY_PART;
		}

		*psize = actual_size;
		memcpy(pbuff, (char *)pnode->pdata + pstream->rd_block_pos, actual_size);
		pbuff[actual_size] = '\0';

		if (state == LF) {
			pstream->rd_block_pos += actual_size + 1;
			pstream->rd_total_pos += actual_size + 1;
			if (pstream->rd_block_pos == STREAM_BLOCK_SIZE) {
				pstream->pnode_rd = double_list_get_after(
					&pstream->list, pstream->pnode_rd);
				pstream->rd_block_pos = 0;
			}
			return STREAM_COPY_OK;
		}
		if (state != CR)
			return STREAM_COPY_OK;
		if (i + 1 == STREAM_BLOCK_SIZE) {
			pstream->pnode_rd = double_list_get_after(
				&pstream->list, pstream->pnode_rd);
			pstream->rd_block_pos = 0;

			if (*((char *)pstream->pnode_rd->pdata) == '\n') {
				pstream->rd_block_pos = 1;
				pstream->rd_total_pos += actual_size + 2;
			} else {
				pstream->rd_total_pos += actual_size + 1;
			}
		} else if (static_cast<char *>(pnode->pdata)[i+1] != '\n') {
			pstream->rd_block_pos += actual_size + 1;
			pstream->rd_total_pos += actual_size + 1;
		} else {
			pstream->rd_total_pos += actual_size + 2;
			if (i + 2 == STREAM_BLOCK_SIZE) {
				pstream->pnode_rd = double_list_get_after(
					&pstream->list, pstream->pnode_rd);
				pstream->rd_block_pos = 0;
			} else {
				pstream->rd_block_pos += actual_size + 2;
			}
		}
		return STREAM_COPY_OK;
	}
	/* span two blocks */
	actual_size = STREAM_BLOCK_SIZE - pstream->rd_block_pos;
	pnode = double_list_get_after(&pstream->list, pstream->pnode_rd);
	if (pnode == pstream->pnode_wr) {
		end = pstream->wr_total_pos % STREAM_BLOCK_SIZE;
	} else {
		end = STREAM_BLOCK_SIZE;
	}
	for (i = 0; i < end; i++) {
		tmp = *((char*)pnode->pdata + i);
		if (tmp == '\n') {
			state = LF;
			break;
		}
		if (tmp == '\r') {
			state = CR;
			break;
		}
	}
	actual_size += i;
	if (actual_size > buf_size) {
		actual_size = buf_size;
		*psize = actual_size;
		if (actual_size >= 0 && static_cast<size_t>(actual_size) >= STREAM_BLOCK_SIZE - pstream->rd_block_pos) {
			i = actual_size - (STREAM_BLOCK_SIZE -
					pstream->rd_block_pos);
			memcpy(pbuff, (char *)pstream->pnode_rd->pdata +
				pstream->rd_block_pos, STREAM_BLOCK_SIZE -
				pstream->rd_block_pos);
			pstream->pnode_rd = double_list_get_after(&pstream->list,
				pstream->pnode_rd);
			memcpy(pbuff + STREAM_BLOCK_SIZE - pstream->rd_block_pos,
			       (char *)pstream->pnode_rd->pdata, i);
			pstream->rd_block_pos = i;
			pstream->rd_total_pos += actual_size;
		} else {
			memcpy(pbuff, (char *)pstream->pnode_rd->pdata +
				pstream->rd_block_pos, actual_size);
			pstream->rd_block_pos += actual_size;
			pstream->rd_total_pos += actual_size;
		}
		pbuff[actual_size] = '\0';
		return STREAM_COPY_PART;
	}

	*psize = actual_size;
	memcpy(pbuff, (char*)pstream->pnode_rd->pdata +
		   pstream->rd_block_pos, STREAM_BLOCK_SIZE -
		   pstream->rd_block_pos);
	pstream->pnode_rd = double_list_get_after(&pstream->list, pstream->pnode_rd);
	memcpy(pbuff + STREAM_BLOCK_SIZE - pstream->rd_block_pos,
	       (char *)pstream->pnode_rd->pdata, i);
	pbuff[actual_size] = '\0';

	if (i == end) {
		return STREAM_COPY_TERM;
	}
	if (state == LF || (pstream->rd_total_pos + actual_size + 1)
	    == pstream->wr_total_pos) {
		pstream->rd_block_pos = i + 1;
		pstream->rd_total_pos += actual_size + 1;
		return STREAM_COPY_OK;
	}
	if (*((char *)pstream->pnode_rd->pdata + i + 1) == '\n') {
		pstream->rd_block_pos = i + 2;
		pstream->rd_total_pos += actual_size + 2;
	} else {
		pstream->rd_block_pos = i + 1;
		pstream->rd_total_pos += actual_size + 1;
	}
	return STREAM_COPY_OK;
}

/*
 *	peek the content of stream into buff, and read pointer will not be moved 
 *	@param
 *		pstream [in]			stream object
 *		pbuff					buffer for retrieving content
 *		size					size of buffer
 *	@return
 *		length of content retrieved
 */
unsigned int STREAM::peek_buffer(char *pbuff, unsigned int size) const
{
	auto pstream = this;
	unsigned int actual_size;

#ifdef _DEBUG_UMTA
	if (pbuff == nullptr) {
		debug_info("[stream]: stream_peek_buffer, param NULL");
		return 0;
	}
#endif
	

	/* 
	if the read pointer has reached the end of the stream, return 
	immediately 
	*/
	if (pstream->rd_total_pos >= pstream->wr_total_pos) {
		return 0;
	}
	
	actual_size = pstream->wr_total_pos - pstream->rd_total_pos;
	const DOUBLE_LIST_NODE *pnode = pstream->pnode_rd;
	
	/* if the read node is the last node of the mem file */
	if (pstream->pnode_rd == pstream->pnode_wr) {
		if (actual_size >= size) {
			memcpy(pbuff, static_cast<char *>(pnode->pdata) + pstream->rd_total_pos, size);
			return size;
		}
		memcpy(pbuff, static_cast<char *>(pnode->pdata) + pstream->rd_total_pos, actual_size);
		return actual_size;
	}
	unsigned int tmp_size = STREAM_BLOCK_SIZE - pstream->rd_block_pos;
	if (tmp_size >= size) {
		memcpy(pbuff, static_cast<char *>(pnode->pdata) + pstream->rd_total_pos, size);
		return size;
	}
	memcpy(pbuff, static_cast<char *>(pnode->pdata) + pstream->rd_total_pos, tmp_size);
	while ((pnode = double_list_get_after(&pstream->list,
		pnode)) != pstream->pnode_wr) {
		if (tmp_size + STREAM_BLOCK_SIZE >= size) {
			memcpy(pbuff + tmp_size, pnode->pdata, size - tmp_size);
			return size;
		}
		memcpy(pbuff + tmp_size, pnode->pdata, STREAM_BLOCK_SIZE);
		tmp_size += STREAM_BLOCK_SIZE;
	}
	if (tmp_size + pstream->wr_block_pos >= size) {
		memcpy(pbuff + tmp_size, pnode->pdata, size - tmp_size);
		return size;
	}
	memcpy(pbuff + tmp_size, pnode->pdata, pstream->wr_block_pos);
	return actual_size;
}

/*
 *	dump content in stream into file
 *	@param
 *		pstream [in]			stream object
 *		fd						file descriptor
 *	@return
 *		STREAM_DUMP_FAIL		fail
 *		STREAM_DUMP_OK			OK
 */
int STREAM::dump(int fd)
{
	void *pbuff;
	unsigned int size = STREAM_BLOCK_SIZE;

	reset_reading();
	while ((pbuff = get_read_buf(&size)) != nullptr) {
		auto wr_result = ::write(fd, pbuff, size);
		if (wr_result < 0 || static_cast<size_t>(wr_result) != size)
			return STREAM_DUMP_FAIL;
		size = STREAM_BLOCK_SIZE;
	}
	return STREAM_DUMP_OK;
}


/*
 *	  forward the reading pointer.
 *	  @param
 *		  pstream [in]	  indicate the stream object
 *		  offset		  Forward offset. Caution: The offset must be smaller
 *					  than one block size.
 *	  @return
 *		  offset actual made
 */
unsigned int STREAM::fwd_read_ptr(unsigned int offset)
{
	auto pstream = this;
	if (offset > pstream->wr_total_pos - pstream->rd_total_pos &&
	    offset < STREAM_BLOCK_SIZE) {
		offset = pstream->wr_total_pos - pstream->rd_total_pos;
	} else if (offset > STREAM_BLOCK_SIZE) {
		offset = STREAM_BLOCK_SIZE;
	}
	if (offset > STREAM_BLOCK_SIZE - pstream->rd_block_pos) {
		pstream->pnode_rd = double_list_get_after(&pstream->list,
			pstream->pnode_rd);
		pstream->rd_block_pos = offset - (STREAM_BLOCK_SIZE -
			pstream->rd_block_pos);
	} else {
		pstream->rd_block_pos += offset;
	}
	pstream->rd_total_pos += offset;
	if (pstream->block_line_pos > pstream->rd_total_pos) {
		pstream->block_line_parse = pstream->rd_total_pos;
		pstream->block_line_pos = pstream->rd_total_pos;
	}
	return offset;
}

int STREAM::write(const void *pbuff, size_t size)
{
	unsigned int buff_size, actual_size;
	size_t offset;

#ifdef _DEBUG_UMTA
	if (pbuff == nullptr) {
		debug_info("[stream]: stream_write, param NULL");
		return STREAM_WRITE_FAIL;
	}
#endif

	offset = 0;
	while (offset < size) {
		buff_size = STREAM_BLOCK_SIZE;
		void *pstream_buff = get_write_buf(&buff_size);
		if (pstream_buff == nullptr)
			return STREAM_WRITE_FAIL;
		actual_size = (size - offset > buff_size)?buff_size:(size - offset);
		memcpy(pstream_buff, static_cast<const char *>(pbuff) + offset, actual_size);
		fwd_write_ptr(actual_size);
		offset += actual_size;
	}
	return STREAM_WRITE_OK;
}

/*
 *	  check if there's a new line in the stream after the read pointer
 *	  @param
 *		  pstream [in]	  indicate the stream object
 *	  @return
 *		  STREAM_EOM_NONE		  can not find <crlf>.<crlf>
 *		  STREAM_EOM_NET		  find <crlf>.<crlf> at the end of stream
 *		  STREAM_EOM_DIRTY		  find <crlf>.<crlf> within stream
 */
int STREAM::has_eom()
{
	auto pstream = this;
	if (STREAM_EOM_WAITING == pstream->eom_result) {
		return STREAM_EOM_NONE;
	} else if (STREAM_EOM_CRLF == pstream->eom_result) {
		return pstream->last_eom_parse == pstream->wr_total_pos - 3 ?
		       STREAM_EOM_NET : STREAM_EOM_DIRTY;
	} else if (STREAM_EOM_CRORLF == pstream->eom_result) {
		return pstream->last_eom_parse == pstream->wr_total_pos - 2 ?
		       STREAM_EOM_NET : STREAM_EOM_DIRTY;
	}
	return STREAM_EOM_ERROR;
}

/*
 *	  mark the <crlf>.<crlf> in stream if it is found
 *	  @param
 *		  pstream [in]	  indicate the stream object
 *
 */
void STREAM::try_mark_eom()
{
	auto pstream = this;
	int i, j;
	int from_pos;
	int until_pos;
	int block_deep;
	int block_offset;
	char *pbuff, temp_buff[6];
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	
	if (STREAM_EOM_WAITING != pstream->eom_result) {
		return;
	}
	
	block_offset = pstream->last_eom_parse % STREAM_BLOCK_SIZE;
	
	block_deep = pstream->wr_total_pos / STREAM_BLOCK_SIZE - 
				 pstream->last_eom_parse / STREAM_BLOCK_SIZE;
	
	pnode = pstream->pnode_wr;
	for (i=0; i<=block_deep; i++) {
		if (i == block_deep) {
			until_pos = block_offset;
		} else {
			until_pos = 0;
		}
		if (0 == i) {
			from_pos = pstream->wr_block_pos - 1;
		} else {
			from_pos = STREAM_BLOCK_SIZE - 1;
		}
		for (j=from_pos; j>=until_pos; j--) {
			pbuff = (char*)pnode->pdata;
			if (pbuff[j] != '.')
				continue;
			if (0 == j) {
				pnode1 = double_list_get_before(&pstream->list, pnode);
				if (NULL == pnode1) {
					goto NONE_EOM;
				}
				temp_buff[0] = ((char*)pnode1->pdata)[STREAM_BLOCK_SIZE - 2];
				temp_buff[1] = ((char*)pnode1->pdata)[STREAM_BLOCK_SIZE - 1];
				temp_buff[2] = '.';
			} else if (1 == j) {
				pnode1 = double_list_get_before(&pstream->list, pnode);
				if (NULL == pnode1) {
					goto NONE_EOM;
				}
				temp_buff[0] = ((char *)pnode1->pdata)[STREAM_BLOCK_SIZE-1];
				temp_buff[1] = pbuff[0];
				temp_buff[2] = '.';
			} else {
				temp_buff[0] = pbuff[j-2];
				temp_buff[1] = pbuff[j-1];
				temp_buff[2] = '.';
			}

			if (from_pos - 1 == j) {
				temp_buff[3] = pbuff[j + 1];
				if (0 == i) {
					temp_buff[4] = '\0';
				} else {
					pnode1 = double_list_get_after(&pstream->list, pnode);
					if (NULL == pnode1) {
						temp_buff[4] = '\0';
					} else {
						temp_buff[4] = ((char *)pnode1->pdata)[0];
					}
				}
			} else if (from_pos == j) {
				if (0 == i) {
					continue;
				} else {
					pnode1 = double_list_get_after(&pstream->list, pnode);
					if (NULL == pnode1) {
						continue;
					} else {
						temp_buff[3] = ((char *)pnode1->pdata)[0];
						temp_buff[4] = ((char *)pnode1->pdata)[1];
					}
				}
			} else {
				temp_buff[3] = pbuff[j + 1];
				temp_buff[4] = pbuff[j + 2];
			}

			temp_buff[5] = '\0';
			if (0 == strcmp(temp_buff, "\r\n.\r\n")) {
				pstream->eom_result = STREAM_EOM_CRLF;
				pstream->last_eom_parse = (pstream->wr_total_pos /
					STREAM_BLOCK_SIZE - i) * STREAM_BLOCK_SIZE + j;
				return;

			} else if (0 == strcmp(temp_buff + 1, "\n.\n") ||
			     0 == strcmp(temp_buff + 1, "\r.\r")) {
				pstream->eom_result = STREAM_EOM_CRORLF;
				pstream->last_eom_parse = (pstream->wr_total_pos /
					STREAM_BLOCK_SIZE - i) * STREAM_BLOCK_SIZE + j;
				return;
			}
		}
		pnode = double_list_get_before(&pstream->list, pnode);
		if (NULL == pnode) {
			goto NONE_EOM;
		}
	}
 NONE_EOM:
	if (pstream->wr_total_pos >= 2) {
		pstream->last_eom_parse = pstream->wr_total_pos - 2;
	} else {
		pstream->last_eom_parse = 0;
	}
	return;
}

/*
 *	  split stream into two according <crlf>.<crlf>
 *	  @param
 *		  pstream [in, out]	   indicate the stream object
 *		  pstream_second [in, out] second part of stream if not NULL
 *
 */
void STREAM::split_eom(STREAM *pstream_second)
{
	auto pstream = this;
	size_t blocks, i, fake_pos;
	unsigned int size;
	void *pbuff;
	DOUBLE_LIST_NODE *pnode;
	
	if (STREAM_EOM_WAITING == pstream->eom_result) {
		return;
	} else if (STREAM_EOM_CRLF == pstream->eom_result) {
		fake_pos = pstream->last_eom_parse + 3;
	} else if (STREAM_EOM_CRORLF == pstream->eom_result) {
		fake_pos = pstream->last_eom_parse + 2;
	} else {
		return;
	}

	blocks = pstream->wr_total_pos / STREAM_BLOCK_SIZE -
				fake_pos / STREAM_BLOCK_SIZE;
	pnode = pstream->pnode_wr;

	for (i=0; i<blocks; i++) {
		pnode = double_list_get_before(&pstream->list, pnode);
		if (NULL == pnode) {
			return;
		}
	}

	if (NULL != pstream_second) {
		STREAM fake_stream = *pstream;
		fake_stream.rd_total_pos = fake_pos;
		fake_stream.rd_block_pos = fake_pos % STREAM_BLOCK_SIZE;
		fake_stream.pnode_rd = pnode;
		pstream_second->clear();
		size = STREAM_BLOCK_SIZE;
		while ((pbuff = fake_stream.get_read_buf(&size)) != nullptr) {
			pstream_second->write(pbuff, size);
			size = STREAM_BLOCK_SIZE;
		}
	
	}
	
	blocks = pstream->wr_total_pos / STREAM_BLOCK_SIZE -
				pstream->last_eom_parse / STREAM_BLOCK_SIZE;
	pnode = pstream->pnode_wr;

	for (i=0; i<blocks; i++) {
		pnode = double_list_get_before(&pstream->list, pnode);
		if (NULL == pnode) {
			return;
		}
	}
	pstream->pnode_wr = pnode;
	pstream->wr_total_pos = pstream->last_eom_parse;
	pstream->wr_block_pos = pstream->last_eom_parse % STREAM_BLOCK_SIZE;
	pstream->eom_result = STREAM_EOM_WAITING;
	pstream->last_eom_parse = 0;
}
