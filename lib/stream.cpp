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

using namespace gromox;

enum {
	STREAM_EOM_WAITING = 0,
	STREAM_EOM_CRLF,
	STREAM_EOM_CRORLF,
};

static BOOL stream_append_node(STREAM *pstream); 

STREAM::STREAM() : list(std::make_shared<std::list<stream_block>>())
{
	auto pstream = this;
	BOOL bappend;
	/* allocate the first node in initialization */
	bappend = stream_append_node(pstream);
	if (!bappend) {
		mlog(LV_DEBUG, "stream: Failed to allocate first node in stream_init");
		throw std::bad_alloc();
	}
	pstream->pnode_rd = pstream->pnode_wr;
}

STREAM &STREAM::operator=(STREAM &&o)
{
	clear();
	std::swap(pnode_rd, o.pnode_rd);
	std::swap(pnode_wr, o.pnode_wr);
	std::swap(line_result, o.line_result);
	std::swap(eom_result, o.eom_result);
	std::swap(rd_block_pos, o.rd_block_pos);
	std::swap(wr_block_pos, o.wr_block_pos);
	std::swap(rd_total_pos, o.rd_total_pos);
	std::swap(wr_total_pos, o.wr_total_pos);
	std::swap(last_eom_parse, o.last_eom_parse);
	std::swap(block_line_parse, o.block_line_parse);
	std::swap(block_line_pos, o.block_line_pos);
	std::swap(list, o.list);
	return *this;
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
		mlog(LV_DEBUG, "stream: stream_readline, param NULL");
		return 0;
	}
#endif
	if (has_newline() != STREAM_LINE_AVAILABLE)
		return 0;
	distance = pstream->block_line_pos - pstream->rd_block_pos;
	*ppline = &pnode_rd->cdata[rd_block_pos];
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

	auto lr = has_newline();
	if (lr == STREAM_LINE_AVAILABLE || lr == STREAM_LINE_FAIL)
		return;
	if (pstream->block_line_parse == STREAM_BLOCK_SIZE) {
		pstream->line_result = STREAM_LINE_FAIL;
		return;
	}
	auto &rlist = *pstream->list;
	auto pnode = rlist.begin();
	/* lines should not overflow in the first block */
	if (pstream->pnode_rd != pnode) {
		pstream->line_result = STREAM_LINE_FAIL;
		return;
	}
	end = pnode == pstream->pnode_wr ? pstream->wr_block_pos : STREAM_BLOCK_SIZE;
	for (i=pstream->block_line_parse; i<end; i++) {
		auto temp1 = pnode->cdata[i];
		switch (temp1) {
		case '\r': {
			if(i > STREAM_BLOCK_SIZE - 2) {
				pstream->line_result = STREAM_LINE_FAIL;
				return;
			}
			auto temp2 = pnode->cdata[i+1];
			if (temp2 == '\n') {
				pstream->block_line_parse = i + 2;
				pstream->block_line_pos = i;
			} else {
				pstream->block_line_parse = i + 1;
				pstream->block_line_pos = i;
			}
			pstream->line_result = STREAM_LINE_AVAILABLE;
			return;
		}
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
	if (i == STREAM_BLOCK_SIZE)
		pstream->line_result = STREAM_LINE_FAIL;
}

/*
 *	  reset the stream object into the initial state
 *	  @param
 *		  pstream [in]	  indicate the stream object
 */
void STREAM::clear()
{
	auto &rlist = *list;
	auto pstream = this;
	if (rlist.size() > 1) {
		std::list<stream_block> keep;
		keep.splice(keep.end(), rlist, rlist.begin());
		rlist = std::move(keep);
	}
	auto phead = rlist.begin();
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

/*
 *	Append one block in stream list. Caution: This function should be invoked
 *	when the last block is fully written. a new block is needed.
 *	  @param
 *		  pstream [in]	  indicate the stream object
 *	  @return
 *		  TRUE	  success
 *		  FALSE	   fail
 */
static BOOL stream_append_node(STREAM *pstream) try
{
	std::list<stream_block>::iterator pnode;
#ifdef _DEBUG_UMTA
	if (pstream == nullptr)
		return FALSE;
#endif
	auto &rlist = *pstream->list;
	if (rlist.size() > 0 && &*pstream->pnode_wr != &*rlist.rbegin()) {
		pnode = std::next(pstream->pnode_wr);
	} else {
		try {
			rlist.emplace_back();
			pnode = std::prev(rlist.end());
		} catch (const std::bad_alloc &) {
			return false;
		}
	}
	pstream->pnode_wr = pnode;
	pstream->wr_block_pos = 0;
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
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
		mlog(LV_DEBUG, "stream: stream_get_wrbuf, param NULL");
		return NULL;
	}
#endif
	if (pstream->wr_block_pos == STREAM_BLOCK_SIZE) {
		*psize = 0;
		return NULL;
	}
	if (*psize > STREAM_BLOCK_SIZE - pstream->wr_block_pos)
		*psize = STREAM_BLOCK_SIZE - pstream->wr_block_pos;
	return &pnode_wr->cdata[wr_block_pos];
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
		mlog(LV_DEBUG, "stream: offset is larger than block size in " 
				   "stream_forward_writing_ptr");
		return 0;
	}
#endif
	pstream->wr_block_pos += offset;
	pstream->wr_total_pos += offset;
	if (pstream->wr_block_pos == STREAM_BLOCK_SIZE)
		stream_append_node(pstream);
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
	auto &rlist = *list;

	if (offset > pstream->wr_total_pos)
		offset = pstream->wr_total_pos;
	if (offset > STREAM_BLOCK_SIZE)
		offset = STREAM_BLOCK_SIZE;
	if (offset > pstream->wr_block_pos) {
		assert(pnode_wr != rlist.begin());
		--pnode_wr;
		pstream->wr_block_pos = STREAM_BLOCK_SIZE - (offset - pstream->wr_block_pos);
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
	auto &rlist = *list;

	if (offset > pstream->rd_total_pos)
		offset = pstream->rd_total_pos;
	if (offset > STREAM_BLOCK_SIZE)
		offset = STREAM_BLOCK_SIZE;
	if (offset > pstream->rd_block_pos) {
		assert(pnode_rd != rlist.begin());
		--pnode_rd;
		pstream->rd_block_pos = STREAM_BLOCK_SIZE - (offset - pstream->rd_block_pos);
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
#ifdef _DEBUG_UMTA
	if (psize == nullptr) {
		mlog(LV_DEBUG, "stream: stream_get_rdbuf, param NULL");
		return NULL;
	}
#endif
	if (pstream->pnode_wr != pstream->pnode_rd) {
		auto ret_ptr = &pnode_rd->cdata[rd_block_pos];
		if (*psize >= STREAM_BLOCK_SIZE - pstream->rd_block_pos) {
			*psize = STREAM_BLOCK_SIZE - pstream->rd_block_pos;
			pstream->rd_block_pos = 0;
			++pnode_rd;
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
		auto ret_ptr = &pnode_rd->cdata[rd_block_pos];
		pstream->rd_block_pos = pstream->wr_block_pos;
		pstream->rd_total_pos = pstream->wr_total_pos;
		return ret_ptr;
	} else {
		auto ret_ptr = &pnode_rd->cdata[rd_block_pos];
		pstream->rd_block_pos += *psize;
		pstream->rd_total_pos += *psize;
		return ret_ptr;
	}
	return nullptr;
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
	pnode_rd = list->begin();
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
scopy_result STREAM::copyline(char *pbuff, unsigned int *psize)
{
	auto pstream = this;
	unsigned int state = 0;

#if defined(_DEBUG_UMTA) || defined(COMPILE_DIAG)
	assert(pstream->rd_block_pos < STREAM_BLOCK_SIZE);
	assert(pstream->wr_block_pos < STREAM_BLOCK_SIZE);
	if (pbuff == nullptr || psize == nullptr) {
		mlog(LV_DEBUG, "stream: stream_copyline, param NULL");
		return scopy_result::error;
	}

	if (*psize <= 0 ) {
		*psize = 0;
		return scopy_result::error;
	}
#endif
	

	/* 
	if the read pointer has reached the end of the stream, return 
	immediately 
	*/
	if (pstream->rd_total_pos >= pstream->wr_total_pos) {
		*psize	= 0;
		return scopy_result::end;
	}

	/* skip the '\n' at the beginning of the stream */
	if (0 == pstream->rd_total_pos && *pnode_rd->cdata == '\n') {
		mlog(LV_DEBUG, "stream: skip \\n at the leading position of the stream "
				"in stream_copyline");
		pstream->rd_block_pos	= 1;
		pstream->rd_total_pos	= 1;
	}

	auto buf_size = *psize - 1; /* reserve last byte for '\0' */
	/* if the read node is the last node of the mem file */
	if (pstream->pnode_rd == pstream->pnode_wr) {
		size_t i, end = pstream->wr_total_pos % STREAM_BLOCK_SIZE;
		auto pnode = pstream->pnode_rd;
		for (i=pstream->rd_block_pos; i<end; i++) {
			auto tmp = pnode->cdata[i];
			if (tmp == '\n') {
				state = LF;
				break;
			}
			if (tmp == '\r') {
				state = CR;
				break;
			}
		}

		assert(i >= pstream->rd_block_pos);
		size_t actual_size = i - pstream->rd_block_pos;
		if (actual_size > buf_size) {
			actual_size = buf_size;
			*psize = actual_size;
			memcpy(pbuff, &pnode->cdata[rd_block_pos],
				actual_size);
			pbuff[actual_size] = '\0';
			pstream->rd_block_pos += actual_size;
			pstream->rd_total_pos += actual_size;
			return scopy_result::part;
		}
		*psize = actual_size;
		memcpy(pbuff, &pnode->cdata[rd_block_pos], actual_size);
		pbuff[actual_size] = '\0';

		/* if the end of the stream is not terminated with \r\n */
		if (i == end) {
			pstream->rd_block_pos = end;
			pstream->rd_total_pos = pstream->wr_total_pos;
			return scopy_result::term;
		}
		
		if (state == LF || i + 1 == end) {
			pstream->rd_block_pos += actual_size + 1;
			pstream->rd_total_pos += actual_size + 1;
			return scopy_result::ok;
		}
		if (pnode->cdata[i+1] == '\n') {
			pstream->rd_block_pos += actual_size + 2;
			pstream->rd_total_pos += actual_size + 2;
		} else {
			pstream->rd_block_pos += actual_size + 1;
			pstream->rd_total_pos += actual_size + 1;
		}
		return scopy_result::ok;
	}

	auto pnode = pstream->pnode_rd;
	size_t i;
	for (i = pstream->rd_block_pos; i < STREAM_BLOCK_SIZE; i++) {
		auto tmp = pnode->cdata[i];
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
		auto actual_size = i - pstream->rd_block_pos;
		if (actual_size > buf_size) {
			actual_size = buf_size;
			*psize = actual_size;
			memcpy(pbuff, &pnode->cdata[rd_block_pos],
				actual_size);
			pbuff[actual_size] = '\0';
			pstream->rd_block_pos += actual_size;
			pstream->rd_total_pos += actual_size;
			return scopy_result::part;
		}

		*psize = actual_size;
		memcpy(pbuff, &pnode->cdata[rd_block_pos], actual_size);
		pbuff[actual_size] = '\0';

		if (state == LF) {
			pstream->rd_block_pos += actual_size + 1;
			pstream->rd_total_pos += actual_size + 1;
			if (pstream->rd_block_pos == STREAM_BLOCK_SIZE) {
				++pnode_rd;
				pstream->rd_block_pos = 0;
			}
			return scopy_result::ok;
		}
		if (state != CR)
			return scopy_result::ok;
		if (i + 1 == STREAM_BLOCK_SIZE) {
			++pnode_rd;
			pstream->rd_block_pos = 0;

			if (*pnode_rd->cdata == '\n') {
				pstream->rd_block_pos = 1;
				pstream->rd_total_pos += actual_size + 2;
			} else {
				pstream->rd_total_pos += actual_size + 1;
			}
		} else if (pnode->cdata[i+1] != '\n') {
			pstream->rd_block_pos += actual_size + 1;
			pstream->rd_total_pos += actual_size + 1;
		} else {
			pstream->rd_total_pos += actual_size + 2;
			if (i + 2 == STREAM_BLOCK_SIZE) {
				++pnode_rd;
				pstream->rd_block_pos = 0;
			} else {
				pstream->rd_block_pos += actual_size + 2;
			}
		}
		return scopy_result::ok;
	}
	/* span two blocks */
	auto actual_size = STREAM_BLOCK_SIZE - pstream->rd_block_pos;
	pnode = std::next(pstream->pnode_rd);
	unsigned int end = pnode != pstream->pnode_wr ? STREAM_BLOCK_SIZE :
	                   pstream->wr_total_pos % STREAM_BLOCK_SIZE;
	for (i = 0; i < end; i++) {
		auto tmp = pnode->cdata[i];
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
			memcpy(pbuff, &pnode_rd->cdata[rd_block_pos], STREAM_BLOCK_SIZE -
				pstream->rd_block_pos);
			++pstream->pnode_rd;
			memcpy(pbuff + STREAM_BLOCK_SIZE - pstream->rd_block_pos,
			       pnode_rd->cdata, i);
			pstream->rd_block_pos = i;
			pstream->rd_total_pos += actual_size;
		} else {
			memcpy(pbuff, &pnode_rd->cdata[rd_block_pos], actual_size);
			pstream->rd_block_pos += actual_size;
			pstream->rd_total_pos += actual_size;
		}
		pbuff[actual_size] = '\0';
		return scopy_result::part;
	}

	*psize = actual_size;
	memcpy(pbuff, &pnode_rd->cdata[rd_block_pos], STREAM_BLOCK_SIZE -
		   pstream->rd_block_pos);
	++pstream->pnode_rd;
	memcpy(pbuff + STREAM_BLOCK_SIZE - pstream->rd_block_pos,
	       pnode_rd->cdata, i);
	pbuff[actual_size] = '\0';

	if (i == end) {
		return scopy_result::term;
	}
	if (state == LF || (pstream->rd_total_pos + actual_size + 1)
	    == pstream->wr_total_pos) {
		pstream->rd_block_pos = i + 1;
		pstream->rd_total_pos += actual_size + 1;
		return scopy_result::ok;
	}
	if (pnode_rd->cdata[i+1] == '\n') {
		pstream->rd_block_pos = i + 2;
		pstream->rd_total_pos += actual_size + 2;
	} else {
		pstream->rd_block_pos = i + 1;
		pstream->rd_total_pos += actual_size + 1;
	}
	return scopy_result::ok;
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
		mlog(LV_DEBUG, "stream: stream_peek_buffer, param NULL");
		return 0;
	}
#endif
	

	/* 
	if the read pointer has reached the end of the stream, return 
	immediately 
	*/
	if (pstream->rd_total_pos >= pstream->wr_total_pos)
		return 0;
	
	actual_size = pstream->wr_total_pos - pstream->rd_total_pos;
	auto pnode = pstream->pnode_rd;
	
	/* if the read node is the last node of the mem file */
	if (pstream->pnode_rd == pstream->pnode_wr) {
		if (actual_size >= size) {
			memcpy(pbuff, &pnode->cdata[rd_total_pos], size);
			return size;
		}
		memcpy(pbuff, &pnode->cdata[rd_total_pos], actual_size);
		return actual_size;
	}
	unsigned int tmp_size = STREAM_BLOCK_SIZE - pstream->rd_block_pos;
	if (tmp_size >= size) {
		memcpy(pbuff, &pnode->cdata[rd_total_pos], size);
		return size;
	}
	memcpy(pbuff, &pnode->cdata[rd_total_pos], tmp_size);
	while (++pnode != pstream->pnode_wr) {
		if (tmp_size + STREAM_BLOCK_SIZE >= size) {
			memcpy(&pbuff[tmp_size], pnode->cdata, size - tmp_size);
			return size;
		}
		memcpy(&pbuff[tmp_size], pnode->cdata, STREAM_BLOCK_SIZE);
		tmp_size += STREAM_BLOCK_SIZE;
	}
	if (tmp_size + pstream->wr_block_pos >= size) {
		memcpy(&pbuff[tmp_size], pnode->cdata, size - tmp_size);
		return size;
	}
	memcpy(&pbuff[tmp_size], pnode->cdata, pstream->wr_block_pos);
	return actual_size;
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
	    offset < STREAM_BLOCK_SIZE)
		offset = pstream->wr_total_pos - pstream->rd_total_pos;
	else if (offset > STREAM_BLOCK_SIZE)
		offset = STREAM_BLOCK_SIZE;
	if (offset > STREAM_BLOCK_SIZE - pstream->rd_block_pos) {
		++pstream->pnode_rd;
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
		mlog(LV_DEBUG, "stream: stream_write, param NULL");
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
	switch (eom_result) {
	case STREAM_EOM_WAITING:
		return STREAM_EOM_NONE;
	case STREAM_EOM_CRLF:
		return pstream->last_eom_parse == pstream->wr_total_pos - 3 ?
		       STREAM_EOM_NET : STREAM_EOM_DIRTY;
	case STREAM_EOM_CRORLF:
		return pstream->last_eom_parse == pstream->wr_total_pos - 2 ?
		       STREAM_EOM_NET : STREAM_EOM_DIRTY;
	default:
		return STREAM_EOM_ERROR;
	}
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
	auto &rlist = *list;
	int i, j;
	int from_pos;
	int until_pos;
	int block_deep;
	int block_offset;
	
	if (eom_result != STREAM_EOM_WAITING)
		return;
	block_offset = pstream->last_eom_parse % STREAM_BLOCK_SIZE;
	block_deep = pstream->wr_total_pos / STREAM_BLOCK_SIZE - 
				 pstream->last_eom_parse / STREAM_BLOCK_SIZE;
	
	auto pnode = pstream->pnode_wr;
	for (i=0; i<=block_deep; i++) {
		until_pos = i == block_deep ? block_offset : 0;
		from_pos  = i == 0 ? pstream->wr_block_pos - 1 : STREAM_BLOCK_SIZE - 1;
		for (j=from_pos; j>=until_pos; j--) {
			auto pbuff = pnode->cdata;
			if (pbuff[j] != '.')
				continue;
			char temp_buff[6];
			if (0 == j) {
				if (pnode == rlist.begin())
					goto NONE_EOM;
				auto pnode1 = std::prev(pnode);
				temp_buff[0] = pnode1->cdata[STREAM_BLOCK_SIZE-2];
				temp_buff[1] = pnode1->cdata[STREAM_BLOCK_SIZE-1];
				temp_buff[2] = '.';
			} else if (1 == j) {
				if (pnode == rlist.begin())
					goto NONE_EOM;
				auto pnode1 = std::prev(pnode);
				temp_buff[0] = pnode1->cdata[STREAM_BLOCK_SIZE-1];
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
					auto pnode1 = std::next(pnode);
					temp_buff[4] = pnode1 == pstream->list->cend() ? '\0' : *pnode1->cdata;
				}
			} else if (from_pos == j) {
				if (0 == i) {
					continue;
				}
				auto pnode1 = std::next(pnode);
				if (pnode1 == rlist.end())
					continue;
				temp_buff[3] = pnode1->cdata[0];
				temp_buff[4] = pnode1->cdata[1];
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
		if (pnode == rlist.begin())
			goto NONE_EOM;
		--pnode;
	}
 NONE_EOM:
	pstream->last_eom_parse = pstream->wr_total_pos >= 2 ? pstream->wr_total_pos - 2 : 0;
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
	auto &rlist = *list;
	size_t blocks, i, fake_pos;
	unsigned int size;
	void *pbuff;
	
	if (eom_result == STREAM_EOM_WAITING)
		return;
	else if (eom_result == STREAM_EOM_CRLF)
		fake_pos = pstream->last_eom_parse + 3;
	else if (eom_result == STREAM_EOM_CRORLF)
		fake_pos = pstream->last_eom_parse + 2;
	else
		return;

	blocks = pstream->wr_total_pos / STREAM_BLOCK_SIZE -
				fake_pos / STREAM_BLOCK_SIZE;
	auto pnode = pstream->pnode_wr;
	for (i=0; i<blocks; i++) {
		if (pnode == rlist.begin())
			return;
		--pnode;
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
		if (pnode == rlist.begin())
			return;
		--pnode;
	}
	pstream->pnode_wr = pnode;
	pstream->wr_total_pos = pstream->last_eom_parse;
	pstream->wr_block_pos = pstream->last_eom_parse % STREAM_BLOCK_SIZE;
	pstream->eom_result = STREAM_EOM_WAITING;
	pstream->last_eom_parse = 0;
}
