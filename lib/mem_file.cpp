// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *	  mem file is actually like the file in disk, but mem file get blocks form
 *	  memory, it is virtual file. Caution: Not thread-safe.
 */
#include <cstring>
#include <gromox/mem_file.hpp>
#include <gromox/util.hpp>

static DOUBLE_LIST_NODE* mem_file_append_node(MEM_FILE *pfile); 

void mem_file_init(MEM_FILE *pfile, LIB_BUFFER *palloc)
{
	DOUBLE_LIST_NODE *pnode;
#ifdef _DEBUG_UMTA
	if (NULL == pfile || NULL == palloc) {
		debug_info("[mem_file]: mem_file_init, param NULL");
		return;
	}
#endif
	
	memset(pfile, 0, sizeof(MEM_FILE));
	pfile->allocator = palloc;
	double_list_init(&pfile->list);

#ifdef _DEBUG_UMTA
	if (palloc->item_size - sizeof(DOUBLE_LIST_NODE) < FILE_BLOCK_SIZE) {
		debug_info("[mem_file]: item size in allocator is too small");
		return;
	}
#endif
	/* allocate the first node in initialization */
	pnode = mem_file_append_node(pfile);

#ifdef _DEBUG_UMTA
	if(NULL == pnode) {
		debug_info("[mem_file]: Failed to allocate first node in mem file's "
				   "init func");
		return;
	}
#endif
	pfile->pnode_rd = pnode;
	pfile->pnode_wr = pnode;

}


/*
 *	  retrieve pointer of the line following the read pointer
 *	  @param	
 *		  pfile [in]		indicate the mem file object
 *		  pbuff [out]		for saving the line string pointer
 *		  size				size of buff
 *	  @return		  
 *		  size of line, not include the token '\n' 
 */
size_t MEM_FILE::readline(char *pbuff, size_t size)
{
	auto pfile = this;
	size_t distance, blocks, i, j, end, actual_size;

#ifdef _DEBUG_UMTA
	if (pbuff == nullptr) {
		debug_info("[mem_file]: mem_file_readline, param NULL");
		return 0;
	}
#endif
	if (0 == size) {
		return 0;
	}
	
	/* 
	if the read pointer has reached the end of the mem file, return 
	immediately 
	*/
	if (pfile->rd_total_pos >= pfile->file_total_len) {
		return MEM_END_OF_FILE;
	}

	size --;  /* reserve last byte for '\0' */
	
	/* if the read node is the last node of the mem file */
	if (pfile->pnode_rd == double_list_get_tail(&pfile->list)) {
		end = pfile->file_total_len%FILE_BLOCK_SIZE;
		for (i=pfile->rd_block_pos; i<end; i++) {
			if (*((char*)pfile->pnode_rd->pdata + i) == '\n') {
				break;
			}
		}
		actual_size = i - pfile->rd_block_pos;

		if (actual_size > size) {
			memcpy(pbuff, (char*)pfile->pnode_rd->pdata + pfile->rd_block_pos,
				 size);
			pfile->rd_block_pos += size;
			pfile->rd_total_pos += size;
			pbuff[size] = '\0';
			return size;
		}

		size = actual_size;
		memcpy(pbuff, (char*)pfile->pnode_rd->pdata + pfile->rd_block_pos, 
			   size);
		pbuff[size] = '\0';
		if (i != end) {
			pfile->rd_block_pos += size + 1;
			pfile->rd_total_pos += size + 1;
		} else {
			pfile->rd_block_pos += size;
			pfile->rd_total_pos += size;
		}
		return size;
		
	} else {
		distance = pfile->file_total_len - pfile->rd_total_pos;
		if (distance > size) {
			distance = size;
		}
		if (pfile->rd_total_pos != 0) { 
			blocks = (distance - (FILE_BLOCK_SIZE - pfile->rd_total_pos)) /
					 FILE_BLOCK_SIZE + 1; 
		} else {
			blocks = distance/FILE_BLOCK_SIZE;
		}
		for (i=pfile->rd_block_pos; i<FILE_BLOCK_SIZE; i++) {
			if (*((char*)pfile->pnode_rd->pdata + i) == '\n') {
				break;
			}
		}
		actual_size = i - pfile->rd_block_pos;


		if (actual_size > size) {
			memcpy(pbuff, (char*)pfile->pnode_rd->pdata + pfile->rd_block_pos,
				   size);
			pfile->rd_block_pos += size;
			pfile->rd_total_pos += size;
			pbuff[size] ='\0';
			return size;
		}

		if (i != FILE_BLOCK_SIZE) {
			size = actual_size;
			memcpy(pbuff, (char*)pfile->pnode_rd->pdata + pfile->rd_block_pos,
				   size);
			pfile->rd_block_pos += size + 1;
			if (pfile->rd_block_pos == FILE_BLOCK_SIZE) {
				pfile->rd_block_pos = 0;
				pfile->pnode_rd = double_list_get_after(&pfile->list,
								  pfile->pnode_rd);
			}
			pfile->rd_total_pos += size + 1;
			pbuff[size] ='\0';
			return size;
		}
		
		memcpy(pbuff, (char*)pfile->pnode_rd->pdata + pfile->rd_block_pos,
			   actual_size);
		pfile->pnode_rd = double_list_get_after(&pfile->list, pfile->pnode_rd);
		for (j=0; j<blocks-1; j++) {
			for (i=0; i<FILE_BLOCK_SIZE; i++) {
				if (*((char*)pfile->pnode_rd->pdata + i) == '\n') {
					break;
				}
			}
			if (FILE_BLOCK_SIZE != i) {
				memcpy(pbuff + actual_size, (char*)pfile->pnode_rd->pdata, i);
				actual_size += i;
				pfile->rd_block_pos = i + 1;
				if (pfile->rd_block_pos == FILE_BLOCK_SIZE) {
					pfile->rd_block_pos = 0;
					pfile->pnode_rd = double_list_get_after(
									  &pfile->list, pfile->pnode_rd);
				}
				pfile->rd_total_pos += actual_size + 1;
				pbuff[actual_size] = '\0';
				return actual_size;
			}

			memcpy(pbuff + actual_size, (char*)pfile->pnode_rd->pdata, 
				   FILE_BLOCK_SIZE);
			actual_size += FILE_BLOCK_SIZE;
			pfile->pnode_rd = double_list_get_after(&pfile->list, 
							  pfile->pnode_rd);
		}
		end = (distance - (FILE_BLOCK_SIZE - pfile->rd_block_pos)) % 
			  FILE_BLOCK_SIZE;
		for (i=0; i<end; i++) {
			if (*((char*)pfile->pnode_rd->pdata + i) == '\n') {
				break;
			}
		}
		memcpy(pbuff+actual_size, (char*)pfile->pnode_rd->pdata, i);
		actual_size += i;
		pbuff[actual_size] = '\0';
		if (i != end){
			pfile->rd_block_pos	 = i + 1;
			pfile->rd_total_pos += actual_size + 1;
		} else {
			pfile->rd_block_pos	 = i;
			pfile->rd_total_pos += actual_size;
		}
		return actual_size;
	}
}

/*
 *	  read buffer from mem file
 *	  @param	
 *		  pfile [in]	indicate the mem file object
 *		  pbuff [out]	buffer for retrieving data
 *		  size			size of buffer
 *	  @return		 
 *		  size of bytes that actually read
 */
size_t MEM_FILE::read(void* pbuff, size_t size)
{
	auto pfile = this;
	size_t i, distance, blocks, actual_size, remains;
	
#ifdef _DEBUG_UMTA
	if (pbuff == nullptr) {
		debug_info("[mem_file]: mem_file_read, param NULL");
		return 0;
	}
#endif


	if (pfile->rd_total_pos >= pfile->file_total_len) {
		return MEM_END_OF_FILE;
	}	 
	
	distance = pfile->file_total_len - pfile->rd_total_pos;
	if (size > distance) {
		size = distance;
	}

	if (FILE_BLOCK_SIZE - pfile->rd_block_pos > size) {
		memcpy(pbuff, (char*)pfile->pnode_rd->pdata + pfile->rd_block_pos, 
			   size);
		pfile->rd_block_pos += size;
		pfile->rd_total_pos += size;
		return size;
	}

	remains = (int)size;

	if (pfile->rd_block_pos != 0) { 
		blocks = (size - (FILE_BLOCK_SIZE - pfile->rd_block_pos)) /
					 FILE_BLOCK_SIZE; 
	} else {
		blocks = size/FILE_BLOCK_SIZE - 1;
	}
	actual_size = FILE_BLOCK_SIZE - pfile->rd_block_pos;
	memcpy(pbuff, (char*)pfile->pnode_rd->pdata + pfile->rd_block_pos,
			actual_size);
	remains -= actual_size;
	
	pfile->pnode_rd = double_list_get_after(&pfile->list, pfile->pnode_rd);
	for (i = 0; i < blocks; i++) {
		memcpy((char*)pbuff + actual_size, pfile->pnode_rd->pdata,
				FILE_BLOCK_SIZE);
		remains -= FILE_BLOCK_SIZE;
		pfile->pnode_rd = double_list_get_after(&pfile->list,
							pfile->pnode_rd);
		actual_size += FILE_BLOCK_SIZE;
	}
	//end = (size - (FILE_BLOCK_SIZE - pfile->rd_total_pos))%FILE_BLOCK_SIZE;
	memcpy((char*)pbuff+actual_size, (char*)pfile->pnode_rd->pdata, remains);
	pfile->rd_block_pos = remains;
	pfile->rd_total_pos += size;
	
	return size;
}


/*
 *	  seek the read pointer or write pointer
 *	  @param	
 *		  pfile [in]	indicate the mem file object
 *		  type			indicate the write or read pointer to seek: 
 *						MEM_FILE_READ_PTR or MEM_FILE_WRITE_PTR
 *		  offset		bytes of offset
 *		  opt			option of seek: MEM_FILE_SEEK_BEGIN MEM_FILE_SEEK_CUR
 *						MEM_FILE_SEEK_END
 *	  @return
 *		  the actual size of seeking
 */
ssize_t	MEM_FILE::seek(int type, ssize_t offset, int opt)
{
	auto pfile = this;
	DOUBLE_LIST_NODE *pnode;
	ssize_t ret_val;
	size_t blocks, end;

	switch(opt) {
	case MEM_FILE_SEEK_BEGIN:
		if (offset < 0) {
			return 0;
		}
		if (static_cast<size_t>(offset) > pfile->file_total_len)
			offset = pfile->file_total_len;
		pnode = double_list_get_head(&pfile->list);
		if (MEM_FILE_READ_PTR == type) {
			if (offset < FILE_BLOCK_SIZE){
				pfile->pnode_rd = pnode;
				pfile->rd_block_pos = offset;
				pfile->rd_total_pos = offset;
			} else {
				blocks = offset/FILE_BLOCK_SIZE;
				pnode = double_list_forward(&pfile->list, pnode, &blocks);
				pfile->rd_block_pos = offset%FILE_BLOCK_SIZE; 
				pfile->rd_total_pos = offset;
				pfile->pnode_rd = pnode;
			}
			ret_val = offset - pfile->rd_total_pos;
		} else {
			if (offset < FILE_BLOCK_SIZE){
				pfile->pnode_wr = pnode;
				pfile->wr_block_pos = offset;
				pfile->wr_total_pos = offset;
			} else {
				blocks = offset/FILE_BLOCK_SIZE;
				pnode = double_list_forward(&pfile->list, pnode, &blocks);
				pfile->wr_block_pos = offset%FILE_BLOCK_SIZE; 
				pfile->wr_total_pos = offset;
				pfile->pnode_wr = pnode;
			}
			ret_val = offset - pfile->wr_total_pos;
		}
		return ret_val;
	case MEM_FILE_SEEK_CUR:
		if (0 == offset) {
			return 0;
		} else if (offset < 0) {
			if (MEM_FILE_READ_PTR == type) {
				if (offset + pfile->rd_total_pos < 0) {
					pfile->pnode_rd = double_list_get_head(&pfile->list);
					pfile->rd_block_pos = 0;
					pfile->rd_total_pos = 0;
					offset = - pfile->rd_total_pos;
				} else {
					if (offset + pfile->rd_block_pos >= 0) {
						pfile->rd_block_pos += offset;
					} else {
						blocks = (-offset - pfile->rd_block_pos) / 
								 FILE_BLOCK_SIZE + 1;
						pfile->rd_block_pos = FILE_BLOCK_SIZE - 
											  (-offset - pfile->rd_block_pos)%
											  FILE_BLOCK_SIZE;
						if (pfile->rd_block_pos == FILE_BLOCK_SIZE) {
							blocks --;
							pfile->rd_block_pos = 0;
						}
						pfile->pnode_rd = double_list_backward(&pfile->list, 
										  pfile->pnode_rd, &blocks);
					}
					pfile->rd_total_pos += offset;
				}
			} else {
				if (offset + pfile->wr_total_pos < 0) {
					pfile->pnode_wr = double_list_get_head(&pfile->list);
					pfile->wr_block_pos = 0;
					pfile->wr_total_pos = 0;
					offset = - pfile->wr_total_pos;
				} else {
					if (offset + pfile->wr_block_pos >= 0) {
						pfile->wr_block_pos += offset;
					} else {
						blocks = (-offset - pfile->wr_block_pos) /
								 FILE_BLOCK_SIZE + 1;
						pfile->wr_block_pos = FILE_BLOCK_SIZE - 
											  (-offset - pfile->wr_block_pos) %
											  FILE_BLOCK_SIZE;
						if (pfile->wr_block_pos == FILE_BLOCK_SIZE) {
							blocks --;
							pfile->wr_block_pos = 0;
						}
						pfile->pnode_wr = double_list_backward(&pfile->list, 
										  pfile->pnode_wr, &blocks);
					}
					pfile->wr_total_pos += offset;
				}
			}
		} else {
			if (MEM_FILE_READ_PTR == type) {
				if (offset + pfile->rd_total_pos >= pfile->file_total_len) {
					pfile->pnode_rd = double_list_get_tail(&pfile->list);
					pfile->rd_block_pos = pfile->file_total_len%FILE_BLOCK_SIZE;
					pfile->rd_total_pos = pfile->file_total_len;
					offset = pfile->file_total_len - pfile->rd_total_pos;
				} else {
					if (offset + pfile->rd_block_pos < FILE_BLOCK_SIZE){
						pfile->rd_block_pos += offset;
					} else {
						if (0 != pfile->rd_block_pos) {
							blocks = (offset - (FILE_BLOCK_SIZE - 
									 pfile->rd_block_pos))/FILE_BLOCK_SIZE + 1;
						} else {
							blocks = offset/FILE_BLOCK_SIZE;
						}
						pfile->rd_block_pos = (offset - (FILE_BLOCK_SIZE -
											  pfile->rd_block_pos))%
											  FILE_BLOCK_SIZE;
						pfile->pnode_rd = double_list_forward(&pfile->list, 
										  pfile->pnode_rd, &blocks);
					}
					pfile->rd_total_pos += offset;
				}
			} else {
				if (offset + pfile->wr_total_pos >= pfile->file_total_len) {
					pfile->pnode_wr = double_list_get_tail(&pfile->list);
					pfile->wr_block_pos = pfile->file_total_len%FILE_BLOCK_SIZE;
					pfile->wr_total_pos = pfile->file_total_len;
					offset = pfile->file_total_len - pfile->wr_total_pos;
				} else {
					if (offset + pfile->wr_block_pos < FILE_BLOCK_SIZE){
						pfile->wr_block_pos += offset;
					} else {
						if(0 != pfile->wr_block_pos) {
							blocks = (offset - (FILE_BLOCK_SIZE - 
									 pfile->wr_block_pos))/FILE_BLOCK_SIZE + 1;
						} else {
							blocks = offset/FILE_BLOCK_SIZE;
						}
						pfile->wr_block_pos = (offset -(FILE_BLOCK_SIZE -
											  pfile->wr_block_pos))%
											  FILE_BLOCK_SIZE;
						pfile->pnode_wr = double_list_forward(&pfile->list, 
										  pfile->pnode_wr, &blocks);
					}
					pfile->wr_total_pos += offset;
				}
			}
		}
		return offset;  
	case MEM_FILE_SEEK_END:
		if (offset >0) {
			return 0;
		}
		if (static_cast<size_t>(-offset) > pfile->file_total_len)
			offset = -pfile->file_total_len;
		pnode = double_list_get_tail(&pfile->list);
		end = pfile->file_total_len%FILE_BLOCK_SIZE;
		if (MEM_FILE_READ_PTR == type) {
			if (static_cast<size_t>(-offset) <= end) {
				pfile->pnode_rd = pnode;
				pfile->rd_block_pos = end + offset;
			} else {
				blocks = (-offset - end)/FILE_BLOCK_SIZE + 1;
				pfile->rd_block_pos = FILE_BLOCK_SIZE - (-offset - end)%
										FILE_BLOCK_SIZE; 
				if (pfile->rd_block_pos == FILE_BLOCK_SIZE) {
					blocks --;
					pfile->rd_block_pos = 0;
				}
				pnode = double_list_backward(&pfile->list, pnode, &blocks);
				pfile->pnode_rd = pnode;
			}
			ret_val = pfile->file_total_len + offset - pfile->rd_total_pos; 
			pfile->rd_total_pos = pfile->file_total_len + offset;
		} else {
			if (static_cast<size_t>(-offset) <= end) {
				pfile->pnode_wr = pnode;
				pfile->wr_block_pos = end + offset;
			} else {
				blocks = (-offset - end)/FILE_BLOCK_SIZE + 1;
				pfile->wr_block_pos = FILE_BLOCK_SIZE - (-offset - end)%
										FILE_BLOCK_SIZE; 
				if(pfile->wr_block_pos == FILE_BLOCK_SIZE) {
					blocks --;
					pfile->wr_block_pos = 0;
				}
				pnode = double_list_backward(&pfile->list, pnode, &blocks);
				pfile->pnode_wr = pnode;
			}
			ret_val = pfile->file_total_len + offset - pfile->wr_total_pos;
			pfile->wr_total_pos = pfile->file_total_len + offset;
		}
		return ret_val;   
	}
	/* never reached */
	return (-1);
}

/*
 *	  write buffer into mem file
 *	  @param
 *		  pfile [in]	  indicate the file object
 *		  pbuffer [in]	  buffer containing data to be read and written into 
 *						  file
 *		  size			  indicate size of buffer
 *	  @return
 *		  indicate actual size that has been written
 */
size_t MEM_FILE::write(const void *pbuff, size_t size)
{
	auto pfile = this;
	size_t bytes_need, cur_end, remains; 
	size_t blocks, actual_written, i;
#ifdef _DEBUG_UMTA
	if (pbuff == nullptr) {
		debug_info("[mem_file]: mem_file_write, param NULL");
		return 0;
	}
#endif

	if (size > pfile->file_total_len - pfile->wr_total_pos) {
		bytes_need = size - (pfile->file_total_len - pfile->wr_total_pos);
		cur_end = pfile->file_total_len % FILE_BLOCK_SIZE;

		if (bytes_need >= FILE_BLOCK_SIZE - cur_end){
			if (0 != cur_end) {
				blocks = (bytes_need - (FILE_BLOCK_SIZE - cur_end)) /
					FILE_BLOCK_SIZE + 1;
			} else {
				blocks = bytes_need / FILE_BLOCK_SIZE;
			}
			for (i = 0; i < blocks; i++) {
				if (NULL == mem_file_append_node(pfile)) {
					break;
				}
			}
			if (i != blocks) {
				size = i*FILE_BLOCK_SIZE + FILE_BLOCK_SIZE - cur_end +
					   pfile->file_total_len - pfile->wr_total_pos - 1;
			}
		}
	}

	if (size < FILE_BLOCK_SIZE - pfile->wr_block_pos) {
		memcpy((char*)pfile->pnode_wr->pdata + pfile->wr_block_pos, pbuff, size);
		pfile->wr_block_pos += size;
		pfile->wr_total_pos += size;
		if (pfile->wr_total_pos > pfile->file_total_len) {
			pfile->file_total_len = pfile->wr_total_pos;
		}
		return size;
	}
	
	remains = (int)size;

	if (0 != pfile->wr_block_pos) {
		blocks = (size - (FILE_BLOCK_SIZE - pfile->wr_block_pos)) /
			FILE_BLOCK_SIZE; 
	} else {
		blocks = size/FILE_BLOCK_SIZE - 1;
	}
	actual_written = FILE_BLOCK_SIZE - pfile->wr_block_pos;
	memcpy((char*)pfile->pnode_wr->pdata + pfile->wr_block_pos, pbuff, actual_written);
	pfile->pnode_wr = double_list_get_after(&pfile->list, pfile->pnode_wr);
	remains -= actual_written;
	for (i = 0; i < blocks; i++) {
		memcpy(pfile->pnode_wr->pdata, static_cast<const char *>(pbuff) + actual_written, FILE_BLOCK_SIZE);
		actual_written += FILE_BLOCK_SIZE;
		pfile->pnode_wr = double_list_get_after(&pfile->list, pfile->pnode_wr);
		remains -= FILE_BLOCK_SIZE;
	}
	memcpy(pfile->pnode_wr->pdata, static_cast<const char *>(pbuff) + actual_written, remains);
	pfile->wr_total_pos += size;
	pfile->wr_block_pos = remains;

	if (pfile->wr_total_pos > pfile->file_total_len) {
		pfile->file_total_len = pfile->wr_total_pos;
	}
	
	return size;
}

/*
 *	  write a line into mem file
 *	  @param
 *		  pfile [in]	  indicate the file object
 *		  pbuffer [in]	  buffer containing data to be read and written into file
 *	  @return
 *		  return actual size written into mem file
 */
size_t MEM_FILE::writeline(const char *pbuff)
{
#ifdef _DEBUG_UMTA
	if (pbuff == nullptr) {
		debug_info("[mem_file]: mem_file_writeline, param NULL");
		return 0;
	}
#endif						 
	auto length = strlen(pbuff);
	auto written = write(pbuff, length);
	if (length == written) {
		if ( write("\n", 1) == 1) {
			return length;
		} else {
			seek(MEM_FILE_WRITE_PTR, MEM_FILE_SEEK_CUR, -1);
			write("\n", 1);
			return length - 1;
		}
	} else {
		return written;
	}
	
}

/*
 *	  reset the mem file object into the initial state
 *	  @param
 *		  pfile [in]	indicate the mem file object
 */
void MEM_FILE::clear()
{
	auto pfile = this;
	DOUBLE_LIST_NODE *pnode, *phead;
#ifdef _DEBUG_UMTA
	if (pfile->allocator == nullptr) {
		debug_info("[mem_file]: mem_file_clear, param NULL");
		return;
	}
#endif
	phead = double_list_get_head(&pfile->list);
	pnode = double_list_get_tail(&pfile->list);
	if (1 == double_list_get_nodes_num(&pfile->list)) {
		goto CLEAR_RETRUN;
	}
	while (true) {
		if (pnode != phead) {
			double_list_remove(&pfile->list, pnode);
		} else {
			break;
		}
		pfile->allocator->put(pnode);
		pnode = double_list_get_tail(&pfile->list);
	}
 CLEAR_RETRUN:
	pfile->wr_block_pos		   = 0;
	pfile->wr_total_pos		   = 0;
	pfile->rd_block_pos		   = 0;
	pfile->rd_total_pos		   = 0;
	pfile->file_total_len	   = 0;
	pfile->pnode_wr			   = phead;
	pfile->pnode_rd			   = phead;
}

void mem_file_free(MEM_FILE *pfile)
{	 
	DOUBLE_LIST_NODE *phead;
#ifdef _DEBUG_UMTA
	if (NULL == pfile || NULL == pfile->allocator) {
		debug_info("[mem_file]: mem_file_free, param NULL");
		return;
	}
#endif
	pfile->clear();
	phead = double_list_pop_front(&pfile->list);
	pfile->allocator->put(phead);
	pfile->allocator = NULL;
	double_list_free(&pfile->list);
}

/*
 *	  append one block in mem file list. Caution: This function should be 
 *	  invoked when the last block is fully written. a new block is needed.
 *	  @param	
 *		  pfile [in]	indicate the mem file object
 *	  @return 
 *		  TRUE	  success
 *		  FALSE	   fail
 */
static DOUBLE_LIST_NODE* mem_file_append_node(MEM_FILE *pfile)
{	 
#ifdef _DEBUG_UMTA
		if (NULL == pfile) {
		debug_info("[mem_file]: mem_file_append_node, param NULL");
		return NULL;
	}
#endif
	auto pnode = pfile->allocator->get<DOUBLE_LIST_NODE>();
	if (NULL == pnode) {
		return NULL;
	}
	pnode->pdata = (char*)pnode + sizeof(DOUBLE_LIST_NODE);
	double_list_append_as_tail(&pfile->list, pnode);
	return pnode;
}

/*
 *	copy mem file from one to another
 *	@param
 *		pfile_src [in]		source file
 *		pfile_dst [in,out]	destination file
 *	@return
 *		bytes actually copied
 */
size_t MEM_FILE::copy_to(MEM_FILE &mdst)
{
	auto pfile_src = this;
	auto pfile_dst = &mdst;
	DOUBLE_LIST_NODE *pnode, *pnode_dst;
	
	mdst.clear();
	auto nodes_num = double_list_get_nodes_num(&list);
	for (size_t i = 0; i < nodes_num - 1; ++i) {
		if (NULL == mem_file_append_node(pfile_dst)) {
			pfile_dst->clear();
			return 0;
		}
	}
	pnode_dst = double_list_get_head(&pfile_dst->list);
	for (pnode= double_list_get_head(&pfile_src->list); pnode!=NULL;
		 pnode=double_list_get_after(&pfile_src->list, pnode)) {
		memcpy(pnode_dst->pdata, pnode->pdata, FILE_BLOCK_SIZE);
		pnode_dst = double_list_get_after(&pfile_dst->list, pnode_dst);
	}
	pfile_dst->rd_block_pos = pfile_src->rd_block_pos;
	pfile_dst->wr_block_pos = pfile_src->wr_block_pos;
	pfile_dst->rd_total_pos = pfile_src->rd_total_pos;
	pfile_dst->wr_total_pos = pfile_src->wr_total_pos;
	pfile_dst->file_total_len = pfile_src->file_total_len;
	nodes_num = pfile_dst->wr_total_pos/FILE_BLOCK_SIZE;
	pnode = double_list_get_head(&pfile_dst->list);
	for (size_t i = 0; i < nodes_num; ++i)
		pnode = double_list_get_after(&pfile_dst->list, pnode);
	pfile_dst->pnode_wr = pnode;
	return pfile_dst->file_total_len;
}
