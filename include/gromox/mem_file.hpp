#pragma once
#include <sys/types.h>
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>
#include <gromox/util.hpp>
#define MEM_END_OF_FILE         0xFFFFFFFF      

/* enumeration for indicating the seek relative position */
enum {
    MEM_FILE_SEEK_BEGIN,
    MEM_FILE_SEEK_CUR,
    MEM_FILE_SEEK_END
};

/* enumeration for indicating the pointer type */
enum {
    MEM_FILE_READ_PTR,
    MEM_FILE_WRITE_PTR
};

/* struct for describing the mem file */
struct MEM_FILE {
	size_t read(void *, size_t);
	size_t readline(char *, size_t);
	ssize_t seek(int type, ssize_t offset, int opt);
	size_t get_total_length() const { return file_total_len; }
	void clear();
	size_t write(const void *, size_t);
	size_t writeline(const char *);
	size_t copy_to(MEM_FILE &dst);

    DOUBLE_LIST_NODE    *pnode_rd;    /* node of current reading */
    DOUBLE_LIST_NODE    *pnode_wr;    /* node of current writing */
    size_t            rd_block_pos;   /* read position in block(node) */
    size_t            wr_block_pos;   /* write position in block */
    size_t            rd_total_pos;   /* total reading position */
    size_t            wr_total_pos;   /* total writing position */
    size_t            file_total_len; /* total file length */
    LIB_BUFFER        *allocator;     /* allocator for get blocks */
    DOUBLE_LIST        list;          /* list of blocks */
};
    
void mem_file_init(MEM_FILE *pfile, LIB_BUFFER *palloc);
void mem_file_free(MEM_FILE *pfile);
