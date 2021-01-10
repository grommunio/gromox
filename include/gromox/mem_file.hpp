#pragma once
#include <gromox/common_types.hpp>
#include <gromox/lib_buffer.hpp>
#include <gromox/double_list.hpp>
#include <sys/types.h>

#define FILE_BLOCK_SIZE         0x100
#define FILE_ALLOC_SIZE    (FILE_BLOCK_SIZE + sizeof(DOUBLE_LIST_NODE))
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
    
#ifdef __cplusplus
extern "C" {
#endif

void mem_file_init(MEM_FILE *pfile, LIB_BUFFER *palloc);

size_t mem_file_read(MEM_FILE *pfile, void* pbuff, size_t size);

size_t mem_file_readline(MEM_FILE *pfile, char* pbuff, size_t size);

ssize_t mem_file_seek(MEM_FILE *pfile, int type, ssize_t offset, int opt);
size_t mem_file_get_total_length(MEM_FILE *pfile);

void mem_file_clear(MEM_FILE *pfile);

void mem_file_free(MEM_FILE *pfile);
extern size_t mem_file_write(MEM_FILE *pfile, const void *buf, size_t size);
extern size_t mem_file_writeline(MEM_FILE *pfile, const char *buf);
size_t mem_file_copy(MEM_FILE *pfile_src, MEM_FILE *pfile_dst);

#ifdef __cplusplus
}
#endif
