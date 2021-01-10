#pragma once
#include <gromox/lib_buffer.hpp>
#include <gromox/double_list.hpp>
#define STREAM_BLOCK_SIZE    0x10000
#define STREAM_ALLOC_SIZE    (STREAM_BLOCK_SIZE + sizeof(DOUBLE_LIST_NODE))

enum {
    STREAM_LINE_ERROR = -2, 
    STREAM_LINE_FAIL,
    STREAM_LINE_UNAVAILABLE = 0,
    STREAM_LINE_AVAILABLE,
};

enum {
    STREAM_EOM_ERROR = -1,
    STREAM_EOM_NONE = 0,
    STREAM_EOM_NET,
    STREAM_EOM_DIRTY,
};

enum {
	STREAM_COPY_ERROR = -3,
    STREAM_COPY_PART,
    STREAM_COPY_TERM,
    STREAM_COPY_OK,
    STREAM_COPY_END
};

enum {
    STREAM_DUMP_FAIL = -1,
    STREAM_DUMP_OK
};

enum {
	STREAM_WRITE_FAIL = -1,
	STREAM_WRITE_OK
};

typedef struct _STREAM{
    DOUBLE_LIST_NODE  *pnode_rd;
    DOUBLE_LIST_NODE  *pnode_wr;
    int               line_result;
	int               eom_result;
    size_t            rd_block_pos;
    size_t            wr_block_pos;
    size_t            rd_total_pos;
    size_t            wr_total_pos;
	size_t            last_eom_parse;
    size_t            block_line_parse;
    size_t            block_line_pos;
    LIB_BUFFER        *allocator;
    DOUBLE_LIST       list;
} STREAM; 

#ifdef __cplusplus
extern "C" {
#endif

void stream_init(STREAM *pstream, LIB_BUFFER *palloc);

int stream_has_newline(STREAM *pstream);

unsigned int stream_readline(STREAM *pstream, char **ppline);

void stream_clear(STREAM *pstream);

void stream_free(STREAM *pstream);

void stream_try_mark_line(STREAM *pstream);

void stream_try_mark_eom(STREAM *pstream);

int stream_has_eom(STREAM *pstream);

void stream_split_eom(STREAM *pstream, STREAM *pstream_second);
extern void *stream_getbuffer_for_writing(STREAM *pstream, unsigned int *psize);
unsigned int stream_forward_writing_ptr(STREAM *pstream, unsigned int offset);

unsigned int stream_forward_reading_ptr(STREAM *pstream, unsigned int offset);

unsigned int stream_backward_writing_ptr(STREAM *pstream, unsigned int offset);

unsigned int stream_backward_reading_ptr(STREAM *pstream, unsigned int offset);
extern void *stream_getbuffer_for_reading(STREAM *pstream, unsigned int *psize);
void stream_reset_reading(STREAM *pstream);

size_t stream_get_total_length(STREAM *pstream);

int stream_copyline(STREAM *pstream, char *pbuff, unsigned int *size);

unsigned int stream_peek_buffer(STREAM *pstream, char *pbuff, unsigned int size);

int stream_dump(STREAM *pstream, int fd);
extern int stream_write(STREAM *pstream, const void *pbuff, size_t size);

#ifdef __cplusplus
} /* extern "C" */
#endif
