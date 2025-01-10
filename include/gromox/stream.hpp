#pragma once
#include <list>
#include <gromox/defs.h>
#include <gromox/util.hpp>

/**
 * %STREAM_LINE_FAIL: mail envelope lines overflow the first buffer of stream
 */
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

enum class scopy_result {
	error = -3, part, term, ok, end,
};

enum {
    STREAM_DUMP_FAIL = -1,
    STREAM_DUMP_OK
};

enum {
	STREAM_WRITE_FAIL = -1,
	STREAM_WRITE_OK
};

struct stream_block {
	char cdata[STREAM_BLOCK_SIZE];
};

struct GX_EXPORT STREAM {
	STREAM();
	STREAM(const STREAM &) = default;
	STREAM(STREAM &&) = delete;
	STREAM &operator=(const STREAM &) = default;
	STREAM &operator=(STREAM &&);

	int has_newline() const { return line_result; }
	unsigned int readline(char **);
	void clear();
	void try_mark_line();
	void try_mark_eom();
	int has_eom();
	void split_eom(STREAM *secondary);
	unsigned int fwd_write_ptr(unsigned int offset);
	unsigned int fwd_read_ptr(unsigned int offset);
	unsigned int rewind_write_ptr(unsigned int offset);
	unsigned int rewind_read_ptr(unsigned int offset);
	void reset_reading();
	void *get_read_buf(unsigned int *size);
	void *get_write_buf(unsigned int *size);
	size_t get_total_length() const { return wr_total_pos; }
	scopy_result copyline(char *buf, unsigned int *size);
	unsigned int peek_buffer(char *, unsigned int) const;
	int write(const void *buf, size_t);

	std::list<stream_block>::iterator pnode_rd{}, pnode_wr{};
	int line_result = 0, eom_result = 0;
	size_t rd_block_pos = 0, wr_block_pos = 0;
	size_t rd_total_pos = 0, wr_total_pos = 0;
	size_t last_eom_parse = 0;
	size_t block_line_parse = 0, block_line_pos = 0;
	/* shared_ptr is used so copies of STREAM are effectively data clones with their own cursors */
	std::shared_ptr<std::list<stream_block>> list;

	protected:
	friend void stream_split_eom(STREAM *, STREAM *);
};
