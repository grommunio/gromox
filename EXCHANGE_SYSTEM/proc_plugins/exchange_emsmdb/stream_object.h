#pragma once
#include "mapi_types.h"

#define MAX_LENGTH_FOR_FOLDER						64*1024

struct STREAM_OBJECT {
	void *pparent;
	int object_type;
	uint8_t open_flags;
	uint32_t proptag;
	uint32_t seek_ptr;
	BINARY content_bin;
	BOOL b_touched;
	uint32_t max_length;
};

#ifdef __cplusplus
extern "C" {
#endif

STREAM_OBJECT* stream_object_create(void *pparent, int object_type,
	uint32_t open_flags, uint32_t proptag, uint32_t max_length);

BOOL stream_object_check(STREAM_OBJECT *pstream);

uint32_t stream_object_get_max_length(STREAM_OBJECT *pstream);

uint16_t stream_object_read(STREAM_OBJECT *pstream,
	void *pbuff, uint16_t buf_len);

uint16_t stream_object_write(STREAM_OBJECT *pstream,
	void *pbuff, uint16_t buf_len);

uint8_t stream_object_get_open_flags(STREAM_OBJECT *pstream);

int stream_object_get_parent_type(STREAM_OBJECT *pstream);

uint32_t stream_object_get_proptag(STREAM_OBJECT *pstream);

void* stream_object_get_content(STREAM_OBJECT *pstream);

uint32_t stream_object_get_length(STREAM_OBJECT *pstream);

BOOL stream_object_set_length(
	STREAM_OBJECT *pstream, uint32_t length);

BOOL stream_object_seek(STREAM_OBJECT *pstream,
	uint8_t opt, int32_t offset);

uint32_t stream_object_get_seek_position(STREAM_OBJECT *pstream);

BOOL stream_object_copy(STREAM_OBJECT *pstream_dst,
	STREAM_OBJECT *pstream_src, uint32_t *plength);

BOOL stream_object_commit(STREAM_OBJECT *pstream);

void stream_object_free(STREAM_OBJECT *pstream);

#ifdef __cplusplus
} /* extern "C" */
#endif
