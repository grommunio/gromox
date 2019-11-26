#include "util.h"
#include "proc_common.h"
#include "common_util.h"
#include "rop_processor.h"
#include "stream_object.h"
#include "folder_object.h"
#include "message_object.h"
#include "attachment_object.h"
#include <stdlib.h>
#include <string.h>

#define STREAM_INIT_BUFFER_LENGTH						4096

STREAM_OBJECT* stream_object_create(void *pparent, int object_type,
	uint32_t open_flags, uint32_t proptag, uint32_t max_length)
{
	void *pvalue;
	int buff_len;
	int utf16_len;
	uint32_t *psize;
	STREAM_OBJECT *pstream;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t proptag_buff[2];
	
	pstream = malloc(sizeof(STREAM_OBJECT));
	if (NULL == pstream) {
		return NULL;
	}
	pstream->pparent = pparent;
	pstream->object_type = object_type;
	pstream->open_flags = open_flags;
	pstream->proptag = proptag;
	pstream->seek_ptr = 0;
	pstream->max_length = max_length;
	pstream->b_touched = FALSE;
	switch (object_type) {
	case OBJECT_TYPE_MESSAGE:
		proptags.count = 2;
		proptags.pproptag = proptag_buff;
		proptag_buff[0] = proptag;
		proptag_buff[1] = PROP_TAG_MESSAGESIZE;
		if (FALSE == message_object_get_properties(
			pparent, 0, &proptags, &propvals)) {
			free(pstream);
			return NULL;
		}
		psize = common_util_get_propvals(
			&propvals, PROP_TAG_MESSAGESIZE);
		if (NULL != psize && *psize >= common_util_get_param(
			COMMON_UTIL_MAX_MAIL_LENGTH)) {
			free(pstream);
			return NULL;
		}
		break;
	case OBJECT_TYPE_ATTACHMENT:
		proptags.count = 2;
		proptags.pproptag = proptag_buff;
		proptag_buff[0] = proptag;
		proptag_buff[1] = PROP_TAG_ATTACHSIZE;
		if (FALSE == attachment_object_get_properties(
			pparent, 0, &proptags, &propvals)) {
			free(pstream);
			return NULL;
		}
		psize = common_util_get_propvals(
			&propvals, PROP_TAG_ATTACHSIZE);
		if (NULL != psize && *psize >= common_util_get_param(
			COMMON_UTIL_MAX_MAIL_LENGTH)) {
			free(pstream);
			return NULL;
		}
		break;
	case OBJECT_TYPE_FOLDER:
		proptags.count = 1;
		proptags.pproptag = &proptag;
		if (FALSE == folder_object_get_properties(
			pparent, &proptags, &propvals)) {
			free(pstream);
			return NULL;
		}
		break;
	default:
		free(pstream);
		return NULL;
	}
	pvalue = common_util_get_propvals(&propvals, proptag);
	if (NULL == pvalue) {
		if (0 == (open_flags & OPENSTREAM_FLAG_CREATE)) {
			/* cannot find proptag, return immediately to
			caller and the caller check the result by
			calling stream_object_check */
			pstream->content_bin.pb = NULL;
			return pstream;
		} else {
			pstream->content_bin.cb = 0;
			pstream->content_bin.pb =
				malloc(STREAM_INIT_BUFFER_LENGTH);
			if (NULL == pstream->content_bin.pb) {
				free(pstream);
				return NULL;
			}
			return pstream;
		}
	}
	switch (proptag & 0xFFFF) {
	case PROPVAL_TYPE_BINARY:
	case PROPVAL_TYPE_OBJECT:
		pstream->content_bin.cb = ((BINARY*)pvalue)->cb;
		pstream->content_bin.pb = malloc(((BINARY*)pvalue)->cb);
		if (NULL == pstream->content_bin.pb) {
			free(pstream);
			return NULL;
		}
		memcpy(pstream->content_bin.pb,
			((BINARY*)pvalue)->pb, ((BINARY*)pvalue)->cb);
		return pstream;
	case PROPVAL_TYPE_STRING:
		pstream->content_bin.cb = strlen(pvalue) + 1;
		pstream->content_bin.pb = malloc(pstream->content_bin.cb);
		if (NULL == pstream->content_bin.pb) {
			free(pstream);
			return NULL;
		}
		memcpy(pstream->content_bin.pb,
			((BINARY*)pvalue)->pb, pstream->content_bin.cb);
		return pstream;
	case PROPVAL_TYPE_WSTRING:
		buff_len = 2*strlen(pvalue) + 2;
		pstream->content_bin.pb = malloc(buff_len);
		if (NULL == pstream->content_bin.pb) {
			free(pstream);
			return NULL;
		}
		utf16_len = utf8_to_utf16le(pvalue,
			pstream->content_bin.pb, buff_len);
		if (utf16_len < 2) {
			pstream->content_bin.pb[0] = '\0';
			pstream->content_bin.pb[1] = '\0';
			utf16_len = 2;
		}
		pstream->content_bin.cb = utf16_len;
		return pstream;
	default:
		free(pstream);
		return NULL;
	}
}

BOOL stream_object_check(STREAM_OBJECT *pstream)
{
	if (NULL != pstream->content_bin.pb) {
		return TRUE;
	} else {
		return FALSE;
	}
}

uint32_t stream_object_get_max_length(STREAM_OBJECT *pstream)
{
	return pstream->max_length;
}

uint16_t stream_object_read(STREAM_OBJECT *pstream,
	void *pbuff, uint16_t buf_len)
{
	uint16_t length;
	
	if (pstream->content_bin.cb <= pstream->seek_ptr) {
		return 0;
	}
	if (pstream->seek_ptr + buf_len > pstream->content_bin.cb) {
		length = pstream->content_bin.cb - pstream->seek_ptr;
	} else {
		length = buf_len;
	}
	memcpy(pbuff, pstream->content_bin.pb + pstream->seek_ptr, length);
	pstream->seek_ptr += length;
	return length;
}

uint16_t stream_object_write(STREAM_OBJECT *pstream,
	void *pbuff, uint16_t buf_len)
{
	if (OPENSTREAM_FLAG_READONLY == pstream->open_flags) {
		return 0;
	}
	if (pstream->content_bin.cb >= pstream->max_length &&
		pstream->seek_ptr >= pstream->content_bin.cb) {
		return 0;
	}
	if (pstream->seek_ptr + buf_len > pstream->content_bin.cb) {
		if (FALSE == stream_object_set_length(pstream,
			pstream->seek_ptr + buf_len)) {
			return 0;	
		}
	}
	if (OBJECT_TYPE_ATTACHMENT == pstream->object_type) {
		if (FALSE == attachment_object_append_stream_object(
			pstream->pparent, pstream)) {
			return 0;	
		} 
	} else if (OBJECT_TYPE_MESSAGE == pstream->object_type) {
		if (FALSE == message_object_append_stream_object(
			pstream->pparent, pstream)) {
			return 0;	
		} 
	}
	memcpy(pstream->content_bin.pb +
		pstream->seek_ptr, pbuff, buf_len);
	pstream->seek_ptr += buf_len;
	pstream->b_touched = TRUE;
	return buf_len;
}

uint8_t stream_object_get_open_flags(STREAM_OBJECT *pstream)
{
	return pstream->open_flags;
}

int stream_object_get_parent_type(STREAM_OBJECT *pstream)
{
	return pstream->object_type;
}

uint32_t stream_object_get_proptag(STREAM_OBJECT *pstream)
{
	return pstream->proptag;
}

void* stream_object_get_content(STREAM_OBJECT *pstream)
{
	void *pcontent;
	uint32_t length;
	
	switch (pstream->proptag & 0xFFFF) {
	case PROPVAL_TYPE_BINARY:
		return &pstream->content_bin;
	case PROPVAL_TYPE_STRING:
		return pstream->content_bin.pb;
	case PROPVAL_TYPE_WSTRING:
		length = 2*pstream->content_bin.cb;
		pcontent = common_util_alloc(length);
		if (NULL == pcontent) {
			return NULL;
		}
		if (FALSE == utf16le_to_utf8(
			pstream->content_bin.pb,
			pstream->content_bin.cb,
			pcontent, length)) {
			return NULL;
		}
		return pcontent;
	}
	return NULL;
}

uint32_t stream_object_get_length(STREAM_OBJECT *pstream)
{
	return pstream->content_bin.cb;
}

BOOL stream_object_set_length(
	STREAM_OBJECT *pstream, uint32_t length)
{
	void *pdata;
	
	if (OPENSTREAM_FLAG_READONLY == pstream->open_flags) {
		return FALSE;
	}
	if (length > pstream->content_bin.cb) {
		if (length > pstream->max_length) {
			return FALSE;
		}
		pdata = realloc(pstream->content_bin.pb, length);
		if (NULL == pdata) {
			return FALSE;
		}
		pstream->content_bin.pb = pdata;
		memset(pstream->content_bin.pb + pstream->content_bin.cb,
							0, length - pstream->content_bin.cb);
	} else {
		if (pstream->seek_ptr > length) {
			pstream->seek_ptr = length;
		}
	}
	pstream->content_bin.cb = length;
	pstream->b_touched = TRUE;
	return TRUE;
}

BOOL stream_object_seek(STREAM_OBJECT *pstream,
	uint8_t opt, int32_t offset)
{	
	switch (opt) {
	case SEEK_POS_BEGIN:
		if (offset <= 0) {
			pstream->seek_ptr = 0;
			return TRUE;
		}
		if (offset > pstream->content_bin.cb) {
			if (FALSE == stream_object_set_length(
				pstream, offset)) {
				return FALSE;
			}
		}
		pstream->seek_ptr = offset;
		return TRUE; 
	case SEEK_POS_CURRENT:
		if (offset < 0) {
			if (pstream->seek_ptr + offset < 0) {
				pstream->seek_ptr = 0;
				return TRUE;
			}
			pstream->seek_ptr += offset;
			return TRUE;
		}
		if (offset + pstream->seek_ptr >
			pstream->content_bin.cb) {
			if (FALSE == stream_object_set_length(
				pstream, pstream->seek_ptr + offset)) {
				return FALSE;
			}
		}
		pstream->seek_ptr += offset;
		return TRUE;
	case SEEK_POS_END:
		if (offset > 0) {
			if (FALSE == stream_object_set_length(
				pstream, pstream->content_bin.cb + offset)) {
				return FALSE;
			}
		}
		pstream->seek_ptr = pstream->content_bin.cb + offset;
		if (pstream->seek_ptr < 0) {
			pstream->seek_ptr = 0;
		}
		return TRUE;
	}
	return FALSE;
}

uint32_t stream_object_get_seek_position(STREAM_OBJECT *pstream)
{
	return pstream->seek_ptr;
}

BOOL stream_object_copy(STREAM_OBJECT *pstream_dst,
	STREAM_OBJECT *pstream_src, uint32_t *plength)
{
	if (pstream_src->seek_ptr >=
		pstream_src->content_bin.cb) {
		*plength = 0;
		return TRUE;
	}
	if (pstream_dst->seek_ptr >=
		pstream_dst->max_length) {
		*plength = 0;
		return TRUE;
	}
	if (pstream_src->seek_ptr + *plength >
		pstream_src->content_bin.cb) {
		*plength = pstream_src->content_bin.cb -
							pstream_src->seek_ptr;
	}
	if (pstream_dst->seek_ptr + *plength >
		pstream_dst->max_length) {
		*plength = pstream_dst->max_length -
						pstream_dst->seek_ptr;
	}
	if (pstream_dst->seek_ptr + *plength >
		pstream_dst->content_bin.cb) {
		if (FALSE == stream_object_set_length(
			pstream_dst, pstream_dst->seek_ptr + *plength)) {
			return FALSE;	
		}
	}
	memcpy(pstream_dst->content_bin.pb +
		pstream_dst->seek_ptr,
		pstream_src->content_bin.pb +
		pstream_src->seek_ptr, *plength);
	pstream_dst->seek_ptr += *plength;
	pstream_src->seek_ptr += *plength;
	return TRUE;
}

BOOL stream_object_commit(STREAM_OBJECT *pstream)
{
	TAGGED_PROPVAL propval;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	
	if (OBJECT_TYPE_FOLDER != pstream->object_type) {
		return FALSE;
	}
	if (OPENSTREAM_FLAG_READONLY == pstream->object_type) {
		return FALSE;
	}
	if (FALSE == pstream->b_touched) {
		return TRUE;
	}
	propvals.count = 1;
	propvals.ppropval = &propval;
	propval.proptag = pstream->proptag;
	propval.pvalue = stream_object_get_content(pstream);
	if (NULL == propval.pvalue) {
		return FALSE;
	}
	if (FALSE == folder_object_set_properties(
		pstream->pparent, &propvals, &problems) ||
		problems.count > 0) {
		return FALSE;
	}
	pstream->b_touched = FALSE;
	return TRUE;
}

void stream_object_free(STREAM_OBJECT *pstream)
{
	if (NULL == pstream->content_bin.pb) {
		free(pstream);
		return;
	}
	switch (pstream->object_type) {
	case OBJECT_TYPE_FOLDER:
		if (TRUE == pstream->b_touched) {
			stream_object_commit(pstream);
		}
		break;
	case OBJECT_TYPE_ATTACHMENT:
		if (TRUE == pstream->b_touched) {
			attachment_object_commit_stream_object(
						pstream->pparent, pstream);
		}
		break;
	case OBJECT_TYPE_MESSAGE:
		if (TRUE == pstream->b_touched) {
			message_object_commit_stream_object(
						pstream->pparent, pstream);
		}
		break;
	}
	free(pstream->content_bin.pb);
	free(pstream);
}
