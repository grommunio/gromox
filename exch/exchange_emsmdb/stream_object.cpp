// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <climits>
#include <cstdint>
#include <memory>
#include <gromox/util.hpp>
#include <gromox/mapidefs.h>
#include <gromox/proc_common.h>
#include <gromox/safeint.hpp>
#include "common_util.h"
#include "rop_processor.h"
#include "stream_object.h"
#include "folder_object.h"
#include "message_object.h"
#include "attachment_object.h"
#include <cstdlib>
#include <cstring>
#define STREAM_INIT_BUFFER_LENGTH						4096

std::unique_ptr<STREAM_OBJECT> stream_object_create(void *pparent, int object_type,
	uint32_t open_flags, uint32_t proptag, uint32_t max_length)
{
	int buff_len;
	int utf16_len;
	uint32_t *psize;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t proptag_buff[2];
	std::unique_ptr<STREAM_OBJECT> pstream;

	try {
		pstream = std::make_unique<STREAM_OBJECT>();
	} catch (const std::bad_alloc &) {
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
		proptag_buff[1] = PR_MESSAGE_SIZE;
		if (!static_cast<MESSAGE_OBJECT *>(pparent)->get_properties(0, &proptags, &propvals))
			return NULL;
		psize = static_cast<uint32_t *>(common_util_get_propvals(&propvals, PR_MESSAGE_SIZE));
		if (NULL != psize && *psize >= common_util_get_param(
			COMMON_UTIL_MAX_MAIL_LENGTH)) {
			return NULL;
		}
		break;
	case OBJECT_TYPE_ATTACHMENT:
		proptags.count = 2;
		proptags.pproptag = proptag_buff;
		proptag_buff[0] = proptag;
		proptag_buff[1] = PROP_TAG_ATTACHSIZE;
		if (!attachment_object_get_properties(static_cast<ATTACHMENT_OBJECT *>(pparent),
		    0, &proptags, &propvals)) {
			return NULL;
		}
		psize = static_cast<uint32_t *>(common_util_get_propvals(
		        &propvals, PROP_TAG_ATTACHSIZE));
		if (NULL != psize && *psize >= common_util_get_param(
			COMMON_UTIL_MAX_MAIL_LENGTH)) {
			return NULL;
		}
		break;
	case OBJECT_TYPE_FOLDER:
		proptags.count = 1;
		proptags.pproptag = &proptag;
		if (!static_cast<FOLDER_OBJECT *>(pparent)->get_properties(&proptags, &propvals))
			return NULL;
		break;
	default:
		return NULL;
	}
	auto pvalue = common_util_get_propvals(&propvals, proptag);
	if (NULL == pvalue) {
		if (0 == (open_flags & OPENSTREAM_FLAG_CREATE)) {
			/* cannot find proptag, return immediately to
			caller and the caller check the result by
			calling stream_object_check */
			pstream->content_bin.pb = NULL;
			return pstream;
		} else {
			pstream->content_bin.cb = 0;
			pstream->content_bin.pv =
				malloc(STREAM_INIT_BUFFER_LENGTH);
			if (pstream->content_bin.pv == nullptr) {
				return NULL;
			}
			return pstream;
		}
	}
	switch (PROP_TYPE(proptag)) {
	case PT_BINARY:
	case PT_OBJECT: {
		auto bv = static_cast<BINARY *>(pvalue);
		pstream->content_bin.cb = bv->cb;
		pstream->content_bin.pv = malloc(bv->cb);
		if (pstream->content_bin.pv == nullptr) {
			return NULL;
		}
		memcpy(pstream->content_bin.pv, bv->pv, bv->cb);
		return pstream;
	}
	case PT_STRING8:
		pstream->content_bin.cb = strlen(static_cast<char *>(pvalue)) + 1;
		pstream->content_bin.pv = malloc(pstream->content_bin.cb);
		if (pstream->content_bin.pv == nullptr) {
			return NULL;
		}
		memcpy(pstream->content_bin.pv, static_cast<BINARY *>(pvalue)->pv,
		       pstream->content_bin.cb);
		return pstream;
	case PT_UNICODE:
		buff_len = 2 * strlen(static_cast<char *>(pvalue)) + 2;
		pstream->content_bin.pv = malloc(buff_len);
		if (pstream->content_bin.pv == nullptr) {
			return NULL;
		}
		utf16_len = utf8_to_utf16le(static_cast<char *>(pvalue),
			pstream->content_bin.pb, buff_len);
		if (utf16_len < 2) {
			pstream->content_bin.pb[0] = '\0';
			pstream->content_bin.pb[1] = '\0';
			utf16_len = 2;
		}
		pstream->content_bin.cb = utf16_len;
		return pstream;
	default:
		return NULL;
	}
}

BOOL stream_object_check(STREAM_OBJECT *pstream)
{
	return pstream->content_bin.pb != nullptr ? TRUE : false;
}

uint32_t stream_object_get_max_length(STREAM_OBJECT *pstream)
{
	return pstream->max_length;
}

uint32_t stream_object_read(STREAM_OBJECT *pstream, void *pbuff, uint32_t buf_len)
{
	if (pstream->content_bin.cb <= pstream->seek_ptr) {
		return 0;
	}
	auto length = std::min(buf_len, pstream->content_bin.cb - pstream->seek_ptr);
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
	int8_t clamped = 0;
	auto newpos = safe_add_s(pstream->seek_ptr, buf_len, &clamped);
	if (clamped >= 1)
		return 0;
	if (newpos > pstream->content_bin.cb &&
	    !stream_object_set_length(pstream, newpos))
		return 0;
	if (OBJECT_TYPE_ATTACHMENT == pstream->object_type) {
		if (!attachment_object_append_stream_object(static_cast<ATTACHMENT_OBJECT *>(pstream->pparent), pstream))
			return 0;	
	} else if (OBJECT_TYPE_MESSAGE == pstream->object_type) {
		if (!static_cast<MESSAGE_OBJECT *>(pstream->pparent)->append_stream_object(pstream))
			return 0;	
	}
	memcpy(pstream->content_bin.pb +
		pstream->seek_ptr, pbuff, buf_len);
	pstream->seek_ptr = newpos;
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
	
	switch (PROP_TYPE(pstream->proptag)) {
	case PT_BINARY:
		return &pstream->content_bin;
	case PT_STRING8:
		return pstream->content_bin.pb;
	case PT_UNICODE:
		length = 2*pstream->content_bin.cb;
		pcontent = common_util_alloc(length);
		if (NULL == pcontent) {
			return NULL;
		}
		if (!utf16le_to_utf8(pstream->content_bin.pb,
		    pstream->content_bin.cb, static_cast<char *>(pcontent), length))
			return NULL;
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
		pstream->content_bin.pv = pdata;
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

BOOL stream_object_seek(STREAM_OBJECT *pstream, uint8_t opt, int64_t offset)
{	
	uint64_t origin;
	switch (opt) {
	case STREAM_SEEK_SET: origin = 0; break;
	case STREAM_SEEK_CUR: origin = pstream->seek_ptr; break;
	case STREAM_SEEK_END: origin = pstream->content_bin.cb; break;
	default: return false;
	}
	int8_t clamped = 0;
	auto newpos = safe_add_s(origin, offset, &clamped);
	if (clamped > 1)
		return false;
	if (newpos > pstream->content_bin.cb &&
	    !stream_object_set_length(pstream, newpos))
		return false;
	pstream->seek_ptr = newpos;
	return TRUE;
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
	if (!static_cast<FOLDER_OBJECT *>(pstream->pparent)->set_properties(&propvals, &problems) ||
	    problems.count > 0)
		return FALSE;
	pstream->b_touched = FALSE;
	return TRUE;
}

STREAM_OBJECT::~STREAM_OBJECT()
{
	auto pstream = this;
	if (NULL == pstream->content_bin.pb) {
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
			attachment_object_commit_stream_object(static_cast<ATTACHMENT_OBJECT *>(pstream->pparent), pstream);
		}
		break;
	case OBJECT_TYPE_MESSAGE:
		if (TRUE == pstream->b_touched) {
			static_cast<MESSAGE_OBJECT *>(pstream->pparent)->commit_stream_object(pstream);
		}
		break;
	}
	free(pstream->content_bin.pb);
}
