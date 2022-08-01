// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <gromox/mapidefs.h>
#include <gromox/proc_common.h>
#include <gromox/safeint.hpp>
#include <gromox/util.hpp>
#include "attachment_object.h"
#include "common_util.h"
#include "folder_object.h"
#include "message_object.h"
#include "rop_processor.h"
#include "stream_object.h"
#define STREAM_INIT_BUFFER_LENGTH						4096

using namespace gromox;

std::unique_ptr<stream_object> stream_object::create(void *pparent,
    int object_type, uint32_t open_flags, uint32_t proptag, uint32_t max_length)
{
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t proptag_buff[2];
	std::unique_ptr<stream_object> pstream;

	try {
		pstream.reset(new stream_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pstream->pparent = pparent;
	pstream->object_type = object_type;
	pstream->open_flags = open_flags;
	pstream->proptag = proptag;
	pstream->max_length = max_length;
	switch (object_type) {
	case OBJECT_TYPE_MESSAGE: {
		proptags.count = 2;
		proptags.pproptag = proptag_buff;
		proptag_buff[0] = proptag;
		proptag_buff[1] = PR_MESSAGE_SIZE;
		if (!static_cast<message_object *>(pparent)->get_properties(0, &proptags, &propvals))
			return NULL;
		auto psize = propvals.get<uint32_t>(PR_MESSAGE_SIZE);
		if (psize != nullptr && *psize >= g_max_mail_len)
			return NULL;
		break;
	}
	case OBJECT_TYPE_ATTACHMENT: {
		proptags.count = 2;
		proptags.pproptag = proptag_buff;
		proptag_buff[0] = proptag;
		proptag_buff[1] = PR_ATTACH_SIZE;
		if (!static_cast<attachment_object *>(pparent)->get_properties(0, &proptags, &propvals))
			return NULL;
		auto psize = propvals.get<uint32_t>(PR_ATTACH_SIZE);
		if (psize != nullptr && *psize >= g_max_mail_len)
			return NULL;
		break;
	}
	case OBJECT_TYPE_FOLDER:
		proptags.count = 1;
		proptags.pproptag = &proptag;
		if (!static_cast<folder_object *>(pparent)->get_properties(&proptags, &propvals))
			return NULL;
		break;
	default:
		return NULL;
	}
	auto pvalue = propvals.getval(proptag);
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
	case PT_UNICODE: {
		auto buff_len = utf8_to_utf16_len(static_cast<char *>(pvalue));
		pstream->content_bin.pv = malloc(buff_len);
		if (pstream->content_bin.pv == nullptr) {
			return NULL;
		}
		auto utf16_len = utf8_to_utf16le(static_cast<char *>(pvalue),
			pstream->content_bin.pb, buff_len);
		if (utf16_len < 2) {
			pstream->content_bin.pb[0] = '\0';
			pstream->content_bin.pb[1] = '\0';
			utf16_len = 2;
		}
		pstream->content_bin.cb = utf16_len;
		return pstream;
	}
	default:
		return NULL;
	}
}

uint32_t stream_object::read(void *pbuff, uint32_t buf_len)
{
	auto pstream = this;
	if (pstream->content_bin.cb <= pstream->seek_ptr) {
		return 0;
	}
	auto length = std::min(buf_len, pstream->content_bin.cb - pstream->seek_ptr);
	memcpy(pbuff, pstream->content_bin.pb + pstream->seek_ptr, length);
	pstream->seek_ptr += length;
	return length;
}

uint16_t stream_object::write(void *pbuff, uint16_t buf_len)
{
	auto pstream = this;
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
	if (newpos > pstream->content_bin.cb && !set_length(newpos))
		return 0;
	if (OBJECT_TYPE_ATTACHMENT == pstream->object_type) {
		if (!static_cast<attachment_object *>(pstream->pparent)->append_stream_object(pstream))
			return 0;	
	} else if (OBJECT_TYPE_MESSAGE == pstream->object_type) {
		if (!static_cast<message_object *>(pstream->pparent)->append_stream_object(pstream))
			return 0;	
	}
	memcpy(pstream->content_bin.pb +
		pstream->seek_ptr, pbuff, buf_len);
	pstream->seek_ptr = newpos;
	pstream->b_touched = TRUE;
	return buf_len;
}

void *stream_object::get_content()
{
	auto pstream = this;
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

BOOL stream_object::set_length(uint32_t length)
{
	auto pstream = this;
	
	if (OPENSTREAM_FLAG_READONLY == pstream->open_flags) {
		return FALSE;
	}
	if (length > pstream->content_bin.cb) {
		if (length > pstream->max_length) {
			return FALSE;
		}
		auto pdata = gromox::re_alloc<uint8_t>(pstream->content_bin.pb, length);
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

BOOL stream_object::seek(uint8_t opt, int64_t offset)
{	
	auto pstream = this;
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
	if (newpos > pstream->content_bin.cb && !set_length(newpos))
		return false;
	pstream->seek_ptr = newpos;
	return TRUE;
}

BOOL stream_object::copy(stream_object *pstream_src, uint32_t *plength)
{
	auto pstream_dst = this;
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
		if (!pstream_dst->set_length(pstream_dst->seek_ptr + *plength))
			return FALSE;	
	}
	memcpy(pstream_dst->content_bin.pb +
		pstream_dst->seek_ptr,
		pstream_src->content_bin.pb +
		pstream_src->seek_ptr, *plength);
	pstream_dst->seek_ptr += *plength;
	pstream_src->seek_ptr += *plength;
	return TRUE;
}

BOOL stream_object::commit()
{
	auto pstream = this;
	TAGGED_PROPVAL propval;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	
	if (OBJECT_TYPE_FOLDER != pstream->object_type) {
		return FALSE;
	}
	if (OPENSTREAM_FLAG_READONLY == pstream->object_type) {
		return FALSE;
	}
	if (!pstream->b_touched)
		return TRUE;
	propvals.count = 1;
	propvals.ppropval = &propval;
	propval.proptag = pstream->proptag;
	propval.pvalue = get_content();
	if (NULL == propval.pvalue) {
		return FALSE;
	}
	if (!static_cast<folder_object *>(pstream->pparent)->set_properties(&propvals, &problems) ||
	    problems.count > 0)
		return FALSE;
	pstream->b_touched = FALSE;
	return TRUE;
}

stream_object::~stream_object()
{
	auto pstream = this;
	if (NULL == pstream->content_bin.pb) {
		return;
	}
	switch (pstream->object_type) {
	case OBJECT_TYPE_FOLDER:
		if (pstream->b_touched)
			commit();
		break;
	case OBJECT_TYPE_ATTACHMENT:
		if (pstream->b_touched)
			static_cast<attachment_object *>(pstream->pparent)->commit_stream_object(pstream);
		break;
	case OBJECT_TYPE_MESSAGE:
		if (pstream->b_touched)
			static_cast<message_object *>(pstream->pparent)->commit_stream_object(pstream);
		break;
	}
	free(pstream->content_bin.pb);
}
