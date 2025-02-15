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
#include "attachment_object.hpp"
#include "common_util.hpp"
#include "folder_object.hpp"
#include "message_object.hpp"
#include "rop_processor.hpp"
#include "stream_object.hpp"

using namespace gromox;

std::unique_ptr<stream_object> stream_object::create(void *pparent,
    ems_objtype object_type, uint32_t open_flags, uint32_t proptag, uint32_t max_length)
{
	TPROPVAL_ARRAY propvals;
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
	case ems_objtype::message: {
		const proptag_t proptag_buff[] = {proptag, PR_MESSAGE_SIZE};
		const PROPTAG_ARRAY proptags = {std::size(proptag_buff), deconst(proptag_buff)};
		if (!static_cast<message_object *>(pparent)->get_properties(0, &proptags, &propvals))
			return NULL;
		auto psize = propvals.get<uint32_t>(PR_MESSAGE_SIZE);
		if (psize != nullptr && *psize >= g_max_mail_len)
			return NULL;
		break;
	}
	case ems_objtype::attach: {
		const proptag_t proptag_buff[] = {proptag, PR_ATTACH_SIZE};
		const PROPTAG_ARRAY proptags = {std::size(proptag_buff), deconst(proptag_buff)};
		if (!static_cast<attachment_object *>(pparent)->get_properties(0, &proptags, &propvals))
			return NULL;
		auto psize = propvals.get<uint32_t>(PR_ATTACH_SIZE);
		if (psize != nullptr && *psize >= g_max_mail_len)
			return NULL;
		break;
	}
	case ems_objtype::folder: {
		const PROPTAG_ARRAY proptags = {1, &proptag};
		if (!static_cast<const folder_object *>(pparent)->get_properties(&proptags, &propvals))
			return NULL;
		break;
	}
	default:
		return NULL;
	}
	auto pvalue = propvals.getval(proptag);
	if (NULL == pvalue) {
		if (!(open_flags & MAPI_CREATE)) {
			/* cannot find proptag, return immediately to
			caller and the caller check the result by
			calling stream_object_check */
			pstream->content_bin.pb = NULL;
			return pstream;
		} else {
			pstream->content_bin.cb = 0;
			pstream->content_bin.pv = malloc(1);
			if (pstream->content_bin.pv == nullptr)
				return NULL;
			return pstream;
		}
	}
	switch (PROP_TYPE(proptag)) {
	case PT_BINARY:
	case PT_OBJECT: {
		auto bv = static_cast<const BINARY *>(pvalue);
		pstream->content_bin.cb = bv->cb;
		pstream->content_bin.pv = malloc(bv->cb);
		if (pstream->content_bin.pv == nullptr)
			return NULL;
		memcpy(pstream->content_bin.pv, bv->pv, bv->cb);
		return pstream;
	}
	case PT_STRING8: {
		auto val = static_cast<const char *>(pvalue);
		pstream->content_bin.cb = strlen(val) + 1;
		pstream->content_bin.pv = malloc(pstream->content_bin.cb);
		if (pstream->content_bin.pv == nullptr)
			return NULL;
		memcpy(pstream->content_bin.pv, val,
		       pstream->content_bin.cb);
		return pstream;
	}
	case PT_UNICODE: {
		auto val = static_cast<const char *>(pvalue);
		auto buff_len = utf8_to_utf16_len(val);
		pstream->content_bin.pv = malloc(buff_len);
		if (pstream->content_bin.pv == nullptr)
			return NULL;
		auto utf16_len = utf8_to_utf16le(val,
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
	if (pstream->content_bin.cb <= pstream->seek_ptr)
		return 0;
	auto length = std::min(buf_len, pstream->content_bin.cb - pstream->seek_ptr);
	memcpy(pbuff, pstream->content_bin.pb + pstream->seek_ptr, length);
	pstream->seek_ptr += length;
	return length;
}

std::pair<uint16_t, ec_error_t> stream_object::write(void *pbuff, uint16_t buf_len)
{
	auto pstream = this;
	if (pstream->open_flags == MAPI_READONLY)
		return {0, STG_E_ACCESSDENIED};
	if (pstream->content_bin.cb >= pstream->max_length &&
	    pstream->seek_ptr >= pstream->content_bin.cb)
		return {0, ecTooBig};
	int8_t clamped = 0;
	auto newpos = safe_add_s(pstream->seek_ptr, buf_len, &clamped);
	if (clamped >= 1)
		return {0, ecTooBig};
	if (newpos > pstream->content_bin.cb) {
		auto ret = set_length(newpos);
		if (ret != ecSuccess)
			return {0, ret};
	}
	if (pstream->object_type == ems_objtype::attach) {
		if (!static_cast<attachment_object *>(pstream->pparent)->append_stream_object(pstream))
			return {0, ecServerOOM};
	} else if (pstream->object_type == ems_objtype::message) {
		if (!static_cast<message_object *>(pstream->pparent)->append_stream_object(pstream))
			return {0, ecServerOOM};
	}
	memcpy(pstream->content_bin.pb +
		pstream->seek_ptr, pbuff, buf_len);
	pstream->seek_ptr = newpos;
	pstream->b_touched = TRUE;
	return {buf_len, ecSuccess};
}

const void *stream_object::get_content() const
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
		if (pcontent == nullptr)
			return NULL;
		if (!utf16le_to_utf8(pstream->content_bin.pb,
		    pstream->content_bin.cb, static_cast<char *>(pcontent), length))
			return NULL;
		return pcontent;
	}
	return NULL;
}

ec_error_t stream_object::set_length(uint32_t length)
{
	auto pstream = this;
	
	if (pstream->open_flags == MAPI_READONLY)
		return STG_E_ACCESSDENIED;
	if (length > pstream->content_bin.cb) {
		if (length > pstream->max_length)
			return ecStreamSizeError;
		auto pdata = gromox::re_alloc<uint8_t>(pstream->content_bin.pb, length);
		if (pdata == nullptr)
			return ecServerOOM;
		pstream->content_bin.pb = pdata;
		memset(pstream->content_bin.pb + pstream->content_bin.cb,
			0, length - pstream->content_bin.cb);
	} else {
		if (pstream->seek_ptr > length)
			pstream->seek_ptr = length;
	}
	pstream->content_bin.cb = length;
	pstream->b_touched = TRUE;
	return ecSuccess;
}

ec_error_t stream_object::seek(uint8_t opt, int64_t offset)
{	
	auto pstream = this;
	uint64_t origin;
	switch (opt) {
	case STREAM_SEEK_SET: origin = 0; break;
	case STREAM_SEEK_CUR: origin = pstream->seek_ptr; break;
	case STREAM_SEEK_END: origin = pstream->content_bin.cb; break;
	default: return STG_E_INVALIDPARAMETER;
	}
	int8_t clamped = 0;
	auto newpos = safe_add_s(origin, offset, &clamped);
	if (clamped > 1)
		return StreamSeekError;
	if (newpos > pstream->content_bin.cb) {
		auto ret = set_length(newpos);
		if (ret != ecSuccess)
			return ret;
	}
	pstream->seek_ptr = newpos;
	return ecSuccess;
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
	if (pstream_src->seek_ptr + *plength > pstream_src->content_bin.cb)
		*plength = pstream_src->content_bin.cb - pstream_src->seek_ptr;
	if (pstream_dst->seek_ptr + *plength > pstream_dst->max_length)
		*plength = pstream_dst->max_length - pstream_dst->seek_ptr;
	if (pstream_dst->seek_ptr + *plength > pstream_dst->content_bin.cb &&
	    pstream_dst->set_length(pstream_dst->seek_ptr + *plength) != ecSuccess)
		return FALSE;
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
	
	if (pstream->object_type != ems_objtype::folder)
		return FALSE;
	if (pstream->open_flags == MAPI_READONLY)
		return FALSE;
	if (!pstream->b_touched)
		return TRUE;
	propvals.count = 1;
	propvals.ppropval = &propval;
	propval.proptag = pstream->proptag;
	propval.pvalue  = deconst(get_content());
	if (propval.pvalue == nullptr)
		return FALSE;
	if (!static_cast<folder_object *>(pstream->pparent)->set_properties(&propvals, &problems) ||
	    problems.count > 0)
		return FALSE;
	pstream->b_touched = FALSE;
	return TRUE;
}

stream_object::~stream_object()
{
	auto pstream = this;
	if (pstream->content_bin.pb == nullptr)
		return;
	switch (pstream->object_type) {
	case ems_objtype::folder:
		if (pstream->b_touched)
			commit();
		break;
	case ems_objtype::attach:
		if (pstream->b_touched)
			static_cast<attachment_object *>(pstream->pparent)->commit_stream_object(pstream);
		break;
	case ems_objtype::message:
		if (pstream->b_touched)
			static_cast<message_object *>(pstream->pparent)->commit_stream_object(pstream);
		break;
	default:
		break;
	}
	free(pstream->content_bin.pb);
}
