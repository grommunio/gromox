// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iconv.h>
#include <memory>
#include <utility>
#include <gromox/mapidefs.h>
#include <gromox/proc_common.h>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "nsp_ndr.hpp"
#define FLAG_HEADER			0x1
#define FLAG_CONTENT		0x2
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != pack_result::ok) return klfdv; } while (false)

using namespace gromox;

static pack_result nsp_ndr_pull_restriction(NDR_PULL &, unsigned int flag, NSPRES *r);
static pack_result nsp_ndr_push_restriction(NDR_PUSH &, unsigned int flag, const NSPRES &r);

static int32_t nsp_ndr_to_utf16(int ndr_flag, const char *src, char *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id = (ndr_flag & NDR_FLAG_BIGENDIAN) ?
	                  iconv_open("UTF-16", "UTF-8") :
	                  iconv_open("UTF-16LE", "UTF-8");
	if (conv_id == (iconv_t)-1)
		return -1;
	auto pin = deconst(src);
	auto pout = dst;
	in_len = strlen(src) + 1;
	memset(dst, 0, len);
	out_len = len;
	if (iconv(conv_id, &pin, &in_len, &pout, &len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return -1;
	} else {
		iconv_close(conv_id);
		return out_len - len;
	}
}

static BOOL nsp_ndr_to_utf8(int ndr_flag, const char *src,
	size_t src_len, char *dst, size_t len)
{
	iconv_t conv_id = (ndr_flag & NDR_FLAG_BIGENDIAN) ?
	                  iconv_open("UTF-8", "UTF-16") :
	                  iconv_open("UTF-8", "UTF-16LE");
	if (conv_id == (iconv_t)-1)
		return false;
	auto pin = deconst(src);
	auto pout = dst;
	memset(dst, 0, len);
	if (iconv(conv_id, &pin, &src_len, &pout, &len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return FALSE;
	} else {
		iconv_close(conv_id);
		return TRUE;
	}
}

static pack_result nsp_ndr_pull_stat(NDR_PULL &x, STAT *r)
{
	TRY(x.align(4));
	TRY(x.g_uint32(&r->sort_type));
	TRY(x.g_uint32(&r->container_id));
	TRY(x.g_uint32(&r->cur_rec));
	TRY(x.g_int32(&r->delta));
	TRY(x.g_uint32(&r->num_pos));
	TRY(x.g_uint32(&r->total_rec));
	uint32_t v;
	TRY(x.g_uint32(&v));
	r->codepage = static_cast<cpid_t>(v);
	TRY(x.g_uint32(&r->template_locale));
	TRY(x.g_uint32(&r->sort_locale));
	return x.trailer_align(4);
}

static pack_result nsp_ndr_push_stat(NDR_PUSH &x, const STAT &r)
{
	TRY(x.align(4));
	TRY(x.p_uint32(r.sort_type));
	TRY(x.p_uint32(r.container_id));
	TRY(x.p_uint32(r.cur_rec));
	TRY(x.p_int32(r.delta));
	TRY(x.p_uint32(r.num_pos));
	TRY(x.p_uint32(r.total_rec));
	TRY(x.p_uint32(r.codepage));
	TRY(x.p_uint32(r.template_locale));
	TRY(x.p_uint32(r.sort_locale));
	return x.trailer_align(4);
}

static pack_result nsp_ndr_pull_flatuid(NDR_PULL &x, FLATUID *r)
{
	return x.g_uint8_a(r->ab, 16);
}

static pack_result nsp_ndr_push_flatuid(NDR_PUSH &x, const FLATUID &r)
{	
	return x.p_uint8_a(r.ab, 16);
}

static pack_result nsp_ndr_pull_proptag_array(NDR_PULL &x, LPROPTAG_ARRAY *r)
{
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	TRY(x.align(4));
	TRY(x.g_uint32(&r->cvalues));
	if (r->cvalues > 100001)
		return pack_result::range;
	TRY(x.g_ulong(&offset));
	TRY(x.g_ulong(&length));
	if (offset != 0 || length > size)
		return pack_result::array_size;
	if (size != r->cvalues + 1 || length != r->cvalues)
		return pack_result::array_size;
	r->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_IN, size);
	if (r->pproptag == nullptr)
		return pack_result::alloc;
	for (size_t cnt = 0; cnt < length; ++cnt)
		TRY(x.g_uint32(&r->pproptag[cnt]));
	return x.trailer_align(4);
}

static pack_result nsp_ndr_pull_proptag_array(NDR_PULL &x, std::vector<proptag_t> *r) try
{
	uint32_t size, offset, length, cvalues;
	
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	TRY(x.align(4));
	TRY(x.g_uint32(&cvalues));
	if (cvalues > 100001)
		return pack_result::range;
	TRY(x.g_ulong(&offset));
	TRY(x.g_ulong(&length));
	if (offset != 0 || length > size)
		return pack_result::array_size;
	if (size != cvalues || length != cvalues)
		return pack_result::array_size;
	r->resize(length);
	for (size_t cnt = 0; cnt < length; ++cnt)
		TRY(x.g_uint32(&(*r)[cnt]));
	return x.trailer_align(4);
} catch (const std::bad_alloc &) {
	return pack_result::alloc;
}

static pack_result nsp_ndr_push_proptag_array(NDR_PUSH &x, proptag_cspan r)
{
	TRY(x.p_ulong(r.size() + 1));
	TRY(x.align(4));
	TRY(x.p_uint32(r.size()));
	TRY(x.p_ulong(0));
	TRY(x.p_ulong(r.size()));
	for (auto t : r)
		TRY(x.p_uint32(t));
	return x.trailer_align(4);
}

static pack_result nsp_ndr_pull_property_name(NDR_PULL &x,
    unsigned int flag, NSP_PROPNAME *r)
{
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_genptr(&ptr));
		if (0 != ptr) {
			r->pguid = ndr_stack_anew<FLATUID>(NDR_STACK_IN);
			if (r->pguid == nullptr)
				return pack_result::alloc;
		} else {
			r->pguid = NULL;
		}
		TRY(x.g_uint32(&r->reserved));
		TRY(x.g_uint32(&r->id));
		TRY(x.trailer_align(5));
	}
	
	if (flag & FLAG_CONTENT && r->pguid != nullptr)
		TRY(nsp_ndr_pull_flatuid(x, r->pguid));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_string_array(NDR_PULL &x,
    unsigned int flag, STRING_ARRAY *r)
{
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;
	uint32_t size1;
	uint32_t offset;
	uint32_t length1;
	

	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_uint32(&r->count));
		if (r->count > 100000)
			return pack_result::range;
		TRY(x.g_genptr(&ptr));
		r->ppstr = ptr != 0 ? reinterpret_cast<char **>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->ppstr == nullptr)
		return pack_result::ok;
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	if (size != r->count)
		/* count set by this or a previous function call with FLAG_HEADER */
		return pack_result::array_size;
	r->ppstr = ndr_stack_anew<char *>(NDR_STACK_IN, size);
	if (r->ppstr == nullptr)
		return pack_result::alloc;
	for (cnt = 0; cnt < size; cnt++) {
		TRY(x.g_genptr(&ptr));
		r->ppstr[cnt] = ptr != 0 ? reinterpret_cast<char *>(static_cast<uintptr_t>(ptr)) : nullptr;
	}
	for (cnt = 0; cnt < size; cnt++) {
		if (r->ppstr[cnt] == nullptr)
			continue;
		TRY(x.g_ulong(&size1));
		TRY(x.g_ulong(&offset));
		TRY(x.g_ulong(&length1));
		if (offset != 0 || length1 > size1)
			return pack_result::array_size;
		TRY(x.check_str(length1, sizeof(uint8_t)));
		r->ppstr[cnt] = ndr_stack_anew<char>(NDR_STACK_IN, length1 + 1);
		if (r->ppstr[cnt] == nullptr)
			return pack_result::alloc;
		TRY(x.g_str(r->ppstr[cnt], length1));
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_push_string_array(NDR_PUSH &x,
    unsigned int flag, const STRING_ARRAY &r)
{
	uint32_t length;
	
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_uint32(r.count));
		TRY(x.p_unique_ptr(r.ppstr));
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r.ppstr == nullptr)
		return pack_result::ok;
	TRY(x.p_ulong(r.count));
	for (size_t cnt = 0; cnt < r.count; ++cnt)
		TRY(x.p_unique_ptr(r.ppstr[cnt]));
	for (size_t cnt = 0; cnt < r.count; ++cnt) {
		if (r.ppstr[cnt] == nullptr)
			continue;
		length = strlen(r.ppstr[cnt]) + 1;
		TRY(x.p_ulong(length));
		TRY(x.p_ulong(0));
		TRY(x.p_ulong(length));
		TRY(x.p_str(r.ppstr[cnt], length));
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_strings_array(NDR_PULL &x,
    unsigned int flag, STRINGS_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;
	uint32_t size1;
	uint32_t offset;
	uint32_t length1;
	
	if (flag & FLAG_HEADER) {
		TRY(x.g_ulong(&size));
		size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
		TRY(x.align(5));
		TRY(x.g_uint32(&r->count));
		if (r->count > 100000)
			return pack_result::range;
		if (r->count != size)
			return pack_result::array_size;
		r->ppstr = ndr_stack_anew<char *>(NDR_STACK_IN, size);
		if (r->ppstr == nullptr)
			return pack_result::alloc;
		for (size_t cnt = 0; cnt < size; ++cnt) {
			TRY(x.g_genptr(&ptr));
			r->ppstr[cnt] = ptr != 0 ? reinterpret_cast<char *>(static_cast<uintptr_t>(ptr)) : nullptr;
		}
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT))
		return pack_result::ok;
	for (size_t cnt = 0; cnt < r->count; ++cnt) {
		if (r->ppstr[cnt] == nullptr)
			continue;
		TRY(x.g_ulong(&size1));
		TRY(x.g_ulong(&offset));
		TRY(x.g_ulong(&length1));
		if (offset != 0 || length1 > size1)
			return pack_result::array_size;
		TRY(x.check_str(length1, sizeof(uint8_t)));
		r->ppstr[cnt] = ndr_stack_anew<char>(NDR_STACK_IN, length1 + 1);
		if (r->ppstr[cnt] == nullptr)
			return pack_result::alloc;
		TRY(x.g_str(r->ppstr[cnt], length1));
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_wstring_array(NDR_PULL &x,
    unsigned int flag, STRING_ARRAY *r)
{
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;
	uint32_t size1;
	uint32_t offset;
	uint32_t length1;
	

	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_uint32(&r->count));
		if (r->count > 100000)
			return pack_result::range;
		TRY(x.g_genptr(&ptr));
		r->ppstr = ptr != 0 ? reinterpret_cast<char **>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->ppstr == nullptr)
		return pack_result::ok;
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	if (size != r->count)
		/* count set by this or a previous function call with FLAG_HEADER */
		return pack_result::array_size;
	r->ppstr = ndr_stack_anew<char *>(NDR_STACK_IN, size);
	if (r->ppstr == nullptr)
		return pack_result::alloc;
	for (cnt = 0; cnt < size; cnt++) {
		TRY(x.g_genptr(&ptr));
		r->ppstr[cnt] = ptr != 0 ? reinterpret_cast<char *>(static_cast<uintptr_t>(ptr)) : nullptr;
	}
	for (cnt = 0; cnt < size; cnt++) {
		if (r->ppstr[cnt] == nullptr)
			continue;
		TRY(x.g_ulong(&size1));
		TRY(x.g_ulong(&offset));
		TRY(x.g_ulong(&length1));
		if (offset != 0 || length1 > size1)
			return pack_result::array_size;
		TRY(x.check_str(length1, sizeof(uint16_t)));
		std::unique_ptr<char[]> pwstring;
		try {
			pwstring = std::make_unique<char[]>(sizeof(uint16_t) * length1 + 1);
		} catch (const std::bad_alloc &) {
			return pack_result::alloc;
		}
		TRY(x.g_str(pwstring.get(), sizeof(uint16_t) * length1));
		r->ppstr[cnt] = ndr_stack_anew<char>(NDR_STACK_IN, 2 * sizeof(uint16_t) * length1);
		if (r->ppstr[cnt] == nullptr)
			return pack_result::alloc;
		if (!nsp_ndr_to_utf8(x.flags, pwstring.get(),
		    sizeof(uint16_t) * length1, r->ppstr[cnt],
		    2 * sizeof(uint16_t) * length1))
			return pack_result::charconv;
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_push_wstring_array(NDR_PUSH &x,
    unsigned int flag, const STRING_ARRAY &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_uint32(r.count));
		TRY(x.p_unique_ptr(r.ppstr));
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r.ppstr == nullptr)
		return pack_result::ok;
	TRY(x.p_ulong(r.count));
	for (size_t cnt = 0; cnt < r.count; ++cnt)
		TRY(x.p_unique_ptr(r.ppstr[cnt]));
	for (size_t cnt = 0; cnt < r.count; ++cnt) {
		if (r.ppstr[cnt] == nullptr)
			continue;
		uint32_t length = utf8_to_utf16_len(r.ppstr[cnt]);
		std::unique_ptr<char[]> pwstring;
		try {
			pwstring = std::make_unique<char[]>(length);
		} catch (const std::bad_alloc &) {
			return pack_result::alloc;
		}
		auto z = nsp_ndr_to_utf16(x.flags,
		         r.ppstr[cnt], pwstring.get(), length);
		if (z < 0)
			return pack_result::charconv;
		length = z;
		TRY(x.p_ulong(length / sizeof(uint16_t)));
		TRY(x.p_ulong(0));
		TRY(x.p_ulong(length / sizeof(uint16_t)));
		TRY(x.p_str(pwstring.get(), length));
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_wstrings_array(NDR_PULL &x,
    unsigned int flag, STRINGS_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;
	uint32_t size1;
	uint32_t offset;
	uint32_t length1;
	
	if (flag & FLAG_HEADER) {
		TRY(x.g_ulong(&size));
		size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
		TRY(x.align(5));
		TRY(x.g_uint32(&r->count));
		if (r->count > 100000) {
			r->count = 0;
			return pack_result::range;
		}
		if (r->count != size) {
			r->count = 0;
			return pack_result::array_size;
		}
		r->ppstr = ndr_stack_anew<char *>(NDR_STACK_IN, size);
		if (r->ppstr == nullptr) {
			r->count = 0;
			return pack_result::alloc;
		}
		for (size_t cnt = 0; cnt < size; ++cnt) {
			TRY(x.g_genptr(&ptr));
			r->ppstr[cnt] = ptr != 0 ? reinterpret_cast<char *>(static_cast<uintptr_t>(ptr)) : nullptr;
		}
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT))
		return pack_result::ok;
	for (size_t cnt = 0; cnt < r->count; ++cnt) {
		if (r->ppstr[cnt] == nullptr)
			continue;
		TRY(x.g_ulong(&size1));
		TRY(x.g_ulong(&offset));
		TRY(x.g_ulong(&length1));
		if (offset != 0 || length1 > size1)
			return pack_result::array_size;
		TRY(x.check_str(length1, sizeof(uint16_t)));
		std::unique_ptr<char[]> pwstring;
		try {
			pwstring = std::make_unique<char[]>(sizeof(uint16_t) * length1 + 1);
		} catch (const std::bad_alloc &) {
			return pack_result::alloc;
		}
		TRY(x.g_str(pwstring.get(), sizeof(uint16_t) * length1));
		r->ppstr[cnt] = ndr_stack_anew<char>(NDR_STACK_IN, 2 * sizeof(uint16_t) * length1);
		if (r->ppstr[cnt] == nullptr)
			return pack_result::alloc;
		if (!nsp_ndr_to_utf8(x.flags, pwstring.get(),
		    sizeof(uint16_t) * length1, r->ppstr[cnt],
		    2 * sizeof(uint16_t) * length1))
			return pack_result::charconv;
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_binary(NDR_PULL &x, unsigned int flag, BINARY *r)
{
	uint32_t ptr;
	uint32_t size;

	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_uint32(&r->cb));
		if (r->cb > 2097152) {
			r->cb = 0;
			return pack_result::range;
		}
		TRY(x.g_genptr(&ptr));
		r->pb = ptr != 0 ? reinterpret_cast<uint8_t *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pb == nullptr)
		return pack_result::ok;
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	if (size != r->cb) {
		/* cb set by this or a previous function call with FLAG_HEADER */
		r->cb = 0;
		return pack_result::array_size;
	}
	r->pb = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (NULL == r->pb) {
		r->cb = 0;
		return pack_result::alloc;
	}
	TRY(x.g_uint8_a(r->pb, size));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_binary(NDR_PUSH &x, unsigned int flag, const BINARY &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_uint32(r.cb));
		TRY(x.p_unique_ptr(r.pb));
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r.pb == nullptr)
		return pack_result::ok;
	TRY(x.p_ulong(r.cb));
	TRY(x.p_uint8_a(r.pb, r.cb));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_filetime(NDR_PULL &x, FILETIME *r)
{
	TRY(x.align(4));
	TRY(x.g_uint32(&r->low_datetime));
	TRY(x.g_uint32(&r->high_datetime));
	return x.trailer_align(4);
}

static pack_result nsp_ndr_push_filetime(NDR_PUSH &x, const FILETIME &r)
{
	TRY(x.align(4));
	TRY(x.p_uint32(r.low_datetime));
	TRY(x.p_uint32(r.high_datetime));
	return x.trailer_align(4);
}

static pack_result nsp_ndr_pull_short_array(NDR_PULL &x,
    unsigned int flag, SHORT_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_uint32(&r->count));
		if (r->count > 100000)
			return pack_result::range;
		TRY(x.g_genptr(&ptr));
		r->ps = ptr != 0 ? reinterpret_cast<uint16_t *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->ps == nullptr)
		return pack_result::ok;
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	if (size != r->count)
		/* count set by this or a previous function call with FLAG_HEADER */
		return pack_result::array_size;
	r->ps = ndr_stack_anew<uint16_t>(NDR_STACK_IN, size);
	if (r->ps == nullptr)
		return pack_result::alloc;
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(x.g_uint16(&r->ps[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_short_array(NDR_PUSH &x,
    unsigned int flag, const SHORT_ARRAY &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_uint32(r.count));
		TRY(x.p_unique_ptr(r.ps));
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r.ps == nullptr)
		return pack_result::ok;
	TRY(x.p_ulong(r.count));
	for (size_t cnt = 0; cnt < r.count; ++cnt)
		TRY(x.p_uint16(r.ps[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_long_array(NDR_PULL &x,
    unsigned int flag, LONG_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_uint32(&r->count));
		if (r->count > 100000)
			return pack_result::range;
		TRY(x.g_genptr(&ptr));
		r->pl = ptr != 0 ? reinterpret_cast<uint32_t *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pl == nullptr)
		return pack_result::ok;
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	if (size != r->count)
		/* count set by this or a previous function call with FLAG_HEADER */
		return pack_result::array_size;
	r->pl = ndr_stack_anew<uint32_t>(NDR_STACK_IN, size);
	if (r->pl == nullptr)
		return pack_result::alloc;
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(x.g_uint32(&r->pl[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_long_array(NDR_PUSH &x,
    unsigned int flag, const LONG_ARRAY &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_uint32(r.count));
		TRY(x.p_unique_ptr(r.pl));
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r.pl == nullptr)
		return pack_result::ok;
	TRY(x.p_ulong(r.count));
	for (size_t cnt = 0; cnt < r.count; ++cnt)
		TRY(x.p_uint32(r.pl[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_binary_array(NDR_PULL &x,
    unsigned int flag, BINARY_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_uint32(&r->count));
		if (r->count > 100000)
			return pack_result::range;
		TRY(x.g_genptr(&ptr));
		r->pbin = ptr != 0 ? reinterpret_cast<BINARY *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pbin == nullptr)
		return pack_result::ok;
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	if (size != r->count)
		/* count set by this or a previous function call with FLAG_HEADER */
		return pack_result::array_size;
	r->pbin = ndr_stack_anew<BINARY>(NDR_STACK_IN, size);
	if (r->pbin == nullptr)
		return pack_result::alloc;
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_binary(x, FLAG_HEADER, &r->pbin[cnt]));
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_binary(x, FLAG_CONTENT, &r->pbin[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_binary_array(NDR_PUSH &x,
    unsigned int flag, const BINARY_ARRAY &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_uint32(r.count));
		TRY(x.p_unique_ptr(r.pbin));
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r.pbin == nullptr)
		return pack_result::ok;
	TRY(x.p_ulong(r.count));
	for (size_t cnt = 0; cnt < r.count; ++cnt)
		TRY(nsp_ndr_push_binary(x, FLAG_HEADER, r.pbin[cnt]));
	for (size_t cnt = 0; cnt < r.count; ++cnt)
		TRY(nsp_ndr_push_binary(x, FLAG_CONTENT, r.pbin[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_flatuid_array(NDR_PULL &x,
    unsigned int flag, FLATUID_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;

	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_uint32(&r->cvalues));
		if (r->cvalues > 100000)
			return pack_result::range;
		TRY(x.g_genptr(&ptr));
		r->ppguid = ptr != 0 ? reinterpret_cast<FLATUID **>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->ppguid == nullptr)
		return pack_result::ok;
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	if (size != r->cvalues)
		/* cvalues set by this or a previous function call with FLAG_HEADER */
		return pack_result::array_size;
	r->ppguid = ndr_stack_anew<FLATUID *>(NDR_STACK_IN, size);
	if (r->ppguid == nullptr)
		return pack_result::alloc;
	for (size_t cnt = 0; cnt < size; ++cnt) {
		TRY(x.g_genptr(&ptr));
		if (0 != ptr) {
			r->ppguid[cnt] = ndr_stack_anew<FLATUID>(NDR_STACK_IN);
			if (r->ppguid[cnt] == nullptr)
				return pack_result::alloc;
		} else {
			r->ppguid[cnt] = NULL;
		}
	}
	for (size_t cnt = 0; cnt < size; ++cnt)
		if (r->ppguid[cnt] != nullptr)
			TRY(nsp_ndr_pull_flatuid(x, r->ppguid[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_flatuid_array(NDR_PUSH &x,
    unsigned int flag, const FLATUID_ARRAY &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_uint32(r.cvalues));
		TRY(x.p_unique_ptr(r.ppguid));
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r.ppguid == nullptr)
		return pack_result::ok;
	TRY(x.p_ulong(r.cvalues));
	for (size_t cnt = 0; cnt < r.cvalues; ++cnt)
		TRY(x.p_unique_ptr(r.ppguid[cnt]));
	for (size_t cnt = 0; cnt < r.cvalues; ++cnt)
		if (r.ppguid[cnt] != nullptr)
			TRY(nsp_ndr_push_flatuid(x, *r.ppguid[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_filetime_array(NDR_PULL &x,
    unsigned int flag, FILETIME_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_uint32(&r->cvalues));
		if (r->cvalues > 100000)
			return pack_result::range;
		TRY(x.g_genptr(&ptr));
		r->pftime = ptr != 0 ? reinterpret_cast<FILETIME *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(x.trailer_align(5));
	}
	if (!(flag & FLAG_CONTENT) || r->pftime == nullptr)
		return pack_result::ok;
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	if (size != r->cvalues)
		/* cvalues set by this or a previous function call with FLAG_HEADER */
		return pack_result::array_size;
	r->pftime = ndr_stack_anew<FILETIME>(NDR_STACK_IN, size);
	if (r->pftime == nullptr)
		return pack_result::alloc;
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_filetime(x, &r->pftime[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_filetime_array(NDR_PUSH &x,
    unsigned int flag, const FILETIME_ARRAY &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_uint32(r.cvalues));
		TRY(x.p_unique_ptr(r.pftime));
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r.pftime == nullptr)
		return pack_result::ok;
	TRY(x.p_ulong(r.cvalues));
	for (size_t cnt = 0; cnt < r.cvalues; ++cnt)
		TRY(nsp_ndr_push_filetime(x, r.pftime[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_prop_val_union(NDR_PULL &x,
    unsigned int flag, uint32_t *ptype, PROP_VAL_UNION *r)
{
	uint32_t ptr;
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	
	if (flag & FLAG_HEADER) {
		TRY(x.union_align(5));
		TRY(x.g_uint32(ptype));
		TRY(x.union_align(5));
		switch (*ptype) {
		case PT_SHORT:
			TRY(x.g_uint16(&r->s));
			break;
		case PT_OBJECT:
			fprintf(stderr, "%s stealing 32bit int\n", __func__);
			[[fallthrough]];
		case PT_LONG:
			TRY(x.g_uint32(&r->l));
			break;
		case PT_FLOAT:
			TRY(x.g_float(&r->flt));
			break;
		case PT_DOUBLE:
		case PT_APPTIME:
			TRY(x.g_double(&r->dbl));
			break;
		case PT_BOOLEAN:
			TRY(x.g_uint8(&r->b));
			break;
		case PT_I8:
		case PT_CURRENCY:
			TRY(x.g_uint32_x2(&r->ll));
			break;
		case PT_STRING8:
		case PT_UNICODE:
			TRY(x.g_genptr(&ptr));
			r->pstr = ptr != 0 ? reinterpret_cast<char *>(static_cast<uintptr_t>(ptr)) : nullptr;
			break;
		case PT_BINARY:
			TRY(nsp_ndr_pull_binary(x, FLAG_HEADER, &r->bin));
			break;
		case PT_CLSID:
			TRY(x.g_genptr(&ptr));
			r->pguid = ptr != 0 ? reinterpret_cast<FLATUID *>(static_cast<uintptr_t>(ptr)) : nullptr;
			break;
		case PT_SYSTIME:
			TRY(nsp_ndr_pull_filetime(x, &r->ftime));
			break;
		case PT_ERROR:
			TRY(x.g_uint32(&r->err));
			break;
		case PT_MV_SHORT:
			TRY(nsp_ndr_pull_short_array(x, FLAG_HEADER, &r->short_array));
			break;
		case PT_MV_LONG:
			TRY(nsp_ndr_pull_long_array(x, FLAG_HEADER, &r->long_array));
			break;
		case PT_MV_STRING8:
			TRY(nsp_ndr_pull_string_array(x, FLAG_HEADER, &r->string_array));
			break;
		case PT_MV_BINARY:
			TRY(nsp_ndr_pull_binary_array(x, FLAG_HEADER, &r->bin_array));
			break;
		case PT_MV_CLSID:
			TRY(nsp_ndr_pull_flatuid_array(x, FLAG_HEADER, &r->guid_array));
			break;
		case PT_MV_UNICODE:
			TRY(nsp_ndr_pull_wstring_array(x, FLAG_HEADER, &r->string_array));
			break;
		case PT_MV_SYSTIME:
			TRY(nsp_ndr_pull_filetime_array(x, FLAG_HEADER, &r->ftime_array));
			break;
		case PT_NULL:
			TRY(x.g_uint32(&r->reserved));
			break;
		default:
			mlog(LV_ERR, "E-1910: nsp_ndr type %xh unhandled", *ptype);
			return pack_result::bad_switch;
		}
	}
	
	if (!(flag & FLAG_CONTENT))
		return pack_result::ok;
	switch (*ptype) {
	case PT_NULL:
	case PT_SHORT:
	case PT_LONG:
	case PT_OBJECT:
	case PT_BOOLEAN:
	case PT_SYSTIME:
	case PT_ERROR:
		break;
	case PT_STRING8:
		if (r->pstr == nullptr)
			break;
		TRY(x.g_ulong(&size));
		TRY(x.g_ulong(&offset));
		TRY(x.g_ulong(&length));
		if (offset != 0 || length > size)
			return pack_result::array_size;
		TRY(x.check_str(length, sizeof(uint8_t)));
		r->pstr = ndr_stack_anew<char>(NDR_STACK_IN, length + 1);
		if (r->pstr == nullptr)
			return pack_result::alloc;
		TRY(x.g_str(r->pstr, length));
		break;
	case PT_UNICODE: {
		if (r->pstr == nullptr)
			break;
		TRY(x.g_ulong(&size));
		TRY(x.g_ulong(&offset));
		TRY(x.g_ulong(&length));
		if (offset != 0 || length > size)
			return pack_result::array_size;
		TRY(x.check_str(length, sizeof(uint16_t)));
		std::unique_ptr<char[]> pwstring;
		try {
			pwstring = std::make_unique<char[]>(sizeof(uint16_t) * length + 1);
		} catch (const std::bad_alloc &) {
			return pack_result::alloc;
		}
		TRY(x.g_str(pwstring.get(), sizeof(uint16_t) * length));
		r->pstr = ndr_stack_anew<char>(NDR_STACK_IN, 2 * sizeof(uint16_t) * length);
		if (r->pstr == nullptr)
			return pack_result::alloc;
		if (!nsp_ndr_to_utf8(x.flags, pwstring.get(),
		    sizeof(uint16_t) * length, r->pstr,
		    2 * sizeof(uint16_t) * length))
			return pack_result::charconv;
		break;
	}
	case PT_BINARY:
		TRY(nsp_ndr_pull_binary(x, FLAG_CONTENT, &r->bin));
		break;
	case PT_CLSID:
		if (r->pguid != nullptr)
			TRY(nsp_ndr_pull_flatuid(x, r->pguid));
		break;
	case PT_MV_SHORT:
		TRY(nsp_ndr_pull_short_array(x, FLAG_CONTENT, &r->short_array));
		break;
	case PT_MV_LONG:
		TRY(nsp_ndr_pull_long_array(x, FLAG_CONTENT, &r->long_array));
		break;
	case PT_MV_STRING8:
		TRY(nsp_ndr_pull_string_array(x, FLAG_CONTENT, &r->string_array));
		break;
	case PT_MV_BINARY:
		TRY(nsp_ndr_pull_binary_array(x, FLAG_CONTENT, &r->bin_array));
		break;
	case PT_MV_CLSID:
		TRY(nsp_ndr_pull_flatuid_array(x, FLAG_CONTENT, &r->guid_array));
		break;
	case PT_MV_UNICODE:
		TRY(nsp_ndr_pull_wstring_array(x, FLAG_CONTENT, &r->string_array));
		break;
	case PT_MV_SYSTIME:
		TRY(nsp_ndr_pull_filetime_array(x, FLAG_CONTENT, &r->ftime_array));
		break;
	default:
		mlog(LV_ERR, "E-1911: nsp_ndr type %xh unhandled", *ptype);
		return pack_result::bad_switch;
	}
	return pack_result::ok;
}

/* This is for RPCH-based NSP only; mh_nsp is serialized elsewhere */
static pack_result nsp_ndr_push_prop_val_union(NDR_PUSH &x,
    unsigned int flag, uint32_t type, const PROP_VAL_UNION &r)
{
	uint32_t length;
	
	if (flag & FLAG_HEADER) {
		TRY(x.union_align(5));
		TRY(x.p_uint32(type));
		TRY(x.union_align(5));
		switch (type) {
		case PT_SHORT:
			TRY(x.p_uint16(r.s));
			break;
		case PT_LONG:
			TRY(x.p_uint32(r.l));
			break;
		case PT_FLOAT:
			TRY(x.p_float(r.flt));
			break;
		case PT_DOUBLE:
		case PT_APPTIME:
			TRY(x.p_double(r.dbl));
			break;
		case PT_BOOLEAN:
			TRY(x.p_uint8(r.b));
			break;
		case PT_OBJECT:
			/*
			 * In rpc-nsp, PT_OBJECT is followed by uint32 ([MS-NSPI] §2.2.1);
			 * but in mh_nsp, it is followed by nothing.
			 */
			TRY(x.p_uint32(0));
			break;
		case PT_I8:
		case PT_CURRENCY:
			TRY(x.p_uint32_x2(r.ll));
			break;
		case PT_STRING8:
		case PT_UNICODE:
			TRY(x.p_unique_ptr(r.pstr));
			break;
		case PT_BINARY:
			TRY(nsp_ndr_push_binary(x, FLAG_HEADER, r.bin));
			break;
		case PT_CLSID:
			TRY(x.p_unique_ptr(r.pguid));
			break;
		case PT_SYSTIME:
			TRY(nsp_ndr_push_filetime(x, r.ftime));
			break;
		case PT_ERROR:
			TRY(x.p_uint32(r.err));
			break;
		case PT_MV_SHORT:
			TRY(nsp_ndr_push_short_array(x, FLAG_HEADER, r.short_array));
			break;
		case PT_MV_LONG:
			TRY(nsp_ndr_push_long_array(x, FLAG_HEADER, r.long_array));
			break;
		case PT_MV_STRING8:
			TRY(nsp_ndr_push_string_array(x, FLAG_HEADER, r.string_array));
			break;
		case PT_MV_BINARY:
			TRY(nsp_ndr_push_binary_array(x, FLAG_HEADER, r.bin_array));
			break;
		case PT_MV_CLSID:
			TRY(nsp_ndr_push_flatuid_array(x, FLAG_HEADER, r.guid_array));
			break;
		case PT_MV_UNICODE:
			TRY(nsp_ndr_push_wstring_array(x, FLAG_HEADER, r.string_array));
			break;
		case PT_MV_SYSTIME:
			TRY(nsp_ndr_push_filetime_array(x, FLAG_HEADER, r.ftime_array));
			break;
		case PT_NULL:
			TRY(x.p_uint32(r.reserved));
			break;
		default:
			/* see also E-1759 for mh_nsp */
			mlog(LV_ERR, "E-1912: nsp_ndr type %xh unhandled", type);
			return pack_result::bad_switch;
		}
	}
	
	if (!(flag & FLAG_CONTENT))
		return pack_result::ok;
	switch (type) {
	case PT_NULL:
	case PT_SHORT:
	case PT_LONG:
	case PT_FLOAT:
	case PT_DOUBLE:
	case PT_APPTIME:
	case PT_OBJECT:
	case PT_BOOLEAN:
	case PT_I8:
	case PT_CURRENCY:
	case PT_SYSTIME:
	case PT_ERROR:
		break;
	case PT_STRING8:
		if (r.pstr == nullptr)
			break;
		length = strlen(r.pstr) + 1;
		TRY(x.p_ulong(length));
		TRY(x.p_ulong(0));
		TRY(x.p_ulong(length));
		TRY(x.p_str(r.pstr, length));
		break;
	case PT_UNICODE: {
		if (r.pstr == nullptr)
			break;
		length = strlen(r.pstr) + 1;
		std::unique_ptr<char[]> pwstring;
		try {
			pwstring = std::make_unique<char[]>(2 * length);
		} catch (const std::bad_alloc &) {
			return pack_result::alloc;
		}
		auto z = nsp_ndr_to_utf16(x.flags, r.pstr, pwstring.get(), 2 * length);
		if (z < 0)
			return pack_result::charconv;
		length = z;
		TRY(x.p_ulong(length / sizeof(uint16_t)));
		TRY(x.p_ulong(0));
		TRY(x.p_ulong(length / sizeof(uint16_t)));
		TRY(x.p_str(pwstring.get(), length));
		break;
	}
	case PT_BINARY:
		TRY(nsp_ndr_push_binary(x, FLAG_CONTENT, r.bin));
		break;
	case PT_CLSID:
		if (r.pguid != nullptr)
			TRY(nsp_ndr_push_flatuid(x, *r.pguid));
		break;
	case PT_MV_SHORT:
		TRY(nsp_ndr_push_short_array(x, FLAG_CONTENT, r.short_array));
		break;
	case PT_MV_LONG:
		TRY(nsp_ndr_push_long_array(x, FLAG_CONTENT, r.long_array));
		break;
	case PT_MV_STRING8:
		TRY(nsp_ndr_push_string_array(x, FLAG_CONTENT, r.string_array));
		break;
	case PT_MV_BINARY:
		TRY(nsp_ndr_push_binary_array(x, FLAG_CONTENT, r.bin_array));
		break;
	case PT_MV_CLSID:
		TRY(nsp_ndr_push_flatuid_array(x, FLAG_CONTENT, r.guid_array));
		break;
	case PT_MV_UNICODE:
		TRY(nsp_ndr_push_wstring_array(x, FLAG_CONTENT, r.string_array));
		break;
	case PT_MV_SYSTIME:
		TRY(nsp_ndr_push_filetime_array(x, FLAG_CONTENT, r.ftime_array));
		break;
	default:
		mlog(LV_ERR, "E-1913: nsp_ndr type %xh unhandled", type);
		return pack_result::bad_switch;
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_property_value(NDR_PULL &x,
    unsigned int flag, PROPERTY_VALUE *r)
{
	if (flag & FLAG_HEADER) {
		uint32_t type = PT_UNSPECIFIED;
		TRY(x.align(5));
		TRY(x.g_uint32(&r->proptag));
		TRY(x.g_uint32(&r->reserved));
		TRY(nsp_ndr_pull_prop_val_union(x, FLAG_HEADER, &type, &r->value));
		if (PROP_TYPE(r->proptag) != type)
			return pack_result::bad_switch;
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT))
		return pack_result::ok;
	uint32_t type = PROP_TYPE(r->proptag);
	TRY(nsp_ndr_pull_prop_val_union(x, FLAG_CONTENT, &type, &r->value));
	return pack_result::ok;
	
}

static pack_result nsp_ndr_push_property_value(NDR_PUSH &x,
    unsigned int flag, const PROPERTY_VALUE &r0)
{
	auto r = &r0;
	PROPERTY_VALUE s{};
	if (flag & FLAG_HEADER) {
		/*
		 * Despite being specified by DCERPC or implemented in e.g.
		 * samba/openchange, it seems like emsmdb32.dll just does not
		 * support these types over RPC. (But emsmdb32 accepts them
		 * over mh_nsp.)
		 */
		switch (PROP_TYPE(r->proptag)) {
		case PT_FLOAT:
		case PT_DOUBLE:
		case PT_I8:
		case PT_CURRENCY:
			s.proptag = PR_NULL;
			r = &s;
			break;
		default:
			break;
		}
		TRY(x.align(5));
		TRY(x.p_uint32(r->proptag));
		TRY(x.p_uint32(r->reserved));
		TRY(nsp_ndr_push_prop_val_union(x, FLAG_HEADER, PROP_TYPE(r->proptag), r->value));
		TRY(x.trailer_align(5));
	}
	if (flag & FLAG_CONTENT)
		TRY(nsp_ndr_push_prop_val_union(x, FLAG_CONTENT, PROP_TYPE(r->proptag), r->value));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_property_row(NDR_PULL &x,
    unsigned int flag, NSP_PROPROW *r)
{
	uint32_t ptr;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_uint32(&r->reserved));
		TRY(x.g_uint32(&r->cvalues));
		if (r->cvalues > 100000)
			return pack_result::range;
		TRY(x.g_genptr(&ptr));
		r->pprops = ptr != 0 ? reinterpret_cast<PROPERTY_VALUE *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pprops == nullptr)
		return pack_result::ok;
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	if (size != r->cvalues)
		/* cvalues set by this or a previous function call with FLAG_HEADER */
		return pack_result::array_size;
	r->pprops = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_IN, size);
	if (r->pprops == nullptr)
		return pack_result::alloc;
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_property_value(x, FLAG_HEADER, &r->pprops[cnt]));
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_property_value(x, FLAG_CONTENT, &r->pprops[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_property_row(NDR_PUSH &x,
    unsigned int flag, const NSP_PROPROW &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_uint32(r.reserved));
		TRY(x.p_uint32(r.cvalues));
		TRY(x.p_unique_ptr(r.pprops));
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r.pprops == nullptr)
		return pack_result::ok;
	TRY(x.p_ulong(r.cvalues));
	for (size_t cnt = 0; cnt < r.cvalues; ++cnt)
		TRY(nsp_ndr_push_property_value(x, FLAG_HEADER, r.pprops[cnt]));
	for (size_t cnt = 0; cnt < r.cvalues; ++cnt)
		TRY(nsp_ndr_push_property_value(x, FLAG_CONTENT, r.pprops[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_proprow_set(NDR_PUSH &x,
    unsigned int flag, const NSP_ROWSET &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.p_ulong(r.crows));
		TRY(x.align(5));
		TRY(x.p_uint32(r.crows));
		for (size_t cnt = 0; cnt < r.crows; ++cnt)
			TRY(nsp_ndr_push_property_row(x, FLAG_HEADER, r.prows[cnt]));
		TRY(x.trailer_align(5));
	}
	if (flag & FLAG_CONTENT)
		for (size_t cnt = 0; cnt < r.crows; ++cnt)
			TRY(nsp_ndr_push_property_row(x, FLAG_CONTENT, r.prows[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_restriction_and_or(NDR_PULL &x,
    unsigned int flag, NSPRES_AND_OR *r)
{
	uint32_t ptr;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_uint32(&r->cres));
		if (r->cres > 100000)
			return pack_result::range;
		TRY(x.g_genptr(&ptr));
		r->pres = ptr != 0 ? reinterpret_cast<NSPRES *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pres == nullptr)
		return pack_result::ok;
	TRY(x.g_ulong(&size));
	size = std::min(size, static_cast<uint32_t>(UINT32_MAX));
	if (size != r->cres)
		/* cres set by this or a previous function call with FLAG_HEADER */
		return pack_result::array_size;
	r->pres = ndr_stack_anew<NSPRES>(NDR_STACK_IN, size);
	if (r->pres == nullptr)
		return pack_result::alloc;
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_restriction(x, FLAG_HEADER, &r->pres[cnt]));
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_restriction(x, FLAG_CONTENT, &r->pres[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_restriction_and_or(NDR_PUSH &x,
    unsigned int flag, const NSPRES_AND_OR &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_uint32(r.cres));
		TRY(x.p_unique_ptr(r.pres));
		TRY(x.trailer_align(5));
	}
	
	if (!(flag & FLAG_CONTENT) || r.pres == nullptr)
		return pack_result::ok;
	TRY(x.p_ulong(r.cres));
	for (size_t cnt = 0; cnt < r.cres; ++cnt)
		TRY(nsp_ndr_push_restriction(x, FLAG_HEADER, r.pres[cnt]));
	for (size_t cnt = 0; cnt < r.cres; ++cnt)
		TRY(nsp_ndr_push_restriction(x, FLAG_CONTENT, r.pres[cnt]));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_restriction_not(NDR_PULL &x,
    unsigned int flag, NSPRES_NOT *r)
{
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_genptr(&ptr));
		if (0 != ptr) {
			r->pres = ndr_stack_anew<NSPRES>(NDR_STACK_IN);
			if (r->pres == nullptr)
				return pack_result::alloc;
		} else {
			r->pres = NULL;
		}
		TRY(x.trailer_align(5));
	}
	
	if (flag & FLAG_CONTENT && r->pres != nullptr)
		TRY(nsp_ndr_pull_restriction(x, FLAG_HEADER | FLAG_CONTENT, r->pres));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_restriction_not(NDR_PUSH &x,
    unsigned int flag, const NSPRES_NOT &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_unique_ptr(r.pres));
		TRY(x.trailer_align(5));
	}
	if (flag & FLAG_CONTENT && r.pres != nullptr)
		TRY(nsp_ndr_push_restriction(x, FLAG_HEADER | FLAG_CONTENT, *r.pres));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_restriction_content(NDR_PULL &x,
    unsigned int flag, NSPRES_CONTENT *r)
{
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_uint32(&r->fuzzy_level));
		TRY(x.g_uint32(&r->proptag));
		TRY(x.g_genptr(&ptr));
		if (0 != ptr) {
			r->pprop = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_IN);
			if (r->pprop == nullptr)
				return pack_result::alloc;
		} else {
			r->pprop = NULL;
		}
		TRY(x.trailer_align(5));
	}
	
	if (flag & FLAG_CONTENT && r->pprop != nullptr)
		TRY(nsp_ndr_pull_property_value(x, FLAG_HEADER | FLAG_CONTENT, r->pprop));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_restriction_content(NDR_PUSH &x,
    unsigned int flag, const NSPRES_CONTENT &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_uint32(r.fuzzy_level));
		TRY(x.p_uint32(r.proptag));
		TRY(x.p_unique_ptr(r.pprop));
		TRY(x.trailer_align(5));
	}
	if (flag & FLAG_CONTENT && r.pprop != nullptr)
		TRY(nsp_ndr_push_property_value(x, FLAG_HEADER | FLAG_CONTENT, *r.pprop));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_restriction_property(NDR_PULL &x,
    unsigned int flag, NSPRES_PROPERTY *r)
{
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		uint32_t v;
		TRY(x.align(5));
		TRY(x.g_uint32(&v));
		r->relop = static_cast<relop>(v);
		TRY(x.g_uint32(&r->proptag));
		TRY(x.g_genptr(&ptr));
		if (0 != ptr) {
			r->pprop = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_IN);
			if (r->pprop == nullptr)
				return pack_result::alloc;
		} else {
			r->pprop = NULL;
		}
		TRY(x.trailer_align(5));
	}
	
	if (flag & FLAG_CONTENT && r->pprop != nullptr)
		TRY(nsp_ndr_pull_property_value(x, FLAG_HEADER | FLAG_CONTENT, r->pprop));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_restriction_property(NDR_PUSH &x,
    unsigned int flag, const NSPRES_PROPERTY &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_uint32(static_cast<uint32_t>(r.relop)));
		TRY(x.p_uint32(r.proptag));
		TRY(x.p_unique_ptr(r.pprop));
		TRY(x.trailer_align(5));
	}
	if (flag & FLAG_CONTENT && r.pprop != nullptr)
		TRY(nsp_ndr_push_property_value(x, FLAG_HEADER | FLAG_CONTENT, *r.pprop));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_restriction_propcompare(NDR_PULL &x,
    NSPRES_PROPCOMPARE *r)
{
	uint32_t v;
	TRY(x.align(4));
	TRY(x.g_uint32(&v));
	r->relop = static_cast<relop>(v);
	TRY(x.g_uint32(&r->proptag1));
	TRY(x.g_uint32(&r->proptag2));
	TRY(x.trailer_align(4));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_restriction_propcompare(NDR_PUSH &x,
    const NSPRES_PROPCOMPARE &r)
{
	TRY(x.align(4));
	TRY(x.p_uint32(static_cast<uint32_t>(r.relop)));
	TRY(x.p_uint32(r.proptag1));
	TRY(x.p_uint32(r.proptag2));
	TRY(x.trailer_align(4));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_restriction_bitmask(NDR_PULL &x, NSPRES_BITMASK *r)
{
	uint32_t v;
	TRY(x.align(4));
	TRY(x.g_uint32(&v));
	r->rel_mbr = static_cast<bm_relop>(v);
	TRY(x.g_uint32(&r->proptag));
	TRY(x.g_uint32(&r->mask));
	TRY(x.trailer_align(4));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_restriction_bitmask(NDR_PUSH &x,
    const NSPRES_BITMASK &r)
{
	TRY(x.align(4));
	TRY(x.p_uint32(static_cast<uint32_t>(r.rel_mbr)));
	TRY(x.p_uint32(r.proptag));
	TRY(x.p_uint32(r.mask));
	TRY(x.trailer_align(4));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_restriction_size(NDR_PULL &x, NSPRES_SIZE *r)
{
	uint32_t v;
	TRY(x.align(4));
	TRY(x.g_uint32(&v));
	r->relop = static_cast<relop>(v);
	TRY(x.g_uint32(&r->proptag));
	TRY(x.g_uint32(&r->cb));
	TRY(x.trailer_align(4));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_restriction_size(NDR_PUSH &x, const NSPRES_SIZE &r)
{
	TRY(x.align(4));
	TRY(x.p_uint32(static_cast<uint32_t>(r.relop)));
	TRY(x.p_uint32(r.proptag));
	TRY(x.p_uint32(r.cb));
	TRY(x.trailer_align(4));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_restriction_exist(NDR_PULL &x, NSPRES_EXIST *r)
{
	TRY(x.align(4));
	TRY(x.g_uint32(&r->reserved1));
	TRY(x.g_uint32(&r->proptag));
	TRY(x.g_uint32(&r->reserved2));
	TRY(x.trailer_align(4));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_restriction_exist(NDR_PUSH &x, const NSPRES_EXIST &r)
{
	TRY(x.align(4));
	TRY(x.p_uint32(r.reserved1));
	TRY(x.p_uint32(r.proptag));
	TRY(x.p_uint32(r.reserved2));
	TRY(x.trailer_align(4));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_restriction_sub(NDR_PULL &x,
    unsigned int flag, NSPRES_SUB *r)
{
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.g_uint32(&r->subobject));
		TRY(x.g_genptr(&ptr));
		if (0 != ptr) {
			r->pres = ndr_stack_anew<NSPRES>(NDR_STACK_IN);
			if (r->pres == nullptr)
				return pack_result::alloc;
		} else {
			r->pres = NULL;
		}
		TRY(x.trailer_align(5));
	}
	
	if (flag & FLAG_CONTENT && r->pres != nullptr)
		TRY(nsp_ndr_pull_restriction(x, FLAG_HEADER | FLAG_CONTENT, r->pres));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_restriction_sub(NDR_PUSH &x,
    unsigned int flag, const NSPRES_SUB &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(5));
		TRY(x.p_uint32(r.subobject));
		TRY(x.p_unique_ptr(r.pres));
		TRY(x.trailer_align(5));
	}
	
	if (flag & FLAG_CONTENT && r.pres != nullptr)
		TRY(nsp_ndr_push_restriction(x, FLAG_HEADER | FLAG_CONTENT, *r.pres));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_restriction_union(NDR_PULL &x,
    unsigned int flag, mapi_rtype *ptype, NSPRES_UNION *r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.union_align(5));
		uint32_t rt;
		TRY(x.g_uint32(&rt));
		*ptype = static_cast<mapi_rtype>(rt);
		TRY(x.union_align(5));
		switch (*ptype) {
		case RES_AND:
		case RES_OR:
			TRY(nsp_ndr_pull_restriction_and_or(x, FLAG_HEADER, &r->res_andor));
			break;
		case RES_NOT:
			TRY(nsp_ndr_pull_restriction_not(x, FLAG_HEADER, &r->res_not));
			break;
		case RES_CONTENT:
			TRY(nsp_ndr_pull_restriction_content(x, FLAG_HEADER, &r->res_content));
			break;
		case RES_PROPERTY:
			TRY(nsp_ndr_pull_restriction_property(x, FLAG_HEADER, &r->res_property));
			break;
		case RES_PROPCOMPARE:
			TRY(nsp_ndr_pull_restriction_propcompare(x, &r->res_propcompare));
			break;
		case RES_BITMASK:
			TRY(nsp_ndr_pull_restriction_bitmask(x, &r->res_bitmask));
			break;
		case RES_SIZE:
			TRY(nsp_ndr_pull_restriction_size(x, &r->res_size));
			break;
		case RES_EXIST:
			TRY(nsp_ndr_pull_restriction_exist(x, &r->res_exist));
			break;
		case RES_SUBRESTRICTION:
			TRY(nsp_ndr_pull_restriction_sub(x, FLAG_HEADER, &r->res_sub));
			break;
		default:
			mlog(LV_WARN, "W-1914: restriction type %u unhandled",
				static_cast<unsigned int>(*ptype));
			return pack_result::bad_switch;
		}
	}
	
	if (!(flag & FLAG_CONTENT))
		return pack_result::ok;
	switch (*ptype) {
	case RES_AND:
	case RES_OR:
		TRY(nsp_ndr_pull_restriction_and_or(x, FLAG_CONTENT, &r->res_andor));
		break;
	case RES_NOT:
		TRY(nsp_ndr_pull_restriction_not(x, FLAG_CONTENT, &r->res_not));
		break;
	case RES_CONTENT:
		TRY(nsp_ndr_pull_restriction_content(x, FLAG_CONTENT, &r->res_content));
		break;
	case RES_PROPERTY:
		TRY(nsp_ndr_pull_restriction_property(x, FLAG_CONTENT, &r->res_property));
		break;
	case RES_PROPCOMPARE:
	case RES_BITMASK:
	case RES_SIZE:
	case RES_EXIST:
		break;
	case RES_SUBRESTRICTION:
		TRY(nsp_ndr_pull_restriction_sub(x, FLAG_CONTENT, &r->res_sub));
		break;
	default:
		mlog(LV_WARN, "W-1915: restriction type %u unhandled",
			static_cast<unsigned int>(*ptype));
		return pack_result::bad_switch;
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_push_restriction_union(NDR_PUSH &x,
    unsigned int flag, mapi_rtype type, const NSPRES_UNION &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.union_align(5));
		TRY(x.p_uint32(static_cast<uint32_t>(type)));
		TRY(x.union_align(5));
		switch (type) {
		case RES_AND:
		case RES_OR:
			TRY(nsp_ndr_push_restriction_and_or(x, FLAG_HEADER, r.res_andor));
			break;
		case RES_NOT:
			TRY(nsp_ndr_push_restriction_not(x, FLAG_HEADER, r.res_not));
			break;
		case RES_CONTENT:
			TRY(nsp_ndr_push_restriction_content(x, FLAG_HEADER, r.res_content));
			break;
		case RES_PROPERTY:
			TRY(nsp_ndr_push_restriction_property(x, FLAG_HEADER, r.res_property));
			break;
		case RES_PROPCOMPARE:
			TRY(nsp_ndr_push_restriction_propcompare(x, r.res_propcompare));
			break;
		case RES_BITMASK:
			TRY(nsp_ndr_push_restriction_bitmask(x, r.res_bitmask));
			break;
		case RES_SIZE:
			TRY(nsp_ndr_push_restriction_size(x, r.res_size));
			break;
		case RES_EXIST:
			TRY(nsp_ndr_push_restriction_exist(x, r.res_exist));
			break;
		case RES_SUBRESTRICTION:
			TRY(nsp_ndr_push_restriction_sub(x, FLAG_HEADER, r.res_sub));
			break;
		default:
			mlog(LV_WARN, "W-1916: restriction type %u unhandled",
				static_cast<unsigned int>(type));
			return pack_result::bad_switch;
		}
	}
	
	if (!(flag & FLAG_CONTENT))
		return pack_result::ok;
	switch (type) {
	case RES_AND:
	case RES_OR:
		TRY(nsp_ndr_push_restriction_and_or(x, FLAG_CONTENT, r.res_andor));
		break;
	case RES_NOT:
		TRY(nsp_ndr_push_restriction_not(x, FLAG_CONTENT, r.res_not));
		break;
	case RES_CONTENT:
		TRY(nsp_ndr_push_restriction_content(x, FLAG_CONTENT, r.res_content));
		break;
	case RES_PROPERTY:
		TRY(nsp_ndr_push_restriction_property(x, FLAG_CONTENT, r.res_property));
		break;
	case RES_PROPCOMPARE:
	case RES_BITMASK:
	case RES_SIZE:
	case RES_EXIST:
		break;
	case RES_SUBRESTRICTION:
		TRY(nsp_ndr_push_restriction_sub(x, FLAG_CONTENT, r.res_sub));
		break;
	default:
		mlog(LV_WARN, "W-1917: restriction type %u unhandled",
			static_cast<unsigned int>(type));
		return pack_result::bad_switch;
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_pull_restriction(NDR_PULL &x,
    unsigned int flag, NSPRES *r)
{
	if (flag & FLAG_HEADER) {
		auto type = RES_NULL;
		TRY(x.align(4));
		uint32_t rt;
		TRY(x.g_uint32(&rt));
		r->res_type = static_cast<mapi_rtype>(rt);
		TRY(nsp_ndr_pull_restriction_union(x, FLAG_HEADER, &type, &r->res));
		if (r->res_type != type)
			return pack_result::bad_switch;
		TRY(x.trailer_align(4));
	}
	
	if (!(flag & FLAG_CONTENT))
		return pack_result::ok;
	auto type = r->res_type;
	TRY(nsp_ndr_pull_restriction_union(x, FLAG_CONTENT, &type, &r->res));
	if (type != r->res_type)
		mlog(LV_WARN, "D-1689: encountered NSP restriction with two rtypes "
			"(%xh,%xh)", static_cast<uint8_t>(r->res_type),
			static_cast<uint8_t>(type));
	return pack_result::ok;
}

static pack_result nsp_ndr_push_restriction(NDR_PUSH &x,
    unsigned int flag, const NSPRES &r)
{
	if (flag & FLAG_HEADER) {
		TRY(x.align(4));
		TRY(x.p_uint32(static_cast<uint32_t>(r.res_type)));
		TRY(nsp_ndr_push_restriction_union(x, FLAG_HEADER, r.res_type, r.res));
		TRY(x.trailer_align(4));
	}
	if (flag & FLAG_CONTENT)
		TRY(nsp_ndr_push_restriction_union(x, FLAG_CONTENT, r.res_type, r.res));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIBIND_IN *r)
{
	uint32_t ptr;

	TRY(x.g_uint32(&r->flags));
	TRY(nsp_ndr_pull_stat(x, &r->stat));
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		r->pserver_guid.emplace();
		TRY(nsp_ndr_pull_flatuid(x, &*r->pserver_guid));
	} else {
		r->pserver_guid.reset();
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIBIND_OUT &r)
{
	TRY(x.p_unique_ptr(r.pserver_guid));
	if (r.pserver_guid.has_value())
		TRY(nsp_ndr_push_flatuid(x, *r.pserver_guid));
	TRY(x.p_ctx_handle(r.handle));
	TRY(x.p_uint32(r.result));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIUNBIND_IN *r)
{
	uint32_t resv;
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&resv));
	return pack_result::ok;
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIUNBIND_OUT &r)
{
	TRY(x.p_ctx_handle(r.handle));
	TRY(x.p_uint32(r.result));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIUPDATESTAT_IN *r)
{
	uint32_t resv, ptr;
	
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&resv));
	TRY(nsp_ndr_pull_stat(x, &r->stat));
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		r->pdelta.emplace();
		TRY(x.g_int32(&*r->pdelta));
	} else {
		r->pdelta.reset();
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIUPDATESTAT_OUT &r)
{
	TRY(nsp_ndr_push_stat(x, r.stat));
	TRY(x.p_unique_ptr(r.pdelta));
	if (r.pdelta.has_value())
		TRY(x.p_int32(*r.pdelta));
	TRY(x.p_uint32(r.result));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIQUERYROWS_IN *r) try
{
	uint32_t ptr, table_count, size;
	
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&r->flags));
	TRY(nsp_ndr_pull_stat(x, &r->stat));
	TRY(x.g_uint32(&table_count));
	if (table_count > 100000)
		return pack_result::range;
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		TRY(x.g_ulong(&size));
		if (size != table_count)
			return pack_result::array_size;
		r->ptable.emplace(size);
		for (size_t cnt = 0; cnt < size; ++cnt)
			TRY(x.g_uint32(&(*r->ptable)[cnt]));
	} else {
		r->ptable.reset();
	}
	TRY(x.g_uint32(&r->count));
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		r->pproptags.emplace();
		TRY(nsp_ndr_pull_proptag_array(x, &*r->pproptags));
	} else {
		r->pproptags.reset();
	}
	return pack_result::ok;
} catch (const std::bad_alloc &) {
	return pack_result::alloc;
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIQUERYROWS_OUT &r)
{
	TRY(nsp_ndr_push_stat(x, r.stat));
	if (r.result != ecSuccess) {
		/* OXNSPI v14 §3.1.4.1.8 SPR ¶3 */
		TRY(x.p_unique_ptr(nullptr));
	} else {
		TRY(x.p_unique_ptr(r.prows));
		if (r.prows != nullptr)
			TRY(nsp_ndr_push_proprow_set(x, FLAG_HEADER | FLAG_CONTENT, *r.prows));
	}
	TRY(x.p_uint32(r.result));
	return pack_result::ok;
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPISEEKENTRIES_IN *r)
{
	uint32_t ptr;
	
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&r->reserved));
	TRY(nsp_ndr_pull_stat(x, &r->stat));
	TRY(nsp_ndr_pull_property_value(x, FLAG_HEADER|FLAG_CONTENT, &r->target));
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		r->ptable.emplace();
		TRY(nsp_ndr_pull_proptag_array(x, &*r->ptable));
	} else {
		r->ptable.reset();
	}
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		r->pproptags.emplace();
		TRY(nsp_ndr_pull_proptag_array(x, &*r->pproptags));
	} else {
		r->pproptags.reset();
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPISEEKENTRIES_OUT &r)
{
	TRY(nsp_ndr_push_stat(x, r.stat));
	if (r.result != ecSuccess) {
		/* OXNSPI v14 §3.1.4.1.9 SPR ¶4 */
		TRY(x.p_unique_ptr(nullptr));
	} else {
		TRY(x.p_unique_ptr(r.prows));
		if (r.prows != nullptr)
			TRY(nsp_ndr_push_proprow_set(x, FLAG_HEADER | FLAG_CONTENT, *r.prows));
	}
	return x.p_uint32(r.result);
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIGETMATCHES_IN *r)
{
	uint32_t resv, ptr;

	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&r->reserved1));
	TRY(nsp_ndr_pull_stat(x, &r->stat));
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		/* Marked as reserved in OXNSPI v14 §3.1.4.1.10 */
		auto ptable = ndr_stack_anew<MINID_ARRAY>(NDR_STACK_IN);
		if (ptable == nullptr)
			return pack_result::alloc;
		TRY(nsp_ndr_pull_proptag_array(x, ptable));
	}
	TRY(x.g_uint32(&resv));
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		r->pfilter = ndr_stack_anew<NSPRES>(NDR_STACK_IN);
		if (r->pfilter == nullptr)
			return pack_result::alloc;
		TRY(nsp_ndr_pull_restriction(x, FLAG_HEADER|FLAG_CONTENT, r->pfilter));
	} else {
		r->pfilter = NULL;
	}
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		r->ppropname = ndr_stack_anew<NSP_PROPNAME>(NDR_STACK_IN);
		if (r->ppropname == nullptr)
			return pack_result::alloc;
		TRY(nsp_ndr_pull_property_name(x, FLAG_HEADER|FLAG_CONTENT, r->ppropname));
	} else {
		r->ppropname = NULL;
	}
	
	TRY(x.g_uint32(&r->requested));
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		r->pproptags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->pproptags == nullptr)
			return pack_result::alloc;
		TRY(nsp_ndr_pull_proptag_array(x, r->pproptags));
	} else {
		r->pproptags = NULL;
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIGETMATCHES_OUT &r)
{
	TRY(nsp_ndr_push_stat(x, r.stat));
	if (r.result != ecSuccess) {
		/* OXNSPI v14 §3.1.4.1.10 SPR ¶4 */
		TRY(x.p_unique_ptr(nullptr));
		TRY(x.p_unique_ptr(nullptr));
	} else {
		TRY(x.p_unique_ptr(r.poutmids));
		if (r.poutmids != nullptr)
			TRY(nsp_ndr_push_proptag_array(x, *r.poutmids));
		TRY(x.p_unique_ptr(r.prows));
		if (r.prows != nullptr)
			TRY(nsp_ndr_push_proprow_set(x, FLAG_HEADER | FLAG_CONTENT, *r.prows));
	}
	return x.p_uint32(r.result);
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIRESORTRESTRICTION_IN *r)
{
	uint32_t resv, ptr;
	
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&resv));
	TRY(nsp_ndr_pull_stat(x, &r->stat));
	TRY(nsp_ndr_pull_proptag_array(x, &r->inmids));
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		auto poutmids = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (poutmids == nullptr)
			return pack_result::alloc;
		TRY(nsp_ndr_pull_proptag_array(x, poutmids));
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIRESORTRESTRICTION_OUT &r)
{
	TRY(nsp_ndr_push_stat(x, r.stat));
	if (r.result != ecSuccess) {
		/* OXNSPI v14 §3.1.4.1.11 SPR ¶3 */
		TRY(x.p_unique_ptr(nullptr));
	} else {
		TRY(x.p_unique_ptr(r.poutmids));
		if (r.poutmids != nullptr)
			TRY(nsp_ndr_push_proptag_array(x, *r.poutmids));
	}
	return x.p_uint32(r.result);
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIDNTOMID_IN *r)
{
	uint32_t resv;
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&resv));
	return nsp_ndr_pull_strings_array(x, FLAG_HEADER|FLAG_CONTENT, &r->names);
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIDNTOMID_OUT &r)
{
	if (r.result != ecSuccess) {
		/* OXNSPI v14 §3.1.4.1.13 SPR ¶1 */
		TRY(x.p_unique_ptr(nullptr));
	} else {
		TRY(x.p_unique_ptr(r.poutmids));
		if (r.poutmids != nullptr)
			TRY(nsp_ndr_push_proptag_array(x, *r.poutmids));
	}
	return x.p_uint32(r.result);
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIGETPROPLIST_IN *r)
{
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&r->flags));
	TRY(x.g_uint32(&r->mid));
	uint32_t v;
	TRY(x.g_uint32(&v));
	r->codepage = static_cast<cpid_t>(v);
	return pack_result::ok;
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIGETPROPLIST_OUT &r)
{
	if (r.result != ecSuccess) {
		/* OXNSPI v14 §3.1.4.1.6 SPR ¶1 */
		TRY(x.p_unique_ptr(nullptr));
	} else {
		TRY(x.p_unique_ptr(r.pproptags));
		if (r.pproptags != nullptr)
			TRY(nsp_ndr_push_proptag_array(x, *r.pproptags));
	}
	return x.p_uint32(r.result);
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIGETPROPS_IN *r)
{
	uint32_t ptr;
	
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&r->flags));
	TRY(nsp_ndr_pull_stat(x, &r->stat));
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		r->pproptags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->pproptags == nullptr)
			return pack_result::alloc;
		TRY(nsp_ndr_pull_proptag_array(x, r->pproptags));
	} else {
		r->pproptags = NULL;
	}
	return pack_result::ok;
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIGETPROPS_OUT &r)
{
	if (r.result != ecSuccess && r.result != ecWarnWithErrors) {
		/* OXNSPI v14 §3.1.4.1.7 SPR ¶1 */
		TRY(x.p_unique_ptr(nullptr));
	} else {
		TRY(x.p_unique_ptr(r.prows));
		if (r.prows != nullptr)
			TRY(nsp_ndr_push_property_row(x, FLAG_HEADER | FLAG_CONTENT, *r.prows));
	}
	return x.p_uint32(r.result);
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPICOMPAREMIDS_IN *r)
{
	uint32_t resv;
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&resv));
	TRY(nsp_ndr_pull_stat(x, &r->stat));
	TRY(x.g_uint32(&r->mid1));
	return x.g_uint32(&r->mid2);
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPICOMPAREMIDS_OUT &r)
{
	TRY(x.p_int32(r.cmp));
	return x.p_uint32(r.result);
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIMODPROPS_IN *r)
{
	uint32_t resv, ptr;
	
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&resv));
	TRY(nsp_ndr_pull_stat(x, &r->stat));
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		r->pproptags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->pproptags == nullptr)
			return pack_result::alloc;
		TRY(nsp_ndr_pull_proptag_array(x, r->pproptags));
	} else {
		r->pproptags = NULL;
	}
	
	return nsp_ndr_pull_property_row(x, FLAG_HEADER|FLAG_CONTENT, &r->row);
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIMODPROPS_OUT &r)
{
	return x.p_uint32(r.result);
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIGETSPECIALTABLE_IN *r)
{
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&r->flags));
	TRY(nsp_ndr_pull_stat(x, &r->stat));
	return x.g_uint32(&r->version);
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIGETSPECIALTABLE_OUT &r)
{
	TRY(x.p_uint32(r.version));
	if (r.result != ecSuccess) {
		/* OXNSPI v14 §3.1.4.1.3 SPR ¶2 */
		TRY(x.p_unique_ptr(nullptr));
	} else {
		TRY(x.p_unique_ptr(r.prows));
		if (r.prows != nullptr)
			TRY(nsp_ndr_push_proprow_set(x, FLAG_HEADER | FLAG_CONTENT, *r.prows));
	}
	return x.p_uint32(r.result);
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIGETTEMPLATEINFO_IN *r)
{
	uint32_t ptr;
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&r->flags));
	TRY(x.g_uint32(&r->type));
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		TRY(x.g_ulong(&size));
		TRY(x.g_ulong(&offset));
		TRY(x.g_ulong(&length));
		if (offset != 0 || length > size)
			return pack_result::array_size;
		TRY(x.check_str(length, sizeof(uint8_t)));
		r->pdn = ndr_stack_anew<char>(NDR_STACK_IN, length + 1);
		if (r->pdn == nullptr)
			return pack_result::alloc;
		TRY(x.g_str(r->pdn, length));
	} else {
		r->pdn = NULL;
	}
	uint32_t v;
	TRY(x.g_uint32(&v));
	r->codepage = static_cast<cpid_t>(v);
	return x.g_uint32(&r->locale_id);
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIGETTEMPLATEINFO_OUT &r)
{
	if (r.result != ecSuccess) {
		/* OXNSPI v14 §3.1.4.1.18 SPR ¶1 */
		TRY(x.p_unique_ptr(nullptr));
	} else {
		TRY(x.p_unique_ptr(r.pdata));
		if (r.pdata != nullptr)
			TRY(nsp_ndr_push_property_row(x, FLAG_HEADER | FLAG_CONTENT, *r.pdata));
	}
	return x.p_uint32(r.result);
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIMODLINKATT_IN *r)
{
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&r->flags));
	TRY(x.g_uint32(&r->proptag));
	TRY(x.g_uint32(&r->mid));
	return nsp_ndr_pull_binary_array(x, FLAG_HEADER|FLAG_CONTENT, &r->entry_ids);
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIMODLINKATT_OUT &r)
{
	return x.p_uint32(r.result);
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIQUERYCOLUMNS_IN *r)
{
	uint32_t resv;
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&resv));
	return x.g_uint32(&r->flags);
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIQUERYCOLUMNS_OUT &r)
{
	if (r.result != ecSuccess) {
		/* OXNSPI v14 §3.1.4.1.5 SPR ¶1 */
		TRY(x.p_unique_ptr(nullptr));
	} else {
		TRY(x.p_unique_ptr(r.pcolumns));
		if (r.pcolumns != nullptr)
			TRY(nsp_ndr_push_proptag_array(x, *r.pcolumns));
	}
	return x.p_uint32(r.result);
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIRESOLVENAMES_IN *r)
{
	uint32_t ptr;
	
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&r->reserved));
	TRY(nsp_ndr_pull_stat(x, &r->stat));
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		r->pproptags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->pproptags == nullptr)
			return pack_result::alloc;
		TRY(nsp_ndr_pull_proptag_array(x, r->pproptags));
	} else {
		r->pproptags = NULL;
	}
	return nsp_ndr_pull_strings_array(x, FLAG_HEADER|FLAG_CONTENT, &r->strs);
	
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIRESOLVENAMES_OUT &r)
{
	if (r.result != ecSuccess) {
		/* OXNSPI v14 §3.1.4.1.16 SPR ¶3 */
		TRY(x.p_unique_ptr(nullptr));
		TRY(x.p_unique_ptr(nullptr));
	} else {
		TRY(x.p_unique_ptr(r.pmids));
		if (r.pmids != nullptr)
			TRY(nsp_ndr_push_proptag_array(x, *r.pmids));
		TRY(x.p_unique_ptr(r.prows));
		if (r.prows != nullptr)
			TRY(nsp_ndr_push_proprow_set(x, FLAG_HEADER | FLAG_CONTENT, *r.prows));
	}
	return x.p_uint32(r.result);
}

static pack_result nsp_ndr_pull(NDR_PULL &x, NSPIRESOLVENAMESW_IN *r)
{
	uint32_t ptr;
	
	TRY(x.g_ctx_handle(&r->handle));
	TRY(x.g_uint32(&r->reserved));
	TRY(nsp_ndr_pull_stat(x, &r->stat));
	TRY(x.g_genptr(&ptr));
	if (0 != ptr) {
		r->pproptags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->pproptags == nullptr)
			return pack_result::alloc;
		TRY(nsp_ndr_pull_proptag_array(x, r->pproptags));
	} else {
		r->pproptags = NULL;
	}
	
	return nsp_ndr_pull_wstrings_array(x, FLAG_HEADER|FLAG_CONTENT, &r->strs);
}

static pack_result nsp_ndr_push(NDR_PUSH &x, const NSPIRESOLVENAMESW_OUT &r)
{
	if (r.result != ecSuccess) {
		/* OXNSPI v14 §3.1.4.1.17 SPR ¶3 */
		TRY(x.p_unique_ptr(nullptr));
		TRY(x.p_unique_ptr(nullptr));
	} else {
		TRY(x.p_unique_ptr(r.pmids));
		if (r.pmids != nullptr)
			TRY(nsp_ndr_push_proptag_array(x, *r.pmids));
		TRY(x.p_unique_ptr(r.prows));
		if (r.prows != nullptr)
			TRY(nsp_ndr_push_proprow_set(x, FLAG_HEADER | FLAG_CONTENT, *r.prows));
	}
	return x.p_uint32(r.result);
}

pack_result exchange_nsp_ndr_pull(unsigned int opnum, NDR_PULL &x,
    std::unique_ptr<universal_base> &ppin) try
{
#define H(rpc, t) \
	case (rpc): { \
		auto r0 = std::make_unique<t ## _IN>(); \
		auto xret = nsp_ndr_pull(x, r0.get()); \
		ppin = std::move(r0); \
		return xret; \
	}

	switch (opnum) {
	H(nspiBind, NSPIBIND);
	H(nspiUnbind, NSPIUNBIND);
	H(nspiUpdateStat, NSPIUPDATESTAT);
	H(nspiQueryRows, NSPIQUERYROWS);
	H(nspiSeekEntries, NSPISEEKENTRIES);
	H(nspiGetMatches, NSPIGETMATCHES);
	H(nspiResortRestriction, NSPIRESORTRESTRICTION);
	H(nspiDNToMId, NSPIDNTOMID);
	H(nspiGetPropList, NSPIGETPROPLIST);
	H(nspiGetProps, NSPIGETPROPS);
	H(nspiCompareMIds, NSPICOMPAREMIDS);
	H(nspiModProps, NSPIMODPROPS);
	H(nspiGetSpecialTable, NSPIGETSPECIALTABLE);
	H(nspiGetTemplateInfo, NSPIGETTEMPLATEINFO);
	H(nspiModLinkAtt, NSPIMODLINKATT);
	H(nspiQueryColumns, NSPIQUERYCOLUMNS);
	H(nspiResolveNames, NSPIRESOLVENAMES);
	H(nspiResolveNamesW, NSPIRESOLVENAMESW);
	default:
		return pack_result::bad_switch;
	}
#undef H
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return pack_result::alloc;
}

pack_result exchange_nsp_ndr_push(unsigned int opnum, NDR_PUSH &x, const rpc_response *pout)
{
#define H(rpc, t) case (rpc): return nsp_ndr_push(x, *static_cast<const t ## _OUT *>(pout));
	switch (opnum) {
	H(nspiBind, NSPIBIND);
	H(nspiUnbind, NSPIUNBIND);
	H(nspiUpdateStat, NSPIUPDATESTAT);
	H(nspiQueryRows, NSPIQUERYROWS);
	H(nspiSeekEntries, NSPISEEKENTRIES);
	H(nspiGetMatches, NSPIGETMATCHES);
	H(nspiResortRestriction, NSPIRESORTRESTRICTION);
	H(nspiDNToMId, NSPIDNTOMID);
	H(nspiGetPropList, NSPIGETPROPLIST);
	H(nspiGetProps, NSPIGETPROPS);
	H(nspiCompareMIds, NSPICOMPAREMIDS);
	H(nspiModProps, NSPIMODPROPS);
	H(nspiGetSpecialTable, NSPIGETSPECIALTABLE);
	H(nspiGetTemplateInfo, NSPIGETTEMPLATEINFO);
	H(nspiModLinkAtt, NSPIMODLINKATT);
	H(nspiQueryColumns, NSPIQUERYCOLUMNS);
	H(nspiResolveNames, NSPIRESOLVENAMES);
	H(nspiResolveNamesW, NSPIRESOLVENAMESW);
	default:
		return pack_result::bad_switch;
	}
#undef H
}
