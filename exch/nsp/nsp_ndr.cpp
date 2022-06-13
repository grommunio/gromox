// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iconv.h>
#include <memory>
#include <gromox/mapidefs.h>
#include <gromox/proc_common.h>
#include <gromox/zz_ndr_stack.hpp>
#include "nsp_ndr.hpp"
#define FLAG_HEADER			0x1
#define FLAG_CONTENT		0x2
#define TRY(expr) do { int v = (expr); if (v != NDR_ERR_SUCCESS) return v; } while (false)

static int nsp_ndr_pull_restriction(NDR_PULL *pndr, unsigned int flag, NSPRES *r);
static int nsp_ndr_push_restriction(NDR_PUSH *pndr, unsigned int flag, const NSPRES *r);

static int32_t nsp_ndr_to_utf16(int ndr_flag, const char *src, char *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	iconv_t conv_id = (ndr_flag & NDR_FLAG_BIGENDIAN) ?
	                  iconv_open("UTF-16", "UTF-8") :
	                  iconv_open("UTF-16LE", "UTF-8");
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

static int nsp_ndr_pull_stat(NDR_PULL *pndr, STAT *r)
{
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint32(pndr, &r->sort_type));
	TRY(ndr_pull_uint32(pndr, &r->container_id));
	TRY(ndr_pull_uint32(pndr, &r->cur_rec));
	TRY(ndr_pull_int32(pndr, &r->delta));
	TRY(ndr_pull_uint32(pndr, &r->num_pos));
	TRY(ndr_pull_uint32(pndr, &r->total_rec));
	TRY(ndr_pull_uint32(pndr, &r->codepage));
	TRY(ndr_pull_uint32(pndr, &r->template_locale));
	TRY(ndr_pull_uint32(pndr, &r->sort_locale));
	return ndr_pull_trailer_align(pndr, 4);
}

static int nsp_ndr_push_stat(NDR_PUSH *pndr, const STAT *r)
{
	TRY(ndr_push_align(pndr, 4));
	TRY(ndr_push_uint32(pndr, r->sort_type));
	TRY(ndr_push_uint32(pndr, r->container_id));
	TRY(ndr_push_uint32(pndr, r->cur_rec));
	TRY(ndr_push_int32(pndr, r->delta));
	TRY(ndr_push_uint32(pndr, r->num_pos));
	TRY(ndr_push_uint32(pndr, r->total_rec));
	TRY(ndr_push_uint32(pndr, r->codepage));
	TRY(ndr_push_uint32(pndr, r->template_locale));
	TRY(ndr_push_uint32(pndr, r->sort_locale));
	return ndr_push_trailer_align(pndr, 4);
}

static int nsp_ndr_pull_flatuid(NDR_PULL *pndr, FLATUID *r)
{
	return ndr_pull_array_uint8(pndr, r->ab, 16);
}

static int nsp_ndr_push_flatuid(NDR_PUSH *pndr, const FLATUID *r)
{	
	return ndr_push_array_uint8(pndr, r->ab, 16);
}

static int nsp_ndr_pull_proptag_array(NDR_PULL *pndr, LPROPTAG_ARRAY *r)
{
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	
	TRY(ndr_pull_ulong(pndr, &size));
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint32(pndr, &r->cvalues));
	if (r->cvalues > 100001)
		return NDR_ERR_RANGE;
	TRY(ndr_pull_ulong(pndr, &offset));
	TRY(ndr_pull_ulong(pndr, &length));
	if (offset != 0 || length > size)
		return NDR_ERR_ARRAY_SIZE;
	if (size != r->cvalues + 1 || length != r->cvalues)
		return NDR_ERR_ARRAY_SIZE;
	r->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_IN, size);
	if (r->pproptag == nullptr)
		return NDR_ERR_ALLOC;
	for (size_t cnt = 0; cnt < length; ++cnt)
		TRY(ndr_pull_uint32(pndr, &r->pproptag[cnt]));
	return ndr_pull_trailer_align(pndr, 4);
}

static int nsp_ndr_push_proptag_array(NDR_PUSH *pndr, const LPROPTAG_ARRAY *r)
{
	TRY(ndr_push_ulong(pndr, r->cvalues + 1));
	TRY(ndr_push_align(pndr, 4));
	TRY(ndr_push_uint32(pndr, r->cvalues));
	TRY(ndr_push_ulong(pndr, 0));
	TRY(ndr_push_ulong(pndr, r->cvalues));
	for (size_t cnt = 0; cnt < r->cvalues; ++cnt)
		TRY(ndr_push_uint32(pndr, r->pproptag[cnt]));
	return ndr_push_trailer_align(pndr, 4);
}

static int nsp_ndr_pull_property_name(NDR_PULL *pndr, unsigned int flag, NSP_PROPNAME *r)
{
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		if (0 != ptr) {
			r->pguid = ndr_stack_anew<FLATUID>(NDR_STACK_IN);
			if (r->pguid == nullptr)
				return NDR_ERR_ALLOC;
		} else {
			r->pguid = NULL;
		}
		TRY(ndr_pull_uint32(pndr, &r->reserved));
		TRY(ndr_pull_uint32(pndr, &r->id));
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (flag & FLAG_CONTENT && r->pguid != nullptr)
		TRY(nsp_ndr_pull_flatuid(pndr, r->pguid));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_string_array(NDR_PULL *pndr, unsigned int flag, STRING_ARRAY *r)
{
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;
	uint32_t size1;
	uint32_t offset;
	uint32_t length1;
	

	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->count));
		if (r->count > 100000)
			return NDR_ERR_RANGE;
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		r->ppstr = ptr != 0 ? reinterpret_cast<char **>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->ppstr == nullptr)
		return NDR_ERR_SUCCESS;
	TRY(ndr_pull_ulong(pndr, &size));
	if (size != r->count)
		return NDR_ERR_ARRAY_SIZE;
	r->ppstr = ndr_stack_anew<char *>(NDR_STACK_IN, size);
	if (r->ppstr == nullptr)
		return NDR_ERR_ALLOC;
	for (cnt = 0; cnt < size; cnt++) {
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		r->ppstr[cnt] = ptr != 0 ? reinterpret_cast<char *>(static_cast<uintptr_t>(ptr)) : nullptr;
	}
	for (cnt = 0; cnt < size; cnt++) {
		if (r->ppstr[cnt] == nullptr)
			continue;
		TRY(ndr_pull_ulong(pndr, &size1));
		TRY(ndr_pull_ulong(pndr, &offset));
		TRY(ndr_pull_ulong(pndr, &length1));
		if (offset != 0 || length1 > size1)
			return NDR_ERR_ARRAY_SIZE;
		TRY(ndr_pull_check_string(pndr, length1, sizeof(uint8_t)));
		r->ppstr[cnt] = ndr_stack_anew<char>(NDR_STACK_IN, length1 + 1);
		if (r->ppstr[cnt] == nullptr)
			return NDR_ERR_ALLOC;
		TRY(ndr_pull_string(pndr, r->ppstr[cnt], length1));
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_string_array(NDR_PUSH *pndr, unsigned int flag, const STRING_ARRAY *r)
{
	uint32_t length;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->count));
		TRY(ndr_push_unique_ptr(pndr, r->ppstr));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->ppstr == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_push_ulong(pndr, r->count));
	for (size_t cnt = 0; cnt < r->count; ++cnt)
		TRY(ndr_push_unique_ptr(pndr, r->ppstr[cnt]));
	for (size_t cnt = 0; cnt < r->count; ++cnt) {
		if (r->ppstr[cnt] == nullptr)
			continue;
		length = strlen(r->ppstr[cnt]) + 1;
		TRY(ndr_push_ulong(pndr, length));
		TRY(ndr_push_ulong(pndr, 0));
		TRY(ndr_push_ulong(pndr, length));
		TRY(ndr_push_string(pndr, r->ppstr[cnt], length));
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_strings_array(NDR_PULL *pndr, unsigned int flag, STRINGS_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;
	uint32_t size1;
	uint32_t offset;
	uint32_t length1;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_ulong(pndr, &size));
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->count));
		if (r->count > 100000)
			return NDR_ERR_RANGE;
		if (r->count != size)
			return NDR_ERR_ARRAY_SIZE;
		r->ppstr = ndr_stack_anew<char *>(NDR_STACK_IN, size);
		if (r->ppstr == nullptr)
			return NDR_ERR_ALLOC;
		for (size_t cnt = 0; cnt < size; ++cnt) {
			TRY(ndr_pull_generic_ptr(pndr, &ptr));
			r->ppstr[cnt] = ptr != 0 ? reinterpret_cast<char *>(static_cast<uintptr_t>(ptr)) : nullptr;
		}
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT))
		return EXT_ERR_SUCCESS;
	for (size_t cnt = 0; cnt < r->count; ++cnt) {
		if (r->ppstr[cnt] == nullptr)
			continue;
		TRY(ndr_pull_ulong(pndr, &size1));
		TRY(ndr_pull_ulong(pndr, &offset));
		TRY(ndr_pull_ulong(pndr, &length1));
		if (offset != 0 || length1 > size1)
			return NDR_ERR_ARRAY_SIZE;
		TRY(ndr_pull_check_string(pndr, length1, sizeof(uint8_t)));
		r->ppstr[cnt] = ndr_stack_anew<char>(NDR_STACK_IN, length1 + 1);
		if (r->ppstr[cnt] == nullptr)
			return NDR_ERR_ALLOC;
		TRY(ndr_pull_string(pndr, r->ppstr[cnt], length1));
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_wstring_array(NDR_PULL *pndr, unsigned int flag, STRING_ARRAY *r)
{
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;
	uint32_t size1;
	uint32_t offset;
	uint32_t length1;
	

	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->count));
		if (r->count > 100000)
			return NDR_ERR_RANGE;
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		r->ppstr = ptr != 0 ? reinterpret_cast<char **>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->ppstr == nullptr)
		return NDR_ERR_SUCCESS;
	TRY(ndr_pull_ulong(pndr, &size));
	if (size != r->count)
		return NDR_ERR_ARRAY_SIZE;
	r->ppstr = ndr_stack_anew<char *>(NDR_STACK_IN, size);
	if (r->ppstr == nullptr)
		return NDR_ERR_ALLOC;
	for (cnt = 0; cnt < size; cnt++) {
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		r->ppstr[cnt] = ptr != 0 ? reinterpret_cast<char *>(static_cast<uintptr_t>(ptr)) : nullptr;
	}
	for (cnt = 0; cnt < size; cnt++) {
		if (r->ppstr[cnt] == nullptr)
			continue;
		TRY(ndr_pull_ulong(pndr, &size1));
		TRY(ndr_pull_ulong(pndr, &offset));
		TRY(ndr_pull_ulong(pndr, &length1));
		if (offset != 0 || length1 > size1)
			return NDR_ERR_ARRAY_SIZE;
		TRY(ndr_pull_check_string(pndr, length1, sizeof(uint16_t)));
		std::unique_ptr<char[]> pwstring;
		try {
			pwstring = std::make_unique<char[]>(sizeof(uint16_t) * length1 + 1);
		} catch (const std::bad_alloc &) {
			return NDR_ERR_ALLOC;
		}
		TRY(ndr_pull_string(pndr, pwstring.get(), sizeof(uint16_t) * length1));
		r->ppstr[cnt] = ndr_stack_anew<char>(NDR_STACK_IN, 2 * sizeof(uint16_t) * length1);
		if (r->ppstr[cnt] == nullptr)
			return NDR_ERR_ALLOC;
		if (!nsp_ndr_to_utf8(pndr->flags, pwstring.get(),
		    sizeof(uint16_t) * length1, r->ppstr[cnt],
		    2 * sizeof(uint16_t) * length1))
			return NDR_ERR_CHARCNV;
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_wstring_array(NDR_PUSH *pndr, unsigned int flag, const STRING_ARRAY *r)
{
	uint32_t length;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->count));
		TRY(ndr_push_unique_ptr(pndr, r->ppstr));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->ppstr == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_push_ulong(pndr, r->count));
	for (size_t cnt = 0; cnt < r->count; ++cnt)
		TRY(ndr_push_unique_ptr(pndr, r->ppstr[cnt]));
	for (size_t cnt = 0; cnt < r->count; ++cnt) {
		if (r->ppstr[cnt] == nullptr)
			continue;
		length = 2*strlen(r->ppstr[cnt]) + 2;
		std::unique_ptr<char[]> pwstring;
		try {
			pwstring = std::make_unique<char[]>(length);
		} catch (const std::bad_alloc &) {
			return NDR_ERR_ALLOC;
		}
		auto z = nsp_ndr_to_utf16(pndr->flags,
		         r->ppstr[cnt], pwstring.get(), length);
		if (z < 0)
			return NDR_ERR_CHARCNV;
		length = z;
		TRY(ndr_push_ulong(pndr, length / sizeof(uint16_t)));
		TRY(ndr_push_ulong(pndr, 0));
		TRY(ndr_push_ulong(pndr, length / sizeof(uint16_t)));
		TRY(ndr_push_string(pndr, pwstring.get(), length));
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_wstrings_array(NDR_PULL *pndr, unsigned int flag, STRINGS_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;
	uint32_t size1;
	uint32_t offset;
	uint32_t length1;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_ulong(pndr, &size));
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->count));
		if (r->count > 100000) {
			r->count = 0;
			return NDR_ERR_RANGE;
		}
		if (r->count != size) {
			r->count = 0;
			return NDR_ERR_ARRAY_SIZE;
		}
		r->ppstr = ndr_stack_anew<char *>(NDR_STACK_IN, size);
		if (r->ppstr == nullptr) {
			r->count = 0;
			return NDR_ERR_ALLOC;
		}
		for (size_t cnt = 0; cnt < size; ++cnt) {
			TRY(ndr_pull_generic_ptr(pndr, &ptr));
			r->ppstr[cnt] = ptr != 0 ? reinterpret_cast<char *>(static_cast<uintptr_t>(ptr)) : nullptr;
		}
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT))
		return EXT_ERR_SUCCESS;
	for (size_t cnt = 0; cnt < r->count; ++cnt) {
		if (r->ppstr[cnt] == nullptr)
			continue;
		TRY(ndr_pull_ulong(pndr, &size1));
		TRY(ndr_pull_ulong(pndr, &offset));
		TRY(ndr_pull_ulong(pndr, &length1));
		if (offset != 0 || length1 > size1)
			return NDR_ERR_ARRAY_SIZE;
		TRY(ndr_pull_check_string(pndr, length1, sizeof(uint16_t)));
		std::unique_ptr<char[]> pwstring;
		try {
			pwstring = std::make_unique<char[]>(sizeof(uint16_t) * length1 + 1);
		} catch (const std::bad_alloc &) {
			return NDR_ERR_ALLOC;
		}
		TRY(ndr_pull_string(pndr, pwstring.get(), sizeof(uint16_t) * length1));
		r->ppstr[cnt] = ndr_stack_anew<char>(NDR_STACK_IN, 2 * sizeof(uint16_t) * length1);
		if (r->ppstr[cnt] == nullptr)
			return NDR_ERR_ALLOC;
		if (!nsp_ndr_to_utf8(pndr->flags, pwstring.get(),
		    sizeof(uint16_t) * length1, r->ppstr[cnt],
		    2 * sizeof(uint16_t) * length1))
			return NDR_ERR_CHARCNV;
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_binary(NDR_PULL *pndr, unsigned int flag, BINARY *r)
{
	uint32_t ptr;
	uint32_t size;

	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->cb));
		if (r->cb > 2097152) {
			r->cb = 0;
			return NDR_ERR_RANGE;
		}
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		r->pb = ptr != 0 ? reinterpret_cast<uint8_t *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pb == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_pull_ulong(pndr, &size));
	if (size != r->cb) {
		r->cb = 0;
		return NDR_ERR_ARRAY_SIZE;
	}
	r->pb = ndr_stack_anew<uint8_t>(NDR_STACK_IN, size);
	if (NULL == r->pb) {
		r->cb = 0;
		return NDR_ERR_ALLOC;
	}
	TRY(ndr_pull_array_uint8(pndr, r->pb, size));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_binary(NDR_PUSH *pndr, unsigned int flag, const BINARY *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->cb));
		TRY(ndr_push_unique_ptr(pndr, r->pb));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pb == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_push_ulong(pndr, r->cb));
	TRY(ndr_push_array_uint8(pndr, r->pb, r->cb));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_filetime(NDR_PULL *pndr, FILETIME *r)
{
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint32(pndr, &r->low_datetime));
	TRY(ndr_pull_uint32(pndr, &r->high_datetime));
	return ndr_pull_trailer_align(pndr, 4);
}

static int nsp_ndr_push_filetime(NDR_PUSH *pndr, const FILETIME *r)
{
	TRY(ndr_push_align(pndr, 4));
	TRY(ndr_push_uint32(pndr, r->low_datetime));
	TRY(ndr_push_uint32(pndr, r->high_datetime));
	return ndr_push_trailer_align(pndr, 4);
}

static int nsp_ndr_pull_short_array(NDR_PULL *pndr, unsigned int flag, SHORT_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->count));
		if (r->count > 100000)
			return NDR_ERR_RANGE;
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		r->ps = ptr != 0 ? reinterpret_cast<uint16_t *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->ps == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_pull_ulong(pndr, &size));
	if (size != r->count)
		return NDR_ERR_ARRAY_SIZE;
	r->ps = ndr_stack_anew<uint16_t>(NDR_STACK_IN, size);
	if (r->ps == nullptr)
		return NDR_ERR_ALLOC;
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(ndr_pull_uint16(pndr, &r->ps[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_short_array(NDR_PUSH *pndr, unsigned int flag, const SHORT_ARRAY *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->count));
		TRY(ndr_push_unique_ptr(pndr, r->ps));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->ps == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_push_ulong(pndr, r->count));
	for (size_t cnt = 0; cnt < r->count; ++cnt)
		TRY(ndr_push_uint16(pndr, r->ps[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_long_array(NDR_PULL *pndr, unsigned int flag, LONG_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->count));
		if (r->count > 100000)
			return NDR_ERR_RANGE;
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		r->pl = ptr != 0 ? reinterpret_cast<uint32_t *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pl == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_pull_ulong(pndr, &size));
	if (size != r->count)
		return NDR_ERR_ARRAY_SIZE;
	r->pl = ndr_stack_anew<uint32_t>(NDR_STACK_IN, size);
	if (r->pl == nullptr)
		return NDR_ERR_ALLOC;
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(ndr_pull_uint32(pndr, &r->pl[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_long_array(NDR_PUSH *pndr, unsigned int flag, const LONG_ARRAY *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->count));
		TRY(ndr_push_unique_ptr(pndr, r->pl));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pl == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_push_ulong(pndr, r->count));
	for (size_t cnt = 0; cnt < r->count; ++cnt)
		TRY(ndr_push_uint32(pndr, r->pl[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_binary_array(NDR_PULL *pndr, unsigned int flag, BINARY_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->count));
		if (r->count > 100000)
			return NDR_ERR_RANGE;
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		r->pbin = ptr != 0 ? reinterpret_cast<BINARY *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pbin == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_pull_ulong(pndr, &size));
	if (size != r->count)
		return NDR_ERR_ARRAY_SIZE;
	r->pbin = ndr_stack_anew<BINARY>(NDR_STACK_IN, size);
	if (r->pbin == nullptr)
		return NDR_ERR_ALLOC;
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_binary(pndr, FLAG_HEADER, &r->pbin[cnt]));
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_binary(pndr, FLAG_CONTENT, &r->pbin[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_binary_array(NDR_PUSH *pndr, unsigned int flag, const BINARY_ARRAY *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->count));
		TRY(ndr_push_unique_ptr(pndr, r->pbin));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pbin == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_push_ulong(pndr, r->count));
	for (size_t cnt = 0; cnt < r->count; ++cnt)
		TRY(nsp_ndr_push_binary(pndr, FLAG_HEADER, &r->pbin[cnt]));
	for (size_t cnt = 0; cnt < r->count; ++cnt)
		TRY(nsp_ndr_push_binary(pndr, FLAG_CONTENT, &r->pbin[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_flatuid_array(NDR_PULL *pndr, unsigned int flag, FLATUID_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;

	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->cvalues));
		if (r->cvalues > 100000)
			return NDR_ERR_RANGE;
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		r->ppguid = ptr != 0 ? reinterpret_cast<FLATUID **>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->ppguid == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_pull_ulong(pndr, &size));
	if (size != r->cvalues)
		return NDR_ERR_ARRAY_SIZE;
	r->ppguid = ndr_stack_anew<FLATUID *>(NDR_STACK_IN, size);
	if (r->ppguid == nullptr)
		return NDR_ERR_ALLOC;
	for (size_t cnt = 0; cnt < size; ++cnt) {
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		if (0 != ptr) {
			r->ppguid[cnt] = ndr_stack_anew<FLATUID>(NDR_STACK_IN);
			if (r->ppguid[cnt] == nullptr)
				return NDR_ERR_ALLOC;
		} else {
			r->ppguid[cnt] = NULL;
		}
	}
	for (size_t cnt = 0; cnt < size; ++cnt)
		if (r->ppguid[cnt] != nullptr)
			TRY(nsp_ndr_pull_flatuid(pndr, r->ppguid[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_flatuid_array(NDR_PUSH *pndr, unsigned int flag, const FLATUID_ARRAY *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->cvalues));
		TRY(ndr_push_unique_ptr(pndr, r->ppguid));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->ppguid == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_push_ulong(pndr, r->cvalues));
	for (size_t cnt = 0; cnt < r->cvalues; ++cnt)
		TRY(ndr_push_unique_ptr(pndr, r->ppguid[cnt]));
	for (size_t cnt = 0; cnt < r->cvalues; ++cnt)
		if (r->ppguid[cnt] != nullptr)
			TRY(nsp_ndr_push_flatuid(pndr, r->ppguid[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_filetime_array(NDR_PULL *pndr, unsigned int flag, FILETIME_ARRAY *r)
{
	uint32_t ptr;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->cvalues));
		if (r->cvalues > 100000)
			return NDR_ERR_RANGE;
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		r->pftime = ptr != 0 ? reinterpret_cast<FILETIME *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	if (!(flag & FLAG_CONTENT) || r->pftime == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_pull_ulong(pndr, &size));
	if (size != r->cvalues)
		return NDR_ERR_ARRAY_SIZE;
	r->pftime = ndr_stack_anew<FILETIME>(NDR_STACK_IN, size);
	if (r->pftime == nullptr)
		return NDR_ERR_ALLOC;
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_filetime(pndr, &r->pftime[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_filetime_array(NDR_PUSH *pndr, unsigned int flag, const FILETIME_ARRAY *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->cvalues));
		TRY(ndr_push_unique_ptr(pndr, r->pftime));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pftime == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_push_ulong(pndr, r->cvalues));
	for (size_t cnt = 0; cnt < r->cvalues; ++cnt)
		TRY(nsp_ndr_push_filetime(pndr, &r->pftime[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_prop_val_union(NDR_PULL *pndr, unsigned int flag,
    uint32_t *ptype, PROP_VAL_UNION *r)
{
	uint32_t ptr;
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_union_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, ptype));
		TRY(ndr_pull_union_align(pndr, 5));
		switch (*ptype) {
		case PT_SHORT:
			TRY(ndr_pull_uint16(pndr, &r->s));
			break;
		case PT_LONG:
		case PT_OBJECT:
			TRY(ndr_pull_uint32(pndr, &r->l));
			break;
		case PT_BOOLEAN:
			TRY(ndr_pull_uint8(pndr, &r->b));
			break;
		case PT_STRING8:
		case PT_UNICODE:
			TRY(ndr_pull_generic_ptr(pndr, &ptr));
			r->pstr = ptr != 0 ? reinterpret_cast<char *>(static_cast<uintptr_t>(ptr)) : nullptr;
			break;
		case PT_BINARY:
			TRY(nsp_ndr_pull_binary(pndr, FLAG_HEADER, &r->bin));
			break;
		case PT_CLSID:
			TRY(ndr_pull_generic_ptr(pndr, &ptr));
			r->pguid = ptr != 0 ? reinterpret_cast<FLATUID *>(static_cast<uintptr_t>(ptr)) : nullptr;
			break;
		case PT_SYSTIME:
			TRY(nsp_ndr_pull_filetime(pndr, &r->ftime));
			break;
		case PT_ERROR:
			TRY(ndr_pull_uint32(pndr, &r->err));
			break;
		case PT_MV_SHORT:
			TRY(nsp_ndr_pull_short_array(pndr, FLAG_HEADER, &r->short_array));
			break;
		case PT_MV_LONG:
			TRY(nsp_ndr_pull_long_array(pndr, FLAG_HEADER, &r->long_array));
			break;
		case PT_MV_STRING8:
			TRY(nsp_ndr_pull_string_array(pndr, FLAG_HEADER, &r->string_array));
			break;
		case PT_MV_BINARY:
			TRY(nsp_ndr_pull_binary_array(pndr, FLAG_HEADER, &r->bin_array));
			break;
		case PT_MV_CLSID:
			TRY(nsp_ndr_pull_flatuid_array(pndr, FLAG_HEADER, &r->guid_array));
			break;
		case PT_MV_UNICODE:
			TRY(nsp_ndr_pull_wstring_array(pndr, FLAG_HEADER, &r->string_array));
			break;
		case PT_MV_SYSTIME:
			TRY(nsp_ndr_pull_filetime_array(pndr, FLAG_HEADER, &r->ftime_array));
			break;
		case PT_NULL:
			TRY(ndr_pull_uint32(pndr, &r->reserved));
			break;
		default:
			fprintf(stderr, "E-1910: nsp_ndr type %xh unhandled\n", *ptype);
			return NDR_ERR_BAD_SWITCH;
		}
	}
	
	if (!(flag & FLAG_CONTENT))
		return EXT_ERR_SUCCESS;
	switch (*ptype) {
	case PT_SHORT:
		break;
	case PT_LONG:
	case PT_OBJECT:
	case PT_BOOLEAN:
		break;
	case PT_STRING8:
		if (r->pstr == nullptr)
			break;
		TRY(ndr_pull_ulong(pndr, &size));
		TRY(ndr_pull_ulong(pndr, &offset));
		TRY(ndr_pull_ulong(pndr, &length));
		if (offset != 0 || length > size)
			return NDR_ERR_ARRAY_SIZE;
		TRY(ndr_pull_check_string(pndr, length, sizeof(uint8_t)));
		r->pstr = ndr_stack_anew<char>(NDR_STACK_IN, length + 1);
		if (r->pstr == nullptr)
			return NDR_ERR_ALLOC;
		TRY(ndr_pull_string(pndr, r->pstr, length));
		break;
	case PT_UNICODE: {
		if (r->pstr == nullptr)
			break;
		TRY(ndr_pull_ulong(pndr, &size));
		TRY(ndr_pull_ulong(pndr, &offset));
		TRY(ndr_pull_ulong(pndr, &length));
		if (offset != 0 || length > size)
			return NDR_ERR_ARRAY_SIZE;
		TRY(ndr_pull_check_string(pndr, length, sizeof(uint16_t)));
		std::unique_ptr<char[]> pwstring;
		try {
			pwstring = std::make_unique<char[]>(sizeof(uint16_t) * length + 1);
		} catch (const std::bad_alloc &) {
			return NDR_ERR_ALLOC;
		}
		TRY(ndr_pull_string(pndr, pwstring.get(), sizeof(uint16_t) * length));
		r->pstr = ndr_stack_anew<char>(NDR_STACK_IN, 2 * sizeof(uint16_t) * length);
		if (r->pstr == nullptr)
			return NDR_ERR_ALLOC;
		if (!nsp_ndr_to_utf8(pndr->flags, pwstring.get(),
		    sizeof(uint16_t) * length, r->pstr,
		    2 * sizeof(uint16_t) * length))
			return NDR_ERR_CHARCNV;
		break;
	}
	case PT_BINARY:
		TRY(nsp_ndr_pull_binary(pndr, FLAG_CONTENT, &r->bin));
		break;
	case PT_CLSID:
		if (r->pguid != nullptr)
			TRY(nsp_ndr_pull_flatuid(pndr, r->pguid));
		break;
	case PT_SYSTIME:
		break;
	case PT_ERROR:
		break;
	case PT_MV_SHORT:
		TRY(nsp_ndr_pull_short_array(pndr, FLAG_CONTENT, &r->short_array));
		break;
	case PT_MV_LONG:
		TRY(nsp_ndr_pull_long_array(pndr, FLAG_CONTENT, &r->long_array));
		break;
	case PT_MV_STRING8:
		TRY(nsp_ndr_pull_string_array(pndr, FLAG_CONTENT, &r->string_array));
		break;
	case PT_MV_BINARY:
		TRY(nsp_ndr_pull_binary_array(pndr, FLAG_CONTENT, &r->bin_array));
		break;
	case PT_MV_CLSID:
		TRY(nsp_ndr_pull_flatuid_array(pndr, FLAG_CONTENT, &r->guid_array));
		break;
	case PT_MV_UNICODE:
		TRY(nsp_ndr_pull_wstring_array(pndr, FLAG_CONTENT, &r->string_array));
		break;
	case PT_MV_SYSTIME:
		TRY(nsp_ndr_pull_filetime_array(pndr, FLAG_CONTENT, &r->ftime_array));
		break;
	case PT_NULL:
		break;
	default:
		fprintf(stderr, "E-1911: nsp_ndr type %xh unhandled\n", *ptype);
		return NDR_ERR_BAD_SWITCH;
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_prop_val_union(NDR_PUSH *pndr, unsigned int flag,
    uint32_t type, const PROP_VAL_UNION *r)
{
	uint32_t length;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_union_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, type));
		TRY(ndr_push_union_align(pndr, 5));
		switch (type) {
		case PT_SHORT:
			TRY(ndr_push_uint16(pndr, r->s));
			break;
		case PT_LONG:
		case PT_OBJECT:
			TRY(ndr_push_uint32(pndr, r->l));
			break;
		case PT_BOOLEAN:
			TRY(ndr_push_uint8(pndr, r->b));
			break;
		case PT_STRING8:
		case PT_UNICODE:
			TRY(ndr_push_unique_ptr(pndr, r->pstr));
			break;
		case PT_BINARY:
			TRY(nsp_ndr_push_binary(pndr, FLAG_HEADER, &r->bin));
			break;
		case PT_CLSID:
			TRY(ndr_push_unique_ptr(pndr, r->pguid));
			break;
		case PT_SYSTIME:
			TRY(nsp_ndr_push_filetime(pndr, &r->ftime));
			break;
		case PT_ERROR:
			TRY(ndr_push_uint32(pndr, r->err));
			break;
		case PT_MV_SHORT:
			TRY(nsp_ndr_push_short_array(pndr, FLAG_HEADER, &r->short_array));
			break;
		case PT_MV_LONG:
			TRY(nsp_ndr_push_long_array(pndr, FLAG_HEADER, &r->long_array));
			break;
		case PT_MV_STRING8:
			TRY(nsp_ndr_push_string_array(pndr, FLAG_HEADER, &r->string_array));
			break;
		case PT_MV_BINARY:
			TRY(nsp_ndr_push_binary_array(pndr, FLAG_HEADER, &r->bin_array));
			break;
		case PT_MV_CLSID:
			TRY(nsp_ndr_push_flatuid_array(pndr, FLAG_HEADER, &r->guid_array));
			break;
		case PT_MV_UNICODE:
			TRY(nsp_ndr_push_wstring_array(pndr, FLAG_HEADER, &r->string_array));
			break;
		case PT_MV_SYSTIME:
			TRY(nsp_ndr_push_filetime_array(pndr, FLAG_HEADER, &r->ftime_array));
			break;
		case PT_NULL:
			TRY(ndr_push_uint32(pndr, r->reserved));
			break;
		default:
			fprintf(stderr, "E-1912: nsp_ndr type %xh unhandled\n", type);
			return NDR_ERR_BAD_SWITCH;
		}
	}
	
	if (!(flag & FLAG_CONTENT))
		return EXT_ERR_SUCCESS;
	switch (type) {
	case PT_SHORT:
		break;
	case PT_LONG:
	case PT_OBJECT:
	case PT_BOOLEAN:
		break;
	case PT_STRING8:
		if (r->pstr == nullptr)
			break;
		length = strlen(r->pstr) + 1;
		TRY(ndr_push_ulong(pndr, length));
		TRY(ndr_push_ulong(pndr, 0));
		TRY(ndr_push_ulong(pndr, length));
		TRY(ndr_push_string(pndr, r->pstr, length));
		break;
	case PT_UNICODE: {
		if (r->pstr == nullptr)
			break;
		length = strlen(r->pstr) + 1;
		std::unique_ptr<char[]> pwstring;
		try {
			pwstring = std::make_unique<char[]>(2 * length);
		} catch (const std::bad_alloc &) {
			return NDR_ERR_ALLOC;
		}
		auto z = nsp_ndr_to_utf16(pndr->flags, r->pstr, pwstring.get(), 2 * length);
		if (z < 0)
			return NDR_ERR_CHARCNV;
		length = z;
		TRY(ndr_push_ulong(pndr, length / sizeof(uint16_t)));
		TRY(ndr_push_ulong(pndr, 0));
		TRY(ndr_push_ulong(pndr, length / sizeof(uint16_t)));
		TRY(ndr_push_string(pndr, pwstring.get(), length));
		break;
	}
	case PT_BINARY:
		TRY(nsp_ndr_push_binary(pndr, FLAG_CONTENT, &r->bin));
		break;
	case PT_CLSID:
		if (r->pguid == nullptr)
			TRY(nsp_ndr_push_flatuid(pndr, r->pguid));
		break;
	case PT_SYSTIME:
		break;
	case PT_ERROR:
		break;
	case PT_MV_SHORT:
		TRY(nsp_ndr_push_short_array(pndr, FLAG_CONTENT, &r->short_array));
		break;
	case PT_MV_LONG:
		TRY(nsp_ndr_push_long_array(pndr, FLAG_CONTENT, &r->long_array));
		break;
	case PT_MV_STRING8:
		TRY(nsp_ndr_push_string_array(pndr, FLAG_CONTENT, &r->string_array));
		break;
	case PT_MV_BINARY:
		TRY(nsp_ndr_push_binary_array(pndr, FLAG_CONTENT, &r->bin_array));
		break;
	case PT_MV_CLSID:
		TRY(nsp_ndr_push_flatuid_array(pndr, FLAG_CONTENT, &r->guid_array));
		break;
	case PT_MV_UNICODE:
		TRY(nsp_ndr_push_wstring_array(pndr, FLAG_CONTENT, &r->string_array));
		break;
	case PT_MV_SYSTIME:
		TRY(nsp_ndr_push_filetime_array(pndr, FLAG_CONTENT, &r->ftime_array));
		break;
	case PT_NULL:
		break;
	default:
		fprintf(stderr, "E-1913: nsp_ndr type %xh unhandled\n", type);
		return NDR_ERR_BAD_SWITCH;
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_property_value(NDR_PULL *pndr, unsigned int flag, PROPERTY_VALUE *r)
{
	if (flag & FLAG_HEADER) {
		uint32_t type = PT_UNSPECIFIED;
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->proptag));
		TRY(ndr_pull_uint32(pndr, &r->reserved));
		TRY(nsp_ndr_pull_prop_val_union(pndr, FLAG_HEADER, &type, &r->value));
		if (PROP_TYPE(r->proptag) != type)
			return NDR_ERR_BAD_SWITCH;
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT))
		return EXT_ERR_SUCCESS;
	uint32_t type = PROP_TYPE(r->proptag);
	TRY(nsp_ndr_pull_prop_val_union(pndr, FLAG_CONTENT, &type, &r->value));
	return NDR_ERR_SUCCESS;
	
}

static int nsp_ndr_push_property_value(NDR_PUSH *pndr, unsigned int flag, const PROPERTY_VALUE *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->proptag));
		TRY(ndr_push_uint32(pndr, r->reserved));
		TRY(nsp_ndr_push_prop_val_union(pndr, FLAG_HEADER, PROP_TYPE(r->proptag), &r->value));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	if (flag & FLAG_CONTENT)
		TRY(nsp_ndr_push_prop_val_union(pndr, FLAG_CONTENT, PROP_TYPE(r->proptag), &r->value));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_property_row(NDR_PULL *pndr, unsigned int flag, NSP_PROPROW *r)
{
	uint32_t ptr;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->reserved));
		TRY(ndr_pull_uint32(pndr, &r->cvalues));
		if (r->cvalues > 100000)
			return NDR_ERR_RANGE;
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		r->pprops = ptr != 0 ? reinterpret_cast<PROPERTY_VALUE *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pprops == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_pull_ulong(pndr, &size));
	if (size != r->cvalues)
		return NDR_ERR_ARRAY_SIZE;
	r->pprops = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_IN, size);
	if (r->pprops == nullptr)
		return NDR_ERR_ALLOC;
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_property_value(pndr, FLAG_HEADER, &r->pprops[cnt]));
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_property_value(pndr, FLAG_CONTENT, &r->pprops[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_property_row(NDR_PUSH *pndr, unsigned int flag, const NSP_PROPROW *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->reserved));
		TRY(ndr_push_uint32(pndr, r->cvalues));
		TRY(ndr_push_unique_ptr(pndr, r->pprops));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pprops == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_push_ulong(pndr, r->cvalues));
	for (size_t cnt = 0; cnt < r->cvalues; ++cnt)
		TRY(nsp_ndr_push_property_value(pndr, FLAG_HEADER, &r->pprops[cnt]));
	for (size_t cnt = 0; cnt < r->cvalues; ++cnt)
		TRY(nsp_ndr_push_property_value(pndr, FLAG_CONTENT, &r->pprops[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_proprow_set(NDR_PUSH *pndr, unsigned int flag, const NSP_ROWSET *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_ulong(pndr, r->crows));
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->crows));
		for (size_t cnt = 0; cnt < r->crows; ++cnt)
			TRY(nsp_ndr_push_property_row(pndr, FLAG_HEADER, &r->prows[cnt]));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	if (flag & FLAG_CONTENT)
		for (size_t cnt = 0; cnt < r->crows; ++cnt)
			TRY(nsp_ndr_push_property_row(pndr, FLAG_CONTENT, &r->prows[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_and_or(NDR_PULL *pndr, unsigned int flag,
    NSPRES_AND_OR *r)
{
	uint32_t ptr;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->cres));
		if (r->cres > 100000)
			return NDR_ERR_RANGE;
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		r->pres = ptr != 0 ? reinterpret_cast<NSPRES *>(static_cast<uintptr_t>(ptr)) : nullptr;
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pres == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_pull_ulong(pndr, &size));
	if (size != r->cres)
		return NDR_ERR_ARRAY_SIZE;
	r->pres = ndr_stack_anew<NSPRES>(NDR_STACK_IN, size);
	if (r->pres == nullptr)
		return NDR_ERR_ALLOC;
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_restriction(pndr, FLAG_HEADER, &r->pres[cnt]));
	for (size_t cnt = 0; cnt < size; ++cnt)
		TRY(nsp_ndr_pull_restriction(pndr, FLAG_CONTENT, &r->pres[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_and_or(NDR_PUSH *pndr, unsigned int flag,
    const NSPRES_AND_OR *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->cres));
		TRY(ndr_push_unique_ptr(pndr, r->pres));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	
	if (!(flag & FLAG_CONTENT) || r->pres == nullptr)
		return EXT_ERR_SUCCESS;
	TRY(ndr_push_ulong(pndr, r->cres));
	for (size_t cnt = 0; cnt < r->cres; ++cnt)
		TRY(nsp_ndr_push_restriction(pndr, FLAG_HEADER, &r->pres[cnt]));
	for (size_t cnt = 0; cnt < r->cres; ++cnt)
		TRY(nsp_ndr_push_restriction(pndr, FLAG_CONTENT, &r->pres[cnt]));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_not(NDR_PULL *pndr, unsigned int flag,
    NSPRES_NOT *r)
{
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		if (0 != ptr) {
			r->pres = ndr_stack_anew<NSPRES>(NDR_STACK_IN);
			if (r->pres == nullptr)
				return NDR_ERR_ALLOC;
		} else {
			r->pres = NULL;
		}
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (flag & FLAG_CONTENT && r->pres != nullptr)
		TRY(nsp_ndr_pull_restriction(pndr, FLAG_HEADER | FLAG_CONTENT, r->pres));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_not(NDR_PUSH *pndr, unsigned int flag,
    const NSPRES_NOT *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_unique_ptr(pndr, r->pres));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	if (flag & FLAG_CONTENT && r->pres != nullptr)
		TRY(nsp_ndr_push_restriction(pndr, FLAG_HEADER | FLAG_CONTENT, r->pres));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_content(NDR_PULL *pndr, unsigned int flag,
     NSPRES_CONTENT *r)
{
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->fuzzy_level));
		TRY(ndr_pull_uint32(pndr, &r->proptag));
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		if (0 != ptr) {
			r->pprop = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_IN);
			if (r->pprop == nullptr)
				return NDR_ERR_ALLOC;
		} else {
			r->pprop = NULL;
		}
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (flag & FLAG_CONTENT && r->pprop != nullptr)
		TRY(nsp_ndr_pull_property_value(pndr, FLAG_HEADER | FLAG_CONTENT, r->pprop));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_content(NDR_PUSH *pndr, unsigned int flag,
    const NSPRES_CONTENT *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->fuzzy_level));
		TRY(ndr_push_uint32(pndr, r->proptag));
		TRY(ndr_push_unique_ptr(pndr, r->pprop));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	if (flag & FLAG_CONTENT && r->pprop != nullptr)
		TRY(nsp_ndr_push_property_value(pndr, FLAG_HEADER | FLAG_CONTENT, r->pprop));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_property(NDR_PULL *pndr, unsigned int flag,
    NSPRES_PROPERTY *r)
{
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->relop));
		TRY(ndr_pull_uint32(pndr, &r->proptag));
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		if (0 != ptr) {
			r->pprop = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_IN);
			if (r->pprop == nullptr)
				return NDR_ERR_ALLOC;
		} else {
			r->pprop = NULL;
		}
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (flag & FLAG_CONTENT && r->pprop != nullptr)
		TRY(nsp_ndr_pull_property_value(pndr, FLAG_HEADER | FLAG_CONTENT, r->pprop));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_property(NDR_PUSH *pndr, unsigned int flag,
    const NSPRES_PROPERTY *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->relop));
		TRY(ndr_push_uint32(pndr, r->proptag));
		TRY(ndr_push_unique_ptr(pndr, r->pprop));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	if (flag & FLAG_CONTENT && r->pprop != nullptr)
		TRY(nsp_ndr_push_property_value(pndr, FLAG_HEADER | FLAG_CONTENT, r->pprop));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_propcompare(NDR_PULL *pndr,
    NSPRES_PROPCOMPARE *r)
{
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint32(pndr, &r->relop));
	TRY(ndr_pull_uint32(pndr, &r->proptag1));
	TRY(ndr_pull_uint32(pndr, &r->proptag2));
	TRY(ndr_pull_trailer_align(pndr, 4));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_propcompare(NDR_PUSH *pndr,
    const NSPRES_PROPCOMPARE *r)
{
	TRY(ndr_push_align(pndr, 4));
	TRY(ndr_push_uint32(pndr, r->relop));
	TRY(ndr_push_uint32(pndr, r->proptag1));
	TRY(ndr_push_uint32(pndr, r->proptag2));
	TRY(ndr_push_trailer_align(pndr, 4));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_bitmask(NDR_PULL *pndr, NSPRES_BITMASK *r)
{
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint32(pndr, &r->rel_mbr));
	TRY(ndr_pull_uint32(pndr, &r->proptag));
	TRY(ndr_pull_uint32(pndr, &r->mask));
	TRY(ndr_pull_trailer_align(pndr, 4));
	
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_bitmask(NDR_PUSH *pndr,
    const NSPRES_BITMASK *r)
{
	TRY(ndr_push_align(pndr, 4));
	TRY(ndr_push_uint32(pndr, r->rel_mbr));
	TRY(ndr_push_uint32(pndr, r->proptag));
	TRY(ndr_push_uint32(pndr, r->mask));
	TRY(ndr_push_trailer_align(pndr, 4));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_size(NDR_PULL *pndr, NSPRES_SIZE *r)
{
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint32(pndr, &r->relop));
	TRY(ndr_pull_uint32(pndr, &r->proptag));
	TRY(ndr_pull_uint32(pndr, &r->cb));
	TRY(ndr_pull_trailer_align(pndr, 4));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_size(NDR_PUSH *pndr, const NSPRES_SIZE *r)
{
	TRY(ndr_push_align(pndr, 4));
	TRY(ndr_push_uint32(pndr, r->relop));
	TRY(ndr_push_uint32(pndr, r->proptag));
	TRY(ndr_push_uint32(pndr, r->cb));
	TRY(ndr_push_trailer_align(pndr, 4));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_exist(NDR_PULL *pndr, NSPRES_EXIST *r)
{
	TRY(ndr_pull_align(pndr, 4));
	TRY(ndr_pull_uint32(pndr, &r->reserved1));
	TRY(ndr_pull_uint32(pndr, &r->proptag));
	TRY(ndr_pull_uint32(pndr, &r->reserved2));
	TRY(ndr_pull_trailer_align(pndr, 4));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_exist(NDR_PUSH *pndr, const NSPRES_EXIST *r)
{
	TRY(ndr_push_align(pndr, 4));
	TRY(ndr_push_uint32(pndr, r->reserved1));
	TRY(ndr_push_uint32(pndr, r->proptag));
	TRY(ndr_push_uint32(pndr, r->reserved2));
	TRY(ndr_push_trailer_align(pndr, 4));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_sub(NDR_PULL *pndr, unsigned int flag, NSPRES_SUB *r)
{
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, &r->subobject));
		TRY(ndr_pull_generic_ptr(pndr, &ptr));
		if (0 != ptr) {
			r->pres = ndr_stack_anew<NSPRES>(NDR_STACK_IN);
			if (r->pres == nullptr)
				return NDR_ERR_ALLOC;
		} else {
			r->pres = NULL;
		}
		TRY(ndr_pull_trailer_align(pndr, 5));
	}
	
	if (flag & FLAG_CONTENT && r->pres != nullptr)
		TRY(nsp_ndr_pull_restriction(pndr, FLAG_HEADER | FLAG_CONTENT, r->pres));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_sub(NDR_PUSH *pndr, unsigned int flag,
    const NSPRES_SUB *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, r->subobject));
		TRY(ndr_push_unique_ptr(pndr, r->pres));
		TRY(ndr_push_trailer_align(pndr, 5));
	}
	
	if (flag & FLAG_CONTENT && r->pres != nullptr)
		TRY(nsp_ndr_push_restriction(pndr, FLAG_HEADER | FLAG_CONTENT, r->pres));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_union(NDR_PULL *pndr, unsigned int flag,
    uint32_t *ptype, NSPRES_UNION *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_pull_union_align(pndr, 5));
		TRY(ndr_pull_uint32(pndr, ptype));
		TRY(ndr_pull_union_align(pndr, 5));
		switch (*ptype) {
		case RES_AND:
			TRY(nsp_ndr_pull_restriction_and_or(pndr, FLAG_HEADER, &r->res_andor));
			break;
		case RES_OR:
			TRY(nsp_ndr_pull_restriction_and_or(pndr, FLAG_HEADER, &r->res_andor));
			break;
		case RES_NOT:
			TRY(nsp_ndr_pull_restriction_not(pndr, FLAG_HEADER, &r->res_not));
			break;
		case RES_CONTENT:
			TRY(nsp_ndr_pull_restriction_content(pndr, FLAG_HEADER, &r->res_content));
			break;
		case RES_PROPERTY:
			TRY(nsp_ndr_pull_restriction_property(pndr, FLAG_HEADER, &r->res_property));
			break;
		case RES_PROPCOMPARE:
			TRY(nsp_ndr_pull_restriction_propcompare(pndr, &r->res_propcompare));
			break;
		case RES_BITMASK:
			TRY(nsp_ndr_pull_restriction_bitmask(pndr, &r->res_bitmask));
			break;
		case RES_SIZE:
			TRY(nsp_ndr_pull_restriction_size(pndr, &r->res_size));
			break;
		case RES_EXIST:
			TRY(nsp_ndr_pull_restriction_exist(pndr, &r->res_exist));
			break;
		case RES_SUBRESTRICTION:
			TRY(nsp_ndr_pull_restriction_sub(pndr, FLAG_HEADER, &r->res_sub));
			break;
		default:
			fprintf(stderr, "E-1914: nsp_ndr type %xh unhandled\n", *ptype);
			return NDR_ERR_BAD_SWITCH;
		}
	}
	
	if (!(flag & FLAG_CONTENT))
		return EXT_ERR_SUCCESS;
	switch (*ptype) {
	case RES_AND:
		TRY(nsp_ndr_pull_restriction_and_or(pndr, FLAG_CONTENT, &r->res_andor));
		break;
	case RES_OR:
		TRY(nsp_ndr_pull_restriction_and_or(pndr, FLAG_CONTENT, &r->res_andor));
		break;
	case RES_NOT:
		TRY(nsp_ndr_pull_restriction_not(pndr, FLAG_CONTENT, &r->res_not));
		break;
	case RES_CONTENT:
		TRY(nsp_ndr_pull_restriction_content(pndr, FLAG_CONTENT, &r->res_content));
		break;
	case RES_PROPERTY:
		TRY(nsp_ndr_pull_restriction_property(pndr, FLAG_CONTENT, &r->res_property));
		break;
	case RES_PROPCOMPARE:
		break;
	case RES_BITMASK:
		break;
	case RES_SIZE:
		break;
	case RES_EXIST:
		break;
	case RES_SUBRESTRICTION:
		TRY(nsp_ndr_pull_restriction_sub(pndr, FLAG_CONTENT, &r->res_sub));
		break;
	default:
		fprintf(stderr, "E-1915: nsp_ndr type %xh unhandled\n", *ptype);
		return NDR_ERR_BAD_SWITCH;
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_union(NDR_PUSH *pndr, unsigned int flag,
    uint32_t type, const NSPRES_UNION *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_union_align(pndr, 5));
		TRY(ndr_push_uint32(pndr, type));
		TRY(ndr_push_union_align(pndr, 5));
		switch (type) {
		case RES_AND:
			TRY(nsp_ndr_push_restriction_and_or(pndr, FLAG_HEADER, &r->res_andor));
			break;
		case RES_OR:
			TRY(nsp_ndr_push_restriction_and_or(pndr, FLAG_HEADER, &r->res_andor));
			break;
		case RES_NOT:
			TRY(nsp_ndr_push_restriction_not(pndr, FLAG_HEADER, &r->res_not));
			break;
		case RES_CONTENT:
			TRY(nsp_ndr_push_restriction_content(pndr, FLAG_HEADER, &r->res_content));
			break;
		case RES_PROPERTY:
			TRY(nsp_ndr_push_restriction_property(pndr, FLAG_HEADER, &r->res_property));
			break;
		case RES_PROPCOMPARE:
			TRY(nsp_ndr_push_restriction_propcompare(pndr, &r->res_propcompare));
			break;
		case RES_BITMASK:
			TRY(nsp_ndr_push_restriction_bitmask(pndr, &r->res_bitmask));
			break;
		case RES_SIZE:
			TRY(nsp_ndr_push_restriction_size(pndr, &r->res_size));
			break;
		case RES_EXIST:
			TRY(nsp_ndr_push_restriction_exist(pndr, &r->res_exist));
			break;
		case RES_SUBRESTRICTION:
			TRY(nsp_ndr_push_restriction_sub(pndr, FLAG_HEADER, &r->res_sub));
			break;
		default:
			fprintf(stderr, "E-1916: nsp_ndr type %xh unhandled\n", type);
			return NDR_ERR_BAD_SWITCH;
		}
	}
	
	if (!(flag & FLAG_CONTENT))
		return EXT_ERR_SUCCESS;
	switch (type) {
	case RES_AND:
		TRY(nsp_ndr_push_restriction_and_or(pndr, FLAG_CONTENT, &r->res_andor));
		break;
	case RES_OR:
		TRY(nsp_ndr_push_restriction_and_or(pndr, FLAG_CONTENT, &r->res_andor));
		break;
	case RES_NOT:
		TRY(nsp_ndr_push_restriction_not(pndr, FLAG_CONTENT, &r->res_not));
		break;
	case RES_CONTENT:
		TRY(nsp_ndr_push_restriction_content(pndr, FLAG_CONTENT, &r->res_content));
		break;
	case RES_PROPERTY:
		TRY(nsp_ndr_push_restriction_property(pndr, FLAG_CONTENT, &r->res_property));
		break;
	case RES_PROPCOMPARE:
		break;
	case RES_BITMASK:
		break;
	case RES_SIZE:
		break;
	case RES_EXIST:
		break;
	case RES_SUBRESTRICTION:
		TRY(nsp_ndr_push_restriction_sub(pndr, FLAG_CONTENT, &r->res_sub));
		break;
	default:
		fprintf(stderr, "E-1917: nsp_ndr type %xh unhandled\n", type);
		return NDR_ERR_BAD_SWITCH;
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction(NDR_PULL *pndr, unsigned int flag, NSPRES *r)
{
	if (flag & FLAG_HEADER) {
		uint32_t type = RES_NULL;
		TRY(ndr_pull_align(pndr, 4));
		TRY(ndr_pull_uint32(pndr, &r->res_type));
		TRY(nsp_ndr_pull_restriction_union(pndr, FLAG_HEADER, &type, &r->res));
		if (r->res_type != type)
			return NDR_ERR_BAD_SWITCH;
		TRY(ndr_pull_trailer_align(pndr, 4));
	}
	
	if (!(flag & FLAG_CONTENT))
		return EXT_ERR_SUCCESS;
	uint32_t type = r->res_type;
	TRY(nsp_ndr_pull_restriction_union(pndr, FLAG_CONTENT, &type, &r->res));
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction(NDR_PUSH *pndr, unsigned int flag, const NSPRES *r)
{
	if (flag & FLAG_HEADER) {
		TRY(ndr_push_align(pndr, 4));
		TRY(ndr_push_uint32(pndr, r->res_type));
		TRY(nsp_ndr_push_restriction_union(pndr, FLAG_HEADER, r->res_type, &r->res));
		TRY(ndr_push_trailer_align(pndr, 4));
	}
	if (flag & FLAG_CONTENT)
		TRY(nsp_ndr_push_restriction_union(pndr, FLAG_CONTENT, r->res_type, &r->res));
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_pull_nspibind(NDR_PULL *pndr, NSPIBIND_IN *r)
{
	uint32_t ptr;
	

	TRY(ndr_pull_uint32(pndr, &r->flags));
	TRY(nsp_ndr_pull_stat(pndr, &r->stat));
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->pserver_guid = ndr_stack_anew<FLATUID>(NDR_STACK_IN);
		if (r->pserver_guid == nullptr)
			return NDR_ERR_ALLOC;
		TRY(nsp_ndr_pull_flatuid(pndr, r->pserver_guid));
	} else {
		r->pserver_guid = NULL;
	}
	
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspibind(NDR_PUSH *pndr, const NSPIBIND_OUT *r)
{
	TRY(ndr_push_unique_ptr(pndr, r->pserver_guid));
	if (r->pserver_guid != nullptr)
		TRY(nsp_ndr_push_flatuid(pndr, r->pserver_guid));
	TRY(ndr_push_context_handle(pndr, &r->handle));
	TRY(ndr_push_uint32(pndr, r->result));
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_pull_nspiunbind(NDR_PULL *pndr, NSPIUNBIND_IN *r)
{
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->reserved));
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspiunbind(NDR_PUSH *pndr, const NSPIUNBIND_OUT *r)
{
	TRY(ndr_push_context_handle(pndr, &r->handle));
	TRY(ndr_push_uint32(pndr, r->result));
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_pull_nspiupdatestat(NDR_PULL *pndr, NSPIUPDATESTAT_IN *r)
{
	uint32_t ptr;
	
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->reserved));
	TRY(nsp_ndr_pull_stat(pndr, &r->stat));
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->pdelta = ndr_stack_anew<int32_t>(NDR_STACK_IN);
		if (r->pdelta == nullptr)
			return NDR_ERR_ALLOC;
		TRY(ndr_pull_int32(pndr, r->pdelta));
	} else {
		r->pdelta = NULL;
	}
	
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspiupdatestat(NDR_PUSH *pndr, const NSPIUPDATESTAT_OUT *r)
{
	TRY(nsp_ndr_push_stat(pndr, &r->stat));
	TRY(ndr_push_unique_ptr(pndr, r->pdelta));
	if (r->pdelta != nullptr)
		TRY(ndr_push_int32(pndr, *r->pdelta));
	TRY(ndr_push_uint32(pndr, r->result));
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_pull_nspiqueryrows(NDR_PULL *pndr, NSPIQUERYROWS_IN *r)
{
	uint32_t ptr;
	uint32_t size;
	
	
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->flags));
	TRY(nsp_ndr_pull_stat(pndr, &r->stat));
	TRY(ndr_pull_uint32(pndr, &r->table_count));
	if (r->table_count > 100000)
		return NDR_ERR_RANGE;
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		TRY(ndr_pull_ulong(pndr, &size));
		if (size != r->table_count)
			return NDR_ERR_ARRAY_SIZE;
		r->ptable = ndr_stack_anew<uint32_t>(NDR_STACK_IN, size);
		if (r->ptable == nullptr)
			return NDR_ERR_ALLOC;
		for (size_t cnt = 0; cnt < size; ++cnt)
			TRY(ndr_pull_uint32(pndr, &r->ptable[cnt]));
	} else {
		r->ptable = NULL;
	}
	TRY(ndr_pull_uint32(pndr, &r->count));
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->pproptags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->pproptags == nullptr)
			return NDR_ERR_ALLOC;
		TRY(nsp_ndr_pull_proptag_array(pndr, r->pproptags));
	} else {
		r->pproptags = NULL;
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspiqueryrows(NDR_PUSH *pndr, const NSPIQUERYROWS_OUT *r)
{
	TRY(nsp_ndr_push_stat(pndr, &r->stat));
	TRY(ndr_push_unique_ptr(pndr, r->prows));
	if (r->prows != nullptr)
		TRY(nsp_ndr_push_proprow_set(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows));
	TRY(ndr_push_uint32(pndr, r->result));
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_pull_nspiseekentries(NDR_PULL *pndr, NSPISEEKENTRIES_IN *r)
{
	uint32_t ptr;
	
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->reserved));
	TRY(nsp_ndr_pull_stat(pndr, &r->stat));
	TRY(nsp_ndr_pull_property_value(pndr, FLAG_HEADER|FLAG_CONTENT, &r->target));
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->ptable = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->ptable == nullptr)
			return NDR_ERR_ALLOC;
		TRY(nsp_ndr_pull_proptag_array(pndr, r->ptable));
	} else {
		r->ptable = NULL;
	}
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->pproptags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->pproptags == nullptr)
			return NDR_ERR_ALLOC;
		TRY(nsp_ndr_pull_proptag_array(pndr, r->pproptags));
	} else {
		r->pproptags = NULL;
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspiseekentries(NDR_PUSH *pndr, const NSPISEEKENTRIES_OUT *r)
{
	TRY(nsp_ndr_push_stat(pndr, &r->stat));
	TRY(ndr_push_unique_ptr(pndr, r->prows));
	if (r->prows != nullptr)
		TRY(nsp_ndr_push_proprow_set(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows));
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspigetmatches(NDR_PULL *pndr, NSPIGETMATCHES_IN *r)
{
	uint32_t ptr;

	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->reserved1));
	TRY(nsp_ndr_pull_stat(pndr, &r->stat));
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->preserved = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->preserved == nullptr)
			return NDR_ERR_ALLOC;
		TRY(nsp_ndr_pull_proptag_array(pndr, r->preserved));
	} else {
		r->preserved = NULL;
	}
	TRY(ndr_pull_uint32(pndr, &r->reserved2));
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->pfilter = ndr_stack_anew<NSPRES>(NDR_STACK_IN);
		if (r->pfilter == nullptr)
			return NDR_ERR_ALLOC;
		TRY(nsp_ndr_pull_restriction(pndr, FLAG_HEADER|FLAG_CONTENT, r->pfilter));
	} else {
		r->pfilter = NULL;
	}
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->ppropname = ndr_stack_anew<NSP_PROPNAME>(NDR_STACK_IN);
		if (r->ppropname == nullptr)
			return NDR_ERR_ALLOC;
		TRY(nsp_ndr_pull_property_name(pndr, FLAG_HEADER|FLAG_CONTENT, r->ppropname));
	} else {
		r->ppropname = NULL;
	}
	
	TRY(ndr_pull_uint32(pndr, &r->requested));
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->pproptags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->pproptags == nullptr)
			return NDR_ERR_ALLOC;
		TRY(nsp_ndr_pull_proptag_array(pndr, r->pproptags));
	} else {
		r->pproptags = NULL;
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspigetmatches(NDR_PUSH *pndr, const NSPIGETMATCHES_OUT *r)
{
	TRY(nsp_ndr_push_stat(pndr, &r->stat));
	TRY(ndr_push_unique_ptr(pndr, r->poutmids));
	if (r->poutmids != nullptr)
		TRY(nsp_ndr_push_proptag_array(pndr, r->poutmids));
	TRY(ndr_push_unique_ptr(pndr, r->prows));
	if (r->prows != nullptr)
		TRY(nsp_ndr_push_proprow_set(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows));
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspiresortrestriction(NDR_PULL *pndr, NSPIRESORTRESTRICTION_IN *r)
{
	uint32_t ptr;
	
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->reserved));
	TRY(nsp_ndr_pull_stat(pndr, &r->stat));
	TRY(nsp_ndr_pull_proptag_array(pndr, &r->inmids));
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->poutmids = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->poutmids == nullptr)
			return NDR_ERR_ALLOC;
		TRY(nsp_ndr_pull_proptag_array(pndr, r->poutmids));
	} else {
		r->poutmids = NULL;
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspiresortrestriction(NDR_PUSH *pndr, const NSPIRESORTRESTRICTION_OUT *r)
{
	TRY(nsp_ndr_push_stat(pndr, &r->stat));
	TRY(ndr_push_unique_ptr(pndr, r->poutmids));
	if (r->poutmids != nullptr)
		TRY(nsp_ndr_push_proptag_array(pndr, r->poutmids));
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspidntomid(NDR_PULL *pndr, NSPIDNTOMID_IN *r)
{
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->reserved));
	return nsp_ndr_pull_strings_array(pndr, FLAG_HEADER|FLAG_CONTENT, &r->names);
}

int nsp_ndr_push_nspidntomid(NDR_PUSH *pndr, const NSPIDNTOMID_OUT *r)
{
	TRY(ndr_push_unique_ptr(pndr, r->poutmids));
	if (r->poutmids != nullptr)
		TRY(nsp_ndr_push_proptag_array(pndr, r->poutmids));
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspigetproplist(NDR_PULL *pndr, NSPIGETPROPLIST_IN *r)
{
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->flags));
	TRY(ndr_pull_uint32(pndr, &r->mid));
	return ndr_pull_uint32(pndr, &r->codepage);
}

int nsp_ndr_push_nspigetproplist(NDR_PUSH *pndr, const NSPIGETPROPLIST_OUT *r)
{
	TRY(ndr_push_unique_ptr(pndr, r->pproptags));
	if (r->pproptags != nullptr)
		TRY(nsp_ndr_push_proptag_array(pndr, r->pproptags));
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspigetprops(NDR_PULL *pndr, NSPIGETPROPS_IN *r)
{
	uint32_t ptr;
	
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->flags));
	TRY(nsp_ndr_pull_stat(pndr, &r->stat));
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->pproptags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->pproptags == nullptr)
			return NDR_ERR_ALLOC;
		TRY(nsp_ndr_pull_proptag_array(pndr, r->pproptags));
	} else {
		r->pproptags = NULL;
	}

	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspigetprops(NDR_PUSH *pndr, const NSPIGETPROPS_OUT *r)
{
	TRY(ndr_push_unique_ptr(pndr, r->prows));
	if (r->prows != nullptr)
		TRY(nsp_ndr_push_property_row(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows));
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspicomparemids(NDR_PULL *pndr, NSPICOMPAREMIDS_IN *r)
{
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->reserved));
	TRY(nsp_ndr_pull_stat(pndr, &r->stat));
	TRY(ndr_pull_uint32(pndr, &r->mid1));
	return ndr_pull_uint32(pndr, &r->mid2);
}

int nsp_ndr_push_nspicomparemids(NDR_PUSH *pndr, const NSPICOMPAREMIDS_OUT *r)
{
	TRY(ndr_push_uint32(pndr, r->result));
	return ndr_push_uint32(pndr, r->result1);
}

int nsp_ndr_pull_nspimodprops(NDR_PULL *pndr, NSPIMODPROPS_IN *r)
{
	uint32_t ptr;
	
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->reserved));
	TRY(nsp_ndr_pull_stat(pndr, &r->stat));
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->pproptags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->pproptags == nullptr)
			return NDR_ERR_ALLOC;
		TRY(nsp_ndr_pull_proptag_array(pndr, r->pproptags));
	} else {
		r->pproptags = NULL;
	}
	
	return nsp_ndr_pull_property_row(pndr, FLAG_HEADER|FLAG_CONTENT, &r->row);
}

int nsp_ndr_push_nspimodprops(NDR_PUSH *pndr, const NSPIMODPROPS_OUT *r)
{
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspigetspecialtable(NDR_PULL *pndr, NSPIGETSPECIALTABLE_IN *r)
{
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->flags));
	TRY(nsp_ndr_pull_stat(pndr, &r->stat));
	return ndr_pull_uint32(pndr, &r->version);
}

int nsp_ndr_push_nspigetspecialtable(NDR_PUSH *pndr, const NSPIGETSPECIALTABLE_OUT *r)
{
	TRY(ndr_push_uint32(pndr, r->version));
	TRY(ndr_push_unique_ptr(pndr, r->prows));
	if (r->prows != nullptr)
		TRY(nsp_ndr_push_proprow_set(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows));
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspigettemplateinfo(NDR_PULL *pndr, NSPIGETTEMPLATEINFO_IN *r)
{
	uint32_t ptr;
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->flags));
	TRY(ndr_pull_uint32(pndr, &r->type));
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		TRY(ndr_pull_ulong(pndr, &size));
		TRY(ndr_pull_ulong(pndr, &offset));
		TRY(ndr_pull_ulong(pndr, &length));
		if (offset != 0 || length > size)
			return NDR_ERR_ARRAY_SIZE;
		TRY(ndr_pull_check_string(pndr, length, sizeof(uint8_t)));
		r->pdn = ndr_stack_anew<char>(NDR_STACK_IN, length + 1);
		if (r->pdn == nullptr)
			return NDR_ERR_ALLOC;
		TRY(ndr_pull_string(pndr, r->pdn, length));
	} else {
		r->pdn = NULL;
	}
	TRY(ndr_pull_uint32(pndr, &r->codepage));
	return ndr_pull_uint32(pndr, &r->locale_id);
}

int nsp_ndr_push_nspigettemplateinfo(NDR_PUSH *pndr, const NSPIGETTEMPLATEINFO_OUT *r)
{
	TRY(ndr_push_unique_ptr(pndr, r->pdata));
	if (r->pdata != nullptr)
		TRY(nsp_ndr_push_property_row(pndr, FLAG_HEADER|FLAG_CONTENT, r->pdata));
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspimodlinkatt(NDR_PULL *pndr, NSPIMODLINKATT_IN *r)
{
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->flags));
	TRY(ndr_pull_uint32(pndr, &r->proptag));
	TRY(ndr_pull_uint32(pndr, &r->mid));
	return nsp_ndr_pull_binary_array(pndr, FLAG_HEADER|FLAG_CONTENT, &r->entry_ids);
}

int nsp_ndr_push_nspimodlinkatt(NDR_PUSH *pndr, const NSPIMODLINKATT_OUT *r)
{
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspiquerycolumns(NDR_PULL *pndr, NSPIQUERYCOLUMNS_IN *r)
{
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->reserved));
	return ndr_pull_uint32(pndr, &r->flags);
}

int nsp_ndr_push_nspiquerycolumns(NDR_PUSH *pndr, const NSPIQUERYCOLUMNS_OUT *r)
{
	TRY(ndr_push_unique_ptr(pndr, r->pcolumns));
	if (r->pcolumns != nullptr)
		TRY(nsp_ndr_push_proptag_array(pndr, r->pcolumns));
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspiresolvenames(NDR_PULL *pndr, NSPIRESOLVENAMES_IN *r)
{
	uint32_t ptr;
	
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->reserved));
	TRY(nsp_ndr_pull_stat(pndr, &r->stat));
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->pproptags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->pproptags == nullptr)
			return NDR_ERR_ALLOC;
		TRY(nsp_ndr_pull_proptag_array(pndr, r->pproptags));
	} else {
		r->pproptags = NULL;
	}
	return nsp_ndr_pull_strings_array(pndr, FLAG_HEADER|FLAG_CONTENT, &r->strs);
	
}

int nsp_ndr_push_nspiresolvenames(NDR_PUSH *pndr, const NSPIRESOLVENAMES_OUT *r)
{
	TRY(ndr_push_unique_ptr(pndr, r->pmids));
	if (r->pmids != nullptr)
		TRY(nsp_ndr_push_proptag_array(pndr, r->pmids));
	TRY(ndr_push_unique_ptr(pndr, r->prows));
	if (r->prows != nullptr)
		TRY(nsp_ndr_push_proprow_set(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows));
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspiresolvenamesw(NDR_PULL *pndr, NSPIRESOLVENAMESW_IN *r)
{
	uint32_t ptr;
	
	TRY(ndr_pull_context_handle(pndr, &r->handle));
	TRY(ndr_pull_uint32(pndr, &r->reserved));
	TRY(nsp_ndr_pull_stat(pndr, &r->stat));
	TRY(ndr_pull_generic_ptr(pndr, &ptr));
	if (0 != ptr) {
		r->pproptags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (r->pproptags == nullptr)
			return NDR_ERR_ALLOC;
		TRY(nsp_ndr_pull_proptag_array(pndr, r->pproptags));
	} else {
		r->pproptags = NULL;
	}
	
	return nsp_ndr_pull_wstrings_array(pndr, FLAG_HEADER|FLAG_CONTENT, &r->strs);
}

int nsp_ndr_push_nspiresolvenamesw(NDR_PUSH *pndr, const NSPIRESOLVENAMESW_OUT *r)
{
	TRY(ndr_push_unique_ptr(pndr, r->pmids));
	if (r->pmids != nullptr)
		TRY(nsp_ndr_push_proptag_array(pndr, r->pmids));
	TRY(ndr_push_unique_ptr(pndr, r->prows));
	if (r->prows != nullptr)
		TRY(nsp_ndr_push_proprow_set(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows));
	return ndr_push_uint32(pndr, r->result);
}
