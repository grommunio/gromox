// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2003 Andrew Tridgell
// This file is part of Gromox.
#include <cassert>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/ndr.hpp>
#define TRY(expr) do { int klfdv = (expr); if (klfdv != NDR_ERR_SUCCESS) return klfdv; } while (false)
#define NDR_BE(pndr) ((pndr->flags & NDR_FLAG_BIGENDIAN) != 0)

int ndr_pull_advance(NDR_PULL *pndr, uint32_t size)
{
	pndr->offset += size;
	return pndr->offset > pndr->data_size ? NDR_ERR_BUFSIZE : NDR_ERR_SUCCESS;
}

void ndr_set_flags(uint32_t *pflags, uint32_t new_flags)
{
	if (new_flags & NDR_ALIGN_FLAGS) {
		/* Ensure we only have the passed-in
		   align flag set in the new_flags,
		   remove any old align flag. */
		(*pflags) &= ~NDR_ALIGN_FLAGS;
	}
	if (new_flags & NDR_FLAG_NO_RELATIVE_REVERSE) {
		(*pflags) &= ~NDR_FLAG_RELATIVE_REVERSE;
	}
	(*pflags) |= new_flags;
}

uint32_t ndr_pull_get_ptrcnt(const NDR_PULL *pndr)
{
	return pndr->ptr_count;
}

static size_t ndr_align_size(uint32_t offset, size_t n)
{
	if (!(offset & (n - 1)))
		return 0;
	return n - (offset & (n - 1));
}


void ndr_pull_init(NDR_PULL *pndr, const void *pdata,
	uint32_t data_size, uint32_t flags)
{
	pndr->data = static_cast<const uint8_t *>(pdata);
	pndr->data_size = data_size;
	pndr->offset = 0;
	pndr->flags = flags;
	pndr->ptr_count = 0;
}

static bool ndr_pull_check_padding(NDR_PULL *pndr, size_t n)
{
	size_t ofs2;

	ofs2 = (pndr->offset + (n - 1)) & ~(n - 1);
	for (size_t i = pndr->offset; i < ofs2; ++i)
		if (pndr->data[i] != 0)
			return false;
	return true;
}

int ndr_pull_align(NDR_PULL *pndr, size_t size)
{
	if (5 == size) {
		size = (pndr->flags & NDR_FLAG_NDR64) ? 8 : 4;
	} else if (3 == size) {
		size = (pndr->flags & NDR_FLAG_NDR64) ? 4 : 2;
	}
	
	if (!(pndr->flags & NDR_FLAG_NOALIGN)) {
		if (pndr->flags & NDR_FLAG_PAD_CHECK) {
			if (!ndr_pull_check_padding(pndr, size))
				return NDR_ERR_PADDING;
		}
		pndr->offset = (pndr->offset + (size - 1)) & ~(size - 1);
	}
	if (pndr->offset > pndr->data_size) {
		return NDR_ERR_BUFSIZE;
	}
	return NDR_ERR_SUCCESS;
}

int ndr_pull_union_align(NDR_PULL *pndr, size_t size)
{
	/* MS-RPCE section 2.2.5.3.4.4 */
	if (pndr->flags & NDR_FLAG_NDR64) {
		return pndr->align(size);
	}
	return NDR_ERR_SUCCESS;
}

int ndr_pull_trailer_align(NDR_PULL *pndr, size_t size)
{
	/* MS-RPCE section 2.2.5.3.4.1 */
	if (pndr->flags & NDR_FLAG_NDR64) {
		return pndr->align(size);
	}
	return NDR_ERR_SUCCESS;
}


int ndr_pull_string(NDR_PULL *pndr, char *buff, uint32_t inbytes)
{
	if (0 == inbytes) {
		buff[0] = '\0';
		return NDR_ERR_SUCCESS;
	}

	if (pndr->data_size < inbytes ||
		pndr->offset + inbytes > pndr->data_size) {
		return NDR_ERR_BUFSIZE;
	}
	
	memcpy(buff, pndr->data + pndr->offset, inbytes);
	buff[inbytes] = '\0';
	
	return ndr_pull_advance(pndr, inbytes);
}

int ndr_pull_uint8(NDR_PULL *pndr, uint8_t *v)
{
	if (pndr->data_size < 1 || pndr->offset + 1 > pndr->data_size) {
		return NDR_ERR_BUFSIZE;
	}
	*v = pndr->data[pndr->offset];
	pndr->offset += 1;
	return NDR_ERR_SUCCESS;
}

int ndr_pull_uint16(NDR_PULL *pndr, uint16_t *v)
{
	TRY(pndr->align(2));
	if (pndr->data_size < 2 || pndr->offset + 2 > pndr->data_size) {
		return NDR_ERR_BUFSIZE;
	}
	auto r = &pndr->data[pndr->offset];
	*v = NDR_BE(pndr) ? be16p_to_cpu(r) : le16p_to_cpu(r);
	pndr->offset += 2;
	return NDR_ERR_SUCCESS;
}

int ndr_pull_int32(NDR_PULL *pndr, int32_t *v)
{
	return pndr->g_uint32(reinterpret_cast<uint32_t *>(v));
}

int ndr_pull_uint32(NDR_PULL *pndr, uint32_t *v)
{
	TRY(pndr->align(4));
	if (pndr->data_size < 4 || pndr->offset + 4 > pndr->data_size) {
		return NDR_ERR_BUFSIZE;
	}
	auto r = &pndr->data[pndr->offset];
	*v = NDR_BE(pndr) ? be32p_to_cpu(r) : le32p_to_cpu(r);
	pndr->offset += 4;
	return NDR_ERR_SUCCESS;
}

int ndr_pull_uint64(NDR_PULL *pndr, uint64_t *v)
{
	TRY(pndr->align(8));
	if (pndr->data_size < 8 || pndr->offset + 8 > pndr->data_size) {
		return NDR_ERR_BUFSIZE;
	}
	auto r = &pndr->data[pndr->offset];
	*v = NDR_BE(pndr) ? be64p_to_cpu(r) : le64p_to_cpu(r);
	pndr->offset += 8;
	return NDR_ERR_SUCCESS;
}

int ndr_pull_ulong(NDR_PULL *pndr, uint32_t *v)
{
	uint64_t v64;
	
	if (pndr->flags & NDR_FLAG_NDR64) {
		TRY(pndr->g_uint64(&v64));
		*v = v64;
		if (v64 != *v) {
			return NDR_ERR_NDR64;
		}
		return NDR_ERR_SUCCESS;
	}
	return pndr->g_uint32(v);
}

static int ndr_pull_bytes(NDR_PULL *pndr, uint8_t *data, uint32_t n)
{
	
	if (pndr->data_size < n || pndr->offset + n > pndr->data_size) {
		return NDR_ERR_BUFSIZE;
	}
	
	memcpy(data, pndr->data + pndr->offset, n);
	pndr->offset += n;
	return NDR_ERR_SUCCESS;
}

int ndr_pull_array_uint8(NDR_PULL *pndr, uint8_t *data, uint32_t n)
{
	return ndr_pull_bytes(pndr, data, n);
}

int ndr_pull_guid(NDR_PULL *pndr, GUID *r)
{
	TRY(pndr->align(4));
	TRY(pndr->g_uint32(&r->time_low));
	TRY(pndr->g_uint16(&r->time_mid));
	TRY(pndr->g_uint16(&r->time_hi_and_version));
	TRY(ndr_pull_array_uint8(pndr, r->clock_seq, 2));
	TRY(ndr_pull_array_uint8(pndr, r->node, 6));
	TRY(pndr->trailer_align(4));
	return NDR_ERR_SUCCESS;
}


int ndr_pull_syntax_id(NDR_PULL *pndr, SYNTAX_ID *r)
{
	TRY(pndr->align(4));
	TRY(ndr_pull_guid(pndr, &r->uuid));
	TRY(pndr->g_uint32(&r->version));
	TRY(pndr->trailer_align(4));
	return NDR_ERR_SUCCESS;
}

int ndr_pull_data_blob(NDR_PULL *pndr, DATA_BLOB *pblob)
{
	uint32_t length;

	length = 0;
	if (pndr->flags & NDR_FLAG_REMAINING) {
		length = pndr->data_size - pndr->offset;
	} else if (pndr->flags & (NDR_ALIGN_FLAGS & ~NDR_FLAG_NOALIGN)) {
		if (pndr->flags & NDR_FLAG_ALIGN2) {
			length = ndr_align_size(pndr->offset, 2);
		} else if (pndr->flags & NDR_FLAG_ALIGN4) {
			length = ndr_align_size(pndr->offset, 4);
		} else if (pndr->flags & NDR_FLAG_ALIGN8) {
			length = ndr_align_size(pndr->offset, 8);
		}
		if (pndr->data_size - pndr->offset < length) {
			length = pndr->data_size - pndr->offset;
		}
	} else {
		TRY(pndr->g_uint32(&length));
	}
	if (pndr->data_size < length ||
		pndr->offset + length > pndr->data_size) {
		return NDR_ERR_BUFSIZE;
	}
	pblob->pb = gromox::me_alloc<uint8_t>(length);
	if (pblob->pb == nullptr)
		return NDR_ERR_ALLOC;
	memcpy(pblob->pb, &pndr->data[pndr->offset], length);
	pblob->cb = length;
	pndr->offset += length;
	return NDR_ERR_SUCCESS;
}

/* free memory internal of blob except of blob itself */
void ndr_free_data_blob(DATA_BLOB *pblob)
{
	if (pblob->pb != nullptr) {
		free(pblob->pb);
		pblob->pb = nullptr;
	}
	pblob->cb = 0;
}

int ndr_pull_check_string(NDR_PULL *pndr,
	uint32_t count, uint32_t element_size)
{
	uint32_t i;
	uint32_t saved_offset;

	saved_offset = pndr->offset;
	TRY(ndr_pull_advance(pndr, (count - 1) * element_size));
	if (pndr->data_size < element_size ||
		pndr->offset + element_size > pndr->data_size) {
		return NDR_ERR_BUFSIZE;
	}
	for (i=0; i<element_size; i++) {
		if (0 != pndr->data[pndr->offset + i]) {
			pndr->offset = saved_offset;
			return NDR_ERR_ARRAY_SIZE;
		}
	}
	
	pndr->offset = saved_offset;
	return NDR_ERR_SUCCESS;
}

int ndr_pull_generic_ptr(NDR_PULL *pndr, uint32_t *v)
{
	auto status = pndr->g_ulong(v);
	if (status == NDR_ERR_SUCCESS && *v != 0)
		pndr->ptr_count ++;
	return NDR_ERR_SUCCESS;
}

int ndr_pull_context_handle(NDR_PULL *pndr, CONTEXT_HANDLE *r)
{
	TRY(pndr->align(4));
	TRY(pndr->g_uint32(&r->handle_type));
	TRY(ndr_pull_guid(pndr, &r->guid));
	TRY(pndr->trailer_align(4));
	return NDR_ERR_SUCCESS;
}

void ndr_push_set_ptrcnt(NDR_PUSH *pndr, uint32_t ptr_count)
{
	pndr->ptr_count = ptr_count;
}

void ndr_push_init(NDR_PUSH *pndr, void *pdata,
	uint32_t alloc_size, uint32_t flags)
{
	pndr->data = static_cast<uint8_t *>(pdata);
	pndr->alloc_size = alloc_size;
	pndr->flags = flags;
	pndr->offset = 0;
	pndr->ptr_count = 0;
	double_list_init(&pndr->full_ptr_list);
}

void ndr_push_destroy(NDR_PUSH *pndr)
{
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(&pndr->full_ptr_list)) != nullptr)
		free(pnode->pdata);
	double_list_free(&pndr->full_ptr_list);
	pndr->data = NULL;
	pndr->alloc_size = 0;
	pndr->flags = 0;
	pndr->offset = 0;
}

static bool ndr_push_check_overflow(NDR_PUSH *pndr, uint32_t extra_size)
{
	uint32_t size;
	
	size = extra_size + pndr->offset;
	if (size > pndr->alloc_size) {
		/* overflow */
		return false;
	}
	/* not overflow */
	return true;
}

static int ndr_push_bytes(NDR_PUSH *pndr, const void *pdata, uint32_t n)
{
	if (n == 0)
		return NDR_ERR_SUCCESS;
	if (!ndr_push_check_overflow(pndr, n))
		return NDR_ERR_BUFSIZE;
	if (pdata == nullptr)
		memset(pndr->data + pndr->offset, 0, n);
	else
		memcpy(pndr->data + pndr->offset, pdata, n);
	pndr->offset += n;
	return NDR_ERR_SUCCESS;
}

int ndr_push_uint8(NDR_PUSH *pndr, uint8_t v)
{
	if (!ndr_push_check_overflow(pndr, 1))
		return NDR_ERR_BUFSIZE;
	pndr->data[pndr->offset] = v;
	pndr->offset += 1;
	return NDR_ERR_SUCCESS;
}

int ndr_push_align(NDR_PUSH *pndr, size_t size)
{
	uint32_t pad;
	
	if (size == 5) {
		size = (pndr->flags & NDR_FLAG_NDR64) ? 8 : 4;
	} else if (size == 3) {
		size = (pndr->flags & NDR_FLAG_NDR64) ? 4 : 2;
	}
	if (!(pndr->flags & NDR_FLAG_NOALIGN)) {
		pad = ((pndr->offset + (size - 1)) & ~(size - 1)) - pndr->offset;
		while (pad--) {
			TRY(pndr->p_uint8(0));
		}
	}
	return NDR_ERR_SUCCESS;
}

int ndr_push_union_align(NDR_PUSH *pndr, size_t size)
{
	if (pndr->flags & NDR_FLAG_NDR64) {
		return ndr_push_align(pndr, size);
	}
	return NDR_ERR_SUCCESS;
}

int ndr_push_trailer_align(NDR_PUSH *pndr, size_t size)
{
	if (pndr->flags & NDR_FLAG_NDR64) {
		return ndr_push_align(pndr, size);
	}
	return NDR_ERR_SUCCESS;
}

int ndr_push_uint16(NDR_PUSH *pndr, uint16_t v)
{
	TRY(pndr->align(2));
	if (!ndr_push_check_overflow(pndr, 2))
		return NDR_ERR_BUFSIZE;
	auto r = &pndr->data[pndr->offset];
	NDR_BE(pndr) ? cpu_to_be16p(r, v) : cpu_to_le16p(r, v);
	pndr->offset += 2;
	return NDR_ERR_SUCCESS;
}

int ndr_push_uint32(NDR_PUSH *pndr, uint32_t v)
{
	TRY(pndr->align(4));
	if (!ndr_push_check_overflow(pndr, 4))
		return NDR_ERR_BUFSIZE;
	auto r = &pndr->data[pndr->offset];
	NDR_BE(pndr) ? cpu_to_be32p(r, v) : cpu_to_le32p(r, v);
	pndr->offset += 4;
	return NDR_ERR_SUCCESS;
}

int ndr_push_uint64(NDR_PUSH *pndr, uint64_t v)
{
	static_assert(CHAR_BIT == 8, "");
	TRY(pndr->align(8));
	if (!ndr_push_check_overflow(pndr, 8))
		return NDR_ERR_BUFSIZE;
	auto r = &pndr->data[pndr->offset];
	NDR_BE(pndr) ? cpu_to_be64p(r, v) : cpu_to_le64p(r, v);
	pndr->offset += 8;
	return NDR_ERR_SUCCESS;
}

int ndr_push_ulong(NDR_PUSH *pndr, uint32_t v)
{
	return (pndr->flags & NDR_FLAG_NDR64) ? pndr->p_uint64(v) : pndr->p_uint32(v);
}

int ndr_push_array_uint8(NDR_PUSH *pndr, const uint8_t *data, uint32_t n)
{
	return ndr_push_bytes(pndr, data, n);
}

/*
 * Push a DATA_BLOB onto the wire.
 * 1) When called with NDR_FLAG_ALIGN* alignment flags set, push padding
 *    bytes _only_. The length is determined by the alignment required and the
 *    current ndr offset.
 * 2) When called with the NDR_FLAG_REMAINING flag, push the byte array to
 *    the ndr buffer.
 * 3) Otherwise, push a uint32 length _and_ a corresponding byte array to the
 *    ndr buffer.
 */
int ndr_push_data_blob(NDR_PUSH *pndr, DATA_BLOB blob)
{
	int length = 0;
	uint8_t buff[8];
	
	if (pndr->flags & NDR_FLAG_REMAINING) {
		/* nothing to do */
	} else if (pndr->flags & (NDR_ALIGN_FLAGS & ~NDR_FLAG_NOALIGN)) {
		if (pndr->flags & NDR_FLAG_ALIGN2) {
			length = ndr_align_size(pndr->offset, 2);
		} else if (pndr->flags & NDR_FLAG_ALIGN4) {
			length = ndr_align_size(pndr->offset, 4);
		} else if (pndr->flags & NDR_FLAG_ALIGN8) {
			length = ndr_align_size(pndr->offset, 8);
		}
		memset(buff, 0, length);
		return pndr->p_uint8_a(buff, length);
	} else {
		TRY(pndr->p_uint32(blob.cb));
	}
	assert(blob.pb != nullptr || blob.cb == 0);
	TRY(pndr->p_uint8_a(blob.pb, blob.cb));
	return NDR_ERR_SUCCESS;
}

int ndr_push_string(NDR_PUSH *pndr, const char *var, uint32_t required)
{	
	if (!ndr_push_check_overflow(pndr, required))
		return NDR_ERR_BUFSIZE;
	memcpy(pndr->data + pndr->offset, var, required);
	pndr->offset += required;
	return NDR_ERR_SUCCESS;
}

int ndr_push_guid(NDR_PUSH *pndr, const GUID *r)
{
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(r->time_low));
	TRY(pndr->p_uint16(r->time_mid));
	TRY(pndr->p_uint16(r->time_hi_and_version));
	TRY(pndr->p_uint8_a(r->clock_seq, 2));
	TRY(pndr->p_uint8_a(r->node, 6));
	return pndr->trailer_align(4);
}

int ndr_push_syntax_id(NDR_PUSH *pndr, const SYNTAX_ID *r)
{
	TRY(pndr->align(4));
	TRY(pndr->p_guid(r->uuid));
	TRY(pndr->p_uint32(r->version));
	TRY(pndr->trailer_align(4));
	return NDR_ERR_SUCCESS;
}

int ndr_push_zero(NDR_PUSH *pndr, uint32_t n)
{
	if (!ndr_push_check_overflow(pndr, n))
		return NDR_ERR_BUFSIZE;
	memset(pndr->data + pndr->offset, 0, n);
	pndr->offset += n;
	return NDR_ERR_SUCCESS;
}

int ndr_push_unique_ptr(NDR_PUSH *pndr, const void *p)
{
	uint32_t ptr;
	
	ptr = 0;
	if (NULL != p) {
		ptr = pndr->ptr_count * 4;
		ptr |= 0x00020000;
		pndr->ptr_count++;
	}
	return pndr->p_ulong(ptr);
}

int ndr_push_context_handle(NDR_PUSH *pndr, const CONTEXT_HANDLE *r)
{
	TRY(pndr->align(4));
	TRY(pndr->p_uint32(r->handle_type));
	TRY(pndr->p_guid(r->guid));
	TRY(pndr->trailer_align(4));
	return NDR_ERR_SUCCESS;
}
