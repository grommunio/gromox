// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <memory>
#include <gromox/mapidefs.h>
#include <gromox/endian_macro.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/util.hpp>
#include <cstdlib>
#include <cstring>
#define TRY(expr) do { int klfdv = (expr); if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)
#define EXT_SVAL(pext, ofs)			SVAL(pext->data,ofs)
#define EXT_IVAL(pext, ofs)			IVAL(pext->data,ofs)
#define EXT_IVALS(pext, ofs)		IVALS(pext->data,ofs)
#define EXT_SSVAL(pext, ofs, v)		SSVAL(pext->data,ofs,v)
#define EXT_SIVAL(pext, ofs, v)		SIVAL(pext->data,ofs,v)
#define EXT_SIVALS(pext, ofs, v)	SIVALS(pext->data,ofs,v)

#define GROWING_BLOCK_SIZE				0x80000

void ext_buffer_pull_init(EXT_PULL *pext, const void *pdata,
	uint32_t data_size, EXT_BUFFER_ALLOC alloc, uint32_t flags)
{
	pext->data = static_cast<const uint8_t *>(pdata);
	pext->data_size = data_size;
	pext->alloc = alloc;
	pext->offset = 0;
	pext->flags = flags;
}

void ext_buffer_pull_free(EXT_PULL *pext)
{
	/* do nothing */
}

int ext_buffer_pull_advance(EXT_PULL *pext, uint32_t size)
{
	pext->offset += size;
	if (pext->offset > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_rpc_header_ext(EXT_PULL *pext, RPC_HEADER_EXT *r)
{
	TRY(ext_buffer_pull_uint16(pext, &r->version));
	TRY(ext_buffer_pull_uint16(pext, &r->flags));
	TRY(ext_buffer_pull_uint16(pext, &r->size));
	return ext_buffer_pull_uint16(pext, &r->size_actual);
}

int ext_buffer_pull_int8(EXT_PULL *pext, int8_t *v)
{
	if (pext->data_size < sizeof(int8_t) ||
		pext->offset + sizeof(int8_t) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	*v = (int8_t)CVAL(pext->data, pext->offset);
	pext->offset += sizeof(int8_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_uint8(EXT_PULL *pext, uint8_t *v)
{
	if (pext->data_size < sizeof(uint8_t) ||
		pext->offset + sizeof(uint8_t) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	*v = CVAL(pext->data, pext->offset);
	pext->offset += sizeof(uint8_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_int16(EXT_PULL *pext, int16_t *v)
{
	if (pext->data_size < sizeof(int16_t) ||
		pext->offset + sizeof(int16_t) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	*v = (int16_t)EXT_SVAL(pext, pext->offset);
	pext->offset += sizeof(int16_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_uint16(EXT_PULL *pext, uint16_t *v)
{
	if (pext->data_size < sizeof(uint16_t) ||
		pext->offset + sizeof(uint16_t) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	*v = EXT_SVAL(pext, pext->offset);
	pext->offset += sizeof(uint16_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_int32(EXT_PULL *pext, int32_t *v)
{
	if (pext->data_size < sizeof(int32_t) ||
		pext->offset + sizeof(int32_t) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	*v = EXT_IVALS(pext, pext->offset);
	pext->offset += sizeof(int32_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_uint32(EXT_PULL *pext, uint32_t *v)
{
	if (pext->data_size < sizeof(uint32_t) ||
		pext->offset + sizeof(uint32_t) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	*v = EXT_IVAL(pext, pext->offset);
	pext->offset += sizeof(uint32_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_int64(EXT_PULL *pext, int64_t *v)
{
	if (pext->data_size < sizeof(int64_t) ||
		pext->offset + sizeof(int64_t) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	*v = EXT_IVAL(pext, pext->offset);
	*v |= (int64_t)(EXT_IVAL(pext, pext->offset+4)) << 32;
	pext->offset += sizeof(int64_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_uint64(EXT_PULL *pext, uint64_t *v)
{
	if (pext->data_size < sizeof(uint64_t) ||
		pext->offset + sizeof(uint64_t) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	*v = EXT_IVAL(pext, pext->offset);
	*v |= (uint64_t)(EXT_IVAL(pext, pext->offset+4)) << 32;
	pext->offset += sizeof(uint64_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_float(EXT_PULL *pext, float *v)
{
	if (pext->data_size < sizeof(float) ||
		pext->offset + sizeof(float) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	memcpy(v, pext->data + pext->offset, sizeof(float));
	pext->offset += sizeof(float);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_double(EXT_PULL *pext, double *v)
{
	if (pext->data_size < sizeof(double) ||
		pext->offset + sizeof(double) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	memcpy(v, pext->data + pext->offset, sizeof(double));
	pext->offset += sizeof(double);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_bool(EXT_PULL *pext, BOOL *v)
{
	uint8_t tmp_byte;
	
	if (pext->data_size < sizeof(uint8_t) ||
		pext->offset + sizeof(uint8_t) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	tmp_byte = CVAL(pext->data, pext->offset);
	pext->offset += sizeof(uint8_t);
	if (0 == tmp_byte) {
		*v = FALSE;
	} else if (1 == tmp_byte) {
		*v = TRUE;
	} else {
		return EXT_ERR_FORMAT;
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_bytes(EXT_PULL *pext, void *data, uint32_t n)
{
	if (pext->data_size < n || pext->offset + n > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	
	memcpy(data, pext->data + pext->offset, n);
	pext->offset += n;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_guid(EXT_PULL *pext, GUID *r)
{
	TRY(ext_buffer_pull_uint32(pext, &r->time_low));
	TRY(ext_buffer_pull_uint16(pext, &r->time_mid));
	TRY(ext_buffer_pull_uint16(pext, &r->time_hi_and_version));
	TRY(ext_buffer_pull_bytes(pext, r->clock_seq, 2));
	TRY(ext_buffer_pull_bytes(pext, r->node, 6));
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_string(EXT_PULL *pext, char **ppstr)
{
	int len;
	
	if (pext->offset >= pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	len = strnlen(pext->cdata + pext->offset, pext->data_size - pext->offset);
	if (len + 1 > pext->data_size - pext->offset) {
		return EXT_ERR_BUFSIZE;
	}
	len ++;
	*ppstr = pext->anew<char>(len);
	if (NULL == *ppstr) {
		return EXT_ERR_ALLOC;
	}
	memcpy(*ppstr, pext->data + pext->offset, len);
	return ext_buffer_pull_advance(pext, len);
}

int ext_buffer_pull_wstring(EXT_PULL *pext, char **ppstr)
{
	int i;
	int len, max_len;
	
	if (0 == (pext->flags & EXT_FLAG_UTF16)) {
		return ext_buffer_pull_string(pext, ppstr);
	}
	if (pext->offset >= pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	max_len = pext->data_size - pext->offset;
	for (i=0; i<max_len-1; i+=2) {
		if (0 == *(pext->data + pext->offset + i) &&
			0 == *(pext->data + pext->offset + i + 1)) {
			break;
		}
	}
	if (i >= max_len - 1) {
		return EXT_ERR_BUFSIZE;
	}
	len = i + 2;
	*ppstr = pext->anew<char>(2 * len);
	if (NULL == *ppstr) {
		return EXT_ERR_ALLOC;
	}
	auto pbuff = static_cast<char *>(malloc(len));
	if (NULL == pbuff) {
		return EXT_ERR_ALLOC;
	}
	memcpy(pbuff, pext->data + pext->offset, len);
	if (FALSE == utf16le_to_utf8(pbuff, len, *ppstr, 2*len)) {
		free(pbuff);
		return EXT_ERR_CHARCNV;
	}
	free(pbuff);
	return ext_buffer_pull_advance(pext, len);
}

int ext_buffer_pull_data_blob(EXT_PULL *pext, DATA_BLOB *pblob)
{
	uint32_t length;
	
	if (pext->offset > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	length = pext->data_size - pext->offset;
	pblob->data = pext->anew<uint8_t>(length);
	if (NULL == pblob->data) {
		return EXT_ERR_ALLOC;
	}
	memcpy(pblob->data, pext->data + pext->offset, length);
	pblob->length = length;
	pext->offset += length;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_binary(EXT_PULL *pext, BINARY *r)
{
	uint16_t cb;
	
	if (pext->flags & EXT_FLAG_WCOUNT) {
		TRY(ext_buffer_pull_uint32(pext, &r->cb));
	} else {
		TRY(ext_buffer_pull_uint16(pext, &cb));
		r->cb = cb;
	}
	if (0 == r->cb) {
		r->pb = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pv = pext->alloc(r->cb);
	if (r->pv == nullptr)
		return EXT_ERR_ALLOC;
	return ext_buffer_pull_bytes(pext, r->pv, r->cb);
}

int ext_buffer_pull_sbinary(EXT_PULL *pext, BINARY *r)
{
	uint16_t cb;
	
	TRY(ext_buffer_pull_uint16(pext, &cb));
	r->cb = cb;
	if (0 == r->cb) {
		r->pb = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pv = pext->alloc(r->cb);
	if (r->pv == nullptr)
		return EXT_ERR_ALLOC;
	return ext_buffer_pull_bytes(pext, r->pv, r->cb);
}

int ext_buffer_pull_exbinary(EXT_PULL *pext, BINARY *r)
{
	TRY(ext_buffer_pull_uint32(pext, &r->cb));
	if (0 == r->cb) {
		r->pb = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pv = pext->alloc(r->cb);
	if (r->pv == nullptr)
		return EXT_ERR_ALLOC;
	return ext_buffer_pull_bytes(pext, r->pv, r->cb);
}

int ext_buffer_pull_short_array(EXT_PULL *pext, SHORT_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	if (0 == r->count) {
		r->ps = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ps = pext->anew<uint16_t>(r->count);
	if (NULL == r->ps) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_uint16(pext, &r->ps[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_long_array(EXT_PULL *pext, LONG_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	if (0 == r->count) {
		r->pl = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pl = pext->anew<uint32_t>(r->count);
	if (NULL == r->pl) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_uint32(pext, &r->pl[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_longlong_array(EXT_PULL *pext, LONGLONG_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	if (0 == r->count) {
		r->pll = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pll = pext->anew<uint64_t>(r->count);
	if (NULL == r->pll) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_uint64(pext, &r->pll[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_slonglong_array(EXT_PULL *pext, LONGLONG_ARRAY *r)
{
	int i;
	uint16_t count;
	
	TRY(ext_buffer_pull_uint16(pext, &count));
	r->count = count;
	if (0 == r->count) {
		r->pll = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pll = pext->anew<uint64_t>(r->count);
	if (NULL == r->pll) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_uint64(pext, &r->pll[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_binary_array(EXT_PULL *pext, BINARY_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	if (0 == r->count) {
		r->pbin = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pbin = pext->anew<BINARY>(r->count);
	if (NULL == r->pbin) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_binary(pext, &r->pbin[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_string_array(EXT_PULL *pext, STRING_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	if (0 == r->count) {
		r->ppstr = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppstr = pext->anew<char *>(r->count);
	if (NULL == r->ppstr) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_string(pext, &r->ppstr[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_wstring_array(EXT_PULL *pext, STRING_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	if (0 == r->count) {
		r->ppstr = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppstr = pext->anew<char *>(r->count);
	if (NULL == r->ppstr) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_wstring(pext, &r->ppstr[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_guid_array(EXT_PULL *pext, GUID_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	if (0 == r->count) {
		r->pguid = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pguid = pext->anew<GUID>(r->count);
	if (NULL == r->pguid) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_guid(pext, &r->pguid[i]));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_restriction_and_or(
	EXT_PULL *pext, RESTRICTION_AND_OR *r)
{
	int i;
	uint16_t count;
	
	if (pext->flags & EXT_FLAG_WCOUNT) {
		TRY(ext_buffer_pull_uint32(pext, &r->count));
	} else {
		TRY(ext_buffer_pull_uint16(pext, &count));
		r->count = count;
	}
	if (0 == r->count) {
		r->pres = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pres = pext->anew<RESTRICTION>(r->count);
	if (NULL == r->pres) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_restriction(pext, &r->pres[i]));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_restriction_not(
	EXT_PULL *pext, RESTRICTION_NOT *r)
{
	return ext_buffer_pull_restriction(pext, &r->res);
}

static int ext_buffer_pull_restriction_content(
	EXT_PULL *pext, RESTRICTION_CONTENT *r)
{
	TRY(ext_buffer_pull_uint32(pext, &r->fuzzy_level));
	TRY(ext_buffer_pull_uint32(pext, &r->proptag));
	return ext_buffer_pull_tagged_propval(pext, &r->propval);
}

static int ext_buffer_pull_restriction_property(
	EXT_PULL *pext, RESTRICTION_PROPERTY *r)
{
	uint8_t relop;
	
	TRY(ext_buffer_pull_uint8(pext, &relop));
	r->relop = static_cast<enum relop>(relop);
	TRY(ext_buffer_pull_uint32(pext, &r->proptag));
	return ext_buffer_pull_tagged_propval(pext, &r->propval);
}

static int ext_buffer_pull_restriction_propcompare(
	EXT_PULL *pext, RESTRICTION_PROPCOMPARE *r)
{
	uint8_t relop;
	
	TRY(ext_buffer_pull_uint8(pext, &relop));
	r->relop = static_cast<enum relop>(relop);
	TRY(ext_buffer_pull_uint32(pext, &r->proptag1));
	return ext_buffer_pull_uint32(pext, &r->proptag2);
}

static int ext_buffer_pull_restriction_bitmask(
	EXT_PULL *pext, RESTRICTION_BITMASK *r)
{
	uint8_t relop;
	
	TRY(ext_buffer_pull_uint8(pext, &relop));
	r->bitmask_relop = static_cast<enum bm_relop>(relop);
	TRY(ext_buffer_pull_uint32(pext, &r->proptag));
	return ext_buffer_pull_uint32(pext, &r->mask);
}

static int ext_buffer_pull_restriction_size(
	EXT_PULL *pext, RESTRICTION_SIZE *r)
{
	uint8_t relop;
	
	TRY(ext_buffer_pull_uint8(pext, &relop));
	r->relop = static_cast<enum relop>(relop);
	TRY(ext_buffer_pull_uint32(pext, &r->proptag));
	return ext_buffer_pull_uint32(pext, &r->size);
}

static int ext_buffer_pull_restriction_exist(
	EXT_PULL *pext, RESTRICTION_EXIST *r)
{
	return ext_buffer_pull_uint32(pext, &r->proptag);
}

static int ext_buffer_pull_restriction_subobj(
	EXT_PULL *pext, RESTRICTION_SUBOBJ *r)
{
	TRY(ext_buffer_pull_uint32(pext, &r->subobject));
	return ext_buffer_pull_restriction(pext, &r->res);
}

static int ext_buffer_pull_restriction_comment(
	EXT_PULL *pext, RESTRICTION_COMMENT *r)
{
	int i;
	uint8_t res_present;
	
	TRY(ext_buffer_pull_uint8(pext, &r->count));
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->ppropval = pext->anew<TAGGED_PROPVAL>(r->count);
	if (NULL == r->ppropval) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_tagged_propval(pext, &r->ppropval[i]));
	}
	TRY(ext_buffer_pull_uint8(pext, &res_present));
	if (0 != res_present) {
		r->pres = pext->anew<RESTRICTION>();
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction(pext, r->pres);
	}
	r->pres = NULL;
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_restriction_count(
	EXT_PULL *pext, RESTRICTION_COUNT *r)
{
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	return ext_buffer_pull_restriction(pext, &r->sub_res);
}

int ext_buffer_pull_restriction(EXT_PULL *pext, RESTRICTION *r)
{
	uint8_t rt;
	
	TRY(ext_buffer_pull_uint8(pext, &rt));
	r->rt = static_cast<res_type>(rt);
	switch (r->rt) {
	case RES_AND:
	case RES_OR:
		r->pres = pext->anew<RESTRICTION_AND_OR>();
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_and_or(pext, r->andor);
	case RES_NOT:
		r->pres = pext->anew<RESTRICTION_NOT>();
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_not(pext, r->xnot);
	case RES_CONTENT:
		r->pres = pext->anew<RESTRICTION_CONTENT>();
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_content(pext, r->cont);
	case RES_PROPERTY:
		r->pres = pext->anew<RESTRICTION_PROPERTY>();
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_property(pext, r->prop);
	case RES_PROPCOMPARE:
		r->pres = pext->anew<RESTRICTION_PROPCOMPARE>();
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_propcompare(pext, r->pcmp);
	case RES_BITMASK:
		r->pres = pext->anew<RESTRICTION_BITMASK>();
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_bitmask(pext, r->bm);
	case RES_SIZE:
		r->pres = pext->anew<RESTRICTION_SIZE>();
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_size(pext, r->size);
	case RES_EXIST:
		r->pres = pext->anew<RESTRICTION_EXIST>();
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_exist(pext, r->exist);
	case RES_SUBRESTRICTION:
		r->pres = pext->anew<RESTRICTION_SUBOBJ>();
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_subobj(pext, r->sub);
	case RES_COMMENT:
		r->pres = pext->anew<RESTRICTION_COMMENT>();
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_comment(pext, r->comment);
	case RES_COUNT:
		r->pres = pext->anew<RESTRICTION_COUNT>();
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_count(pext, r->count);
	case RES_NULL:
		r->pres = NULL;
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int ext_buffer_pull_svreid(EXT_PULL *pext, SVREID *r)
{
	uint8_t ours;
	uint16_t length;
	
	TRY(ext_buffer_pull_uint16(pext, &length));
	TRY(ext_buffer_pull_uint8(pext, &ours));
	if (0 == ours) {
		r->folder_id = 0;
		r->message_id = 0;
		r->instance = 0;
		r->pbin = pext->anew<BINARY>();
		if (NULL == r->pbin) {
			return EXT_ERR_ALLOC;
		}
		r->pbin->cb = length - 1;
		r->pbin->pv = pext->alloc(r->pbin->cb);
		if (r->pbin->pv == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_bytes(pext, r->pbin->pv, r->pbin->cb);
	}
	if (21 != length) {
		return EXT_ERR_FORMAT;
	}
	r->pbin = NULL;
	TRY(ext_buffer_pull_uint64(pext, &r->folder_id));
	TRY(ext_buffer_pull_uint64(pext, &r->message_id));
	return ext_buffer_pull_uint32(pext, &r->instance);
}

int ext_buffer_pull_store_entryid(EXT_PULL *pext, STORE_ENTRYID *r)
{
	TRY(ext_buffer_pull_uint32(pext, &r->flags));
	TRY(ext_buffer_pull_bytes(pext, r->provider_uid, 16));
	TRY(ext_buffer_pull_uint8(pext, &r->version));
	TRY(ext_buffer_pull_uint8(pext, &r->flag));
	TRY(ext_buffer_pull_bytes(pext, r->dll_name, 14));
	TRY(ext_buffer_pull_uint32(pext, &r->wrapped_flags));
	TRY(ext_buffer_pull_bytes(pext, r->wrapped_provider_uid, 16));
	TRY(ext_buffer_pull_uint32(pext, &r->wrapped_type));
	TRY(ext_buffer_pull_string(pext, &r->pserver_name));
	return ext_buffer_pull_string(pext, &r->pmailbox_dn);
}

static int ext_buffer_pull_movecopy_action(EXT_PULL *pext, MOVECOPY_ACTION *r)
{
	uint16_t eid_size;
	
	TRY(ext_buffer_pull_uint8(pext, &r->same_store));
	TRY(ext_buffer_pull_uint16(pext, &eid_size));
	if (0 == r->same_store) {
		r->pstore_eid = pext->anew<STORE_ENTRYID>();
		if (NULL == r->pstore_eid) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_store_entryid(pext, r->pstore_eid));
	} else {
		r->pstore_eid = NULL;
		TRY(ext_buffer_pull_advance(pext, eid_size));
	}
	if (0 != r->same_store) {
		r->pfolder_eid = pext->anew<SVREID>();
		if (NULL == r->pfolder_eid) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_svreid(pext, static_cast<SVREID *>(r->pfolder_eid));
	} else {
		r->pfolder_eid = pext->anew<BINARY>();
		if (NULL == r->pfolder_eid) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_binary(pext, static_cast<BINARY *>(r->pfolder_eid));
	}
}

static int ext_buffer_pull_reply_action(EXT_PULL *pext, REPLY_ACTION *r)
{
	TRY(ext_buffer_pull_uint64(pext, &r->template_folder_id));
	TRY(ext_buffer_pull_uint64(pext, &r->template_message_id));
	return ext_buffer_pull_guid(pext, &r->template_guid);
}

static int ext_buffer_pull_recipient_block(EXT_PULL *pext, RECIPIENT_BLOCK *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint8(pext, &r->reserved));
	TRY(ext_buffer_pull_uint16(pext, &r->count));
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->ppropval = pext->anew<TAGGED_PROPVAL>(r->count);
	if (NULL == r->ppropval) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_tagged_propval(pext, &r->ppropval[i]));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_forwarddelegate_action(
	EXT_PULL *pext, FORWARDDELEGATE_ACTION *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint16(pext, &r->count));
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->pblock = pext->anew<RECIPIENT_BLOCK>(r->count);
	if (NULL == r->pblock) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_recipient_block(pext, &r->pblock[i]));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_action_block(EXT_PULL *pext, ACTION_BLOCK *r)
{
	uint16_t tmp_len;
	
	TRY(ext_buffer_pull_uint16(pext, &r->length));
	TRY(ext_buffer_pull_uint8(pext, &r->type));
	TRY(ext_buffer_pull_uint32(pext, &r->flavor));
	TRY(ext_buffer_pull_uint32(pext, &r->flags));
	switch (r->type) {
	case ACTION_TYPE_OP_MOVE:
	case ACTION_TYPE_OP_COPY:
		r->pdata = pext->anew<MOVECOPY_ACTION>();
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_movecopy_action(pext, static_cast<MOVECOPY_ACTION *>(r->pdata));
	case ACTION_TYPE_OP_REPLY:
	case ACTION_TYPE_OP_OOF_REPLY:
		r->pdata = pext->anew<REPLY_ACTION>();
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_reply_action(pext, static_cast<REPLY_ACTION *>(r->pdata));
	case ACTION_TYPE_OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - 2*sizeof(uint32_t);
		r->pdata = pext->alloc(tmp_len);
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_bytes(pext, r->pdata, tmp_len);
	case ACTION_TYPE_OP_BOUNCE:
		r->pdata = pext->anew<uint32_t>();
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint32(pext, static_cast<uint32_t *>(r->pdata));
	case ACTION_TYPE_OP_FORWARD:
	case ACTION_TYPE_OP_DELEGATE:
		r->pdata = pext->anew<FORWARDDELEGATE_ACTION>();
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_forwarddelegate_action(pext, static_cast<FORWARDDELEGATE_ACTION *>(r->pdata));
	case ACTION_TYPE_OP_TAG:
		r->pdata = pext->anew<TAGGED_PROPVAL>();
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_tagged_propval(pext, static_cast<TAGGED_PROPVAL *>(r->pdata));
	case ACTION_TYPE_OP_DELETE:
	case ACTION_TYPE_OP_MARK_AS_READ:
		r->pdata = NULL;
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int ext_buffer_pull_rule_actions(EXT_PULL *pext, RULE_ACTIONS *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint16(pext, &r->count));
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->pblock = pext->anew<ACTION_BLOCK>(r->count);
	if (NULL == r->pblock) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_action_block(pext, &r->pblock[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_propval(EXT_PULL *pext, uint16_t type, void **ppval)
{
	/* convert multi-value instance into single value */
	if ((type & MVI_FLAG) == MVI_FLAG)
		type &= ~MVI_FLAG;
	switch (type) {
	case PT_UNSPECIFIED:
		*ppval = pext->anew<TYPED_PROPVAL>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_typed_propval(pext, static_cast<TYPED_PROPVAL *>(*ppval));
	case PT_SHORT:
		*ppval = pext->anew<uint16_t>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint16(pext, static_cast<uint16_t *>(*ppval));
	case PT_LONG:
	case PT_ERROR:
		*ppval = pext->anew<uint32_t>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint32(pext, static_cast<uint32_t *>(*ppval));
	case PT_FLOAT:
		*ppval = pext->anew<float>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_float(pext, static_cast<float *>(*ppval));
	case PT_DOUBLE:
	case PT_APPTIME:
		*ppval = pext->anew<double>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_double(pext, static_cast<double *>(*ppval));
	case PT_BOOLEAN:
		*ppval = pext->anew<uint8_t>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint8(pext, static_cast<uint8_t *>(*ppval));
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		*ppval = pext->anew<uint64_t>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint64(pext, static_cast<uint64_t *>(*ppval));
	case PT_STRING8:
		return ext_buffer_pull_string(pext, (char**)ppval);
	case PT_UNICODE:
		return ext_buffer_pull_wstring(pext, (char**)ppval);
	case PT_SVREID:
		*ppval = pext->anew<SVREID>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_svreid(pext, static_cast<SVREID *>(*ppval));
	case PT_CLSID:
		*ppval = pext->anew<GUID>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_guid(pext, static_cast<GUID *>(*ppval));
	case PT_SRESTRICT:
		*ppval = pext->anew<RESTRICTION>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction(pext, static_cast<RESTRICTION *>(*ppval));
	case PT_ACTIONS:
		*ppval = pext->anew<RULE_ACTIONS>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_rule_actions(pext, static_cast<RULE_ACTIONS *>(*ppval));
	case PT_BINARY:
	case PT_OBJECT:
		*ppval = pext->anew<BINARY>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_binary(pext, static_cast<BINARY *>(*ppval));
	case PT_MV_SHORT:
		*ppval = pext->anew<SHORT_ARRAY>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_short_array(pext, static_cast<SHORT_ARRAY *>(*ppval));
	case PT_MV_LONG:
		*ppval = pext->anew<LONG_ARRAY>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_long_array(pext, static_cast<LONG_ARRAY *>(*ppval));
	case PT_MV_I8:
		*ppval = pext->anew<LONGLONG_ARRAY>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_longlong_array(pext, static_cast<LONGLONG_ARRAY *>(*ppval));
	case PT_MV_STRING8:
		*ppval = pext->anew<STRING_ARRAY>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_string_array(pext, static_cast<STRING_ARRAY *>(*ppval));
	case PT_MV_UNICODE:
		*ppval = pext->anew<STRING_ARRAY>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_wstring_array(pext, static_cast<STRING_ARRAY *>(*ppval));
	case PT_MV_CLSID:
		*ppval = pext->anew<GUID_ARRAY>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_guid_array(pext, static_cast<GUID_ARRAY *>(*ppval));
	case PT_MV_BINARY:
		*ppval = pext->anew<BINARY_ARRAY>();
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_binary_array(pext, static_cast<BINARY_ARRAY *>(*ppval));
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int ext_buffer_pull_typed_propval(EXT_PULL *pext, TYPED_PROPVAL *r)
{
	TRY(ext_buffer_pull_uint16(pext, &r->type));
	return ext_buffer_pull_propval(pext, r->type, &r->pvalue);
}

int ext_buffer_pull_tagged_propval(EXT_PULL *pext, TAGGED_PROPVAL *r)
{
	TRY(ext_buffer_pull_uint32(pext, &r->proptag));
	return ext_buffer_pull_propval(pext, PROP_TYPE(r->proptag), &r->pvalue);
}

int ext_buffer_pull_long_term_id(EXT_PULL *pext, LONG_TERM_ID *r)
{
	TRY(ext_buffer_pull_guid(pext, &r->guid));
	TRY(ext_buffer_pull_bytes(pext, r->global_counter, 6));
	return ext_buffer_pull_uint16(pext, &r->padding);
}

int ext_buffer_pull_long_term_id_rang(EXT_PULL *pext, LONG_TERM_ID_RANGE *r)
{
	TRY(ext_buffer_pull_long_term_id(pext, &r->min));
	return ext_buffer_pull_long_term_id(pext, &r->max);
}

int ext_buffer_pull_proptag_array(EXT_PULL *pext, PROPTAG_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint16(pext, &r->count));
	if (0 == r->count) {
		r->pproptag = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pproptag = pext->anew<uint32_t>(r->count);
	if (NULL == r->pproptag) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_uint32(pext, &r->pproptag[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_property_name(EXT_PULL *pext, PROPERTY_NAME *r)
{
	uint32_t offset;
	uint8_t name_size;
	
	TRY(ext_buffer_pull_uint8(pext, &r->kind));
	TRY(ext_buffer_pull_guid(pext, &r->guid));
	r->plid = NULL;
	r->pname = NULL;
	if (r->kind == MNID_ID) {
		r->plid = pext->anew<uint32_t>();
		if (NULL == r->plid) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_uint32(pext, r->plid));
	} else if (r->kind == MNID_STRING) {
		TRY(ext_buffer_pull_uint8(pext, &name_size));
		if (name_size < 2) {
			return EXT_ERR_FORMAT;
		}
		offset = pext->offset + name_size;
		TRY(ext_buffer_pull_wstring(pext, &r->pname));
		if (pext->offset > offset) {
			return EXT_ERR_FORMAT;
		}
		pext->offset = offset;
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_propname_array(EXT_PULL *pext, PROPNAME_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint16(pext, &r->count));
	if (0 == r->count) {
		r->ppropname = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropname = pext->anew<PROPERTY_NAME>(r->count);
	if (NULL == r->ppropname) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_property_name(pext, r->ppropname + i));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_propid_array(EXT_PULL *pext, PROPID_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint16(pext, &r->count));
	if (0 == r->count) {
		r->ppropid = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropid = pext->anew<uint16_t>(r->count);
	if (NULL == r->ppropid) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_uint16(pext, r->ppropid + i));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_tpropval_array(EXT_PULL *pext, TPROPVAL_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint16(pext, &r->count));
	if (0 == r->count) {
		r->ppropval = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropval = pext->anew<TAGGED_PROPVAL>(r->count);
	if (NULL == r->ppropval) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_tagged_propval(pext, r->ppropval + i));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_tarray_set(EXT_PULL *pext, TARRAY_SET *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	if (0 == r->count) {
		r->pparray = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pparray = pext->anew<TPROPVAL_ARRAY *>(r->count);
	if (NULL == r->pparray) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		r->pparray[i] = pext->anew<TPROPVAL_ARRAY>();
		if (NULL == r->pparray[i]) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_tpropval_array(pext, r->pparray[i]));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_property_problem(EXT_PULL *pext, PROPERTY_PROBLEM *r)
{
	TRY(ext_buffer_pull_uint16(pext, &r->index));
	TRY(ext_buffer_pull_uint32(pext, &r->proptag));
	return ext_buffer_pull_uint32(pext, &r->err);
}

int ext_buffer_pull_problem_array(EXT_PULL *pext, PROBLEM_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint16(pext, &r->count));
	r->pproblem = pext->anew<PROPERTY_PROBLEM>(r->count);
	if (NULL == r->pproblem) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_property_problem(pext, r->pproblem + i));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_xid(EXT_PULL *pext, uint8_t size, XID *pxid)
{
	if (size < 17 || size > 24) {
		return EXT_ERR_FORMAT;
	}
	TRY(ext_buffer_pull_guid(pext, &pxid->guid));
	return ext_buffer_pull_bytes(pext, pxid->local_id, size - 16);
}

int ext_buffer_pull_folder_entryid(EXT_PULL *pext, FOLDER_ENTRYID *r)
{
	TRY(ext_buffer_pull_uint32(pext, &r->flags));
	TRY(ext_buffer_pull_bytes(pext, r->provider_uid, 16));
	TRY(ext_buffer_pull_uint16(pext, &r->folder_type));
	TRY(ext_buffer_pull_guid(pext, &r->database_guid));
	TRY(ext_buffer_pull_bytes(pext, r->global_counter, 6));
	return ext_buffer_pull_bytes(pext, r->pad, 2);
}

static int ext_buffer_pull_ext_movecopy_action(
	EXT_PULL *pext, EXT_MOVECOPY_ACTION *r)
{
	uint32_t size;
	
	TRY(ext_buffer_pull_uint32(pext, &size));
	if (0 == size) {
		return EXT_ERR_FORMAT;
	} else {
		TRY(ext_buffer_pull_advance(pext, size));
	}
	TRY(ext_buffer_pull_uint32(pext, &size));
	if (46 != size) {
		return EXT_ERR_FORMAT;
	}
	return ext_buffer_pull_folder_entryid(pext, &r->folder_eid);
}

int ext_buffer_pull_message_entryid(EXT_PULL *pext, MESSAGE_ENTRYID *r)
{
	TRY(ext_buffer_pull_uint32(pext, &r->flags));
	TRY(ext_buffer_pull_bytes(pext, r->provider_uid, 16));
	TRY(ext_buffer_pull_uint16(pext, &r->message_type));
	TRY(ext_buffer_pull_guid(pext, &r->folder_database_guid));
	TRY(ext_buffer_pull_bytes(pext, r->folder_global_counter, 6));
	TRY(ext_buffer_pull_bytes(pext, r->pad1, 2));
	TRY(ext_buffer_pull_guid(pext, &r->message_database_guid));
	TRY(ext_buffer_pull_bytes(pext, r->message_global_counter, 6));
	return ext_buffer_pull_bytes(pext, r->pad2, 2);
}

static int ext_buffer_pull_ext_reply_action(
	EXT_PULL *pext, EXT_REPLY_ACTION *r)
{
	uint32_t size;
	
	TRY(ext_buffer_pull_uint32(pext, &size));
	if (70 != size) {
		return EXT_ERR_FORMAT;
	}
	TRY(ext_buffer_pull_message_entryid(pext, &r->message_eid));
	return ext_buffer_pull_guid(pext, &r->template_guid);
}


static int ext_buffer_pull_ext_recipient_block(
	EXT_PULL *pext, EXT_RECIPIENT_BLOCK *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint8(pext, &r->reserved));
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->ppropval = pext->anew<TAGGED_PROPVAL>(r->count);
	if (NULL == r->ppropval) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_tagged_propval(pext, &r->ppropval[i]));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_ext_forwarddelegate_action(EXT_PULL *pext,
	EXT_FORWARDDELEGATE_ACTION *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->pblock = pext->anew<EXT_RECIPIENT_BLOCK>(r->count);
	if (NULL == r->pblock) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_ext_recipient_block(pext, &r->pblock[i]));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_ext_action_block(
	EXT_PULL *pext, EXT_ACTION_BLOCK *r)
{
	uint32_t tmp_len;
	
	TRY(ext_buffer_pull_uint32(pext, &r->length));
	TRY(ext_buffer_pull_uint8(pext, &r->type));
	TRY(ext_buffer_pull_uint32(pext, &r->flavor));
	TRY(ext_buffer_pull_uint32(pext, &r->flags));
	switch (r->type) {
	case ACTION_TYPE_OP_MOVE:
	case ACTION_TYPE_OP_COPY:
		r->pdata = pext->anew<EXT_MOVECOPY_ACTION>();
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_ext_movecopy_action(pext, static_cast<EXT_MOVECOPY_ACTION *>(r->pdata));
	case ACTION_TYPE_OP_REPLY:
	case ACTION_TYPE_OP_OOF_REPLY:
		r->pdata = pext->anew<EXT_REPLY_ACTION>();
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_ext_reply_action(pext, static_cast<EXT_REPLY_ACTION *>(r->pdata));
	case ACTION_TYPE_OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - sizeof(uint32_t);
		r->pdata = pext->alloc(tmp_len);
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_bytes(pext, r->pdata, tmp_len);
	case ACTION_TYPE_OP_BOUNCE:
		r->pdata = pext->anew<uint32_t>();
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint32(pext, static_cast<uint32_t *>(r->pdata));
	case ACTION_TYPE_OP_FORWARD:
	case ACTION_TYPE_OP_DELEGATE:
		r->pdata = pext->anew<EXT_FORWARDDELEGATE_ACTION>();
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_ext_forwarddelegate_action(pext, static_cast<EXT_FORWARDDELEGATE_ACTION *>(r->pdata));
	case ACTION_TYPE_OP_TAG:
		r->pdata = pext->anew<TAGGED_PROPVAL>();
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_tagged_propval(pext, static_cast<TAGGED_PROPVAL *>(r->pdata));
	case ACTION_TYPE_OP_DELETE:
	case ACTION_TYPE_OP_MARK_AS_READ:
		r->pdata = NULL;
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int ext_buffer_pull_ext_rule_actions(EXT_PULL *pext, EXT_RULE_ACTIONS *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->pblock = pext->anew<EXT_ACTION_BLOCK>(r->count);
	if (NULL == r->pblock) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_ext_action_block(pext, &r->pblock[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_namedproperty_information(
	EXT_PULL *pext, NAMEDPROPERTY_INFOMATION *r)
{
	int i;
	uint32_t size;
	uint32_t offset;
	
	TRY(ext_buffer_pull_uint16(pext, &r->count));
	if (0 == r->count) {
		r->ppropid = NULL;
		r->ppropname = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropid = pext->anew<uint16_t>(r->count);
	if (NULL == r->ppropid) {
		return EXT_ERR_ALLOC;
	}
	r->ppropname = pext->anew<PROPERTY_NAME>(r->count);
	if (NULL == r->ppropname) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_uint16(pext, r->ppropid + i));
	}
	TRY(ext_buffer_pull_uint32(pext, &size));
	offset = pext->offset + size;
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_property_name(pext, r->ppropname + i));
	}
	if (offset < pext->offset) {
		return EXT_ERR_FORMAT;
	}
	pext->offset = offset;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_flagged_propval(EXT_PULL *pext,
	uint16_t type, FLAGGED_PROPVAL *r)
{
	void **ppvalue;
	
	if (type == PT_UNSPECIFIED) {
		TRY(ext_buffer_pull_uint16(pext, &type));
		r->pvalue = pext->anew<TYPED_PROPVAL>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		((TYPED_PROPVAL*)r->pvalue)->type = type;
		ppvalue = &((TYPED_PROPVAL*)r->pvalue)->pvalue;
	} else {
		ppvalue = &r->pvalue;
	}
	TRY(ext_buffer_pull_uint8(pext, &r->flag));
	switch (r->flag) {
	case FLAGGED_PROPVAL_FLAG_AVAILABLE:
		return ext_buffer_pull_propval(pext, type, ppvalue);
	case FLAGGED_PROPVAL_FLAG_UNAVAILABLE:
		*ppvalue = NULL;
		return EXT_ERR_SUCCESS;
	case FLAGGED_PROPVAL_FLAG_ERROR:
		*ppvalue = pext->anew<uint32_t>();
		if (NULL == *ppvalue) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint32(pext, static_cast<uint32_t *>(*ppvalue));
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int ext_buffer_pull_property_row(EXT_PULL *pext,
	const PROPTAG_ARRAY *pcolumns, PROPERTY_ROW *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint8(pext, &r->flag));
	r->pppropval = pext->anew<void *>(pcolumns->count);
	if (NULL == r->pppropval) {
		return EXT_ERR_ALLOC;
	}
	if (PROPERTY_ROW_FLAG_NONE == r->flag) {
		for (i=0; i<pcolumns->count; i++) {
			TRY(ext_buffer_pull_propval(pext, PROP_TYPE(pcolumns->pproptag[i]), &r->pppropval[i]));
		}
		return EXT_ERR_SUCCESS;
	} else if (PROPERTY_ROW_FLAG_FLAGGED == r->flag) {
		for (i=0; i<pcolumns->count; i++) {
			r->pppropval[i] = pext->anew<FLAGGED_PROPVAL>();
			if (NULL == r->pppropval[i]) {
				return EXT_ERR_ALLOC;
			}
			TRY(ext_buffer_pull_flagged_propval(pext, PROP_TYPE(pcolumns->pproptag[i]),
			         static_cast<FLAGGED_PROPVAL *>(r->pppropval[i])));
		}
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int ext_buffer_pull_sort_order(EXT_PULL *pext, SORT_ORDER *r)
{
	TRY(ext_buffer_pull_uint16(pext, &r->type));
	if ((r->type & MVI_FLAG) == MV_FLAG)
		/* MV_FLAG set without MV_INSTANCE */
		return EXT_ERR_FORMAT;
	TRY(ext_buffer_pull_uint16(pext, &r->propid));
	return ext_buffer_pull_uint8(pext, &r->table_sort);
}

int ext_buffer_pull_sortorder_set(EXT_PULL *pext, SORTORDER_SET *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint16(pext, &r->count));
	TRY(ext_buffer_pull_uint16(pext, &r->ccategories));
	TRY(ext_buffer_pull_uint16(pext, &r->cexpanded));
	if (0 == r->count || r->ccategories > r->count ||
		r->cexpanded > r->ccategories) {
		return EXT_ERR_FORMAT;
	}
	r->psort = pext->anew<SORT_ORDER>(r->count);
	if (NULL == r->psort) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_sort_order(pext, r->psort + i));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_recipient_row(EXT_PULL *pext,
	const PROPTAG_ARRAY *pproptags, RECIPIENT_ROW *r)
{
	uint8_t type;
	BOOL b_unicode;
	PROPTAG_ARRAY proptags;
	
	TRY(ext_buffer_pull_uint16(pext, &r->flags));
	type = r->flags & 0x0007;
	b_unicode = FALSE;
	if (r->flags & RECIPIENT_ROW_FLAG_UNICODE) {
		b_unicode = TRUE;
	}
	r->pprefix_used = NULL;
	r->pdisplay_type = NULL;
	r->px500dn = NULL;
	if (RECIPIENT_ROW_TYPE_X500DN == type) {
		r->pprefix_used = pext->anew<uint8_t>();
		if (NULL == r->pprefix_used) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_uint8(pext, r->pprefix_used));
		r->pdisplay_type = pext->anew<uint8_t>();
		if (NULL == r->pprefix_used) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_uint8(pext, r->pdisplay_type));
		TRY(ext_buffer_pull_string(pext, &r->px500dn));
	}
	r->pentry_id = NULL;
	r->psearch_key = NULL;
	if (RECIPIENT_ROW_TYPE_PERSONAL_DLIST1 == type ||
		RECIPIENT_ROW_TYPE_PERSONAL_DLIST2 == type) {
		r->pentry_id = pext->anew<BINARY>();
		if (NULL == r->pentry_id) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_binary(pext, r->pentry_id));
		r->psearch_key = pext->anew<BINARY>();
		if (NULL == r->psearch_key) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_binary(pext, r->psearch_key));
	}
	r->paddress_type = NULL;
	if (RECIPIENT_ROW_TYPE_NONE == type &&
		(r->flags & RECIPIENT_ROW_FLAG_OUTOFSTANDARD)) {
		TRY(ext_buffer_pull_string(pext, &r->paddress_type));
	}
	r->pmail_address = NULL;
	if (RECIPIENT_ROW_FLAG_EMAIL & r->flags) {
		if (TRUE == b_unicode) {
			TRY(ext_buffer_pull_wstring(pext, &r->pmail_address));
		} else {
			TRY(ext_buffer_pull_string(pext, &r->pmail_address));
		}
	}
	r->pdisplay_name = NULL;
	if (r->flags & RECIPIENT_ROW_FLAG_DISPLAY) {
		if (TRUE == b_unicode) {
			TRY(ext_buffer_pull_wstring(pext, &r->pdisplay_name));
		} else {
			TRY(ext_buffer_pull_string(pext, &r->pdisplay_name));
		}
	}
	r->psimple_name = NULL;
	if (r->flags & RECIPIENT_ROW_FLAG_SIMPLE) {
		if (TRUE == b_unicode) {
			TRY(ext_buffer_pull_wstring(pext, &r->psimple_name));
		} else {
			TRY(ext_buffer_pull_string(pext, &r->psimple_name));
		}
	}
	r->ptransmittable_name = NULL;
	if (r->flags & RECIPIENT_ROW_FLAG_TRANSMITTABLE) {
		if (TRUE == b_unicode) {
			TRY(ext_buffer_pull_wstring(pext, &r->ptransmittable_name));
		} else {
			TRY(ext_buffer_pull_string(pext, &r->ptransmittable_name));
		}
	}
	if (RECIPIENT_ROW_FLAG_SAME == r->flags) {
		if (NULL == r->pdisplay_name && NULL != r->ptransmittable_name) {
			r->pdisplay_name = r->ptransmittable_name;
		} else if (NULL != r->pdisplay_name && NULL == r->ptransmittable_name) {
			r->ptransmittable_name = r->pdisplay_name;
		}
	}
	TRY(ext_buffer_pull_uint16(pext, &r->count));
	if (r->count > pproptags->count) {
		return EXT_ERR_FORMAT;
	}
	proptags.count = r->count;
	proptags.pproptag = (uint32_t*)pproptags->pproptag;
	return ext_buffer_pull_property_row(pext, &proptags, &r->properties);
}

int ext_buffer_pull_modifyrecipient_row(EXT_PULL *pext,
	PROPTAG_ARRAY *pproptags, MODIFYRECIPIENT_ROW *r)
{
	uint32_t offset;
	uint16_t row_size;
	
	TRY(ext_buffer_pull_uint32(pext, &r->row_id));
	TRY(ext_buffer_pull_uint8(pext, &r->recipient_type));
	TRY(ext_buffer_pull_uint16(pext, &row_size));
	if (0 == row_size) {
		r->precipient_row = NULL;
		return EXT_ERR_SUCCESS;
	}
	offset = pext->offset + row_size;
	r->precipient_row = pext->anew<RECIPIENT_ROW>();
	if (NULL == r->precipient_row) {
		return EXT_ERR_ALLOC;
	}
	TRY(ext_buffer_pull_recipient_row(pext, pproptags, r->precipient_row));
	if (pext->offset > offset) {
		return EXT_ERR_FORMAT;
	}
	pext->offset = offset;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_permission_data(EXT_PULL *pext, PERMISSION_DATA *r)
{
	TRY(ext_buffer_pull_uint8(pext, &r->flags));
	return ext_buffer_pull_tpropval_array(pext, &r->propvals);
}

int ext_buffer_pull_rule_data(EXT_PULL *pext, RULE_DATA *r)
{
	TRY(ext_buffer_pull_uint8(pext, &r->flags));
	return ext_buffer_pull_tpropval_array(pext, &r->propvals);
}

int ext_buffer_pull_addressbook_entryid(
	EXT_PULL *pext, ADDRESSBOOK_ENTRYID *r)
{
	TRY(ext_buffer_pull_uint32(pext, &r->flags));
	TRY(ext_buffer_pull_bytes(pext, r->provider_uid, 16));
	TRY(ext_buffer_pull_uint32(pext, &r->version));
	TRY(ext_buffer_pull_uint32(pext, &r->type));
	return ext_buffer_pull_string(pext, &r->px500dn);
}

int ext_buffer_pull_oneoff_entryid(EXT_PULL *pext, ONEOFF_ENTRYID *r)
{
	TRY(ext_buffer_pull_uint32(pext, &r->flags));
	TRY(ext_buffer_pull_bytes(pext, r->provider_uid, 16));
	TRY(ext_buffer_pull_uint16(pext, &r->version));
	TRY(ext_buffer_pull_uint16(pext, &r->ctrl_flags));
	if (r->ctrl_flags & CTRL_FLAG_UNICODE) {
		TRY(ext_buffer_pull_wstring(pext, &r->pdisplay_name));
		TRY(ext_buffer_pull_wstring(pext, &r->paddress_type));
		return ext_buffer_pull_wstring(pext, &r->pmail_address);
	} else {
		TRY(ext_buffer_pull_string(pext, &r->pdisplay_name));
		TRY(ext_buffer_pull_string(pext, &r->paddress_type));
		return ext_buffer_pull_string(pext, &r->pmail_address);
	}
}

int ext_buffer_pull_oneoff_array(EXT_PULL *pext, ONEOFF_ARRAY *r)
{
	int i;
	uint32_t bytes;
	uint8_t pad_len;
	uint32_t offset;
	uint32_t offset2;
	
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	r->pentry_id = pext->anew<ONEOFF_ENTRYID>(r->count);
	if (NULL == r->pentry_id) {
		return EXT_ERR_ALLOC;
	}
	TRY(ext_buffer_pull_uint32(pext, &bytes));
	offset = pext->offset + bytes;
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_uint32(pext, &bytes));
		offset2 = pext->offset + bytes;
		TRY(ext_buffer_pull_oneoff_entryid(pext, r->pentry_id + i));
		if (pext->offset > offset2) {
			return EXT_ERR_FORMAT;
		}
		pext->offset = offset2;
		pad_len = ((bytes + 3) & ~3) - bytes;
		TRY(ext_buffer_pull_advance(pext, pad_len));
	}
	if (pext->offset > offset) {
		return EXT_ERR_FORMAT;
	}
	pext->offset = offset;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_eid_array(EXT_PULL *pext, EID_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint32(pext, &r->count));
	if (0 == r->count) {
		r->pids = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pids = pext->anew<uint64_t>(r->count);
	if (NULL == r->pids) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_pull_uint64(pext, &r->pids[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_systemtime(EXT_PULL *pext, SYSTEMTIME *r)
{
	TRY(ext_buffer_pull_int16(pext, &r->year));
	TRY(ext_buffer_pull_int16(pext, &r->month));
	TRY(ext_buffer_pull_int16(pext, &r->dayofweek));
	TRY(ext_buffer_pull_int16(pext, &r->day));
	TRY(ext_buffer_pull_int16(pext, &r->hour));
	TRY(ext_buffer_pull_int16(pext, &r->minute));
	TRY(ext_buffer_pull_int16(pext, &r->second));
	return ext_buffer_pull_int16(pext, &r->milliseconds);
}

int ext_buffer_pull_timezonestruct(EXT_PULL *pext, TIMEZONESTRUCT *r)
{
	TRY(ext_buffer_pull_int32(pext, &r->bias));
	TRY(ext_buffer_pull_int32(pext, &r->standardbias));
	TRY(ext_buffer_pull_int32(pext, &r->daylightbias));
	TRY(ext_buffer_pull_int16(pext, &r->standardyear));
	TRY(ext_buffer_pull_systemtime(pext, &r->standarddate));
	TRY(ext_buffer_pull_int16(pext, &r->daylightyear));
	return ext_buffer_pull_systemtime(pext, &r->daylightdate);
}

static int ext_buffer_pull_tzrule(EXT_PULL *pext, TZRULE *r)
{
	TRY(ext_buffer_pull_uint8(pext, &r->major));
	TRY(ext_buffer_pull_uint8(pext, &r->minor));
	TRY(ext_buffer_pull_uint16(pext, &r->reserved));
	TRY(ext_buffer_pull_uint16(pext, &r->flags));
	TRY(ext_buffer_pull_int16(pext, &r->year));
	TRY(ext_buffer_pull_bytes(pext, r->x, 14));
	TRY(ext_buffer_pull_int32(pext, &r->bias));
	TRY(ext_buffer_pull_int32(pext, &r->standardbias));
	TRY(ext_buffer_pull_int32(pext, &r->daylightbias));
	TRY(ext_buffer_pull_systemtime(pext, &r->standarddate));
	return ext_buffer_pull_systemtime(pext, &r->daylightdate);
}

int ext_buffer_pull_timezonedefinition(EXT_PULL *pext, TIMEZONEDEFINITION *r)
{
	int i;
	uint16_t cbheader;
	char tmp_buff[262];
	uint16_t cchkeyname;
	char tmp_buff1[1024];
	
	TRY(ext_buffer_pull_uint8(pext, &r->major));
	TRY(ext_buffer_pull_uint8(pext, &r->minor));
	TRY(ext_buffer_pull_uint16(pext, &cbheader));
	if (cbheader > 266) {
		return EXT_ERR_FORMAT;
	}
	TRY(ext_buffer_pull_uint16(pext, &r->reserved));
	TRY(ext_buffer_pull_uint16(pext, &cchkeyname));
	if (cbheader != 6 + 2*cchkeyname) {
		return EXT_ERR_FORMAT;
	}
	memset(tmp_buff, 0, sizeof(tmp_buff));
	TRY(ext_buffer_pull_bytes(pext, tmp_buff, cbheader - 6));
	if (FALSE == utf16le_to_utf8(tmp_buff, cbheader - 4, tmp_buff1, 1024)) {
		return EXT_ERR_CHARCNV;
	}
	r->keyname = pext->anew<char>(strlen(tmp_buff1) + 1);
	if (NULL == r->keyname) {
		return EXT_ERR_ALLOC;
	}
	strcpy(r->keyname, tmp_buff1);
	TRY(ext_buffer_pull_uint16(pext, &r->crules));
	r->prules = pext->anew<TZRULE>(r->crules);
	if (NULL == r->prules) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->crules; i++) {
		TRY(ext_buffer_pull_tzrule(pext, r->prules + i));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_patterntypespecific(EXT_PULL *pext,
	uint16_t patterntype, PATTERNTYPESPECIFIC *r)
{
	switch (patterntype) {
	case PATTERNTYPE_DAY:
		/* do nothing */
		return EXT_ERR_SUCCESS;
	case PATTERNTYPE_WEEK:
		return ext_buffer_pull_uint32(pext, &r->weekrecurrence);
	case PATTERNTYPE_MONTH:
	case PATTERNTYPE_MONTHEND:
	case PATTERNTYPE_HJMONTH:
	case PATTERNTYPE_HJMONTHEND:
		return ext_buffer_pull_uint32(pext, &r->dayofmonth);
	case PATTERNTYPE_MONTHNTH:
	case PATTERNTYPE_HJMONTHNTH:
		TRY(ext_buffer_pull_uint32(pext, &r->monthnth.weekrecurrence));
		return ext_buffer_pull_uint32(pext,
				&r->monthnth.recurrencenum);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

static int ext_buffer_pull_recurrencepattern(
	EXT_PULL *pext, RECURRENCEPATTERN *r)
{
	int i;
	
	TRY(ext_buffer_pull_uint16(pext, &r->readerversion));
	TRY(ext_buffer_pull_uint16(pext, &r->writerversion));
	TRY(ext_buffer_pull_uint16(pext, &r->recurfrequency));
	TRY(ext_buffer_pull_uint16(pext, &r->patterntype));
	TRY(ext_buffer_pull_uint16(pext, &r->calendartype));
	TRY(ext_buffer_pull_uint32(pext, &r->firstdatetime));
	TRY(ext_buffer_pull_uint32(pext, &r->period));
	TRY(ext_buffer_pull_uint32(pext, &r->slidingflag));
	TRY(ext_buffer_pull_patterntypespecific(pext, r->patterntype, &r->patterntypespecific));
	TRY(ext_buffer_pull_uint32(pext, &r->endtype));
	TRY(ext_buffer_pull_uint32(pext, &r->occurrencecount));
	TRY(ext_buffer_pull_uint32(pext, &r->firstdow));
	TRY(ext_buffer_pull_uint32(pext, &r->deletedinstancecount));
	if (0 == r->deletedinstancecount) {
		r->pdeletedinstancedates = NULL;
	} else {
		r->pdeletedinstancedates = pext->anew<uint32_t>(r->deletedinstancecount);
		if (NULL == r->pdeletedinstancedates) {
			return EXT_ERR_ALLOC;
		}
	}
	for (i=0; i<r->deletedinstancecount; i++) {
		TRY(ext_buffer_pull_uint32(pext, &r->pdeletedinstancedates[i]));
	}
	TRY(ext_buffer_pull_uint32(pext, &r->modifiedinstancecount));
	if (0 == r->modifiedinstancecount) {
		r->pmodifiedinstancedates = NULL;
	} else {
		r->pmodifiedinstancedates = pext->anew<uint32_t>(r->modifiedinstancecount);
		if (NULL == r->pmodifiedinstancedates) {
			return EXT_ERR_ALLOC;
		}
	}
	for (i=0; i<r->modifiedinstancecount; i++) {
		TRY(ext_buffer_pull_uint32(pext, &r->pmodifiedinstancedates[i]));
	}
	TRY(ext_buffer_pull_uint32(pext, &r->startdate));
	return ext_buffer_pull_uint32(pext, &r->enddate);
}

static int ext_buffer_pull_exceptioninfo(EXT_PULL *pext, EXCEPTIONINFO *r)
{
	uint16_t tmp_len;
	uint16_t tmp_len2;
	
	TRY(ext_buffer_pull_uint32(pext, &r->startdatetime));
	TRY(ext_buffer_pull_uint32(pext, &r->enddatetime));
	TRY(ext_buffer_pull_uint32(pext, &r->originalstartdate));
	TRY(ext_buffer_pull_uint16(pext, &r->overrideflags));
	if (r->overrideflags & OVERRIDEFLAG_SUBJECT) {
		TRY(ext_buffer_pull_uint16(pext, &tmp_len));
		TRY(ext_buffer_pull_uint16(pext, &tmp_len2));
		if (tmp_len != tmp_len2 + 1) {
			return EXT_ERR_FORMAT;
		}
		r->subject = pext->anew<char>(tmp_len);
		if (NULL == r->subject) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_bytes(pext, r->subject, tmp_len2));
		r->subject[tmp_len2] = '\0';
	}
	if (r->overrideflags & OVERRIDEFLAG_MEETINGTYPE) {
		TRY(ext_buffer_pull_uint32(pext, &r->meetingtype));
	}
	if (r->overrideflags & OVERRIDEFLAG_REMINDERDELTA) {
		TRY(ext_buffer_pull_uint32(pext, &r->reminderdelta));
	}
	if (r->overrideflags & OVERRIDEFLAG_REMINDER) {
		TRY(ext_buffer_pull_uint32(pext, &r->reminderset));
	}
	if (r->overrideflags & OVERRIDEFLAG_LOCATION) {
		TRY(ext_buffer_pull_uint16(pext, &tmp_len));
		TRY(ext_buffer_pull_uint16(pext, &tmp_len2));
		if (tmp_len != tmp_len2 + 1) {
			return EXT_ERR_FORMAT;
		}
		r->location = pext->anew<char>(tmp_len);
		if (NULL == r->location) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_bytes(pext, r->location, tmp_len2));
		r->location[tmp_len2] = '\0';
	}
	if (r->overrideflags & OVERRIDEFLAG_BUSYSTATUS) {
		TRY(ext_buffer_pull_uint32(pext, &r->busystatus));
	}
	if (r->overrideflags & OVERRIDEFLAG_ATTACHMENT) {
		TRY(ext_buffer_pull_uint32(pext, &r->attachment));
	}
	if (r->overrideflags & OVERRIDEFLAG_SUBTYPE) {
		TRY(ext_buffer_pull_uint32(pext, &r->subtype));
	}
	if (r->overrideflags & OVERRIDEFLAG_APPTCOLOR) {
		TRY(ext_buffer_pull_uint32(pext, &r->appointmentcolor));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_changehighlight(
	EXT_PULL *pext, CHANGEHIGHLIGHT *r)
{
	TRY(ext_buffer_pull_uint32(pext, &r->size));
	TRY(ext_buffer_pull_uint32(pext, &r->value));
	if (r->size < sizeof(uint32_t)) {
		return EXT_ERR_FORMAT;
	} else if (sizeof(uint32_t) == r->size) {
		r->preserved = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->preserved = pext->anew<uint8_t>(r->size - sizeof(uint32_t));
	if (NULL == r->preserved) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_bytes(pext, r->preserved,
						r->size - sizeof(uint32_t));
}

static int ext_buffer_pull_extendedexception(
	EXT_PULL *pext, uint32_t writerversion2,
	uint16_t overrideflags, EXTENDEDEXCEPTION *r)
{
	int string_len;
	uint16_t tmp_len;
	
	if (writerversion2 >= 0x00003009) {
		TRY(ext_buffer_pull_changehighlight(pext, &r->changehighlight));
	}
	TRY(ext_buffer_pull_uint32(pext, &r->reservedblockee1size));
	if (0 == r->reservedblockee1size) {
		r->preservedblockee1 = NULL;
	} else {
		r->preservedblockee1 = pext->anew<uint8_t>(r->reservedblockee1size);
		if (NULL == r->preservedblockee1) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_bytes(pext, r->preservedblockee1, r->reservedblockee1size));
	}
	if ((overrideflags & OVERRIDEFLAG_LOCATION) ||
		(overrideflags & OVERRIDEFLAG_SUBJECT)) {
		TRY(ext_buffer_pull_uint32(pext, &r->startdatetime));
		TRY(ext_buffer_pull_uint32(pext, &r->enddatetime));
		TRY(ext_buffer_pull_uint32(pext, &r->originalstartdate));
	}
	if (overrideflags & OVERRIDEFLAG_SUBJECT) {
		TRY(ext_buffer_pull_uint16(pext, &tmp_len));
		tmp_len *= 2;
		std::unique_ptr<char[]> pbuff;
		try {
			pbuff = std::make_unique<char[]>(3 * (tmp_len + 2));
		} catch (const std::bad_alloc &) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_bytes(pext, pbuff.get(), tmp_len));
		pbuff[tmp_len ++] = '\0';
		pbuff[tmp_len ++] = '\0';
		if (!utf16le_to_utf8(pbuff.get(), tmp_len, &pbuff[tmp_len], 2 * tmp_len))
			return EXT_ERR_CHARCNV;
		string_len = strlen(&pbuff[tmp_len]);
		r->subject = pext->anew<char>(string_len + 1);
		if (NULL == r->subject) {
			return EXT_ERR_ALLOC;
		}
		strcpy(r->subject, &pbuff[tmp_len]);
	}
	if (overrideflags & OVERRIDEFLAG_LOCATION) {
		TRY(ext_buffer_pull_uint16(pext, &tmp_len));
		tmp_len *= 2;
		std::unique_ptr<char[]> pbuff;
		try {
			pbuff = std::make_unique<char[]>(3 * (tmp_len + 2));
		} catch (const std::bad_alloc &) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_bytes(pext, pbuff.get(), tmp_len));
		pbuff[tmp_len ++] = '\0';
		pbuff[tmp_len ++] = '\0';
		if (!utf16le_to_utf8(pbuff.get(), tmp_len, &pbuff[tmp_len], 2 * tmp_len))
			return EXT_ERR_CHARCNV;
		string_len = strlen(&pbuff[tmp_len]);
		r->location = pext->anew<char>(string_len + 1);
		if (NULL == r->location) {
			return EXT_ERR_ALLOC;
		}
		strcpy(r->location, &pbuff[tmp_len]);
	}
	if ((overrideflags & OVERRIDEFLAG_LOCATION) ||
		(overrideflags & OVERRIDEFLAG_SUBJECT)) {
		TRY(ext_buffer_pull_uint32(pext, &r->reservedblockee2size));
		if (0 == r->reservedblockee2size) {
			r->preservedblockee2 = NULL;
		} else {
			r->preservedblockee2 = pext->anew<uint8_t>(r->reservedblockee2size);
			if (NULL == r->preservedblockee2) {
				return EXT_ERR_ALLOC;
			}
			TRY(ext_buffer_pull_bytes(pext, r->preservedblockee2, r->reservedblockee2size));
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_appointmentrecurrencepattern(
	EXT_PULL *pext, APPOINTMENTRECURRENCEPATTERN *r)
{
	int i;
	
	TRY(ext_buffer_pull_recurrencepattern(pext, &r->recurrencepattern));
	TRY(ext_buffer_pull_uint32(pext, &r->readerversion2));
	TRY(ext_buffer_pull_uint32(pext, &r->writerversion2));
	TRY(ext_buffer_pull_uint32(pext, &r->starttimeoffset));
	TRY(ext_buffer_pull_uint32(pext, &r->endtimeoffset));
	TRY(ext_buffer_pull_uint16(pext, &r->exceptioncount));
	if (0 == r->exceptioncount) {
		r->pexceptioninfo = NULL;
		r->pextendedexception = NULL;
	} else {
		r->pexceptioninfo = pext->anew<EXCEPTIONINFO>(r->exceptioncount);
		if (NULL == r->pexceptioninfo) {
			return EXT_ERR_ALLOC;
		}
		r->pextendedexception = pext->anew<EXTENDEDEXCEPTION>(r->exceptioncount);
		if (NULL == r->pextendedexception) {
			return EXT_ERR_ALLOC;
		}
	}
	for (i=0; i<r->exceptioncount; i++) {
		TRY(ext_buffer_pull_exceptioninfo(pext, &r->pexceptioninfo[i]));
	}
	TRY(ext_buffer_pull_uint32(pext, &r->reservedblock1size));
	if (0 == r->reservedblock1size) {
		r->preservedblock1 = NULL;
	} else {
		r->preservedblock1 = pext->anew<uint8_t>(r->reservedblock1size);
		if (NULL == r->preservedblock1) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_bytes(pext, r->preservedblock1, r->reservedblock1size));
	}
	for (i=0; i<r->exceptioncount; i++) {
		TRY(ext_buffer_pull_extendedexception(pext, r->writerversion2, r->pexceptioninfo[i].overrideflags, &r->pextendedexception[i]));
	}
	TRY(ext_buffer_pull_uint32(pext, &r->reservedblock2size));
	if (0 == r->reservedblock2size) {
		r->preservedblock2 = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->preservedblock2 = pext->anew<uint8_t>(r->reservedblock2size);
	if (NULL == r->preservedblock2) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_bytes(pext,
			r->preservedblock2,
			r->reservedblock2size);
}

int ext_buffer_pull_globalobjectid(EXT_PULL *pext, GLOBALOBJECTID *r)
{
	uint8_t yh;
	uint8_t yl;
	
	TRY(ext_buffer_pull_bytes(pext, r->arrayid, 16));
	TRY(ext_buffer_pull_uint8(pext, &yh));
	TRY(ext_buffer_pull_uint8(pext, &yl));
	r->year = ((uint16_t)yh) << 8 | yl;
	TRY(ext_buffer_pull_uint8(pext, &r->month));
	TRY(ext_buffer_pull_uint8(pext, &r->day));
	TRY(ext_buffer_pull_uint64(pext, &r->creationtime));
	TRY(ext_buffer_pull_bytes(pext, r->x, 8));
	return ext_buffer_pull_exbinary(pext, &r->data);
}

static int ext_buffer_pull_attachment_list(EXT_PULL *pext, ATTACHMENT_LIST *r)
{
	int i;
	uint8_t tmp_byte;
	
	TRY(ext_buffer_pull_uint16(pext, &r->count));
	r->pplist = pext->anew<ATTACHMENT_CONTENT *>(r->count);
	if (NULL == r->pplist) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		r->pplist[i] = pext->anew<ATTACHMENT_CONTENT>();
		if (NULL == r->pplist[i]) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_tpropval_array(pext, &r->pplist[i]->proplist));
		TRY(ext_buffer_pull_uint8(pext, &tmp_byte));
		if (0 != tmp_byte) {
			r->pplist[i]->pembedded = pext->anew<MESSAGE_CONTENT>();
			if (NULL == r->pplist[i]->pembedded) {
				return EXT_ERR_ALLOC;
			}
			TRY(ext_buffer_pull_message_content(pext, r->pplist[i]->pembedded));
		} else {
			r->pplist[i]->pembedded = NULL;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_message_content(EXT_PULL *pext, MESSAGE_CONTENT *r)
{
	uint8_t tmp_byte;
	
	TRY(ext_buffer_pull_tpropval_array(pext, &r->proplist));
	TRY(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 != tmp_byte) {
		r->children.prcpts = pext->anew<TARRAY_SET>();
		if (NULL == r->children.prcpts) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_tarray_set(pext, r->children.prcpts));
	} else {
		r->children.prcpts = NULL;
	}
	TRY(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 != tmp_byte) {
		r->children.pattachments = pext->anew<ATTACHMENT_LIST>();
		if (NULL == r->children.pattachments) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_attachment_list(
				pext, r->children.pattachments);
	}
	r->children.pattachments = NULL;
	return EXT_ERR_SUCCESS;
}

BOOL ext_buffer_push_init(EXT_PUSH *pext, void *pdata,
	uint32_t alloc_size, uint32_t flags)
{
	if (NULL == pdata) {
		pext->b_alloc = TRUE;
		if (0 == alloc_size) {
			pext->alloc_size = alloc_size;
		} else {
			pext->alloc_size = GROWING_BLOCK_SIZE;
		}
		pext->data = static_cast<uint8_t *>(malloc(pext->alloc_size));
		if (NULL == pext->data) {
			return FALSE;
		}
	} else {
		pext->b_alloc = FALSE;
		pext->data = static_cast<uint8_t *>(pdata);
		pext->alloc_size = alloc_size;
	}
	pext->offset = 0;
	pext->flags = flags;
	return TRUE;
}

void ext_buffer_push_free(EXT_PUSH *pext)
{
	if (TRUE == pext->b_alloc) {
		free(pext->data);
	}
}

int ext_buffer_push_rpc_header_ext(EXT_PUSH *pext, const RPC_HEADER_EXT *r)
{
	TRY(ext_buffer_push_uint16(pext, r->version));
	TRY(ext_buffer_push_uint16(pext, r->flags));
	TRY(ext_buffer_push_uint16(pext, r->size));
	return ext_buffer_push_uint16(pext, r->size_actual);
}

/* FALSE: overflow, TRUE: not overflow */
BOOL ext_buffer_push_check_overflow(EXT_PUSH *pext, uint32_t extra_size)
{
	uint32_t size;
	uint32_t alloc_size;
	
	size = extra_size + pext->offset;
	if (pext->alloc_size >= size) {
		return TRUE;
	}
	if (FALSE == pext->b_alloc) {
		return FALSE;
	}
	for (alloc_size=pext->alloc_size; alloc_size<size;
		alloc_size+=GROWING_BLOCK_SIZE);
	auto pdata = static_cast<uint8_t *>(realloc(pext->data, alloc_size));
	if (NULL == pdata) {
		return FALSE;
	}
	pext->data = pdata;
	pext->alloc_size = alloc_size;
	return TRUE;
}

int ext_buffer_push_advance(EXT_PUSH *pext, uint32_t size)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, size)) {
		return EXT_ERR_BUFSIZE;
	}
	pext->offset += size;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_bytes(EXT_PUSH *pext, const void *pdata, uint32_t n)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, n)) {
		return EXT_ERR_BUFSIZE;
	}
	memcpy(pext->data + pext->offset, pdata, n);
	pext->offset += n;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_int8(EXT_PUSH *pext, int8_t v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(int8_t))) {
		return EXT_ERR_BUFSIZE;
	}
	SCVAL(pext->data, pext->offset, (uint8_t)v);
	pext->offset += sizeof(int8_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_uint8(EXT_PUSH *pext, uint8_t v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(uint8_t))) {
		return EXT_ERR_BUFSIZE;
	}
	SCVAL(pext->data, pext->offset, v);
	pext->offset += sizeof(uint8_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_int16(EXT_PUSH *pext, int16_t v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(int16_t))) {
		return EXT_ERR_BUFSIZE;
	}
	EXT_SSVAL(pext, pext->offset, (uint16_t)v);
	pext->offset += sizeof(int16_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_uint16(EXT_PUSH *pext, uint16_t v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(uint16_t))) {
		return EXT_ERR_BUFSIZE;
	}
	EXT_SSVAL(pext, pext->offset, v);
	pext->offset += sizeof(uint16_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_int32(EXT_PUSH *pext, int32_t v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(int32_t))) {
		return EXT_ERR_BUFSIZE;
	}
	EXT_SIVALS(pext, pext->offset, v);
	pext->offset += sizeof(int32_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_uint32(EXT_PUSH *pext, uint32_t v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(uint32_t))) {
		return EXT_ERR_BUFSIZE;
	}
	EXT_SIVAL(pext, pext->offset, v);
	pext->offset += sizeof(uint32_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_uint64(EXT_PUSH *pext, uint64_t v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(uint64_t))) {
		return EXT_ERR_BUFSIZE;
	}
	EXT_SIVAL(pext, pext->offset, (v & 0xFFFFFFFF));
	EXT_SIVAL(pext, pext->offset+4, (v>>32));
	pext->offset += sizeof(uint64_t);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_float(EXT_PUSH *pext, float v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(float))) {
		return EXT_ERR_BUFSIZE;
	}
	memcpy(pext->data + pext->offset, &v, 4);
	pext->offset += sizeof(float);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_double(EXT_PUSH *pext, double v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(double))) {
		return EXT_ERR_BUFSIZE;
	}
	memcpy(pext->data + pext->offset, &v, 8);
	pext->offset += sizeof(double);
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_bool(EXT_PUSH *pext, BOOL v)
{
	uint8_t tmp_byte;
	
	if (TRUE == v) {
		tmp_byte = 1;
	} else if (FALSE == v) {
		tmp_byte = 0;
	} else {
		return EXT_ERR_FORMAT;
	}
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(uint8_t))) {
		return EXT_ERR_BUFSIZE;
	}
	SCVAL(pext->data, pext->offset, tmp_byte);
	pext->offset += sizeof(uint8_t);
	return EXT_ERR_SUCCESS;
	
}

int ext_buffer_push_data_blob(EXT_PUSH *pext, DATA_BLOB blob)
{
	return ext_buffer_push_bytes(pext, blob.data, blob.length);
}

int ext_buffer_push_binary(EXT_PUSH *pext, const BINARY *r)
{
	if (pext->flags & EXT_FLAG_WCOUNT) {
		TRY(ext_buffer_push_uint32(pext, r->cb));
	} else {
		if (r->cb > 0xFFFF) {
			return EXT_ERR_FORMAT;
		}
		TRY(ext_buffer_push_uint16(pext, r->cb));
	}
	if (0 == r->cb) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_push_bytes(pext, r->pb, r->cb);
}

int ext_buffer_push_sbinary(EXT_PUSH *pext, const BINARY *r)
{
	if (r->cb > 0xFFFF) {
		return EXT_ERR_FORMAT;
	}
	TRY(ext_buffer_push_uint16(pext, r->cb));
	if (0 == r->cb) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_push_bytes(pext, r->pb, r->cb);
}

int ext_buffer_push_exbinary(EXT_PUSH *pext, const BINARY *r)
{
	TRY(ext_buffer_push_uint32(pext, r->cb));
	if (0 == r->cb) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_push_bytes(pext, r->pb, r->cb);
}

int ext_buffer_push_guid(EXT_PUSH *pext, const GUID *r)
{
	TRY(ext_buffer_push_uint32(pext, r->time_low));
	TRY(ext_buffer_push_uint16(pext, r->time_mid));
	TRY(ext_buffer_push_uint16(pext, r->time_hi_and_version));
	TRY(ext_buffer_push_bytes(pext, r->clock_seq, 2));
	return ext_buffer_push_bytes(pext, r->node, 6);
}

int ext_buffer_push_string(EXT_PUSH *pext, const char *pstr)
{
	size_t len = strlen(pstr);
	if (pext->flags & EXT_FLAG_TBLLMT) {
		if (len > 509) {
			TRY(ext_buffer_push_bytes(pext, pstr, 509));
			return ext_buffer_push_uint8(pext, 0);
		}
	}
	return ext_buffer_push_bytes(pext, pstr, len + 1);
}

int ext_buffer_push_wstring(EXT_PUSH *pext, const char *pstr)
{
	int len;
	
	if (0 == (pext->flags & EXT_FLAG_UTF16)) {
		return ext_buffer_push_string(pext, pstr);
	}
	len = 2*strlen(pstr) + 2;
	std::unique_ptr<char[]> pbuff;
	try {
		pbuff = std::make_unique<char[]>(len);
	} catch (const std::bad_alloc &) {
		return EXT_ERR_ALLOC;
	}
	len = utf8_to_utf16le(pstr, pbuff.get(), len);
	if (len < 2) {
		pbuff[0] = '\0';
		pbuff[1] = '\0';
		len = 2;
	}
	if (pext->flags & EXT_FLAG_TBLLMT) {
		if (len > 510) {
			len = 510;
			pbuff[508] = '\0';
			pbuff[509] = '\0';
		}
	}
	return ext_buffer_push_bytes(pext, pbuff.get(), len);
}

int ext_buffer_push_short_array(EXT_PUSH *pext, const SHORT_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint32(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_uint16(pext, r->ps[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_long_array(EXT_PUSH *pext, const LONG_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint32(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_uint32(pext, r->pl[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_longlong_array(EXT_PUSH *pext, const LONGLONG_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint32(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_uint64(pext, r->pll[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_slonglong_array(EXT_PUSH *pext, const LONGLONG_ARRAY *r)
{
	int i;
	
	if (r->count > 0xFFFF) {
		return EXT_ERR_FORMAT;
	}
	TRY(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_uint64(pext, r->pll[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_binary_array(EXT_PUSH *pext, const BINARY_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint32(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_binary(pext, &r->pbin[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_string_array(EXT_PUSH *pext, const STRING_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint32(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_string(pext, r->ppstr[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_wstring_array(EXT_PUSH *pext, const STRING_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint32(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_wstring(pext, r->ppstr[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_guid_array(EXT_PUSH *pext, const GUID_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint32(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_guid(pext, &r->pguid[i]));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_restriction_and_or(
	EXT_PUSH *pext, const RESTRICTION_AND_OR *r)
{
	int i;
	
	if (pext->flags & EXT_FLAG_WCOUNT) {
		TRY(ext_buffer_push_uint32(pext, r->count));
	} else {
		TRY(ext_buffer_push_uint16(pext, r->count));
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_restriction(pext, &r->pres[i]));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_restriction_not(
	EXT_PUSH *pext, const RESTRICTION_NOT *r)
{
	return ext_buffer_push_restriction(pext, &r->res);
}

static int ext_buffer_push_restriction_content(
	EXT_PUSH *pext, const RESTRICTION_CONTENT *r)
{
	TRY(ext_buffer_push_uint32(pext, r->fuzzy_level));
	TRY(ext_buffer_push_uint32(pext, r->proptag));
	return ext_buffer_push_tagged_propval(pext, &r->propval);
}

static int ext_buffer_push_restriction_property(
	EXT_PUSH *pext, const RESTRICTION_PROPERTY *r)
{
	TRY(ext_buffer_push_uint8(pext, r->relop));
	TRY(ext_buffer_push_uint32(pext, r->proptag));
	return ext_buffer_push_tagged_propval(pext, &r->propval);
}

static int ext_buffer_push_restriction_propcompare(
	EXT_PUSH *pext, const RESTRICTION_PROPCOMPARE *r)
{
	TRY(ext_buffer_push_uint8(pext, r->relop));
	TRY(ext_buffer_push_uint32(pext, r->proptag1));
	return ext_buffer_push_uint32(pext, r->proptag2);
}

static int ext_buffer_push_restriction_bitmask(
	EXT_PUSH *pext, const RESTRICTION_BITMASK *r)
{
	TRY(ext_buffer_push_uint8(pext, r->bitmask_relop));
	TRY(ext_buffer_push_uint32(pext, r->proptag));
	return ext_buffer_push_uint32(pext, r->mask);
}

static int ext_buffer_push_restriction_size(
	EXT_PUSH *pext, const RESTRICTION_SIZE *r)
{
	TRY(ext_buffer_push_uint8(pext, r->relop));
	TRY(ext_buffer_push_uint32(pext, r->proptag));
	return ext_buffer_push_uint32(pext, r->size);
}

static int ext_buffer_push_restriction_exist(
	EXT_PUSH *pext, const RESTRICTION_EXIST *r)
{
	return ext_buffer_push_uint32(pext, r->proptag);
}

static int ext_buffer_push_restriction_subobj(
	EXT_PUSH *pext, const RESTRICTION_SUBOBJ *r)
{
	TRY(ext_buffer_push_uint32(pext, r->subobject));
	return ext_buffer_push_restriction(pext, &r->res);
}

static int ext_buffer_push_restriction_comment(
	EXT_PUSH *pext, const RESTRICTION_COMMENT *r)
{
	int i;
	
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	TRY(ext_buffer_push_uint8(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_tagged_propval(pext, &r->ppropval[i]));
	}
	if (NULL != r->pres) {
		TRY(ext_buffer_push_uint8(pext, 1));
		return ext_buffer_push_restriction(pext, r->pres);
	}
	return ext_buffer_push_uint8(pext, 0);
}

static int ext_buffer_push_restriction_count(
	EXT_PUSH *pext, const RESTRICTION_COUNT *r)
{
	TRY(ext_buffer_push_uint32(pext, r->count));
	return ext_buffer_push_restriction(pext, &r->sub_res);
}

int ext_buffer_push_restriction(EXT_PUSH *pext, const RESTRICTION *r)
{
	TRY(ext_buffer_push_uint8(pext, r->rt));
	switch (r->rt) {
	case RES_AND:
	case RES_OR:
		return ext_buffer_push_restriction_and_or(pext, r->andor);
	case RES_NOT:
		return ext_buffer_push_restriction_not(pext, r->xnot);
	case RES_CONTENT:
		return ext_buffer_push_restriction_content(pext, r->cont);
	case RES_PROPERTY:
		return ext_buffer_push_restriction_property(pext, r->prop);
	case RES_PROPCOMPARE:
		return ext_buffer_push_restriction_propcompare(pext, r->pcmp);
	case RES_BITMASK:
		return ext_buffer_push_restriction_bitmask(pext, r->bm);
	case RES_SIZE:
		return ext_buffer_push_restriction_size(pext, r->size);
	case RES_EXIST:
		return ext_buffer_push_restriction_exist(pext, r->exist);
	case RES_SUBRESTRICTION:
		return ext_buffer_push_restriction_subobj(pext, r->sub);
	case RES_COMMENT:
		return ext_buffer_push_restriction_comment(pext, r->comment);
	case RES_COUNT:
		return ext_buffer_push_restriction_count(pext, r->count);
	case RES_NULL:
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int ext_buffer_push_svreid(EXT_PUSH *pext, const SVREID *r)
{
	if (NULL != r->pbin) {
		TRY(ext_buffer_push_uint16(pext, r->pbin->cb + 1));
		TRY(ext_buffer_push_uint8(pext, 0));
		return ext_buffer_push_bytes(pext, r->pbin->pb, r->pbin->cb);
	}
	TRY(ext_buffer_push_uint16(pext, 21));
	TRY(ext_buffer_push_uint8(pext, 1));
	TRY(ext_buffer_push_uint64(pext, r->folder_id));
	TRY(ext_buffer_push_uint64(pext, r->message_id));
	return ext_buffer_push_uint32(pext, r->instance);
}

int ext_buffer_push_store_entryid(EXT_PUSH *pext, const STORE_ENTRYID *r)
{
	TRY(ext_buffer_push_uint32(pext, r->flags));
	TRY(ext_buffer_push_bytes(pext, r->provider_uid, 16));
	TRY(ext_buffer_push_uint8(pext, r->version));
	TRY(ext_buffer_push_uint8(pext, r->flag));
	TRY(ext_buffer_push_bytes(pext, r->dll_name, 14));
	TRY(ext_buffer_push_uint32(pext, r->wrapped_flags));
	TRY(ext_buffer_push_bytes(pext, r->wrapped_provider_uid, 16));
	TRY(ext_buffer_push_uint32(pext, r->wrapped_type));
	TRY(ext_buffer_push_string(pext, r->pserver_name));
	return ext_buffer_push_string(pext, r->pmailbox_dn);
}

static int ext_buffer_push_movecopy_action(EXT_PUSH *pext,
    const MOVECOPY_ACTION *r)
{
	uint32_t offset;
	uint32_t offset1;
	uint16_t eid_size;
	
	TRY(ext_buffer_push_uint8(pext, r->same_store));
	if (0 == r->same_store) {
		offset = pext->offset;
		TRY(ext_buffer_push_advance(pext, sizeof(uint16_t)));
		if (NULL == r->pstore_eid) {
			return EXT_ERR_FORMAT;
		}
		TRY(ext_buffer_push_store_entryid(pext, r->pstore_eid));
		offset1 = pext->offset;
		eid_size = offset1 - (offset + sizeof(uint16_t));
		pext->offset = offset;
		TRY(ext_buffer_push_uint16(pext, eid_size));
		pext->offset = offset1;
	} else {
		TRY(ext_buffer_push_uint16(pext, 1));
		TRY(ext_buffer_push_uint8(pext, 0));
	}
	if (0 != r->same_store) {
		return ext_buffer_push_svreid(pext, static_cast<SVREID *>(r->pfolder_eid));
	} else {
		return ext_buffer_push_binary(pext, static_cast<BINARY *>(r->pfolder_eid));
	}
}

static int ext_buffer_push_reply_action(
	EXT_PUSH *pext, const REPLY_ACTION *r)
{
	TRY(ext_buffer_push_uint64(pext, r->template_folder_id));
	TRY(ext_buffer_push_uint64(pext, r->template_message_id));
	return ext_buffer_push_guid(pext, &r->template_guid);
}

static int ext_buffer_push_recipient_block(
	EXT_PUSH *pext, const RECIPIENT_BLOCK *r)
{
	int i;
	
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	TRY(ext_buffer_push_uint8(pext, r->reserved));
	TRY(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_tagged_propval(pext, &r->ppropval[i]));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_forwarddelegate_action(
	EXT_PUSH *pext, const FORWARDDELEGATE_ACTION *r)
{
	int i;
	
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	TRY(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_recipient_block(pext, &r->pblock[i]));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_action_block(
	EXT_PUSH *pext, const ACTION_BLOCK *r)
{
	uint32_t offset;
	uint32_t offset1;
	uint16_t tmp_len;
	
	offset = pext->offset;
	TRY(ext_buffer_push_advance(pext, sizeof(uint16_t)));
	TRY(ext_buffer_push_uint8(pext, r->type));
	TRY(ext_buffer_push_uint32(pext, r->flavor));
	TRY(ext_buffer_push_uint32(pext, r->flags));
	switch (r->type) {
	case ACTION_TYPE_OP_MOVE:
	case ACTION_TYPE_OP_COPY:
		TRY(ext_buffer_push_movecopy_action(pext, static_cast<MOVECOPY_ACTION *>(r->pdata)));
		break;
	case ACTION_TYPE_OP_REPLY:
	case ACTION_TYPE_OP_OOF_REPLY:
		TRY(ext_buffer_push_reply_action(pext, static_cast<REPLY_ACTION *>(r->pdata)));
		break;
	case ACTION_TYPE_OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - 2*sizeof(uint32_t);
		TRY(ext_buffer_push_bytes(pext, r->pdata, tmp_len));
		break;
	case ACTION_TYPE_OP_BOUNCE:
		TRY(ext_buffer_push_uint32(pext, *static_cast<uint32_t *>(r->pdata)));
		break;
	case ACTION_TYPE_OP_FORWARD:
	case ACTION_TYPE_OP_DELEGATE:
		TRY(ext_buffer_push_forwarddelegate_action(pext, static_cast<FORWARDDELEGATE_ACTION *>(r->pdata)));
		break;
	case ACTION_TYPE_OP_TAG:
		TRY(ext_buffer_push_tagged_propval(pext, static_cast<TAGGED_PROPVAL *>(r->pdata)));
	case ACTION_TYPE_OP_DELETE:
	case ACTION_TYPE_OP_MARK_AS_READ:
		break;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
	tmp_len = pext->offset - (offset + sizeof(uint16_t));
	offset1 = pext->offset;
	pext->offset = offset;
	TRY(ext_buffer_push_uint16(pext, tmp_len));
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_rule_actions(EXT_PUSH *pext, const RULE_ACTIONS *r)
{
	int i;
	
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	TRY(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_action_block(pext, &r->pblock[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_propval(EXT_PUSH *pext, uint16_t type, const void *pval)
{
	/* convert multi-value instance into single value */
	if ((type & MVI_FLAG) == MVI_FLAG)
		type &= ~MVI_FLAG;
	switch (type) {
	case PT_UNSPECIFIED:
		return ext_buffer_push_typed_propval(pext, static_cast<const TYPED_PROPVAL *>(pval));
	case PT_SHORT:
		return ext_buffer_push_uint16(pext, *(uint16_t*)pval);
	case PT_LONG:
	case PT_ERROR:
		return ext_buffer_push_uint32(pext, *(uint32_t*)pval);
	case PT_FLOAT:
		return ext_buffer_push_float(pext, *(float*)pval);
	case PT_DOUBLE:
	case PT_APPTIME:
		return ext_buffer_push_double(pext, *(double*)pval);
	case PT_BOOLEAN:
		return ext_buffer_push_uint8(pext, *(uint8_t*)pval);
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		return ext_buffer_push_uint64(pext, *(uint64_t*)pval);
	case PT_STRING8:
		return ext_buffer_push_string(pext, static_cast<const char *>(pval));
	case PT_UNICODE:
		return ext_buffer_push_wstring(pext, static_cast<const char *>(pval));
	case PT_CLSID:
		return ext_buffer_push_guid(pext, static_cast<const GUID *>(pval));
	case PT_SVREID:
		return ext_buffer_push_svreid(pext, static_cast<const SVREID *>(pval));
	case PT_SRESTRICT:
		return ext_buffer_push_restriction(pext, static_cast<const RESTRICTION *>(pval));
	case PT_ACTIONS:
		return ext_buffer_push_rule_actions(pext, static_cast<const RULE_ACTIONS *>(pval));
	case PT_BINARY:
	case PT_OBJECT:
		return ext_buffer_push_binary(pext, static_cast<const BINARY *>(pval));
	case PT_MV_SHORT:
		return ext_buffer_push_short_array(pext, static_cast<const SHORT_ARRAY *>(pval));
	case PT_MV_LONG:
		return ext_buffer_push_long_array(pext, static_cast<const LONG_ARRAY *>(pval));
	case PT_MV_I8:
		return ext_buffer_push_longlong_array(pext, static_cast<const LONGLONG_ARRAY *>(pval));
	case PT_MV_STRING8:
		return ext_buffer_push_string_array(pext, static_cast<const STRING_ARRAY *>(pval));
	case PT_MV_UNICODE:
		return ext_buffer_push_wstring_array(pext, static_cast<const STRING_ARRAY *>(pval));
	case PT_MV_CLSID:
		return ext_buffer_push_guid_array(pext, static_cast<const GUID_ARRAY *>(pval));
	case PT_MV_BINARY:
		return ext_buffer_push_binary_array(pext, static_cast<const BINARY_ARRAY *>(pval));
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int ext_buffer_push_typed_propval(EXT_PUSH *pext, const TYPED_PROPVAL *r)
{
	TRY(ext_buffer_push_uint16(pext, r->type));
	return ext_buffer_push_propval(pext, r->type, r->pvalue);
}

int ext_buffer_push_tagged_propval(EXT_PUSH *pext, const TAGGED_PROPVAL *r)
{
	TRY(ext_buffer_push_uint32(pext, r->proptag));
	return ext_buffer_push_propval(pext, PROP_TYPE(r->proptag), r->pvalue);
}

int ext_buffer_push_long_term_id(EXT_PUSH *pext, const LONG_TERM_ID *r)
{
	TRY(ext_buffer_push_guid(pext, &r->guid));
	TRY(ext_buffer_push_bytes(pext, r->global_counter, 6));
	return ext_buffer_push_uint16(pext, r->padding);
}

int ext_buffer_push_long_term_id_array(
	EXT_PUSH *pext, const LONG_TERM_ID_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_long_term_id(pext, &r->pids[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_proptag_array(EXT_PUSH *pext, const PROPTAG_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_uint32(pext, r->pproptag[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_property_name(EXT_PUSH *pext, const PROPERTY_NAME *r)
{
	uint32_t offset;
	uint32_t offset1;
	uint8_t name_size;
	
	TRY(ext_buffer_push_uint8(pext, r->kind));
	TRY(ext_buffer_push_guid(pext, &r->guid));
	if (r->kind == MNID_ID) {
		TRY(ext_buffer_push_uint32(pext, *r->plid));
	} else if (r->kind == MNID_STRING) {
		offset = pext->offset;
		TRY(ext_buffer_push_advance(pext, sizeof(uint8_t)));
		TRY(ext_buffer_push_wstring(pext, r->pname));
		name_size = pext->offset - (offset + sizeof(uint8_t));
		offset1 = pext->offset;
		pext->offset = offset;
		TRY(ext_buffer_push_uint8(pext, name_size));
		pext->offset = offset1;
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_propname_array(EXT_PUSH *pext, const PROPNAME_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_property_name(pext, r->ppropname + i));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_propid_array(EXT_PUSH *pext, const PROPID_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_uint16(pext, r->ppropid[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_tpropval_array(EXT_PUSH *pext, const TPROPVAL_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_tagged_propval(pext, r->ppropval + i));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_tarray_set(EXT_PUSH *pext, const TARRAY_SET *r)
{
	int i;
	
	TRY(ext_buffer_push_uint32(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_tpropval_array(pext, r->pparray[i]));
	}
	return EXT_ERR_SUCCESS;
}


static int ext_buffer_push_property_problem(EXT_PUSH *pext, const PROPERTY_PROBLEM *r)
{
	TRY(ext_buffer_push_uint16(pext, r->index));
	TRY(ext_buffer_push_uint32(pext, r->proptag));
	return ext_buffer_push_uint32(pext, r->err);
}

int ext_buffer_push_problem_array(EXT_PUSH *pext, const PROBLEM_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_property_problem(pext, r->pproblem + i));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_xid(EXT_PUSH *pext, uint8_t size, const XID *pxid)
{
	if (size < 17 || size > 24) {
		return EXT_ERR_FORMAT;
	}
	TRY(ext_buffer_push_guid(pext, &pxid->guid));
	return ext_buffer_push_bytes(pext, pxid->local_id, size - 16);
}

int ext_buffer_push_folder_entryid(
	EXT_PUSH *pext, const FOLDER_ENTRYID *r)
{
	TRY(ext_buffer_push_uint32(pext, r->flags));
	TRY(ext_buffer_push_bytes(pext, r->provider_uid, 16));
	TRY(ext_buffer_push_uint16(pext, r->folder_type));
	TRY(ext_buffer_push_guid(pext, &r->database_guid));
	TRY(ext_buffer_push_bytes(pext, r->global_counter, 6));
	return ext_buffer_push_bytes(pext, r->pad, 2);
}

int ext_buffer_push_message_entryid(EXT_PUSH *pext, const MESSAGE_ENTRYID *r)
{
	TRY(ext_buffer_push_uint32(pext, r->flags));
	TRY(ext_buffer_push_bytes(pext, r->provider_uid, 16));
	TRY(ext_buffer_push_uint16(pext, r->message_type));
	TRY(ext_buffer_push_guid(pext, &r->folder_database_guid));
	TRY(ext_buffer_push_bytes(pext, r->folder_global_counter, 6));
	TRY(ext_buffer_push_bytes(pext, r->pad1, 2));
	TRY(ext_buffer_push_guid(pext, &r->message_database_guid));
	TRY(ext_buffer_push_bytes(pext, r->message_global_counter, 6));
	return ext_buffer_push_bytes(pext, r->pad2, 2);
}

int ext_buffer_push_flagged_propval(EXT_PUSH *pext,
	uint16_t type, const FLAGGED_PROPVAL *r)
{
	void *pvalue;
	
	if (type == PT_UNSPECIFIED) {
		if (FLAGGED_PROPVAL_FLAG_UNAVAILABLE == r->flag) {
			type = 0;
		} else if (FLAGGED_PROPVAL_FLAG_ERROR == r->flag) {
			type = PT_ERROR;
			pvalue = r->pvalue;
		} else {
			type = ((TYPED_PROPVAL*)r->pvalue)->type;
			pvalue = ((TYPED_PROPVAL*)r->pvalue)->pvalue;
		}
		TRY(ext_buffer_push_uint16(pext, type));
	} else {
		pvalue = r->pvalue;
	}
	TRY(ext_buffer_push_uint8(pext, r->flag));
	switch (r->flag) {
	case FLAGGED_PROPVAL_FLAG_AVAILABLE:
		return ext_buffer_push_propval(pext, type, pvalue);
	case FLAGGED_PROPVAL_FLAG_UNAVAILABLE:
		return EXT_ERR_SUCCESS;
	case FLAGGED_PROPVAL_FLAG_ERROR:
		return ext_buffer_push_uint32(pext, *(uint32_t*)pvalue);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int ext_buffer_push_property_row(EXT_PUSH *pext,
	const PROPTAG_ARRAY *pcolumns, const PROPERTY_ROW *r)
{
	int i;
	
	TRY(ext_buffer_push_uint8(pext, r->flag));
	if (PROPERTY_ROW_FLAG_NONE == r->flag) {
		for (i=0; i<pcolumns->count; i++) {
			TRY(ext_buffer_push_propval(pext, PROP_TYPE(pcolumns->pproptag[i]), r->pppropval[i]));
		}
		return EXT_ERR_SUCCESS;
	} else if (PROPERTY_ROW_FLAG_FLAGGED == r->flag) {
		for (i=0; i<pcolumns->count; i++) {
			TRY(ext_buffer_push_flagged_propval(pext, PROP_TYPE(pcolumns->pproptag[i]),
			         static_cast<FLAGGED_PROPVAL *>(r->pppropval[i])));
		}
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int ext_buffer_push_sort_order(EXT_PUSH *pext, const SORT_ORDER *r)
{
	if ((r->type & MVI_FLAG) == MV_FLAG)
		/* MV_FLAG set without MV_INSTANCE */
		return EXT_ERR_FORMAT;
	TRY(ext_buffer_push_uint16(pext, r->type));
	TRY(ext_buffer_push_uint16(pext, r->propid));
	return ext_buffer_push_uint8(pext, r->table_sort);
}

int ext_buffer_push_sortorder_set(EXT_PUSH *pext, const SORTORDER_SET *r)
{
	int i;
	
	if (0 == r->count || r->ccategories > r->count ||
		r->cexpanded > r->ccategories) {
		return EXT_ERR_FORMAT;
	}
	TRY(ext_buffer_push_uint16(pext, r->count));
	TRY(ext_buffer_push_uint16(pext, r->ccategories));
	TRY(ext_buffer_push_uint16(pext, r->cexpanded));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_sort_order(pext, r->psort + i));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_typed_string(EXT_PUSH *pext, const TYPED_STRING *r)
{
	TRY(ext_buffer_push_uint8(pext, r->string_type));
	switch(r->string_type) {
	case STRING_TYPE_NONE:
	case STRING_TYPE_EMPTY:
		return EXT_ERR_SUCCESS;
	case STRING_TYPE_STRING8:
	case STRING_TYPE_UNICODE_REDUCED:
		return ext_buffer_push_string(pext, r->pstring);
	case STRING_TYPE_UNICODE:
		return ext_buffer_push_wstring(pext, r->pstring);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int ext_buffer_push_recipient_row(EXT_PUSH *pext,
	const PROPTAG_ARRAY *pproptags, const RECIPIENT_ROW *r)
{
	BOOL b_unicode;
	PROPTAG_ARRAY proptags;
	
	b_unicode = FALSE;
	if (r->flags & RECIPIENT_ROW_FLAG_UNICODE) {
		b_unicode = TRUE;
	}
	TRY(ext_buffer_push_uint16(pext, r->flags));
	if (NULL != r->pprefix_used) {
		TRY(ext_buffer_push_uint8(pext, *r->pprefix_used));
	}
	if (NULL != r->pdisplay_type) {
		TRY(ext_buffer_push_uint8(pext, *r->pdisplay_type));
	}
	if (NULL != r->px500dn) {
		TRY(ext_buffer_push_string(pext, r->px500dn));
	}
	if (NULL != r->pentry_id) {
		TRY(ext_buffer_push_binary(pext, r->pentry_id));
	}
	if (NULL != r->psearch_key) {
		TRY(ext_buffer_push_binary(pext, r->psearch_key));
	}
	if (NULL != r->paddress_type) {
		TRY(ext_buffer_push_string(pext, r->paddress_type));
	}
	if (NULL != r->pmail_address) {
		if (TRUE == b_unicode) {
			TRY(ext_buffer_push_wstring(pext, r->pmail_address));
		} else {
			TRY(ext_buffer_push_string(pext, r->pmail_address));
		}
	}
	if (NULL != r->pdisplay_name) {
		if (TRUE == b_unicode) {
			TRY(ext_buffer_push_wstring(pext, r->pdisplay_name));
		} else {
			TRY(ext_buffer_push_string(pext, r->pdisplay_name));
		}
	}
	if (NULL != r->psimple_name) {
		if (TRUE == b_unicode) {
			TRY(ext_buffer_push_wstring(pext, r->psimple_name));
		} else {
			TRY(ext_buffer_push_string(pext, r->psimple_name));
		}
	}
	if (NULL != r->ptransmittable_name) {
		if (TRUE == b_unicode) {
			TRY(ext_buffer_push_wstring(pext, r->ptransmittable_name));
		} else {
			TRY(ext_buffer_push_string(pext, r->ptransmittable_name));
		}
	}
	TRY(ext_buffer_push_uint16(pext, r->count));
	if (r->count > pproptags->count) {
		return EXT_ERR_FORMAT;
	}
	proptags.count = r->count;
	proptags.pproptag = (uint32_t*)pproptags->pproptag;
	return ext_buffer_push_property_row(pext, &proptags, &r->properties);
}

int ext_buffer_push_openrecipient_row(EXT_PUSH *pext,
	const PROPTAG_ARRAY *pproptags, const OPENRECIPIENT_ROW *r)
{
	uint32_t offset;
	uint32_t offset1;
	uint16_t row_size;
	
	TRY(ext_buffer_push_uint8(pext, r->recipient_type));
	TRY(ext_buffer_push_uint16(pext, r->cpid));
	TRY(ext_buffer_push_uint16(pext, r->reserved));
	offset = pext->offset;
	TRY(ext_buffer_push_advance(pext, sizeof(uint16_t)));
	TRY(ext_buffer_push_recipient_row(pext, pproptags, &r->recipient_row));
	row_size = pext->offset - (offset + sizeof(uint16_t));
	offset1 = pext->offset;
	pext->offset = offset;
	TRY(ext_buffer_push_uint16(pext, row_size));
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_readrecipient_row(EXT_PUSH *pext,
	PROPTAG_ARRAY *pproptags, const READRECIPIENT_ROW *r)
{
	uint32_t offset;
	uint32_t offset1;
	uint16_t row_size;
	
	TRY(ext_buffer_push_uint32(pext, r->row_id));
	TRY(ext_buffer_push_uint8(pext, r->recipient_type));
	TRY(ext_buffer_push_uint16(pext, r->cpid));
	TRY(ext_buffer_push_uint16(pext, r->reserved));
	offset = pext->offset;
	TRY(ext_buffer_push_advance(pext, sizeof(uint16_t)));
	TRY(ext_buffer_push_recipient_row(pext, pproptags, &r->recipient_row));
	row_size = pext->offset - (offset + sizeof(uint16_t));
	offset1 = pext->offset;
	pext->offset = offset;
	TRY(ext_buffer_push_uint16(pext, row_size));
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_permission_data(EXT_PUSH *pext, const PERMISSION_DATA *r)
{
	TRY(ext_buffer_push_uint8(pext, r->flags));
	return ext_buffer_push_tpropval_array(pext, &r->propvals);
}

int ext_buffer_push_rule_data(EXT_PUSH *pext, const RULE_DATA *r)
{
	TRY(ext_buffer_push_uint8(pext, r->flags));
	return ext_buffer_push_tpropval_array(pext, &r->propvals);
}

int ext_buffer_push_addressbook_entryid(
	EXT_PUSH *pext, const ADDRESSBOOK_ENTRYID *r)
{
	TRY(ext_buffer_push_uint32(pext, r->flags));
	TRY(ext_buffer_push_bytes(pext, r->provider_uid, 16));
	TRY(ext_buffer_push_uint32(pext, r->version));
	TRY(ext_buffer_push_uint32(pext, r->type));
	return ext_buffer_push_string(pext, r->px500dn);
}

int ext_buffer_push_oneoff_entryid(EXT_PUSH *pext,
	const ONEOFF_ENTRYID *r)
{
	TRY(ext_buffer_push_uint32(pext, r->flags));
	TRY(ext_buffer_push_bytes(pext, r->provider_uid, 16));
	TRY(ext_buffer_push_uint16(pext, r->version));
	TRY(ext_buffer_push_uint16(pext, r->ctrl_flags));
	if (r->ctrl_flags & CTRL_FLAG_UNICODE) {
		TRY(ext_buffer_push_wstring(pext, r->pdisplay_name));
		TRY(ext_buffer_push_wstring(pext, r->paddress_type));
		return ext_buffer_push_wstring(pext, r->pmail_address);
	} else {
		TRY(ext_buffer_push_string(pext, r->pdisplay_name));
		TRY(ext_buffer_push_string(pext, r->paddress_type));
		return ext_buffer_push_string(pext, r->pmail_address);
	}
}

static int ext_buffer_push_persistelement(
	EXT_PUSH *pext, const PERSISTELEMENT *r)
{
	TRY(ext_buffer_push_uint16(pext, r->element_id));
	switch (r->element_id) {
	case RSF_ELID_HEADER:
		TRY(ext_buffer_push_uint16(pext, 4));
		return ext_buffer_push_uint32(pext, 0);
	case RSF_ELID_ENTRYID:
		return ext_buffer_push_binary(pext, r->pentry_id);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

static int ext_buffer_push_persistdata(EXT_PUSH *pext, const PERSISTDATA *r)
{
	uint32_t offset;
	uint32_t offset1;
	uint16_t tmp_size;
	
	TRY(ext_buffer_push_uint16(pext, r->persist_id));
	if (PERSIST_SENTINEL == r->persist_id) {
		return ext_buffer_push_uint16(pext, 0);
	}
	offset = pext->offset;
	TRY(ext_buffer_push_advance(pext, sizeof(uint16_t)));
	TRY(ext_buffer_push_persistelement(pext, &r->element));
	tmp_size = pext->offset - (offset + sizeof(uint16_t));
	offset1 = pext->offset;
	pext->offset = offset;
	TRY(ext_buffer_push_uint16(pext, tmp_size));
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_persistdata_array(
	EXT_PUSH *pext, const PERSISTDATA_ARRAY *r)
{
	int i;
	PERSISTDATA last_data;
	
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_persistdata(pext, r->ppitems[i]));
	}
	last_data.persist_id = PERSIST_SENTINEL;
	last_data.element.element_id = ELEMENT_SENTINEL;
	last_data.element.pentry_id = NULL;
	return ext_buffer_push_persistdata(pext, &last_data);
}

int ext_buffer_push_eid_array(EXT_PUSH *pext, const EID_ARRAY *r)
{
	int i;
	
	TRY(ext_buffer_push_uint32(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_uint64(pext, r->pids[i]));
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_systemtime(EXT_PUSH *pext, const SYSTEMTIME *r)
{
	TRY(ext_buffer_push_int16(pext, r->year));
	TRY(ext_buffer_push_int16(pext, r->month));
	TRY(ext_buffer_push_int16(pext, r->dayofweek));
	TRY(ext_buffer_push_int16(pext, r->day));
	TRY(ext_buffer_push_int16(pext, r->hour));
	TRY(ext_buffer_push_int16(pext, r->minute));
	TRY(ext_buffer_push_int16(pext, r->second));
	return ext_buffer_push_int16(pext, r->milliseconds);
}

int ext_buffer_push_timezonestruct(EXT_PUSH *pext, const TIMEZONESTRUCT *r)
{
	TRY(ext_buffer_push_int32(pext, r->bias));
	TRY(ext_buffer_push_int32(pext, r->standardbias));
	TRY(ext_buffer_push_int32(pext, r->daylightbias));
	TRY(ext_buffer_push_int16(pext, r->standardyear));
	TRY(ext_buffer_push_systemtime(pext, &r->standarddate));
	TRY(ext_buffer_push_int16(pext, r->daylightyear));
	return ext_buffer_push_systemtime(pext, &r->daylightdate);
}

static int ext_buffer_push_tzrule(EXT_PUSH *pext, const TZRULE *r)
{
	TRY(ext_buffer_push_uint8(pext, r->major));
	TRY(ext_buffer_push_uint8(pext, r->minor));
	TRY(ext_buffer_push_uint16(pext, r->reserved));
	TRY(ext_buffer_push_uint16(pext, r->flags));
	TRY(ext_buffer_push_int16(pext, r->year));
	TRY(ext_buffer_push_bytes(pext, r->x, 14));
	TRY(ext_buffer_push_int32(pext, r->bias));
	TRY(ext_buffer_push_int32(pext, r->standardbias));
	TRY(ext_buffer_push_int32(pext, r->daylightbias));
	TRY(ext_buffer_push_systemtime(pext, &r->standarddate));
	return ext_buffer_push_systemtime(pext, &r->daylightdate);
}

int ext_buffer_push_timezonedefinition(
	EXT_PUSH *pext, const TIMEZONEDEFINITION *r)
{
	int i;
	int len;
	uint16_t cbheader;
	char tmp_buff[262];
	
	TRY(ext_buffer_push_uint8(pext, r->major));
	TRY(ext_buffer_push_uint8(pext, r->minor));
	len = utf8_to_utf16le(r->keyname, tmp_buff, 262);
	if (len < 2) {
		return EXT_ERR_CHARCNV;
	}
	len -= 2;
	cbheader = 6 + len;
	TRY(ext_buffer_push_uint16(pext, cbheader));
	TRY(ext_buffer_push_uint16(pext, r->reserved));
	TRY(ext_buffer_push_uint16(pext, len / 2));
	TRY(ext_buffer_push_bytes(pext, tmp_buff, len));
	TRY(ext_buffer_push_uint16(pext, r->crules));
	for (i=0; i<r->crules; i++) {
		TRY(ext_buffer_push_tzrule(pext, r->prules + i));
	}
	return EXT_ERR_SUCCESS;
}
static int ext_buffer_push_patterntypespecific(EXT_PUSH *pext,
	uint16_t patterntype, const PATTERNTYPESPECIFIC *r)
{
	switch (patterntype) {
	case PATTERNTYPE_DAY:
		/* do nothing */
		return EXT_ERR_SUCCESS;
	case PATTERNTYPE_WEEK:
		return ext_buffer_push_uint32(pext, r->weekrecurrence);
	case PATTERNTYPE_MONTH:
	case PATTERNTYPE_MONTHEND:
	case PATTERNTYPE_HJMONTH:
	case PATTERNTYPE_HJMONTHEND:
		return ext_buffer_push_uint32(pext, r->dayofmonth);
	case PATTERNTYPE_MONTHNTH:
	case PATTERNTYPE_HJMONTHNTH:
		TRY(ext_buffer_push_uint32(pext, r->monthnth.weekrecurrence));
		return ext_buffer_push_uint32(pext,
				r->monthnth.recurrencenum);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

static int ext_buffer_push_recurrencepattern(
	EXT_PUSH *pext, const RECURRENCEPATTERN *r)
{
	int i;
	
	TRY(ext_buffer_push_uint16(pext, r->readerversion));
	TRY(ext_buffer_push_uint16(pext, r->writerversion));
	TRY(ext_buffer_push_uint16(pext, r->recurfrequency));
	TRY(ext_buffer_push_uint16(pext, r->patterntype));
	TRY(ext_buffer_push_uint16(pext, r->calendartype));
	TRY(ext_buffer_push_uint32(pext, r->firstdatetime));
	TRY(ext_buffer_push_uint32(pext, r->period));
	TRY(ext_buffer_push_uint32(pext, r->slidingflag));
	TRY(ext_buffer_push_patterntypespecific(pext, r->patterntype, &r->patterntypespecific));
	TRY(ext_buffer_push_uint32(pext, r->endtype));
	TRY(ext_buffer_push_uint32(pext, r->occurrencecount));
	TRY(ext_buffer_push_uint32(pext, r->firstdow));
	TRY(ext_buffer_push_uint32(pext, r->deletedinstancecount));
	for (i=0; i<r->deletedinstancecount; i++) {
		TRY(ext_buffer_push_uint32(pext, r->pdeletedinstancedates[i]));
	}
	TRY(ext_buffer_push_uint32(pext, r->modifiedinstancecount));
	for (i=0; i<r->modifiedinstancecount; i++) {
		TRY(ext_buffer_push_uint32(pext, r->pmodifiedinstancedates[i]));
	}
	TRY(ext_buffer_push_uint32(pext, r->startdate));
	return ext_buffer_push_uint32(pext, r->enddate);
}

static int ext_buffer_push_exceptioninfo(
	EXT_PUSH *pext, const EXCEPTIONINFO *r)
{
	uint16_t tmp_len;
	
	TRY(ext_buffer_push_uint32(pext, r->startdatetime));
	TRY(ext_buffer_push_uint32(pext, r->enddatetime));
	TRY(ext_buffer_push_uint32(pext, r->originalstartdate));
	TRY(ext_buffer_push_uint16(pext, r->overrideflags));
	if (r->overrideflags & OVERRIDEFLAG_SUBJECT) {
		tmp_len = strlen(r->subject);
		TRY(ext_buffer_push_uint16(pext, tmp_len + 1));
		TRY(ext_buffer_push_uint16(pext, tmp_len));
		TRY(ext_buffer_push_bytes(pext, r->subject, tmp_len));
	}
	if (r->overrideflags & OVERRIDEFLAG_MEETINGTYPE) {
		TRY(ext_buffer_push_uint32(pext, r->meetingtype));
	}
	if (r->overrideflags & OVERRIDEFLAG_REMINDERDELTA) {
		TRY(ext_buffer_push_uint32(pext, r->reminderdelta));
	}
	if (r->overrideflags & OVERRIDEFLAG_REMINDER) {
		TRY(ext_buffer_push_uint32(pext, r->reminderset));
	}
	if (r->overrideflags & OVERRIDEFLAG_LOCATION) {
		tmp_len = strlen(r->location);
		TRY(ext_buffer_push_uint16(pext, tmp_len + 1));
		TRY(ext_buffer_push_uint16(pext, tmp_len));
		TRY(ext_buffer_push_bytes(pext, r->location, tmp_len));
	}
	if (r->overrideflags & OVERRIDEFLAG_BUSYSTATUS) {
		TRY(ext_buffer_push_uint32(pext, r->busystatus));
	}
	if (r->overrideflags & OVERRIDEFLAG_ATTACHMENT) {
		TRY(ext_buffer_push_uint32(pext, r->attachment));
	}
	if (r->overrideflags & OVERRIDEFLAG_SUBTYPE) {
		TRY(ext_buffer_push_uint32(pext, r->subtype));
	}
	if (r->overrideflags & OVERRIDEFLAG_APPTCOLOR) {
		TRY(ext_buffer_push_uint32(pext, r->appointmentcolor));
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_changehighlight(
	EXT_PUSH *pext, const CHANGEHIGHLIGHT *r)
{
	TRY(ext_buffer_push_uint32(pext, r->size));
	TRY(ext_buffer_push_uint32(pext, r->value));
	if (r->size < sizeof(uint32_t)) {
		return EXT_ERR_FORMAT;
	} else if (sizeof(uint32_t) == r->size) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_push_bytes(pext, r->preserved,
						r->size - sizeof(uint32_t));
}

static int ext_buffer_push_extendedexception(
	EXT_PUSH *pext, uint32_t writerversion2,
	uint16_t overrideflags, const EXTENDEDEXCEPTION *r)
{
	int string_len;
	uint16_t tmp_len;
	
	if (writerversion2 >= 0x00003009) {
		TRY(ext_buffer_push_changehighlight(pext, &r->changehighlight));
	}
	TRY(ext_buffer_push_uint32(pext, r->reservedblockee1size));
	if (0 != r->reservedblockee1size) {
		TRY(ext_buffer_push_bytes(pext, r->preservedblockee1, r->reservedblockee1size));
	}
	if ((overrideflags & OVERRIDEFLAG_LOCATION) ||
		(overrideflags & OVERRIDEFLAG_SUBJECT)) {
		TRY(ext_buffer_push_uint32(pext, r->startdatetime));
		TRY(ext_buffer_push_uint32(pext, r->enddatetime));
		TRY(ext_buffer_push_uint32(pext, r->originalstartdate));
	}
	if (overrideflags & OVERRIDEFLAG_SUBJECT) {
		tmp_len = strlen(r->subject) + 1;
		std::unique_ptr<char[]> pbuff;
		try {
			pbuff = std::make_unique<char[]>(2 * tmp_len);
		} catch (const std::bad_alloc &) {
			return EXT_ERR_ALLOC;
		}
		string_len = utf8_to_utf16le(r->subject, pbuff.get(), 2 * tmp_len);
		if (string_len < 2) {
			return EXT_ERR_CHARCNV;
		}
		string_len -= 2;
		TRY(ext_buffer_push_uint16(pext, string_len / 2));
		TRY(ext_buffer_push_bytes(pext, pbuff.get(), string_len));
	}
	if (overrideflags & OVERRIDEFLAG_LOCATION) {
		tmp_len = strlen(r->location) + 1;
		std::unique_ptr<char[]> pbuff;
		try {
			pbuff = std::make_unique<char[]>(2 * tmp_len);
		} catch (const std::bad_alloc &) {
			return EXT_ERR_ALLOC;
		}
		string_len = utf8_to_utf16le(r->location, pbuff.get(), 2 * tmp_len);
		if (string_len < 2) {
			return EXT_ERR_CHARCNV;
		}
		string_len -= 2;
		TRY(ext_buffer_push_uint16(pext, string_len / 2));
		TRY(ext_buffer_push_bytes(pext, pbuff.get(), string_len));
	}
	if ((overrideflags & OVERRIDEFLAG_LOCATION) ||
		(overrideflags & OVERRIDEFLAG_SUBJECT)) {
		TRY(ext_buffer_push_uint32(pext, r->reservedblockee2size));
		if (0 != r->reservedblockee2size) {
			TRY(ext_buffer_push_bytes(pext, r->preservedblockee2, r->reservedblockee2size));
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_appointmentrecurrencepattern(
	EXT_PUSH *pext, const APPOINTMENTRECURRENCEPATTERN *r)
{
	int i;
	
	TRY(ext_buffer_push_recurrencepattern(pext, &r->recurrencepattern));
	TRY(ext_buffer_push_uint32(pext, r->readerversion2));
	TRY(ext_buffer_push_uint32(pext, r->writerversion2));
	TRY(ext_buffer_push_uint32(pext, r->starttimeoffset));
	TRY(ext_buffer_push_uint32(pext, r->endtimeoffset));
	TRY(ext_buffer_push_uint16(pext, r->exceptioncount));
	for (i=0; i<r->exceptioncount; i++) {
		TRY(ext_buffer_push_exceptioninfo(pext, &r->pexceptioninfo[i]));
	}
	TRY(ext_buffer_push_uint32(pext, r->reservedblock1size));
	for (i=0; i<r->exceptioncount; i++) {
		TRY(ext_buffer_push_extendedexception(pext, r->writerversion2, r->pexceptioninfo[i].overrideflags, &r->pextendedexception[i]));
	}
	TRY(ext_buffer_push_uint32(pext, r->reservedblock2size));
	if (0 == r->reservedblock2size) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_push_bytes(pext,
			r->preservedblock2,
			r->reservedblock2size);
}

int ext_buffer_push_globalobjectid(EXT_PUSH *pext, const GLOBALOBJECTID *r)
{
	TRY(ext_buffer_push_bytes(pext, r->arrayid, 16));
	TRY(ext_buffer_push_uint8(pext, r->year >> 8));
	TRY(ext_buffer_push_uint8(pext, r->year & 0xFF));
	TRY(ext_buffer_push_uint8(pext, r->month));
	TRY(ext_buffer_push_uint8(pext, r->day));
	TRY(ext_buffer_push_uint64(pext, r->creationtime));
	TRY(ext_buffer_push_bytes(pext, r->x, 8));
	return ext_buffer_push_exbinary(pext, &r->data);
}


static int ext_buffer_push_attachment_list(
	EXT_PUSH *pext, const ATTACHMENT_LIST *r)
{
	int i;
	
	TRY(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_buffer_push_tpropval_array(pext, &r->pplist[i]->proplist));
		if (NULL != r->pplist[i]->pembedded) {
			TRY(ext_buffer_push_uint8(pext, 1));
			TRY(ext_buffer_push_message_content(pext, r->pplist[i]->pembedded));
		} else {
			TRY(ext_buffer_push_uint8(pext, 0));
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_message_content(
	EXT_PUSH *pext, const MESSAGE_CONTENT *r)
{
	TRY(ext_buffer_push_tpropval_array(pext, &r->proplist));
	if (NULL != r->children.prcpts) {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_tarray_set(pext, r->children.prcpts));
	} else {
		TRY(ext_buffer_push_uint8(pext, 0));
	}
	if (NULL != r->children.pattachments) {
		TRY(ext_buffer_push_uint8(pext, 1));
		return ext_buffer_push_attachment_list(
				pext, r->children.pattachments);
	} else {
		return ext_buffer_push_uint8(pext, 0);
	}
}

uint8_t *ext_buffer_push_release(EXT_PUSH *p)
{
	uint8_t *t = p->data;
	p->data = nullptr;
	p->b_alloc = false;
	p->offset = 0;
	return t;
}
