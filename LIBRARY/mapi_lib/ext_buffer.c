#include <gromox/mapidefs.h>
#include "endian_macro.h"
#include "ext_buffer.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

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
	pext->data = pdata;
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
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->version);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
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
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->time_low);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->time_mid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->time_hi_and_version);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->clock_seq, 2);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->node, 6);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
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
	*ppstr = pext->alloc(len);
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
	char *pbuff;
	
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
	*ppstr = pext->alloc(2*len);
	if (NULL == *ppstr) {
		return EXT_ERR_ALLOC;
	}
	pbuff = malloc(len);
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
	pblob->data = pext->alloc(length);
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
	int status;
	uint16_t cb;
	
	if (pext->flags & EXT_FLAG_WCOUNT) {
		status = ext_buffer_pull_uint32(pext, &r->cb);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_pull_uint16(pext, &cb);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		r->cb = cb;
	}
	if (0 == r->cb) {
		r->pb = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pb = pext->alloc(r->cb);
	if (NULL == r->pb) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_bytes(pext, r->pb, r->cb);
}

int ext_buffer_pull_sbinary(EXT_PULL *pext, BINARY *r)
{
	int status;
	uint16_t cb;
	
	status = ext_buffer_pull_uint16(pext, &cb);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	r->cb = cb;
	if (0 == r->cb) {
		r->pb = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pb = pext->alloc(r->cb);
	if (NULL == r->pb) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_bytes(pext, r->pb, r->cb);
}

int ext_buffer_pull_exbinary(EXT_PULL *pext, BINARY *r)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->cb);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->cb) {
		r->pb = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pb = pext->alloc(r->cb);
	if (NULL == r->pb) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_bytes(pext, r->pb, r->cb);
}

int ext_buffer_pull_short_array(EXT_PULL *pext, SHORT_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->ps = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ps = pext->alloc(sizeof(uint16_t)*r->count);
	if (NULL == r->ps) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_uint16(pext, &r->ps[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_long_array(EXT_PULL *pext, LONG_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->pl = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pl = pext->alloc(sizeof(uint32_t)*r->count);
	if (NULL == r->pl) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_uint32(pext, &r->pl[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_longlong_array(EXT_PULL *pext, LONGLONG_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->pll = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pll = pext->alloc(sizeof(uint64_t)*r->count);
	if (NULL == r->pll) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_uint64(pext, &r->pll[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_slonglong_array(EXT_PULL *pext, LONGLONG_ARRAY *r)
{
	int i;
	int status;
	uint16_t count;
	
	status = ext_buffer_pull_uint16(pext, &count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	r->count = count;
	if (0 == r->count) {
		r->pll = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pll = pext->alloc(sizeof(uint64_t)*r->count);
	if (NULL == r->pll) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_uint64(pext, &r->pll[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_binary_array(EXT_PULL *pext, BINARY_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->pbin = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pbin = pext->alloc(sizeof(BINARY)*r->count);
	if (NULL == r->pbin) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_binary(pext, &r->pbin[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_string_array(EXT_PULL *pext, STRING_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->ppstr = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppstr = pext->alloc(sizeof(char*)*r->count);
	if (NULL == r->ppstr) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_string(pext, &r->ppstr[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_wstring_array(EXT_PULL *pext, STRING_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->ppstr = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppstr = pext->alloc(sizeof(char*)*r->count);
	if (NULL == r->ppstr) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_wstring(pext, &r->ppstr[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_guid_array(EXT_PULL *pext, GUID_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->pguid = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pguid = pext->alloc(sizeof(GUID)*r->count);
	if (NULL == r->pguid) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_guid(pext, &r->pguid[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_restriction_and_or(
	EXT_PULL *pext, RESTRICTION_AND_OR *r)
{
	int i;
	int status;
	uint16_t count;
	
	if (pext->flags & EXT_FLAG_WCOUNT) {
		status = ext_buffer_pull_uint32(pext, &r->count);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_pull_uint16(pext, &count);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		r->count = count;
	}
	if (0 == r->count) {
		r->pres = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pres = pext->alloc(r->count*sizeof(RESTRICTION));
	if (NULL == r->pres) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_restriction(pext, &r->pres[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
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
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->fuzzy_level);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_tagged_propval(pext, &r->propval);
}

static int ext_buffer_pull_restriction_property(
	EXT_PULL *pext, RESTRICTION_PROPERTY *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->relop);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_tagged_propval(pext, &r->propval);
}

static int ext_buffer_pull_restriction_propcompare(
	EXT_PULL *pext, RESTRICTION_PROPCOMPARE *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->relop);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->proptag1);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->proptag2);
}

static int ext_buffer_pull_restriction_bitmask(
	EXT_PULL *pext, RESTRICTION_BITMASK *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->bitmask_relop);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->mask);
}

static int ext_buffer_pull_restriction_size(
	EXT_PULL *pext, RESTRICTION_SIZE *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->relop);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
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
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->subobject);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_restriction(pext, &r->res);
}

static int ext_buffer_pull_restriction_comment(
	EXT_PULL *pext, RESTRICTION_COMMENT *r)
{
	int i;
	int status;
	uint8_t res_present;
	
	status = ext_buffer_pull_uint8(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->ppropval = pext->alloc(sizeof(TAGGED_PROPVAL)*r->count);
	if (NULL == r->ppropval) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_tagged_propval(pext, &r->ppropval[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint8(pext, &res_present);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != res_present) {
		r->pres = pext->alloc(sizeof(RESTRICTION));
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
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_restriction(pext, &r->sub_res);
}

int ext_buffer_pull_restriction(EXT_PULL *pext, RESTRICTION *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->rt);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch (r->rt) {
	case RESTRICTION_TYPE_AND:
	case RESTRICTION_TYPE_OR:
		r->pres = pext->alloc(sizeof(RESTRICTION_AND_OR));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_and_or(pext, r->pres);
	case RESTRICTION_TYPE_NOT:
		r->pres = pext->alloc(sizeof(RESTRICTION_NOT));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_not(pext, r->pres);
	case RESTRICTION_TYPE_CONTENT:
		r->pres = pext->alloc(sizeof(RESTRICTION_CONTENT));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_content(pext, r->pres);
	case RESTRICTION_TYPE_PROPERTY:
		r->pres = pext->alloc(sizeof(RESTRICTION_PROPERTY));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_property(pext, r->pres);
	case RESTRICTION_TYPE_PROPCOMPARE:
		r->pres = pext->alloc(sizeof(RESTRICTION_PROPCOMPARE));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_propcompare(pext, r->pres);
	case RESTRICTION_TYPE_BITMASK:
		r->pres = pext->alloc(sizeof(RESTRICTION_BITMASK));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_bitmask(pext, r->pres);
	case RESTRICTION_TYPE_SIZE:
		r->pres = pext->alloc(sizeof(RESTRICTION_SIZE));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_size(pext, r->pres);
	case RESTRICTION_TYPE_EXIST:
		r->pres = pext->alloc(sizeof(RESTRICTION_EXIST));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_exist(pext, r->pres);
	case RESTRICTION_TYPE_SUBOBJ:
		r->pres = pext->alloc(sizeof(RESTRICTION_SUBOBJ));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_subobj(pext, r->pres);
	case RESTRICTION_TYPE_COMMENT:
		r->pres = pext->alloc(sizeof(RESTRICTION_COMMENT));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_comment(pext, r->pres);
	case RESTRICTION_TYPE_COUNT:
		r->pres = pext->alloc(sizeof(RESTRICTION_COUNT));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction_count(pext, r->pres);
	case RESTRICTION_TYPE_NULL:
		r->pres = NULL;
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int ext_buffer_pull_svreid(EXT_PULL *pext, SVREID *r)
{
	int status;
	uint8_t ours;
	uint16_t length;
	
	status = ext_buffer_pull_uint16(pext, &length);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &ours);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == ours) {
		r->folder_id = 0;
		r->message_id = 0;
		r->instance = 0;
		r->pbin = pext->alloc(sizeof(BINARY));
		if (NULL == r->pbin) {
			return EXT_ERR_ALLOC;
		}
		r->pbin->cb = length - 1;
		r->pbin->pb = pext->alloc(r->pbin->cb);
		if (NULL == r->pbin) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_bytes(pext, r->pbin->pb, r->pbin->cb);
	}
	if (21 != length) {
		return EXT_ERR_FORMAT;
	}
	r->pbin = NULL;
	status = ext_buffer_pull_uint64(pext, &r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext, &r->message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->instance);
}

int ext_buffer_pull_store_entryid(EXT_PULL *pext, STORE_ENTRYID *r)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->provider_uid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->version);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->flag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->dll_name, 14);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->wrapped_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->wrapped_provider_uid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->wrapped_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_string(pext, &r->pserver_name);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_string(pext, &r->pmailbox_dn);
}

static int ext_buffer_pull_movecopy_action(EXT_PULL *pext, MOVECOPY_ACTION *r)
{
	int status;
	uint16_t eid_size;
	
	status = ext_buffer_pull_uint8(pext, &r->same_store);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &eid_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->same_store) {
		r->pstore_eid = pext->alloc(sizeof(STORE_ENTRYID));
		if (NULL == r->pstore_eid) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_store_entryid(pext, r->pstore_eid);
	} else {
		r->pstore_eid = NULL;
		status = ext_buffer_pull_advance(pext, eid_size);
	}
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != r->same_store) {
		r->pfolder_eid = pext->alloc(sizeof(SVREID));
		if (NULL == r->pfolder_eid) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_svreid(pext, r->pfolder_eid);
	} else {
		r->pfolder_eid = pext->alloc(sizeof(BINARY));
		if (NULL == r->pfolder_eid) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_binary(pext, r->pfolder_eid);
	}
}

static int ext_buffer_pull_reply_action(EXT_PULL *pext, REPLY_ACTION *r)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext, &r->template_folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext, &r->template_message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_guid(pext, &r->template_guid);
}

static int ext_buffer_pull_recipient_block(EXT_PULL *pext, RECIPIENT_BLOCK *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->ppropval = pext->alloc(sizeof(TAGGED_PROPVAL)*r->count);
	if (NULL == r->ppropval) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_tagged_propval(pext, &r->ppropval[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_forwarddelegate_action(
	EXT_PULL *pext, FORWARDDELEGATE_ACTION *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->pblock = pext->alloc(sizeof(RECIPIENT_BLOCK)*r->count);
	if (NULL == r->pblock) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_recipient_block(pext, &r->pblock[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_action_block(EXT_PULL *pext, ACTION_BLOCK *r)
{
	int status;
	uint16_t tmp_len;
	
	status = ext_buffer_pull_uint16(pext, &r->length);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->flavor);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch (r->type) {
	case ACTION_TYPE_OP_MOVE:
	case ACTION_TYPE_OP_COPY:
		r->pdata = pext->alloc(sizeof(MOVECOPY_ACTION));
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_movecopy_action(pext, r->pdata);
	case ACTION_TYPE_OP_REPLY:
	case ACTION_TYPE_OP_OOF_REPLY:
		r->pdata = pext->alloc(sizeof(REPLY_ACTION));
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_reply_action(pext, r->pdata);
	case ACTION_TYPE_OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - 2*sizeof(uint32_t);
		r->pdata = pext->alloc(tmp_len);
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_bytes(pext, r->pdata, tmp_len);
	case ACTION_TYPE_OP_BOUNCE:
		r->pdata = pext->alloc(sizeof(uint32_t));
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint32(pext, r->pdata);
	case ACTION_TYPE_OP_FORWARD:
	case ACTION_TYPE_OP_DELEGATE:
		r->pdata = pext->alloc(sizeof(FORWARDDELEGATE_ACTION));
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_forwarddelegate_action(pext, r->pdata);
	case ACTION_TYPE_OP_TAG:
		r->pdata = pext->alloc(sizeof(TAGGED_PROPVAL));
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_tagged_propval(pext, r->pdata);
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
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->pblock = pext->alloc(sizeof(ACTION_BLOCK)*r->count);
	if (NULL == r->pblock) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_action_block(pext, &r->pblock[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_propval(EXT_PULL *pext, uint16_t type, void **ppval)
{
	/* convert multi-value instance into single value */
	if (0x3000 == (type & 0x3000)) {
		type &= ~0x3000;
	}
	switch (type) {
	case PT_UNSPECIFIED:
		*ppval = pext->alloc(sizeof(TYPED_PROPVAL));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_typed_propval(pext, *ppval);
	case PT_SHORT:
		*ppval = pext->alloc(sizeof(uint16_t));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint16(pext, *ppval);
	case PT_LONG:
	case PT_ERROR:
		*ppval = pext->alloc(sizeof(uint32_t));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint32(pext, *ppval);
	case PT_FLOAT:
		*ppval = pext->alloc(sizeof(float));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_float(pext, *ppval);
	case PT_DOUBLE:
	case PT_APPTIME:
		*ppval = pext->alloc(sizeof(double));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_double(pext, *ppval);
	case PT_BOOLEAN:
		*ppval = pext->alloc(sizeof(uint8_t));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint8(pext, *ppval);
	case PT_CURRENCY:
	case PROPVAL_TYPE_LONGLONG:
	case PROPVAL_TYPE_FILETIME:
		*ppval = pext->alloc(sizeof(uint64_t));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint64(pext, *ppval);
	case PT_STRING8:
		return ext_buffer_pull_string(pext, (char**)ppval);
	case PT_UNICODE:
		return ext_buffer_pull_wstring(pext, (char**)ppval);
	case PROPVAL_TYPE_SVREID:
		*ppval = pext->alloc(sizeof(SVREID));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_svreid(pext, *ppval);
	case PT_CLSID:
		*ppval = pext->alloc(sizeof(GUID));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_guid(pext, *ppval);
	case PROPVAL_TYPE_RESTRICTION:
		*ppval = pext->alloc(sizeof(RESTRICTION));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction(pext, *ppval);
	case PROPVAL_TYPE_RULE:
		*ppval = pext->alloc(sizeof(RULE_ACTIONS));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_rule_actions(pext, *ppval);
	case PT_BINARY:
	case PT_OBJECT:
		*ppval = pext->alloc(sizeof(BINARY));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_binary(pext, *ppval);
	case PT_MV_SHORT:
		*ppval = pext->alloc(sizeof(SHORT_ARRAY));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_short_array(pext, *ppval);
	case PT_MV_LONG:
		*ppval = pext->alloc(sizeof(LONG_ARRAY));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_long_array(pext, *ppval);
	case PROPVAL_TYPE_LONGLONG_ARRAY:
		*ppval = pext->alloc(sizeof(LONGLONG_ARRAY));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_longlong_array(pext, *ppval);
	case PT_MV_STRING8:
		*ppval = pext->alloc(sizeof(STRING_ARRAY));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_string_array(pext, *ppval);
	case PT_MV_UNICODE:
		*ppval = pext->alloc(sizeof(STRING_ARRAY));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_wstring_array(pext, *ppval);
	case PT_MV_CLSID:
		*ppval = pext->alloc(sizeof(GUID_ARRAY));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_guid_array(pext, *ppval);
	case PT_MV_BINARY:
		*ppval = pext->alloc(sizeof(BINARY_ARRAY));
		if (NULL == (*ppval)) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_binary_array(pext, *ppval);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int ext_buffer_pull_typed_propval(EXT_PULL *pext, TYPED_PROPVAL *r)
{
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_propval(pext, r->type, &r->pvalue);
}

int ext_buffer_pull_tagged_propval(EXT_PULL *pext, TAGGED_PROPVAL *r)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_propval(pext, PROP_TYPE(r->proptag), &r->pvalue);
}

int ext_buffer_pull_long_term_id(EXT_PULL *pext, LONG_TERM_ID *r)
{
	int status;

	status = ext_buffer_pull_guid(pext, &r->guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->global_counter, 6);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint16(pext, &r->padding);
}

int ext_buffer_pull_long_term_id_array(EXT_PULL *pext, LONG_TERM_ID_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->pids = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pids = pext->alloc(sizeof(LONG_TERM_ID)*r->count);
	if (NULL == r->pids) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_long_term_id(pext, &r->pids[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_long_term_id_rang(EXT_PULL *pext, LONG_TERM_ID_RANGE *r)
{
	int status;
	
	status = ext_buffer_pull_long_term_id(pext, &r->min);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_long_term_id(pext, &r->max);
}

int ext_buffer_pull_proptag_array(EXT_PULL *pext, PROPTAG_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->pproptag = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pproptag = pext->alloc(sizeof(uint32_t)*r->count);
	if (NULL == r->pproptag) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_uint32(pext, &r->pproptag[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_property_name(EXT_PULL *pext, PROPERTY_NAME *r)
{
	int status;
	uint32_t offset;
	uint8_t name_size;
	
	status = ext_buffer_pull_uint8(pext, &r->kind);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_guid(pext, &r->guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	r->plid = NULL;
	r->pname = NULL;
	if (KIND_LID == r->kind) {
		r->plid = pext->alloc(sizeof(uint32_t));
		if (NULL == r->plid) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint32(pext, r->plid);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else if (KIND_NAME == r->kind) {
		status = ext_buffer_pull_uint8(pext, &name_size);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (name_size < 2) {
			return EXT_ERR_FORMAT;
		}
		offset = pext->offset + name_size;
		status = ext_buffer_pull_wstring(pext, &r->pname);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
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
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->ppropname = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropname = pext->alloc(sizeof(PROPERTY_NAME)*r->count);
	if (NULL == r->ppropname) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_property_name(pext, r->ppropname + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_propid_array(EXT_PULL *pext, PROPID_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->ppropid = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropid = pext->alloc(sizeof(uint16_t)*r->count);
	if (NULL == r->ppropid) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_uint16(pext, r->ppropid + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_tpropval_array(EXT_PULL *pext, TPROPVAL_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->ppropval = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropval = pext->alloc(sizeof(TAGGED_PROPVAL)*r->count);
	if (NULL == r->ppropval) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_tagged_propval(pext, r->ppropval + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_tarray_set(EXT_PULL *pext, TARRAY_SET *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->pparray = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pparray = pext->alloc(sizeof(TPROPVAL_ARRAY*)*r->count);
	if (NULL == r->pparray) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		r->pparray[i] = pext->alloc(sizeof(TPROPVAL_ARRAY));
		if (NULL == r->pparray[i]) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_tpropval_array(pext, r->pparray[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_property_problem(EXT_PULL *pext, PROPERTY_PROBLEM *r)
{
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->index);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->err);
}

int ext_buffer_pull_problem_array(EXT_PULL *pext, PROBLEM_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	r->pproblem = pext->alloc(sizeof(PROPERTY_PROBLEM)*r->count);
	if (NULL == r->pproblem) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_property_problem(pext, r->pproblem + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_xid(EXT_PULL *pext, uint8_t size, XID *pxid)
{
	int status;
	
	if (size < 17 || size > 24) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_pull_guid(pext, &pxid->guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bytes(pext, pxid->local_id, size - 16);
}

int ext_buffer_pull_folder_entryid(EXT_PULL *pext, FOLDER_ENTRYID *r)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->provider_uid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->folder_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_guid(pext, &r->database_guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->global_counter, 6);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bytes(pext, r->pad, 2);
}

static int ext_buffer_pull_ext_movecopy_action(
	EXT_PULL *pext, EXT_MOVECOPY_ACTION *r)
{
	int status;
	uint32_t size;
	
	status = ext_buffer_pull_uint32(pext, &size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == size) {
		return EXT_ERR_FORMAT;
	} else {
		status = ext_buffer_pull_advance(pext, size);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext, &size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (46 != size) {
		return EXT_ERR_FORMAT;
	}
	return ext_buffer_pull_folder_entryid(pext, &r->folder_eid);
}

int ext_buffer_pull_message_entryid(EXT_PULL *pext, MESSAGE_ENTRYID *r)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->provider_uid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->message_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_guid(pext, &r->folder_database_guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->folder_global_counter, 6);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->pad1, 2);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_guid(pext, &r->message_database_guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->message_global_counter, 6);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bytes(pext, r->pad2, 2);
}

static int ext_buffer_pull_ext_reply_action(
	EXT_PULL *pext, EXT_REPLY_ACTION *r)
{
	int status;
	uint32_t size;
	
	status = ext_buffer_pull_uint32(pext, &size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (70 != size) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_pull_message_entryid(pext, &r->message_eid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_guid(pext, &r->template_guid);
}


static int ext_buffer_pull_ext_recipient_block(
	EXT_PULL *pext, EXT_RECIPIENT_BLOCK *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->ppropval = pext->alloc(sizeof(TAGGED_PROPVAL)*r->count);
	if (NULL == r->ppropval) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_tagged_propval(pext, &r->ppropval[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_ext_forwarddelegate_action(EXT_PULL *pext,
	EXT_FORWARDDELEGATE_ACTION *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->pblock = pext->alloc(sizeof(EXT_RECIPIENT_BLOCK)*r->count);
	if (NULL == r->pblock) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_ext_recipient_block(pext, &r->pblock[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_ext_action_block(
	EXT_PULL *pext, EXT_ACTION_BLOCK *r)
{
	int status;
	uint32_t tmp_len;
	
	status = ext_buffer_pull_uint32(pext, &r->length);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->flavor);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch (r->type) {
	case ACTION_TYPE_OP_MOVE:
	case ACTION_TYPE_OP_COPY:
		r->pdata = pext->alloc(sizeof(EXT_MOVECOPY_ACTION));
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_ext_movecopy_action(pext, r->pdata);
	case ACTION_TYPE_OP_REPLY:
	case ACTION_TYPE_OP_OOF_REPLY:
		r->pdata = pext->alloc(sizeof(EXT_REPLY_ACTION));
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_ext_reply_action(pext, r->pdata);
	case ACTION_TYPE_OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - sizeof(uint32_t);
		r->pdata = pext->alloc(tmp_len);
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_bytes(pext, r->pdata, tmp_len);
	case ACTION_TYPE_OP_BOUNCE:
		r->pdata = pext->alloc(sizeof(uint32_t));
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint32(pext, r->pdata);
	case ACTION_TYPE_OP_FORWARD:
	case ACTION_TYPE_OP_DELEGATE:
		r->pdata = pext->alloc(sizeof(EXT_FORWARDDELEGATE_ACTION));
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_ext_forwarddelegate_action(pext, r->pdata);
	case ACTION_TYPE_OP_TAG:
		r->pdata = pext->alloc(sizeof(TAGGED_PROPVAL));
		if (NULL == r->pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_tagged_propval(pext, r->pdata);
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
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->pblock = pext->alloc(sizeof(EXT_ACTION_BLOCK)*r->count);
	if (NULL == r->pblock) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_ext_action_block(pext, &r->pblock[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_namedproperty_information(
	EXT_PULL *pext, NAMEDPROPERTY_INFOMATION *r)
{
	int i;
	int status;
	uint32_t size;
	uint32_t offset;
	
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->ppropid = NULL;
		r->ppropname = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppropid = pext->alloc(sizeof(uint16_t)*r->count);
	if (NULL == r->ppropid) {
		return EXT_ERR_ALLOC;
	}
	r->ppropname = pext->alloc(sizeof(PROPERTY_NAME)*r->count);
	if (NULL == r->ppropname) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_uint16(pext, r->ppropid + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext, &size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	offset = pext->offset + size;
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_property_name(pext, r->ppropname + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
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
	int status;
	void **ppvalue;
	
	if (type == PT_UNSPECIFIED) {
		status = ext_buffer_pull_uint16(pext, &type);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		r->pvalue = pext->alloc(sizeof(TYPED_PROPVAL));
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		((TYPED_PROPVAL*)r->pvalue)->type = type;
		ppvalue = &((TYPED_PROPVAL*)r->pvalue)->pvalue;
	} else {
		ppvalue = &r->pvalue;
	}
	status = ext_buffer_pull_uint8(pext, &r->flag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch (r->flag) {
	case FLAGGED_PROPVAL_FLAG_AVAILABLE:
		return ext_buffer_pull_propval(pext, type, ppvalue);
	case FLAGGED_PROPVAL_FLAG_UNAVAILABLE:
		*ppvalue = NULL;
		return EXT_ERR_SUCCESS;
	case FLAGGED_PROPVAL_FLAG_ERROR:
		*ppvalue = pext->alloc(sizeof(uint32_t));
		if (NULL == *ppvalue) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint32(pext, *ppvalue);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int ext_buffer_pull_property_row(EXT_PULL *pext,
	const PROPTAG_ARRAY *pcolumns, PROPERTY_ROW *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->flag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	r->pppropval = pext->alloc(sizeof(void*)*pcolumns->count);
	if (NULL == r->pppropval) {
		return EXT_ERR_ALLOC;
	}
	if (PROPERTY_ROW_FLAG_NONE == r->flag) {
		for (i=0; i<pcolumns->count; i++) {
			status = ext_buffer_pull_propval(pext,
			         PROP_TYPE(pcolumns->pproptag[i]), &r->pppropval[i]);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		}
		return EXT_ERR_SUCCESS;
	} else if (PROPERTY_ROW_FLAG_FLAGGED == r->flag) {
		for (i=0; i<pcolumns->count; i++) {
			r->pppropval[i] = pext->alloc(sizeof(FLAGGED_PROPVAL));
			if (NULL == r->pppropval[i]) {
				return EXT_ERR_ALLOC;
			}
			status = ext_buffer_pull_flagged_propval(pext,
			         PROP_TYPE(pcolumns->pproptag[i]), r->pppropval[i]);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		}
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int ext_buffer_pull_proprow_set(EXT_PULL *pext,
	const PROPTAG_ARRAY *pcolumns, PROPROW_SET *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->prows = NULL;
	}
	r->prows = pext->alloc(sizeof(PROPERTY_ROW)*r->count);
	if (NULL == r->prows) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_property_row(pext, pcolumns, &r->prows[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_sort_order(EXT_PULL *pext, SORT_ORDER *r)
{
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (r->type & 0x1000 && 0 == (r->type & 0x2000)) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_pull_uint16(pext, &r->propid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->table_sort);
}

int ext_buffer_pull_sortorder_set(EXT_PULL *pext, SORTORDER_SET *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->ccategories);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->cexpanded);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count || r->ccategories > r->count ||
		r->cexpanded > r->ccategories) {
		return EXT_ERR_FORMAT;
	}
	r->psort = pext->alloc(sizeof(SORT_ORDER)*r->count);
	if (NULL == r->psort) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_sort_order(pext, r->psort + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_typed_string(EXT_PULL *pext, TYPED_STRING *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->string_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch(r->string_type) {
	case STRING_TYPE_NONE:
	case STRING_TYPE_EMPTY:
		return EXT_ERR_SUCCESS;
	case STRING_TYPE_STRING8:
	case STRING_TYPE_UNICODE_REDUCED:
		return ext_buffer_pull_string(pext, &r->pstring);
	case STRING_TYPE_UNICODE:
		return ext_buffer_pull_wstring(pext, &r->pstring);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int ext_buffer_pull_recipient_row(EXT_PULL *pext,
	const PROPTAG_ARRAY *pproptags, RECIPIENT_ROW *r)
{
	int status;
	uint8_t type;
	BOOL b_unicode;
	PROPTAG_ARRAY proptags;
	
	status = ext_buffer_pull_uint16(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	type = r->flags & 0x0007;
	b_unicode = FALSE;
	if (r->flags & RECIPIENT_ROW_FLAG_UNICODE) {
		b_unicode = TRUE;
	}
	r->pprefix_used = NULL;
	r->pdisplay_type = NULL;
	r->px500dn = NULL;
	if (RECIPIENT_ROW_TYPE_X500DN == type) {
		r->pprefix_used = pext->alloc(sizeof(uint8_t));
		if (NULL == r->pprefix_used) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint8(pext, r->pprefix_used);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		r->pdisplay_type = pext->alloc(sizeof(uint8_t));
		if (NULL == r->pprefix_used) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint8(pext, r->pdisplay_type);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_string(pext, &r->px500dn);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	r->pentry_id = NULL;
	r->psearch_key = NULL;
	if (RECIPIENT_ROW_TYPE_PERSONAL_DLIST1 == type ||
		RECIPIENT_ROW_TYPE_PERSONAL_DLIST2 == type) {
		r->pentry_id = pext->alloc(sizeof(BINARY));
		if (NULL == r->pentry_id) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_binary(pext, r->pentry_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		r->psearch_key = pext->alloc(sizeof(BINARY));
		if (NULL == r->psearch_key) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_binary(pext, r->psearch_key);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	r->paddress_type = NULL;
	if (RECIPIENT_ROW_TYPE_NONE == type &&
		(r->flags & RECIPIENT_ROW_FLAG_OUTOFSTANDARD)) {
		status = ext_buffer_pull_string(pext, &r->paddress_type);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	r->pmail_address = NULL;
	if (RECIPIENT_ROW_FLAG_EMAIL & r->flags) {
		if (TRUE == b_unicode) {
			status = ext_buffer_pull_wstring(pext, &r->pmail_address);
		} else {
			status = ext_buffer_pull_string(pext, &r->pmail_address);
		}
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	r->pdisplay_name = NULL;
	if (r->flags & RECIPIENT_ROW_FLAG_DISPLAY) {
		if (TRUE == b_unicode) {
			status = ext_buffer_pull_wstring(pext, &r->pdisplay_name);
		} else {
			status = ext_buffer_pull_string(pext, &r->pdisplay_name);
		}
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	r->psimple_name = NULL;
	if (r->flags & RECIPIENT_ROW_FLAG_SIMPLE) {
		if (TRUE == b_unicode) {
			status = ext_buffer_pull_wstring(pext, &r->psimple_name);
		} else {
			status = ext_buffer_pull_string(pext, &r->psimple_name);
		}
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	r->ptransmittable_name = NULL;
	if (r->flags & RECIPIENT_ROW_FLAG_TRANSMITTABLE) {
		if (TRUE == b_unicode) {
			status = ext_buffer_pull_wstring(pext, &r->ptransmittable_name);
		} else {
			status = ext_buffer_pull_string(pext, &r->ptransmittable_name);
		}
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (RECIPIENT_ROW_FLAG_SAME == r->flags) {
		if (NULL == r->pdisplay_name && NULL != r->ptransmittable_name) {
			r->pdisplay_name = r->ptransmittable_name;
		} else if (NULL != r->pdisplay_name && NULL == r->ptransmittable_name) {
			r->ptransmittable_name = r->pdisplay_name;
		}
	}
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (r->count > pproptags->count) {
		return EXT_ERR_FORMAT;
	}
	proptags.count = r->count;
	proptags.pproptag = (uint32_t*)pproptags->pproptag;
	return ext_buffer_pull_property_row(pext, &proptags, &r->properties);
}

int ext_buffer_pull_openrecipient_row(EXT_PULL *pext,
	const PROPTAG_ARRAY *pproptags, OPENRECIPIENT_ROW *r)
{
	int status;
	uint32_t offset;
	uint16_t row_size;
	
	
	status = ext_buffer_pull_uint8(pext, &r->recipient_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &row_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	offset = pext->offset + row_size;
	status = ext_buffer_pull_recipient_row(pext, pproptags, &r->recipient_row);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (pext->offset > offset) {
		return EXT_ERR_FORMAT;
	}
	pext->offset = offset;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_modifyrecipient_row(EXT_PULL *pext,
	PROPTAG_ARRAY *pproptags, MODIFYRECIPIENT_ROW *r)
{
	int status;
	uint32_t offset;
	uint16_t row_size;
	
	status = ext_buffer_pull_uint32(pext, &r->row_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->recipient_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &row_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == row_size) {
		r->precipient_row = NULL;
		return EXT_ERR_SUCCESS;
	}
	offset = pext->offset + row_size;
	r->precipient_row = pext->alloc(sizeof(RECIPIENT_ROW));
	if (NULL == r->precipient_row) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_pull_recipient_row(pext, pproptags, r->precipient_row);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (pext->offset > offset) {
		return EXT_ERR_FORMAT;
	}
	pext->offset = offset;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_readrecipient_row(EXT_PULL *pext,
	PROPTAG_ARRAY *pproptags, READRECIPIENT_ROW *r)
{
	int status;
	uint32_t offset;
	uint16_t row_size;
	
	status = ext_buffer_pull_uint32(pext, &r->row_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->recipient_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &row_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	offset = pext->offset + row_size;
	status = ext_buffer_pull_recipient_row(pext, pproptags, &r->recipient_row);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (pext->offset > offset) {
		return EXT_ERR_FORMAT;
	}
	pext->offset = offset;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_permission_data(EXT_PULL *pext, PERMISSION_DATA *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_tpropval_array(pext, &r->propvals);
}

int ext_buffer_pull_rule_data(EXT_PULL *pext, RULE_DATA *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_tpropval_array(pext, &r->propvals);
}

int ext_buffer_pull_addressbook_entryid(
	EXT_PULL *pext, ADDRESSBOOK_ENTRYID *r)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->provider_uid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->version);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_string(pext, &r->px500dn);
}

int ext_buffer_pull_oneoff_entryid(EXT_PULL *pext, ONEOFF_ENTRYID *r)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->provider_uid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->version);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->ctrl_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (r->ctrl_flags & CTRL_FLAG_UNICODE) {
		status = ext_buffer_pull_wstring(pext, &r->pdisplay_name);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_wstring(pext, &r->paddress_type);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_wstring(pext, &r->pmail_address);
	} else {
		status = ext_buffer_pull_string(pext, &r->pdisplay_name);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_string(pext, &r->paddress_type);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_string(pext, &r->pmail_address);
	}
}

int ext_buffer_pull_oneoff_array(EXT_PULL *pext, ONEOFF_ARRAY *r)
{
	int i;
	int status;
	uint32_t bytes;
	uint8_t pad_len;
	uint32_t offset;
	uint32_t offset2;
	
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	r->pentry_id = pext->alloc(sizeof(ONEOFF_ENTRYID)*r->count);
	if (NULL == r->pentry_id) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_pull_uint32(pext, &bytes);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	offset = pext->offset + bytes;
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_uint32(pext, &bytes);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		offset2 = pext->offset + bytes;
		status = ext_buffer_pull_oneoff_entryid(pext, r->pentry_id + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (pext->offset > offset2) {
			return EXT_ERR_FORMAT;
		}
		pext->offset = offset2;
		pad_len = ((bytes + 3) & ~3) - bytes;
		status = ext_buffer_pull_advance(pext, pad_len);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (pext->offset > offset) {
		return EXT_ERR_FORMAT;
	}
	pext->offset = offset;
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_persistelement(EXT_PULL *pext, PERSISTELEMENT *r)
{
	int status;
	uint16_t tmp_size;
	
	status = ext_buffer_pull_uint16(pext, &r->element_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch (r->element_id) {
	case RSF_ELID_HEADER:
		status = ext_buffer_pull_uint16(pext, &tmp_size);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (4 != tmp_size) {
			return EXT_ERR_FORMAT;
		}
		r->pentry_id = NULL;
		return ext_buffer_pull_advance(pext, 4);
	case RSF_ELID_ENTRYID:
		r->pentry_id = pext->alloc(sizeof(BINARY*));
		if (NULL == r->pentry_id) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_binary(pext, r->pentry_id);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

static int ext_buffer_pull_persistdata(EXT_PULL *pext, PERSISTDATA *r)
{
	int status;
	uint32_t offset;
	uint16_t tmp_size;
	
	status = ext_buffer_pull_uint16(pext, &r->persist_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &tmp_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (PERSIST_SENTINEL == r->persist_id) {
		if (0 != tmp_size) {
			return EXT_ERR_FORMAT;
		}
		return EXT_ERR_SUCCESS;
	}
	offset = pext->offset + tmp_size;
	status = ext_buffer_pull_persistelement(pext, &r->element);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (PERSIST_SENTINEL == r->persist_id) {
		if (ELEMENT_SENTINEL != r->element.element_id) {
			return EXT_ERR_FORMAT;
		}
	} else {
		if (pext->offset > offset) {
			return EXT_ERR_FORMAT;
		}
		pext->offset = offset;
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_persistdata_array(EXT_PULL *pext, PERSISTDATA_ARRAY *r)
{
	int status;
	
	for (r->count=0; r->count<256; r->count++) {
		r->ppitems[r->count] = pext->alloc(sizeof(PERSISTDATA));
		if (NULL == r->ppitems[r->count]) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_persistdata(pext, r->ppitems[r->count]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (PERSIST_SENTINEL == r->ppitems[r->count]->persist_id) {
			return EXT_ERR_SUCCESS;
		}
	}
	return EXT_ERR_FORMAT;
}

int ext_buffer_pull_eid_array(EXT_PULL *pext, EID_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->pids = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pids = pext->alloc(sizeof(uint64_t)*r->count);
	if (NULL == r->pids) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_uint64(pext, &r->pids[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_systemtime(EXT_PULL *pext, SYSTEMTIME *r)
{
	int status;
	
	status = ext_buffer_pull_int16(pext, &r->year);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int16(pext, &r->month);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int16(pext, &r->dayofweek);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int16(pext, &r->day);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int16(pext, &r->hour);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int16(pext, &r->minute);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int16(pext, &r->second);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_int16(pext, &r->milliseconds);
}

int ext_buffer_pull_timezonestruct(EXT_PULL *pext, TIMEZONESTRUCT *r)
{
	int status;
	
	status = ext_buffer_pull_int32(pext, &r->bias);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int32(pext, &r->standardbias);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int32(pext, &r->daylightbias);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int16(pext, &r->standardyear);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_systemtime(pext, &r->standarddate);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int16(pext, &r->daylightyear);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_systemtime(pext, &r->daylightdate);
}

static int ext_buffer_pull_tzrule(EXT_PULL *pext, TZRULE *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->major);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->minor);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int16(pext, &r->year);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->x, 14);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int32(pext, &r->bias);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int32(pext, &r->standardbias);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int32(pext, &r->daylightbias);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_systemtime(pext, &r->standarddate);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_systemtime(pext, &r->daylightdate);
}

int ext_buffer_pull_timezonedefinition(EXT_PULL *pext, TIMEZONEDEFINITION *r)
{
	int i;
	int status;
	uint16_t cbheader;
	char tmp_buff[262];
	uint16_t cchkeyname;
	char tmp_buff1[1024];
	
	status = ext_buffer_pull_uint8(pext, &r->major);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->minor);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &cbheader);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (cbheader > 266) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_pull_uint16(pext, &r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &cchkeyname);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (cbheader != 6 + 2*cchkeyname) {
		return EXT_ERR_FORMAT;
	}
	memset(tmp_buff, 0, sizeof(tmp_buff));
	status = ext_buffer_pull_bytes(pext, tmp_buff, cbheader - 6);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (FALSE == utf16le_to_utf8(tmp_buff, cbheader - 4, tmp_buff1, 1024)) {
		return EXT_ERR_CHARCNV;
	}
	r->keyname = pext->alloc(strlen(tmp_buff1) + 1);
	if (NULL == r->keyname) {
		return EXT_ERR_ALLOC;
	}
	strcpy(r->keyname, tmp_buff1);
	status = ext_buffer_pull_uint16(pext, &r->crules);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	r->prules = pext->alloc(sizeof(TZRULE)*r->crules);
	if (NULL == r->prules) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->crules; i++) {
		status = ext_buffer_pull_tzrule(pext, r->prules + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_patterntypespecific(EXT_PULL *pext,
	uint16_t patterntype, PATTERNTYPESPECIFIC *r)
{
	int status;
	
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
		status = ext_buffer_pull_uint32(pext,
				&r->monthnth.weekrecurrence);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
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
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->readerversion);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->writerversion);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->recurfrequency);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->patterntype);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->calendartype);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->firstdatetime);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->period);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->slidingflag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_patterntypespecific(pext,
			r->patterntype, &r->patterntypespecific);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->endtype);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->occurrencecount);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->firstdow);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->deletedinstancecount);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->deletedinstancecount) {
		r->pdeletedinstancedates = NULL;
	} else {
		r->pdeletedinstancedates = pext->alloc(
			sizeof(uint32_t)*r->deletedinstancecount);
		if (NULL == r->pdeletedinstancedates) {
			return EXT_ERR_ALLOC;
		}
	}
	for (i=0; i<r->deletedinstancecount; i++) {
		status = ext_buffer_pull_uint32(pext,
				&r->pdeletedinstancedates[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext, &r->modifiedinstancecount);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->modifiedinstancecount) {
		r->pmodifiedinstancedates = NULL;
	} else {
		r->pmodifiedinstancedates = pext->alloc(
			sizeof(uint32_t)*r->modifiedinstancecount);
		if (NULL == r->pmodifiedinstancedates) {
			return EXT_ERR_ALLOC;
		}
	}
	for (i=0; i<r->modifiedinstancecount; i++) {
		status = ext_buffer_pull_uint32(pext,
				&r->pmodifiedinstancedates[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext, &r->startdate);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->enddate);
}

static int ext_buffer_pull_exceptioninfo(EXT_PULL *pext, EXCEPTIONINFO *r)
{
	int status;
	uint16_t tmp_len;
	uint16_t tmp_len2;
	
	status = ext_buffer_pull_uint32(pext, &r->startdatetime);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->enddatetime);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->originalstartdate);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->overrideflags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (r->overrideflags & OVERRIDEFLAG_SUBJECT) {
		status = ext_buffer_pull_uint16(pext, &tmp_len);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint16(pext, &tmp_len2);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (tmp_len != tmp_len2 + 1) {
			return EXT_ERR_FORMAT;
		}
		r->subject = pext->alloc(tmp_len);
		if (NULL == r->subject) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_bytes(pext, r->subject, tmp_len2);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		r->subject[tmp_len2] = '\0';
	}
	if (r->overrideflags & OVERRIDEFLAG_MEETINGTYPE) {
		status = ext_buffer_pull_uint32(pext, &r->meetingtype);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_REMINDERDELTA) {
		status = ext_buffer_pull_uint32(pext, &r->reminderdelta);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_REMINDER) {
		status = ext_buffer_pull_uint32(pext, &r->reminderset);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_LOCATION) {
		status = ext_buffer_pull_uint16(pext, &tmp_len);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint16(pext, &tmp_len2);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (tmp_len != tmp_len2 + 1) {
			return EXT_ERR_FORMAT;
		}
		r->location = pext->alloc(tmp_len);
		if (NULL == r->location) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_bytes(pext, r->location, tmp_len2);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		r->location[tmp_len2] = '\0';
	}
	if (r->overrideflags & OVERRIDEFLAG_BUSYSTATUS) {
		status = ext_buffer_pull_uint32(pext, &r->busystatus);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_ATTACHMENT) {
		status = ext_buffer_pull_uint32(pext, &r->attachment);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_SUBTYPE) {
		status = ext_buffer_pull_uint32(pext, &r->subtype);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_APPTCOLOR) {
		status = ext_buffer_pull_uint32(pext, &r->appointmentcolor);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_pull_changehighlight(
	EXT_PULL *pext, CHANGEHIGHLIGHT *r)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->value);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (r->size < sizeof(uint32_t)) {
		return EXT_ERR_FORMAT;
	} else if (sizeof(uint32_t) == r->size) {
		r->preserved = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->preserved = pext->alloc(r->size - sizeof(uint32_t));
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
	int status;
	char *pbuff;
	int string_len;
	uint16_t tmp_len;
	
	if (writerversion2 >= 0x00003009) {
		status = ext_buffer_pull_changehighlight(
					pext, &r->changehighlight);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext, &r->reservedblockee1size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->reservedblockee1size) {
		r->preservedblockee1 = NULL;
	} else {
		r->preservedblockee1 = pext->alloc(r->reservedblockee1size);
		if (NULL == r->preservedblockee1) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_bytes(pext,
			r->preservedblockee1, r->reservedblockee1size);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if ((overrideflags & OVERRIDEFLAG_LOCATION) ||
		(overrideflags & OVERRIDEFLAG_SUBJECT)) {
		status = ext_buffer_pull_uint32(pext, &r->startdatetime);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint32(pext, &r->enddatetime);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint32(pext, &r->originalstartdate);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (overrideflags & OVERRIDEFLAG_SUBJECT) {
		status = ext_buffer_pull_uint16(pext, &tmp_len);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		tmp_len *= 2;
		pbuff = malloc(3*(tmp_len + 2));
		if (NULL == pbuff) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_bytes(pext, pbuff, tmp_len);
		if (EXT_ERR_SUCCESS != status) {
			free(pbuff);
			return status;
		}
		pbuff[tmp_len ++] = '\0';
		pbuff[tmp_len ++] = '\0';
		if (FALSE == utf16le_to_utf8(pbuff,
			tmp_len, pbuff + tmp_len, 2*tmp_len)) {
			free(pbuff);
			return EXT_ERR_CHARCNV;
		}
		string_len = strlen(pbuff + tmp_len);
		r->subject = pext->alloc(string_len + 1);
		if (NULL == r->subject) {
			free(pbuff);
			return EXT_ERR_ALLOC;
		}
		strcpy(r->subject, pbuff + tmp_len);
		free(pbuff);
	}
	if (overrideflags & OVERRIDEFLAG_LOCATION) {
		status = ext_buffer_pull_uint16(pext, &tmp_len);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		tmp_len *= 2;
		pbuff = malloc(3*(tmp_len + 2));
		if (NULL == pbuff) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_bytes(pext, pbuff, tmp_len);
		if (EXT_ERR_SUCCESS != status) {
			free(pbuff);
			return status;
		}
		pbuff[tmp_len ++] = '\0';
		pbuff[tmp_len ++] = '\0';
		if (FALSE == utf16le_to_utf8(pbuff,
			tmp_len, pbuff + tmp_len, 2*tmp_len)) {
			free(pbuff);
			return EXT_ERR_CHARCNV;
		}
		string_len = strlen(pbuff + tmp_len);
		r->location = pext->alloc(string_len + 1);
		if (NULL == r->location) {
			free(pbuff);
			return EXT_ERR_ALLOC;
		}
		strcpy(r->location, pbuff + tmp_len);
		free(pbuff);
	}
	if ((overrideflags & OVERRIDEFLAG_LOCATION) ||
		(overrideflags & OVERRIDEFLAG_SUBJECT)) {
		status = ext_buffer_pull_uint32(pext, &r->reservedblockee2size);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (0 == r->reservedblockee2size) {
			r->preservedblockee2 = NULL;
		} else {
			r->preservedblockee2 = pext->alloc(r->reservedblockee2size);
			if (NULL == r->preservedblockee2) {
				return EXT_ERR_ALLOC;
			}
			status = ext_buffer_pull_bytes(pext,
				r->preservedblockee2, r->reservedblockee2size);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return status;
}

int ext_buffer_pull_appointmentrecurrencepattern(
	EXT_PULL *pext, APPOINTMENTRECURRENCEPATTERN *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_recurrencepattern(
				pext, &r->recurrencepattern);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->readerversion2);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->writerversion2);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->starttimeoffset);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->endtimeoffset);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->exceptioncount);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->exceptioncount) {
		r->pexceptioninfo = NULL;
		r->pextendedexception = NULL;
	} else {
		r->pexceptioninfo = pext->alloc(
			sizeof(EXCEPTIONINFO)*r->exceptioncount);
		if (NULL == r->pexceptioninfo) {
			return EXT_ERR_ALLOC;
		}
		r->pextendedexception = pext->alloc(
			sizeof(EXTENDEDEXCEPTION)*r->exceptioncount);
		if (NULL == r->pextendedexception) {
			return EXT_ERR_ALLOC;
		}
	}
	for (i=0; i<r->exceptioncount; i++) {
		status = ext_buffer_pull_exceptioninfo(
					pext, &r->pexceptioninfo[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext, &r->reservedblock1size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->reservedblock1size) {
		r->preservedblock1 = NULL;
	} else {
		r->preservedblock1 = pext->alloc(r->reservedblock1size);
		if (NULL == r->preservedblock1) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_bytes(pext,
			r->preservedblock1, r->reservedblock1size);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	for (i=0; i<r->exceptioncount; i++) {
		status = ext_buffer_pull_extendedexception(pext, r->writerversion2,
			r->pexceptioninfo[i].overrideflags, &r->pextendedexception[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext, &r->reservedblock2size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->reservedblock2size) {
		r->preservedblock2 = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->preservedblock2 = pext->alloc(r->reservedblock2size);
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
	int status;
	
	status = ext_buffer_pull_bytes(pext, r->arrayid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &yh);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &yl);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	r->year = ((uint16_t)yh) << 8 | yl;
	status = ext_buffer_pull_uint8(pext, &r->month);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->day);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext, &r->creationtime);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bytes(pext, r->x, 8);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_exbinary(pext, &r->data);
}

static int ext_buffer_pull_attachment_list(EXT_PULL *pext, ATTACHMENT_LIST *r)
{
	int i;
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	r->pplist = pext->alloc(sizeof(ATTACHMENT_CONTENT*)*r->count);
	if (NULL == r->pplist) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		r->pplist[i] = pext->alloc(sizeof(ATTACHMENT_CONTENT));
		if (NULL == r->pplist[i]) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_tpropval_array(
					pext, &r->pplist[i]->proplist);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint8(pext, &tmp_byte);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != tmp_byte) {
			r->pplist[i]->pembedded = pext->alloc(sizeof(MESSAGE_CONTENT));
			if (NULL == r->pplist[i]->pembedded) {
				return EXT_ERR_ALLOC;
			}
			status = ext_buffer_pull_message_content(
						pext, r->pplist[i]->pembedded);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		} else {
			r->pplist[i]->pembedded = NULL;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_pull_message_content(EXT_PULL *pext, MESSAGE_CONTENT *r)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_tpropval_array(pext, &r->proplist);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != tmp_byte) {
		r->children.prcpts = pext->alloc(sizeof(TARRAY_SET));
		if (NULL == r->children.prcpts) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_tarray_set(pext, r->children.prcpts);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->children.prcpts = NULL;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != tmp_byte) {
		r->children.pattachments = pext->alloc(sizeof(ATTACHMENT_LIST));
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
		pext->data = malloc(pext->alloc_size);
		if (NULL == pext->data) {
			return FALSE;
		}
	} else {
		pext->b_alloc = FALSE;
		pext->data = pdata;
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
	int status;
	
	status = ext_buffer_push_uint16(pext, r->version);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint16(pext, r->size_actual);
}

/* FALSE: overflow, TRUE: not overflow */
BOOL ext_buffer_push_check_overflow(EXT_PUSH *pext, uint32_t extra_size)
{
	uint32_t size;
	uint8_t *pdata;
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
	pdata = realloc(pext->data, alloc_size);
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

int ext_buffer_push_int64(EXT_PUSH *pext, int64_t v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(int64_t))) {
		return EXT_ERR_BUFSIZE;
	}
	EXT_SIVAL(pext, pext->offset, (v & 0xFFFFFFFF));
	EXT_SIVAL(pext, pext->offset+4, (v>>32));
	pext->offset += sizeof(int64_t);
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
	int status;
	
	if (pext->flags & EXT_FLAG_WCOUNT) {
		status = ext_buffer_push_uint32(pext, r->cb);
	} else {
		if (r->cb > 0xFFFF) {
			return EXT_ERR_FORMAT;
		}
		status = ext_buffer_push_uint16(pext, r->cb);
	}
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->cb) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_push_bytes(pext, r->pb, r->cb);
}

int ext_buffer_push_sbinary(EXT_PUSH *pext, const BINARY *r)
{
	int status;
	
	if (r->cb > 0xFFFF) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_push_uint16(pext, r->cb);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->cb) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_push_bytes(pext, r->pb, r->cb);
}

int ext_buffer_push_exbinary(EXT_PUSH *pext, const BINARY *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, r->cb);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->cb) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_push_bytes(pext, r->pb, r->cb);
}

int ext_buffer_push_guid(EXT_PUSH *pext, const GUID *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, r->time_low);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->time_mid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->time_hi_and_version);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->clock_seq, 2);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bytes(pext, r->node, 6);
}

int ext_buffer_push_string(EXT_PUSH *pext, const char *pstr)
{
	int len;
	int status;
	
	len = strlen(pstr) + 1;
	if (pext->flags & EXT_FLAG_TBLLMT) {
		if (len > 510) {
			status = ext_buffer_push_bytes(pext, pstr, 509);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
			return ext_buffer_push_uint8(pext, 0);
		}
	}
	return ext_buffer_push_bytes(pext, pstr, len);
}

int ext_buffer_push_wstring(EXT_PUSH *pext, const char *pstr)
{
	int len;
	int status;
	char *pbuff;
	
	if (0 == (pext->flags & EXT_FLAG_UTF16)) {
		return ext_buffer_push_string(pext, pstr);
	}
	len = 2*strlen(pstr) + 2;
	pbuff = malloc(len);
	if (NULL == pbuff) {
		return EXT_ERR_ALLOC;
	}
	len = utf8_to_utf16le(pstr, pbuff, len);
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
	status = ext_buffer_push_bytes(pext, pbuff, len);
	free(pbuff);
	return status;
}

int ext_buffer_push_short_array(EXT_PUSH *pext, const SHORT_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_uint16(pext, r->ps[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_long_array(EXT_PUSH *pext, const LONG_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_uint32(pext, r->pl[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_longlong_array(EXT_PUSH *pext, const LONGLONG_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_uint64(pext, r->pll[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_slonglong_array(EXT_PUSH *pext, const LONGLONG_ARRAY *r)
{
	int i;
	int status;
	
	if (r->count > 0xFFFF) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_uint64(pext, r->pll[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_binary_array(EXT_PUSH *pext, const BINARY_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_binary(pext, &r->pbin[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_string_array(EXT_PUSH *pext, const STRING_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_string(pext, r->ppstr[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_wstring_array(EXT_PUSH *pext, const STRING_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_wstring(pext, r->ppstr[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_guid_array(EXT_PUSH *pext, const GUID_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_guid(pext, &r->pguid[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_restriction_and_or(
	EXT_PUSH *pext, const RESTRICTION_AND_OR *r)
{
	int i;
	int status;
	
	if (pext->flags & EXT_FLAG_WCOUNT) {
		status = ext_buffer_push_uint32(pext, r->count);
	} else {
		status = ext_buffer_push_uint16(pext, r->count);
	}
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_restriction(pext, &r->pres[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
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
	int status;
	
	status = ext_buffer_push_uint32(pext, r->fuzzy_level);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_tagged_propval(pext, &r->propval);
}

static int ext_buffer_push_restriction_property(
	EXT_PUSH *pext, const RESTRICTION_PROPERTY *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->relop);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_tagged_propval(pext, &r->propval);
}

static int ext_buffer_push_restriction_propcompare(
	EXT_PUSH *pext, const RESTRICTION_PROPCOMPARE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->relop);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->proptag1);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext, r->proptag2);
}

static int ext_buffer_push_restriction_bitmask(
	EXT_PUSH *pext, const RESTRICTION_BITMASK *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->bitmask_relop);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext, r->mask);
}

static int ext_buffer_push_restriction_size(
	EXT_PUSH *pext, const RESTRICTION_SIZE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->relop);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
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
	int status;
	
	status = ext_buffer_push_uint32(pext, r->subobject);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_restriction(pext, &r->res);
}

static int ext_buffer_push_restriction_comment(
	EXT_PUSH *pext, const RESTRICTION_COMMENT *r)
{
	int i;
	int status;
	
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_push_uint8(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_tagged_propval(pext, &r->ppropval[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pres) {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_restriction(pext, r->pres);
	}
	return ext_buffer_push_uint8(pext, 0);
}

static int ext_buffer_push_restriction_count(
	EXT_PUSH *pext, const RESTRICTION_COUNT *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_restriction(pext, &r->sub_res);
}

int ext_buffer_push_restriction(EXT_PUSH *pext, const RESTRICTION *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->rt);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch (r->rt) {
	case RESTRICTION_TYPE_AND:
	case RESTRICTION_TYPE_OR:
		return ext_buffer_push_restriction_and_or(pext, r->pres);
	case RESTRICTION_TYPE_NOT:
		return ext_buffer_push_restriction_not(pext, r->pres);
	case RESTRICTION_TYPE_CONTENT:
		return ext_buffer_push_restriction_content(pext, r->pres);
	case RESTRICTION_TYPE_PROPERTY:
		return ext_buffer_push_restriction_property(pext, r->pres);
	case RESTRICTION_TYPE_PROPCOMPARE:
		return ext_buffer_push_restriction_propcompare(pext, r->pres);
	case RESTRICTION_TYPE_BITMASK:
		return ext_buffer_push_restriction_bitmask(pext, r->pres);
	case RESTRICTION_TYPE_SIZE:
		return ext_buffer_push_restriction_size(pext, r->pres);
	case RESTRICTION_TYPE_EXIST:
		return ext_buffer_push_restriction_exist(pext, r->pres);
	case RESTRICTION_TYPE_SUBOBJ:
		return ext_buffer_push_restriction_subobj(pext, r->pres);
	case RESTRICTION_TYPE_COMMENT:
		return ext_buffer_push_restriction_comment(pext, r->pres);
	case RESTRICTION_TYPE_COUNT:
		return ext_buffer_push_restriction_count(pext, r->pres);
	case RESTRICTION_TYPE_NULL:
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int ext_buffer_push_svreid(EXT_PUSH *pext, const SVREID *r)
{
	int status;
	
	if (NULL != r->pbin) {
		status = ext_buffer_push_uint16(pext, r->pbin->cb + 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_bytes(pext, r->pbin->pb, r->pbin->cb);
	}
	status = ext_buffer_push_uint16(pext, 21);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, 1);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext, r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext, r->message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext, r->instance);
}

int ext_buffer_push_store_entryid(EXT_PUSH *pext, const STORE_ENTRYID *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->provider_uid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->version);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->flag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->dll_name, 14);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->wrapped_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->wrapped_provider_uid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->wrapped_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_string(pext, r->pserver_name);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_string(pext, r->pmailbox_dn);
}

static int ext_buffer_push_movecopy_action(EXT_PUSH *pext,
    const MOVECOPY_ACTION *r)
{
	int status;
	uint32_t offset;
	uint32_t offset1;
	uint16_t eid_size;
	
	status = ext_buffer_push_uint8(pext, r->same_store);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->same_store) {
		offset = pext->offset;
		status = ext_buffer_push_advance(pext, sizeof(uint16_t));
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (NULL == r->pstore_eid) {
			return EXT_ERR_FORMAT;
		}
		status = ext_buffer_push_store_entryid(pext, r->pstore_eid);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		offset1 = pext->offset;
		eid_size = offset1 - (offset + sizeof(uint16_t));
		pext->offset = offset;
		status = ext_buffer_push_uint16(pext, eid_size);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		pext->offset = offset1;
	} else {
		status = ext_buffer_push_uint16(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (0 != r->same_store) {
		return ext_buffer_push_svreid(pext, r->pfolder_eid);
	} else {
		return ext_buffer_push_binary(pext, r->pfolder_eid);
	}
}

static int ext_buffer_push_reply_action(
	EXT_PUSH *pext, const REPLY_ACTION *r)
{
	int status;
	
	status = ext_buffer_push_uint64(pext, r->template_folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext, r->template_message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_guid(pext, &r->template_guid);
}

static int ext_buffer_push_recipient_block(
	EXT_PUSH *pext, const RECIPIENT_BLOCK *r)
{
	int i;
	int status;
	
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_push_uint8(pext, r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_tagged_propval(pext, &r->ppropval[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_forwarddelegate_action(
	EXT_PUSH *pext, const FORWARDDELEGATE_ACTION *r)
{
	int i;
	int status;
	
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_recipient_block(pext, &r->pblock[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_action_block(
	EXT_PUSH *pext, const ACTION_BLOCK *r)
{
	int status;
	uint32_t offset;
	uint32_t offset1;
	uint16_t tmp_len;
	
	offset = pext->offset;
	status = ext_buffer_push_advance(pext, sizeof(uint16_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->flavor);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch (r->type) {
	case ACTION_TYPE_OP_MOVE:
	case ACTION_TYPE_OP_COPY:
		status = ext_buffer_push_movecopy_action(pext, r->pdata);
		break;
	case ACTION_TYPE_OP_REPLY:
	case ACTION_TYPE_OP_OOF_REPLY:
		status = ext_buffer_push_reply_action(pext, r->pdata);
		break;
	case ACTION_TYPE_OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - 2*sizeof(uint32_t);
		status = ext_buffer_push_bytes(pext, r->pdata, tmp_len);
		break;
	case ACTION_TYPE_OP_BOUNCE:
		status = ext_buffer_push_uint32(pext, *(uint32_t*)r->pdata);
		break;
	case ACTION_TYPE_OP_FORWARD:
	case ACTION_TYPE_OP_DELEGATE:
		status = ext_buffer_push_forwarddelegate_action(pext, r->pdata);
		break;
	case ACTION_TYPE_OP_TAG:
		status = ext_buffer_push_tagged_propval(pext, r->pdata);
	case ACTION_TYPE_OP_DELETE:
	case ACTION_TYPE_OP_MARK_AS_READ:
		status = EXT_ERR_SUCCESS;
		break;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	tmp_len = pext->offset - (offset + sizeof(uint16_t));
	offset1 = pext->offset;
	pext->offset = offset;
	status = ext_buffer_push_uint16(pext, tmp_len);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_rule_actions(EXT_PUSH *pext, const RULE_ACTIONS *r)
{
	int i;
	int status;
	
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_action_block(pext, &r->pblock[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_propval(EXT_PUSH *pext, uint16_t type, const void *pval)
{
	/* convert multi-value instance into single value */
	if (0x3000 == (type & 0x3000)) {
		type &= ~0x3000;
	}
	switch (type) {
	case PT_UNSPECIFIED:
		return ext_buffer_push_typed_propval(pext, pval);
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
	case PROPVAL_TYPE_LONGLONG:
	case PROPVAL_TYPE_FILETIME:
		return ext_buffer_push_uint64(pext, *(uint64_t*)pval);
	case PT_STRING8:
		return ext_buffer_push_string(pext, pval);
	case PT_UNICODE:
		return ext_buffer_push_wstring(pext, pval);
	case PT_CLSID:
		return ext_buffer_push_guid(pext, pval);
	case PROPVAL_TYPE_SVREID:
		return ext_buffer_push_svreid(pext, pval);
	case PROPVAL_TYPE_RESTRICTION:
		return ext_buffer_push_restriction(pext, pval);
	case PROPVAL_TYPE_RULE:
		return ext_buffer_push_rule_actions(pext, pval);
	case PT_BINARY:
	case PT_OBJECT:
		return ext_buffer_push_binary(pext, pval);
	case PT_MV_SHORT:
		return ext_buffer_push_short_array(pext, pval);
	case PT_MV_LONG:
		return ext_buffer_push_long_array(pext, pval);
	case PROPVAL_TYPE_LONGLONG_ARRAY:
		return ext_buffer_push_longlong_array(pext, pval);
	case PT_MV_STRING8:
		return ext_buffer_push_string_array(pext, pval);
	case PT_MV_UNICODE:
		return ext_buffer_push_wstring_array(pext, pval);
	case PT_MV_CLSID:
		return ext_buffer_push_guid_array(pext, pval);
	case PT_MV_BINARY:
		return ext_buffer_push_binary_array(pext, pval);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int ext_buffer_push_typed_propval(EXT_PUSH *pext, const TYPED_PROPVAL *r)
{
	int status;
	
	status = ext_buffer_push_uint16(pext, r->type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_propval(pext, r->type, r->pvalue);
}

int ext_buffer_push_tagged_propval(EXT_PUSH *pext, const TAGGED_PROPVAL *r)
{
	int status;

	status = ext_buffer_push_uint32(pext, r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_propval(pext, PROP_TYPE(r->proptag), r->pvalue);
}

int ext_buffer_push_long_term_id(EXT_PUSH *pext, const LONG_TERM_ID *r)
{
	int status;

	status = ext_buffer_push_guid(pext, &r->guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->global_counter, 6);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint16(pext, r->padding);
}

int ext_buffer_push_long_term_id_array(
	EXT_PUSH *pext, const LONG_TERM_ID_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_long_term_id(pext, &r->pids[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_long_term_id_rang(EXT_PUSH *pext, const LONG_TERM_ID_RANGE *r)
{
	int status;
	
	status = ext_buffer_push_long_term_id(pext, &r->min);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_long_term_id(pext, &r->max);
}

int ext_buffer_push_proptag_array(EXT_PUSH *pext, const PROPTAG_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_uint32(pext, r->pproptag[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_property_name(EXT_PUSH *pext, const PROPERTY_NAME *r)
{
	int status;
	uint32_t offset;
	uint32_t offset1;
	uint8_t name_size;
	
	status = ext_buffer_push_uint8(pext, r->kind);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_guid(pext, &r->guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (KIND_LID == r->kind) {
		status = ext_buffer_push_uint32(pext, *r->plid);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else if (KIND_NAME == r->kind) {
		offset = pext->offset;
		status = ext_buffer_push_advance(pext, sizeof(uint8_t));
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_wstring(pext, r->pname);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		name_size = pext->offset - (offset + sizeof(uint8_t));
		offset1 = pext->offset;
		pext->offset = offset;
		status = ext_buffer_push_uint8(pext, name_size);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		pext->offset = offset1;
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_propname_array(EXT_PUSH *pext, const PROPNAME_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_property_name(pext, r->ppropname + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_propid_array(EXT_PUSH *pext, const PROPID_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_uint16(pext, r->ppropid[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_tpropval_array(EXT_PUSH *pext, const TPROPVAL_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_tagged_propval(pext, r->ppropval + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_tarray_set(EXT_PUSH *pext, const TARRAY_SET *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_tpropval_array(pext, r->pparray[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}


static int ext_buffer_push_property_problem(EXT_PUSH *pext, const PROPERTY_PROBLEM *r)
{
	int status;
	
	status = ext_buffer_push_uint16(pext, r->index);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext, r->err);
}

int ext_buffer_push_problem_array(EXT_PUSH *pext, const PROBLEM_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_property_problem(pext, r->pproblem + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_xid(EXT_PUSH *pext, uint8_t size, const XID *pxid)
{
	int status;
	
	if (size < 17 || size > 24) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_push_guid(pext, &pxid->guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bytes(pext, pxid->local_id, size - 16);
}

int ext_buffer_push_folder_entryid(
	EXT_PUSH *pext, const FOLDER_ENTRYID *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->provider_uid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->folder_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_guid(pext, &r->database_guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->global_counter, 6);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bytes(pext, r->pad, 2);
}

static int ext_buffer_push_ext_movecopy_action(
	EXT_PUSH *pext, const EXT_MOVECOPY_ACTION *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, 1);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, 0);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, 46);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_folder_entryid(pext, &r->folder_eid);
}

int ext_buffer_push_message_entryid(EXT_PUSH *pext, const MESSAGE_ENTRYID *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->provider_uid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->message_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_guid(pext, &r->folder_database_guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->folder_global_counter, 6);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->pad1, 2);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_guid(pext, &r->message_database_guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->message_global_counter, 6);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bytes(pext, r->pad2, 2);
}

static int ext_buffer_push_ext_reply_action(
	EXT_PUSH *pext, const EXT_REPLY_ACTION *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, 70);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_message_entryid(pext, &r->message_eid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_guid(pext, &r->template_guid);
}

static int ext_buffer_push_ext_recipient_block(
	EXT_PUSH *pext, const EXT_RECIPIENT_BLOCK *r)
{
	int i;
	int status;
	
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_push_uint8(pext, r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_tagged_propval(pext, &r->ppropval[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_ext_forwarddelegate_action(
	EXT_PUSH *pext, const EXT_FORWARDDELEGATE_ACTION *r)
{
	int i;
	int status;
	
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_ext_recipient_block(pext, &r->pblock[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_ext_action_block(
	EXT_PUSH *pext, const EXT_ACTION_BLOCK *r)
{
	int status;
	uint32_t offset;
	uint32_t offset1;
	uint32_t tmp_len;
	
	status = ext_buffer_push_advance(pext, sizeof(uint32_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	offset = pext->offset;
	status = ext_buffer_push_uint8(pext, r->type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->flavor);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch (r->type) {
	case ACTION_TYPE_OP_MOVE:
	case ACTION_TYPE_OP_COPY:
		status = ext_buffer_push_ext_movecopy_action(pext, r->pdata);
		break;
	case ACTION_TYPE_OP_REPLY:
	case ACTION_TYPE_OP_OOF_REPLY:
		status = ext_buffer_push_ext_reply_action(pext, r->pdata);
		break;
	case ACTION_TYPE_OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - sizeof(uint32_t);
		status = ext_buffer_push_bytes(pext, r->pdata, tmp_len);
		break;
	case ACTION_TYPE_OP_BOUNCE:
		status = ext_buffer_push_uint32(pext, *(uint32_t*)r->pdata);
		break;
	case ACTION_TYPE_OP_FORWARD:
	case ACTION_TYPE_OP_DELEGATE:
		status = ext_buffer_push_ext_forwarddelegate_action(pext, r->pdata);
		break;
	case ACTION_TYPE_OP_TAG:
		status = ext_buffer_push_tagged_propval(pext, r->pdata);
	case ACTION_TYPE_OP_DELETE:
	case ACTION_TYPE_OP_MARK_AS_READ:
		status = EXT_ERR_SUCCESS;
		break;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	tmp_len = pext->offset - offset;
	offset1 = pext->offset;
	pext->offset = offset - sizeof(uint32_t);
	status = ext_buffer_push_uint32(pext, tmp_len);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_ext_rule_actions(EXT_PUSH *pext, const EXT_RULE_ACTIONS *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_ext_action_block(pext, &r->pblock[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_namedproperty_information(
	EXT_PUSH *pext, const NAMEDPROPERTY_INFOMATION *r)
{
	int i;
	int status;
	uint32_t size;
	uint32_t offset;
	uint32_t offset1;
	
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_uint16(pext, r->ppropid[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	offset = pext->offset;
	status = ext_buffer_push_advance(pext, sizeof(uint32_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_property_name(pext, r->ppropname + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	offset1 = pext->offset;
	size = offset1 - (offset + sizeof(uint32_t));
	pext->offset = offset;
	status = ext_buffer_push_uint32(pext, size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_flagged_propval(EXT_PUSH *pext,
	uint16_t type, const FLAGGED_PROPVAL *r)
{
	int status;
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
		status = ext_buffer_push_uint16(pext, type);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		pvalue = r->pvalue;
	}
	status = ext_buffer_push_uint8(pext, r->flag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
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
	int status;
	
	status = ext_buffer_push_uint8(pext, r->flag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (PROPERTY_ROW_FLAG_NONE == r->flag) {
		for (i=0; i<pcolumns->count; i++) {
			status = ext_buffer_push_propval(pext,
			         PROP_TYPE(pcolumns->pproptag[i]), r->pppropval[i]);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		}
		return EXT_ERR_SUCCESS;
	} else if (PROPERTY_ROW_FLAG_FLAGGED == r->flag) {
		for (i=0; i<pcolumns->count; i++) {
			status = ext_buffer_push_flagged_propval(pext,
			         PROP_TYPE(pcolumns->pproptag[i]), r->pppropval[i]);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		}
		return EXT_ERR_SUCCESS;
	}
	return EXT_ERR_BAD_SWITCH;
}

int ext_buffer_push_proprow_set(EXT_PUSH *pext,
	const PROPTAG_ARRAY *pcolumns, const PROPROW_SET *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_property_row(pext, pcolumns, &r->prows[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_sort_order(EXT_PUSH *pext, const SORT_ORDER *r)
{
	int status;
	
	if (r->type & 0x1000 && 0 == (r->type & 0x2000)) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_push_uint16(pext, r->type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->propid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint8(pext, r->table_sort);
}

int ext_buffer_push_sortorder_set(EXT_PUSH *pext, const SORTORDER_SET *r)
{
	int i;
	int status;
	
	if (0 == r->count || r->ccategories > r->count ||
		r->cexpanded > r->ccategories) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->ccategories);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->cexpanded);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_sort_order(pext, r->psort + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_typed_string(EXT_PUSH *pext, const TYPED_STRING *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->string_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
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
	int status;
	BOOL b_unicode;
	PROPTAG_ARRAY proptags;
	
	b_unicode = FALSE;
	if (r->flags & RECIPIENT_ROW_FLAG_UNICODE) {
		b_unicode = TRUE;
	}
	status = ext_buffer_push_uint16(pext, r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->pprefix_used) {
		status = ext_buffer_push_uint8(pext,  *r->pprefix_used);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pdisplay_type) {
		status = ext_buffer_push_uint8(pext, *r->pdisplay_type);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->px500dn) {
		status = ext_buffer_push_string(pext, r->px500dn);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pentry_id) {
		status = ext_buffer_push_binary(pext, r->pentry_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->psearch_key) {
		status = ext_buffer_push_binary(pext, r->psearch_key);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->paddress_type) {
		status = ext_buffer_push_string(pext, r->paddress_type);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pmail_address) {
		if (TRUE == b_unicode) {
			status = ext_buffer_push_wstring(pext, r->pmail_address);
		} else {
			status = ext_buffer_push_string(pext, r->pmail_address);
		}
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pdisplay_name) {
		if (TRUE == b_unicode) {
			status = ext_buffer_push_wstring(pext, r->pdisplay_name);
		} else {
			status = ext_buffer_push_string(pext, r->pdisplay_name);
		}
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->psimple_name) {
		if (TRUE == b_unicode) {
			status = ext_buffer_push_wstring(pext, r->psimple_name);
		} else {
			status = ext_buffer_push_string(pext, r->psimple_name);
		}
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->ptransmittable_name) {
		if (TRUE == b_unicode) {
			status = ext_buffer_push_wstring(pext, r->ptransmittable_name);
		} else {
			status = ext_buffer_push_string(pext, r->ptransmittable_name);
		}
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
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
	int status;
	uint32_t offset;
	uint32_t offset1;
	uint16_t row_size;
	
	status = ext_buffer_push_uint8(pext, r->recipient_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	offset = pext->offset;
	status = ext_buffer_push_advance(pext, sizeof(uint16_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_recipient_row(pext, pproptags, &r->recipient_row);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	row_size = pext->offset - (offset + sizeof(uint16_t));
	offset1 = pext->offset;
	pext->offset = offset;
	status = ext_buffer_push_uint16(pext, row_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_modifyrecipient_row(EXT_PUSH *pext,
	PROPTAG_ARRAY *pproptags, const MODIFYRECIPIENT_ROW *r)
{
	int status;
	uint32_t offset;
	uint32_t offset1;
	uint16_t row_size;
	
	status = ext_buffer_push_uint32(pext, r->row_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->recipient_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == r->precipient_row) {
		return ext_buffer_push_uint16(pext, 0);
	}
	offset = pext->offset;
	status = ext_buffer_push_advance(pext, sizeof(uint16_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_recipient_row(pext, pproptags, r->precipient_row);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	row_size = pext->offset - (offset + sizeof(uint16_t));
	offset1 = pext->offset;
	pext->offset = offset;
	status = ext_buffer_push_uint16(pext, row_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_readrecipient_row(EXT_PUSH *pext,
	PROPTAG_ARRAY *pproptags, const READRECIPIENT_ROW *r)
{
	int status;
	uint32_t offset;
	uint32_t offset1;
	uint16_t row_size;
	
	status = ext_buffer_push_uint32(pext, r->row_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->recipient_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	offset = pext->offset;
	status = ext_buffer_push_advance(pext, sizeof(uint16_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_recipient_row(pext, pproptags, &r->recipient_row);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	row_size = pext->offset - (offset + sizeof(uint16_t));
	offset1 = pext->offset;
	pext->offset = offset;
	status = ext_buffer_push_uint16(pext, row_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_permission_data(EXT_PUSH *pext, const PERMISSION_DATA *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_tpropval_array(pext, &r->propvals);
}

int ext_buffer_push_rule_data(EXT_PUSH *pext, const RULE_DATA *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_tpropval_array(pext, &r->propvals);
}

int ext_buffer_push_addressbook_entryid(
	EXT_PUSH *pext, const ADDRESSBOOK_ENTRYID *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->provider_uid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->version);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_string(pext, r->px500dn);
}

int ext_buffer_push_oneoff_entryid(EXT_PUSH *pext,
	const ONEOFF_ENTRYID *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->provider_uid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->version);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->ctrl_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (r->ctrl_flags & CTRL_FLAG_UNICODE) {
		status = ext_buffer_push_wstring(pext, r->pdisplay_name);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_wstring(pext, r->paddress_type);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_wstring(pext, r->pmail_address);
	} else {
		status = ext_buffer_push_string(pext, r->pdisplay_name);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext, r->paddress_type);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_string(pext, r->pmail_address);
	}
}

int ext_buffer_push_oneoff_array(EXT_PUSH *pext, const ONEOFF_ARRAY *r)
{
	int i;
	int status;
	uint32_t bytes;
	uint8_t pad_len;
	uint32_t offset;
	uint32_t offset1;
	uint32_t offset2;
	uint8_t pad_bytes[3] = {0, 0, 0};
	
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	offset = pext->offset;
	status = ext_buffer_push_advance(pext, sizeof(uint32_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		offset1 = pext->offset;
		status = ext_buffer_push_advance(pext, sizeof(uint32_t));
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_oneoff_entryid(pext, r->pentry_id + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		offset2 = pext->offset;
		bytes = offset2 - (offset1 + sizeof(uint32_t));
		pext->offset = offset1;
		status = ext_buffer_push_uint32(pext, bytes);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		pext->offset = offset2;
		pad_len = ((bytes + 3) & ~3) - bytes;
		status = ext_buffer_push_bytes(pext, pad_bytes, pad_len);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	bytes = pext->offset - (offset + sizeof(uint32_t));
	offset1 = pext->offset;
	pext->offset = offset;
	status = ext_buffer_push_uint32(pext, bytes);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_persistelement(
	EXT_PUSH *pext, const PERSISTELEMENT *r)
{
	int status;
	
	status = ext_buffer_push_uint16(pext, r->element_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch (r->element_id) {
	case RSF_ELID_HEADER:
		status = ext_buffer_push_uint16(pext, 4);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_uint32(pext, 0);
	case RSF_ELID_ENTRYID:
		return ext_buffer_push_binary(pext, r->pentry_id);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

static int ext_buffer_push_persistdata(EXT_PUSH *pext, const PERSISTDATA *r)
{
	int status;
	uint32_t offset;
	uint32_t offset1;
	uint16_t tmp_size;
	
	status = ext_buffer_push_uint16(pext, r->persist_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (PERSIST_SENTINEL == r->persist_id) {
		return ext_buffer_push_uint16(pext, 0);
	}
	offset = pext->offset;
	status = ext_buffer_push_advance(pext, sizeof(uint16_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_persistelement(pext, &r->element);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	tmp_size = pext->offset - (offset + sizeof(uint16_t));
	offset1 = pext->offset;
	pext->offset = offset;
	status = ext_buffer_push_uint16(pext, tmp_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_persistdata_array(
	EXT_PUSH *pext, const PERSISTDATA_ARRAY *r)
{
	int i;
	int status;
	PERSISTDATA last_data;
	
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_persistdata(pext, r->ppitems[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	last_data.persist_id = PERSIST_SENTINEL;
	last_data.element.element_id = ELEMENT_SENTINEL;
	last_data.element.pentry_id = NULL;
	return ext_buffer_push_persistdata(pext, &last_data);
}

int ext_buffer_push_eid_array(EXT_PUSH *pext, const EID_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint32(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_uint64(pext, r->pids[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_systemtime(EXT_PUSH *pext, const SYSTEMTIME *r)
{
	int status;
	
	status = ext_buffer_push_int16(pext, r->year);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int16(pext, r->month);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int16(pext, r->dayofweek);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int16(pext, r->day);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int16(pext, r->hour);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int16(pext, r->minute);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int16(pext, r->second);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_int16(pext, r->milliseconds);
}

int ext_buffer_push_timezonestruct(EXT_PUSH *pext, const TIMEZONESTRUCT *r)
{
	int status;
	
	status = ext_buffer_push_int32(pext, r->bias);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int32(pext, r->standardbias);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int32(pext, r->daylightbias);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int16(pext, r->standardyear);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_systemtime(pext, &r->standarddate);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int16(pext, r->daylightyear);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_systemtime(pext, &r->daylightdate);
}

static int ext_buffer_push_tzrule(EXT_PUSH *pext, const TZRULE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->major);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->minor);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int16(pext, r->year);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->x, 14);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int32(pext, r->bias);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int32(pext, r->standardbias);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int32(pext, r->daylightbias);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_systemtime(pext, &r->standarddate);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_systemtime(pext, &r->daylightdate);
}

int ext_buffer_push_timezonedefinition(
	EXT_PUSH *pext, const TIMEZONEDEFINITION *r)
{
	int i;
	int len;
	int status;
	uint16_t cbheader;
	char tmp_buff[262];
	
	status = ext_buffer_push_uint8(pext, r->major);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->minor);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	len = utf8_to_utf16le(r->keyname, tmp_buff, 262);
	if (len < 2) {
		return EXT_ERR_CHARCNV;
	}
	len -= 2;
	cbheader = 6 + len;
	status = ext_buffer_push_uint16(pext, cbheader);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, len/2);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, tmp_buff, len);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->crules);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->crules; i++) {
		status = ext_buffer_push_tzrule(pext, r->prules + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}
static int ext_buffer_push_patterntypespecific(EXT_PUSH *pext,
	uint16_t patterntype, const PATTERNTYPESPECIFIC *r)
{
	int status;
	
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
		status = ext_buffer_push_uint32(pext,
				r->monthnth.weekrecurrence);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
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
	int status;
	
	status = ext_buffer_push_uint16(pext, r->readerversion);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->writerversion);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->recurfrequency);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->patterntype);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->calendartype);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->firstdatetime);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->period);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->slidingflag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_patterntypespecific(pext,
			r->patterntype, &r->patterntypespecific);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->endtype);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->occurrencecount);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->firstdow);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->deletedinstancecount);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->deletedinstancecount; i++) {
		status = ext_buffer_push_uint32(pext,
				r->pdeletedinstancedates[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint32(pext, r->modifiedinstancecount);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->modifiedinstancecount; i++) {
		status = ext_buffer_push_uint32(pext,
				r->pmodifiedinstancedates[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint32(pext, r->startdate);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext, r->enddate);
}

static int ext_buffer_push_exceptioninfo(
	EXT_PUSH *pext, const EXCEPTIONINFO *r)
{
	int status;
	uint16_t tmp_len;
	
	status = ext_buffer_push_uint32(pext, r->startdatetime);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->enddatetime);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->originalstartdate);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->overrideflags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (r->overrideflags & OVERRIDEFLAG_SUBJECT) {
		tmp_len = strlen(r->subject);
		status = ext_buffer_push_uint16(pext, tmp_len + 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_uint16(pext, tmp_len);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_bytes(pext, r->subject, tmp_len);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_MEETINGTYPE) {
		status = ext_buffer_push_uint32(pext, r->meetingtype);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_REMINDERDELTA) {
		status = ext_buffer_push_uint32(pext, r->reminderdelta);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_REMINDER) {
		status = ext_buffer_push_uint32(pext, r->reminderset);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_LOCATION) {
		tmp_len = strlen(r->location);
		status = ext_buffer_push_uint16(pext, tmp_len + 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_uint16(pext, tmp_len);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_bytes(pext, r->location, tmp_len);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_BUSYSTATUS) {
		status = ext_buffer_push_uint32(pext, r->busystatus);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_ATTACHMENT) {
		status = ext_buffer_push_uint32(pext, r->attachment);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_SUBTYPE) {
		status = ext_buffer_push_uint32(pext, r->subtype);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (r->overrideflags & OVERRIDEFLAG_APPTCOLOR) {
		status = ext_buffer_push_uint32(pext, r->appointmentcolor);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int ext_buffer_push_changehighlight(
	EXT_PUSH *pext, const CHANGEHIGHLIGHT *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, r->size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->value);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
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
	int status;
	char *pbuff;
	int string_len;
	uint16_t tmp_len;
	
	if (writerversion2 >= 0x00003009) {
		status = ext_buffer_push_changehighlight(
					pext, &r->changehighlight);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint32(pext, r->reservedblockee1size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != r->reservedblockee1size) {
		status = ext_buffer_push_bytes(pext,
			r->preservedblockee1, r->reservedblockee1size);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if ((overrideflags & OVERRIDEFLAG_LOCATION) ||
		(overrideflags & OVERRIDEFLAG_SUBJECT)) {
		status = ext_buffer_push_uint32(pext, r->startdatetime);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_uint32(pext, r->enddatetime);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_uint32(pext, r->originalstartdate);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (overrideflags & OVERRIDEFLAG_SUBJECT) {
		tmp_len = strlen(r->subject) + 1;
		pbuff = malloc(2*tmp_len);
		if (NULL == pbuff) {
			return EXT_ERR_ALLOC;
		}
		string_len = utf8_to_utf16le(r->subject, pbuff, 2*tmp_len);
		if (string_len < 2) {
			free(pbuff);
			return EXT_ERR_CHARCNV;
		}
		string_len -= 2;
		status = ext_buffer_push_uint16(pext, string_len/2);
		if (EXT_ERR_SUCCESS != status) {
			free(pbuff);
			return status;
		}
		status = ext_buffer_push_bytes(pext, pbuff, string_len);
		if (EXT_ERR_SUCCESS != status) {
			free(pbuff);
			return status;
		}
		free(pbuff);
	}
	if (overrideflags & OVERRIDEFLAG_LOCATION) {
		tmp_len = strlen(r->location) + 1;
		pbuff = malloc(2*tmp_len);
		if (NULL == pbuff) {
			return EXT_ERR_ALLOC;
		}
		string_len = utf8_to_utf16le(r->location, pbuff, 2*tmp_len);
		if (string_len < 2) {
			free(pbuff);
			return EXT_ERR_CHARCNV;
		}
		string_len -= 2;
		status = ext_buffer_push_uint16(pext, string_len/2);
		if (EXT_ERR_SUCCESS != status) {
			free(pbuff);
			return status;
		}
		status = ext_buffer_push_bytes(pext, pbuff, string_len);
		if (EXT_ERR_SUCCESS != status) {
			free(pbuff);
			return status;
		}
		free(pbuff);
	}
	if ((overrideflags & OVERRIDEFLAG_LOCATION) ||
		(overrideflags & OVERRIDEFLAG_SUBJECT)) {
		status = ext_buffer_push_uint32(pext, r->reservedblockee2size);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != r->reservedblockee2size) {
			status = ext_buffer_push_bytes(pext,
				r->preservedblockee2, r->reservedblockee2size);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return status;
}

int ext_buffer_push_appointmentrecurrencepattern(
	EXT_PUSH *pext, const APPOINTMENTRECURRENCEPATTERN *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_recurrencepattern(
				pext, &r->recurrencepattern);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->readerversion2);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->writerversion2);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->starttimeoffset);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->endtimeoffset);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->exceptioncount);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->exceptioncount; i++) {
		status = ext_buffer_push_exceptioninfo(
					pext, &r->pexceptioninfo[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint32(pext, r->reservedblock1size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->exceptioncount; i++) {
		status = ext_buffer_push_extendedexception(pext, r->writerversion2,
			r->pexceptioninfo[i].overrideflags, &r->pextendedexception[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint32(pext, r->reservedblock2size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->reservedblock2size) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_push_bytes(pext,
			r->preservedblock2,
			r->reservedblock2size);
}

int ext_buffer_push_globalobjectid(EXT_PUSH *pext, const GLOBALOBJECTID *r)
{
	int status;
	
	status = ext_buffer_push_bytes(pext, r->arrayid, 16);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->year >> 8);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->year & 0xFF);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->month);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->day);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext, r->creationtime);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(pext, r->x, 8);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_exbinary(pext, &r->data);
}


static int ext_buffer_push_attachment_list(
	EXT_PUSH *pext, const ATTACHMENT_LIST *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_tpropval_array(
					pext, &r->pplist[i]->proplist);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (NULL != r->pplist[i]->pembedded) {
			status = ext_buffer_push_uint8(pext, 1);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
			status = ext_buffer_push_message_content(
						pext, r->pplist[i]->pembedded);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		} else {
			status = ext_buffer_push_uint8(pext, 0);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return EXT_ERR_SUCCESS;
}

int ext_buffer_push_message_content(
	EXT_PUSH *pext, const MESSAGE_CONTENT *r)
{
	int status;
	
	status = ext_buffer_push_tpropval_array(pext, &r->proplist);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->children.prcpts) {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_tarray_set(pext, r->children.prcpts);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->children.pattachments) {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_attachment_list(
				pext, r->children.pattachments);
	} else {
		return ext_buffer_push_uint8(pext, 0);
	}
}
