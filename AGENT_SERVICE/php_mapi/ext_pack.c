#include "ext_pack.h"
#include <stdlib.h>
#include <string.h>
#include <iconv.h>

#define CVAL(buf, pos) ((unsigned int)(((const uint8_t *)(buf))[pos]))
#define CVAL_NC(buf, pos) (((uint8_t *)(buf))[pos])
#define PVAL(buf, pos) (CVAL(buf,pos))
#define SCVAL(buf, pos, val) (CVAL_NC(buf,pos) = (val))
#define SVAL(buf, pos) (PVAL(buf,pos)|PVAL(buf,(pos)+1)<<8)
#define IVAL(buf, pos) (SVAL(buf,pos)|SVAL(buf,(pos)+2)<<16)
#define IVALS(buf, pos) ((int32_t)IVAL(buf,pos))
#define SSVALX(buf, pos, val) (CVAL_NC(buf,pos)=(uint8_t)((val)&0xFF),CVAL_NC(buf,pos+1)=(uint8_t)((val)>>8))
#define SIVALX(buf, pos, val) (SSVALX(buf,pos,val&0xFFFF),SSVALX(buf,pos+2,val>>16))
#define SSVAL(buf, pos, val) SSVALX((buf),(pos),((uint16_t)(val)))
#define SIVAL(buf, pos, val) SIVALX((buf),(pos),((uint32_t)(val)))
#define SIVALS(buf, pos, val) SIVALX((buf),(pos),((int32_t)(val)))

#define GROWING_BLOCK_SIZE				0x1000

static int utf8_to_utf16le(const char *src, char *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	char *pin, *pout;
	iconv_t conv_id;

	conv_id = iconv_open("UTF-16LE", "UTF-8");
	pin = (char*)src;
	pout = dst;
	in_len = strlen(src) + 1;
	memset(dst, 0, len);
	out_len = len;
	if (-1 == iconv(conv_id, &pin, &in_len, &pout, &len)) {
		iconv_close(conv_id);
		return -1;
	} else {
		iconv_close(conv_id);
		return out_len - len;
	}
}

static zend_bool utf16le_to_utf8(const char *src,
	size_t src_len, char *dst, size_t len)
{
	char *pin, *pout;
	iconv_t conv_id;

	conv_id = iconv_open("UTF-8", "UTF-16LE");
	pin = (char*)src;
	pout = dst;
	memset(dst, 0, len);
	if (-1 == iconv(conv_id, &pin, &src_len, &pout, &len)) {
		iconv_close(conv_id);
		return 0;
	} else {
		iconv_close(conv_id);
		return 1;
	}
}

void ext_pack_pull_init(PULL_CTX *pctx,
	const uint8_t *pdata, uint32_t data_size)
{
	pctx->data = pdata;
	pctx->data_size = data_size;
	pctx->offset = 0;
}

zend_bool ext_pack_pull_advance(PULL_CTX *pctx, uint32_t size)
{
	pctx->offset += size;
	if (pctx->offset > pctx->data_size) {
		return 0;
	}
	return 1;
}

zend_bool ext_pack_pull_uint8(PULL_CTX *pctx, uint8_t *v)
{
	if (pctx->data_size < sizeof(uint8_t) ||
		pctx->offset + sizeof(uint8_t) > pctx->data_size) {
		return 0;
	}
	*v = CVAL(pctx->data, pctx->offset);
	pctx->offset += sizeof(uint8_t);
	return 1;
}

zend_bool ext_pack_pull_uint16(PULL_CTX *pctx, uint16_t *v)
{
	if (pctx->data_size < sizeof(uint16_t) ||
		pctx->offset + sizeof(uint16_t) > pctx->data_size) {
		return 0;
	}
	*v = SVAL(pctx->data, pctx->offset);
	pctx->offset += sizeof(uint16_t);
	return 1;
}

zend_bool ext_pack_pull_uint32(PULL_CTX *pctx, uint32_t *v)
{
	if (pctx->data_size < sizeof(uint32_t) ||
		pctx->offset + sizeof(uint32_t) > pctx->data_size) {
		return 0;
	}
	*v = IVAL(pctx->data, pctx->offset);
	pctx->offset += sizeof(uint32_t);
	return 1;
}

zend_bool ext_pack_pull_int32(PULL_CTX *pctx, int32_t *v)
{
	if (pctx->data_size < sizeof(int32_t) ||
		pctx->offset + sizeof(int32_t) > pctx->data_size) {
		return 0;
	}
	*v = IVALS(pctx->data, pctx->offset);
	pctx->offset += sizeof(int32_t);
	return 1;
}

zend_bool ext_pack_pull_uint64(PULL_CTX *pctx, uint64_t *v)
{
	if (pctx->data_size < sizeof(uint64_t) ||
		pctx->offset + sizeof(uint64_t) > pctx->data_size) {
		return 0;
	}
	*v = IVAL(pctx->data, pctx->offset);
	*v |= (uint64_t)(IVAL(pctx->data, pctx->offset+4)) << 32;
	pctx->offset += sizeof(uint64_t);
	return 1;
}

zend_bool ext_pack_pull_float(PULL_CTX *pctx, float *v)
{
	if (pctx->data_size < sizeof(float) ||
		pctx->offset + sizeof(float) > pctx->data_size) {
		return 0;
	}
	memcpy(v, pctx->data + pctx->offset, sizeof(float));
	pctx->offset += sizeof(float);
	return 1;
}

zend_bool ext_pack_pull_double(PULL_CTX *pctx, double *v)
{
	if (pctx->data_size < sizeof(double) ||
		pctx->offset + sizeof(double) > pctx->data_size) {
		return 0;
	}
	memcpy(v, pctx->data + pctx->offset, sizeof(double));
	pctx->offset += sizeof(double);
	return 1;
}

zend_bool ext_pack_pull_bytes(PULL_CTX *pctx, uint8_t *data, uint32_t n)
{
	if (pctx->data_size < n || pctx->offset + n > pctx->data_size) {
		return 0;
	}
	memcpy(data, pctx->data + pctx->offset, n);
	pctx->offset += n;
	return 1;
}

zend_bool ext_pack_pull_guid(PULL_CTX *pctx, GUID *r)
{
	if (!ext_pack_pull_uint32(pctx, &r->time_low)) {
		return 0;
	}
	if (!ext_pack_pull_uint16(pctx, &r->time_mid)) {
		return 0;
	}
	if (!ext_pack_pull_uint16(pctx, &r->time_hi_and_version)) {
		return 0;
	}
	if (!ext_pack_pull_bytes(pctx, r->clock_seq, 2)) {
		return 0;
	}
	return ext_pack_pull_bytes(pctx, r->node, 6);
}

zend_bool ext_pack_pull_string(PULL_CTX *pctx, char **ppstr)
{
	int len;
	
	if (pctx->offset >= pctx->data_size) {
		return 0;
	}
	len = strnlen(pctx->data + pctx->offset, pctx->data_size - pctx->offset);
	if (len + 1 > pctx->data_size - pctx->offset) {
		return 0;
	}
	len ++;
	*ppstr = emalloc(len);
	if (NULL == *ppstr) {
		return 0;
	}
	memcpy(*ppstr, pctx->data + pctx->offset, len);
	return ext_pack_pull_advance(pctx, len);
}

zend_bool ext_pack_pull_wstring(PULL_CTX *pctx, char **ppstr)
{
	int i;
	char *pbuff;
	int len, max_len;
	
	if (pctx->offset >= pctx->data_size) {
		return 0;
	}
	max_len = pctx->data_size - pctx->offset;
	for (i=0; i<max_len-1; i+=2) {
		if (0 == *(pctx->data + pctx->offset + i) &&
			0 == *(pctx->data + pctx->offset + i + 1)) {
			break;
		}
	}
	if (i >= max_len - 1) {
		return 0;
	}
	len = i + 2;
	*ppstr = emalloc(2*len);
	if (NULL == *ppstr) {
		return 0;
	}
	pbuff = malloc(len);
	if (0 == pbuff) {
		return 0;
	}
	memcpy(pbuff, pctx->data + pctx->offset, len);
	if (0 == utf16le_to_utf8(pbuff, len, *ppstr, 2*len)) {
		free(pbuff);
		return 0;
	}
	free(pbuff);
	return ext_pack_pull_advance(pctx, len);
}

zend_bool ext_pack_pull_binary(PULL_CTX *pctx, BINARY *r)
{
	if (!ext_pack_pull_uint32(pctx, &r->cb)) {
		return 0;
	}
	if (0 == r->cb) {
		r->pb = NULL;
		return 1;
	}
	r->pb = emalloc(r->cb);
	if (NULL == r->pb) {
		return 0;
	}
	return ext_pack_pull_bytes(pctx, r->pb, r->cb);
}

zend_bool ext_pack_pull_short_array(PULL_CTX *pctx, SHORT_ARRAY *r)
{
	int i;
	
	if (!ext_pack_pull_uint32(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->ps = NULL;
		return 1;
	}
	r->ps = emalloc(sizeof(uint16_t)*r->count);
	if (NULL == r->ps) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_uint16(pctx, &r->ps[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_long_array(PULL_CTX *pctx, LONG_ARRAY *r)
{
	int i;
	
	if (!ext_pack_pull_uint32(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->pl = NULL;
		return 1;
	}
	r->pl = emalloc(sizeof(uint32_t)*r->count);
	if (NULL == r->pl) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_uint32(pctx, &r->pl[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_longlong_array(PULL_CTX *pctx, LONGLONG_ARRAY *r)
{
	int i;
	
	if (!ext_pack_pull_uint32(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->pll = NULL;
		return 1;
	}
	r->pll = emalloc(sizeof(uint64_t)*r->count);
	if (NULL == r->pll) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_uint64(pctx, &r->pll[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_binary_array(PULL_CTX *pctx, BINARY_ARRAY *r)
{
	int i;
	
	if (!ext_pack_pull_uint32(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->pbin = NULL;
		return 1;
	}
	r->pbin = emalloc(sizeof(BINARY)*r->count);
	if (NULL == r->pbin) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_binary(pctx, &r->pbin[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_string_array(PULL_CTX *pctx, STRING_ARRAY *r)
{
	int i;
	
	if (!ext_pack_pull_uint32(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->ppstr = NULL;
		return 1;
	}
	r->ppstr = emalloc(sizeof(char*)*r->count);
	if (NULL == r->ppstr) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_string(pctx, &r->ppstr[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_wstring_array(PULL_CTX *pctx, STRING_ARRAY *r)
{
	int i;
	
	if (!ext_pack_pull_uint32(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->ppstr = NULL;
		return 1;
	}
	r->ppstr = emalloc(sizeof(char*)*r->count);
	if (NULL == r->ppstr) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_wstring(pctx, &r->ppstr[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_guid_array(PULL_CTX *pctx, GUID_ARRAY *r)
{
	int i;
	
	if (!ext_pack_pull_uint32(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->pguid = NULL;
		return 1;
	}
	r->pguid = emalloc(sizeof(GUID)*r->count);
	if (NULL == r->pguid) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_guid(pctx, &r->pguid[i])) {
			return 0;
		}
	}
	return 1;
}

static zend_bool ext_pack_pull_restriction_and_or(
	PULL_CTX *pctx, RESTRICTION_AND_OR *r)
{
	int i;
	
	if (!ext_pack_pull_uint32(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->pres = NULL;
		return 1;
	}
	r->pres = emalloc(r->count*sizeof(RESTRICTION));
	if (NULL == r->pres) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_restriction(pctx, &r->pres[i])) {
			return 0;
		}
	}
	return 1;
}

static zend_bool ext_pack_pull_restriction_not(
	PULL_CTX *pctx, RESTRICTION_NOT *r)
{
	return ext_pack_pull_restriction(pctx, &r->res);
}

static zend_bool ext_pack_pull_restriction_content(
	PULL_CTX *pctx, RESTRICTION_CONTENT *r)
{
	if (!ext_pack_pull_uint32(pctx, &r->fuzzy_level)) {
		return 0;
	}
	if (!ext_pack_pull_uint32(pctx, &r->proptag)) {
		return 0;
	}
	return ext_pack_pull_tagged_propval(pctx, &r->propval);
}

static zend_bool ext_pack_pull_restriction_property(
	PULL_CTX *pctx, RESTRICTION_PROPERTY *r)
{
	if (!ext_pack_pull_uint8(pctx, &r->relop)) {
		return 0;
	}
	if (!ext_pack_pull_uint32(pctx, &r->proptag)) {
		return 0;
	}
	return ext_pack_pull_tagged_propval(pctx, &r->propval);
}

static zend_bool ext_pack_pull_restriction_propcompare(
	PULL_CTX *pctx, RESTRICTION_PROPCOMPARE *r)
{
	if (!ext_pack_pull_uint8(pctx, &r->relop)) {
		return 0;
	}
	if (!ext_pack_pull_uint32(pctx, &r->proptag1)) {
		return 0;
	}
	return ext_pack_pull_uint32(pctx, &r->proptag2);
}

static zend_bool ext_pack_pull_restriction_bitmask(
	PULL_CTX *pctx, RESTRICTION_BITMASK *r)
{
	if (!ext_pack_pull_uint8(pctx, &r->bitmask_relop)) {
		return 0;
	}
	if (!ext_pack_pull_uint32(pctx, &r->proptag)) {
		return 0;
	}
	return ext_pack_pull_uint32(pctx, &r->mask);
}

static zend_bool ext_pack_pull_restriction_size(
	PULL_CTX *pctx, RESTRICTION_SIZE *r)
{
	if (!ext_pack_pull_uint8(pctx, &r->relop)) {
		return 0;
	}
	if (!ext_pack_pull_uint32(pctx, &r->proptag)) {
		return 0;
	}
	return ext_pack_pull_uint32(pctx, &r->size);
}

static zend_bool ext_pack_pull_restriction_exist(
	PULL_CTX *pctx, RESTRICTION_EXIST *r)
{
	return ext_pack_pull_uint32(pctx, &r->proptag);
}

static zend_bool ext_pack_pull_restriction_subobj(
	PULL_CTX *pctx, RESTRICTION_SUBOBJ *r)
{
	if (!ext_pack_pull_uint32(pctx, &r->subobject)) {
		return 0;
	}
	return ext_pack_pull_restriction(pctx, &r->res);
}

static zend_bool ext_pack_pull_restriction_comment(
	PULL_CTX *pctx, RESTRICTION_COMMENT *r)
{
	int i;
	uint8_t res_present;
	
	if (!ext_pack_pull_uint8(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		return 0;
	}
	r->ppropval = emalloc(sizeof(TAGGED_PROPVAL)*r->count);
	if (NULL == r->ppropval) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_tagged_propval(pctx, &r->ppropval[i])) {
			return 0;
		}
	}
	if (!ext_pack_pull_uint8(pctx, &res_present)) {
		return 0;
	}
	if (0 != res_present) {
		r->pres = emalloc(sizeof(RESTRICTION));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction(pctx, r->pres);
	}
	r->pres = NULL;
	return 1;
}

static zend_bool ext_pack_pull_restriction_count(
	PULL_CTX *pctx, RESTRICTION_COUNT *r)
{
	if (!ext_pack_pull_uint32(pctx, &r->count)) {
		return 0;
	}
	return ext_pack_pull_restriction(pctx, &r->sub_res);
}

zend_bool ext_pack_pull_restriction(PULL_CTX *pctx, RESTRICTION *r)
{
	if (!ext_pack_pull_uint8(pctx, &r->rt)) {
		return 0;
	}
	switch (r->rt) {
	case RESTRICTION_TYPE_AND:
	case RESTRICTION_TYPE_OR:
		r->pres = emalloc(sizeof(RESTRICTION_AND_OR));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_and_or(pctx, r->pres);
	case RESTRICTION_TYPE_NOT:
		r->pres = emalloc(sizeof(RESTRICTION_NOT));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_not(pctx, r->pres);
	case RESTRICTION_TYPE_CONTENT:
		r->pres = emalloc(sizeof(RESTRICTION_CONTENT));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_content(pctx, r->pres);
	case RESTRICTION_TYPE_PROPERTY:
		r->pres = emalloc(sizeof(RESTRICTION_PROPERTY));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_property(pctx, r->pres);
	case RESTRICTION_TYPE_PROPCOMPARE:
		r->pres = emalloc(sizeof(RESTRICTION_PROPCOMPARE));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_propcompare(pctx, r->pres);
	case RESTRICTION_TYPE_BITMASK:
		r->pres = emalloc(sizeof(RESTRICTION_BITMASK));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_bitmask(pctx, r->pres);
	case RESTRICTION_TYPE_SIZE:
		r->pres = emalloc(sizeof(RESTRICTION_SIZE));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_size(pctx, r->pres);
	case RESTRICTION_TYPE_EXIST:
		r->pres = emalloc(sizeof(RESTRICTION_EXIST));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_exist(pctx, r->pres);
	case RESTRICTION_TYPE_SUBOBJ:
		r->pres = emalloc(sizeof(RESTRICTION_SUBOBJ));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_subobj(pctx, r->pres);
	case RESTRICTION_TYPE_COMMENT:
		r->pres = emalloc(sizeof(RESTRICTION_COMMENT));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_comment(pctx, r->pres);
	case RESTRICTION_TYPE_COUNT:
		r->pres = emalloc(sizeof(RESTRICTION_COUNT));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_count(pctx, r->pres);
	case RESTRICTION_TYPE_NULL:
		r->pres = NULL;
		return 1;
	default:
		return 0;
	}
}

static zend_bool ext_pack_pull_movecopy_action(PULL_CTX *pctx, MOVECOPY_ACTION *r)
{
	if (!ext_pack_pull_binary(pctx, &r->store_eid)) {
		return 0;
	}
	return ext_pack_pull_binary(pctx, &r->folder_eid);
}

static zend_bool ext_pack_pull_reply_action(PULL_CTX *pctx, REPLY_ACTION *r)
{
	if (!ext_pack_pull_binary(pctx, &r->message_eid)) {
		return 0;
	}
	return ext_pack_pull_guid(pctx, &r->template_guid);
}

static zend_bool ext_pack_pull_recipient_block(PULL_CTX *pctx, RECIPIENT_BLOCK *r)
{
	int i;
	
	if (!ext_pack_pull_uint8(pctx, &r->reserved)) {
		return 0;
	}
	if (!ext_pack_pull_uint16(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		return 0;
	}
	r->ppropval = emalloc(sizeof(TAGGED_PROPVAL)*r->count);
	if (NULL == r->ppropval) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_tagged_propval(pctx, &r->ppropval[i])) {
			return 0;
		}
	}
	return 1;
}

static zend_bool ext_pack_pull_forwarddelegate_action(
	PULL_CTX *pctx, FORWARDDELEGATE_ACTION *r)
{
	int i;
	
	if (!ext_pack_pull_uint16(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		return 0;
	}
	r->pblock = emalloc(sizeof(RECIPIENT_BLOCK)*r->count);
	if (NULL == r->pblock) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_recipient_block(pctx, &r->pblock[i])) {
			return 0;
		}
	}
	return 1;
}

static zend_bool ext_pack_pull_action_block(PULL_CTX *pctx, ACTION_BLOCK *r)
{
	uint16_t tmp_len;
	
	if (!ext_pack_pull_uint16(pctx, &r->length)) {
		return 0;
	}
	if (!ext_pack_pull_uint8(pctx, &r->type)) {
		return 0;
	}
	if (!ext_pack_pull_uint32(pctx, &r->flavor)) {
		return 0;
	}
	if (!ext_pack_pull_uint32(pctx, &r->flags)) {
		return 0;
	}
	switch (r->type) {
	case ACTION_TYPE_OP_MOVE:
	case ACTION_TYPE_OP_COPY:
		r->pdata = emalloc(sizeof(MOVECOPY_ACTION));
		if (NULL == r->pdata) {
			return 0;
		}
		return ext_pack_pull_movecopy_action(pctx, r->pdata);
	case ACTION_TYPE_OP_REPLY:
	case ACTION_TYPE_OP_OOF_REPLY:
		r->pdata = emalloc(sizeof(REPLY_ACTION));
		if (NULL == r->pdata) {
			return 0;
		}
		return ext_pack_pull_reply_action(pctx, r->pdata);
	case ACTION_TYPE_OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - 2*sizeof(uint32_t);
		r->pdata = emalloc(tmp_len);
		if (NULL == r->pdata) {
			return 0;
		}
		return ext_pack_pull_bytes(pctx, r->pdata, tmp_len);
	case ACTION_TYPE_OP_BOUNCE:
		r->pdata = emalloc(sizeof(uint32_t));
		if (NULL == r->pdata) {
			return 0;
		}
		return ext_pack_pull_uint32(pctx, r->pdata);
	case ACTION_TYPE_OP_FORWARD:
	case ACTION_TYPE_OP_DELEGATE:
		r->pdata = emalloc(sizeof(FORWARDDELEGATE_ACTION));
		if (NULL == r->pdata) {
			return 0;
		}
		return ext_pack_pull_forwarddelegate_action(pctx, r->pdata);
	case ACTION_TYPE_OP_TAG:
		r->pdata = emalloc(sizeof(TAGGED_PROPVAL));
		if (NULL == r->pdata) {
			return 0;
		}
		return ext_pack_pull_tagged_propval(pctx, r->pdata);
	case ACTION_TYPE_OP_DELETE:
	case ACTION_TYPE_OP_MARK_AS_READ:
		r->pdata = NULL;
		return 1;
	default:
		return 0;
	}
}

zend_bool ext_pack_pull_rule_actions(PULL_CTX *pctx, RULE_ACTIONS *r)
{
	int i;
	
	if (!ext_pack_pull_uint16(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		return 0;
	}
	r->pblock = emalloc(sizeof(ACTION_BLOCK)*r->count);
	if (NULL == r->pblock) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_action_block(pctx, &r->pblock[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_propval(PULL_CTX *pctx, uint16_t type, void **ppval)
{
	/* convert multi-value instance into single value */
	if (0x3000 == (type & 0x3000)) {
		type &= ~0x3000;
	}
	switch (type) {
	case PROPVAL_TYPE_SHORT:
		*ppval = emalloc(sizeof(uint16_t));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_uint16(pctx, *ppval);
	case PROPVAL_TYPE_LONG:
	case PROPVAL_TYPE_ERROR:
		*ppval = emalloc(sizeof(uint32_t));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_uint32(pctx, *ppval);
	case PROPVAL_TYPE_FLOAT:
		*ppval = emalloc(sizeof(float));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_float(pctx, *ppval);
	case PROPVAL_TYPE_DOUBLE:
	case PROPVAL_TYPE_FLOATINGTIME:
		*ppval = emalloc(sizeof(double));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_double(pctx, *ppval);
	case PROPVAL_TYPE_BYTE:
		*ppval = emalloc(sizeof(uint8_t));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_uint8(pctx, *ppval);
	case PROPVAL_TYPE_LONGLONG:
	case PROPVAL_TYPE_FILETIME:
		*ppval = emalloc(sizeof(uint64_t));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_uint64(pctx, *ppval);
	case PROPVAL_TYPE_STRING:
	case PROPVAL_TYPE_WSTRING:
		return ext_pack_pull_string(pctx, (char**)ppval);
	case PROPVAL_TYPE_GUID:
		*ppval = emalloc(sizeof(GUID));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_guid(pctx, *ppval);
	case PROPVAL_TYPE_RESTRICTION:
		*ppval = emalloc(sizeof(RESTRICTION));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_restriction(pctx, *ppval);
	case PROPVAL_TYPE_RULE:
		*ppval = emalloc(sizeof(RULE_ACTIONS));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_rule_actions(pctx, *ppval);
	case PROPVAL_TYPE_BINARY:
		*ppval = emalloc(sizeof(BINARY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_binary(pctx, *ppval);
	case PROPVAL_TYPE_SHORT_ARRAY:
		*ppval = emalloc(sizeof(SHORT_ARRAY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_short_array(pctx, *ppval);
	case PROPVAL_TYPE_LONG_ARRAY:
		*ppval = emalloc(sizeof(LONG_ARRAY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_long_array(pctx, *ppval);
	case PROPVAL_TYPE_LONGLONG_ARRAY:
		*ppval = emalloc(sizeof(LONGLONG_ARRAY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_longlong_array(pctx, *ppval);
	case PROPVAL_TYPE_STRING_ARRAY:
	case PROPVAL_TYPE_WSTRING_ARRAY:
		*ppval = emalloc(sizeof(STRING_ARRAY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_string_array(pctx, *ppval);
	case PROPVAL_TYPE_GUID_ARRAY:
		*ppval = emalloc(sizeof(GUID_ARRAY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_guid_array(pctx, *ppval);
	case PROPVAL_TYPE_BINARY_ARRAY:
		*ppval = emalloc(sizeof(BINARY_ARRAY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_binary_array(pctx, *ppval);
	default:
		return 0;
	}
}

zend_bool ext_pack_pull_tagged_propval(PULL_CTX *pctx, TAGGED_PROPVAL *r)
{	
	if (!ext_pack_pull_uint32(pctx, &r->proptag)) {
		return 0;
	}
	return ext_pack_pull_propval(pctx, r->proptag&0xFFFF, &r->pvalue);
}

zend_bool ext_pack_pull_proptag_array(PULL_CTX *pctx, PROPTAG_ARRAY *r)
{
	int i;
	
	if (!ext_pack_pull_uint16(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->pproptag = NULL;
		return 1;
	}
	r->pproptag = emalloc(sizeof(uint32_t)*r->count);
	if (NULL == r->pproptag) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_uint32(pctx, &r->pproptag[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_property_name(PULL_CTX *pctx, PROPERTY_NAME *r)
{
	uint32_t offset;
	uint8_t name_size;
	
	if (!ext_pack_pull_uint8(pctx, &r->kind)) {
		return 0;
	}
	if (!ext_pack_pull_guid(pctx, &r->guid)) {
		return 0;
	}
	r->plid = NULL;
	r->pname = NULL;
	if (KIND_LID == r->kind) {
		r->plid = emalloc(sizeof(uint32_t));
		if (NULL == r->plid) {
			return 0;
		}
		if (!ext_pack_pull_uint32(pctx, r->plid)) {
			return 0;
		}
	} else if (KIND_NAME == r->kind) {
		if (!ext_pack_pull_uint8(pctx, &name_size)) {
			return 0;
		}
		if (name_size < 2) {
			return 0;
		}
		offset = pctx->offset + name_size;
		if (!ext_pack_pull_string(pctx, &r->pname)) {
			return 0;
		}
		if (pctx->offset > offset) {
			return 0;
		}
		pctx->offset = offset;
	}
	return 1;
}

zend_bool ext_pack_pull_propname_array(PULL_CTX *pctx, PROPNAME_ARRAY *r)
{
	int i;
	
	if (!ext_pack_pull_uint16(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->ppropname = NULL;
		return 1;
	}
	r->ppropname = emalloc(sizeof(PROPERTY_NAME)*r->count);
	if (NULL == r->ppropname) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_property_name(pctx, r->ppropname + i)) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_propid_array(PULL_CTX *pctx, PROPID_ARRAY *r)
{
	int i;
	
	if (!ext_pack_pull_uint16(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->ppropid = NULL;
		return 1;
	}
	r->ppropid = emalloc(sizeof(uint16_t)*r->count);
	if (NULL == r->ppropid) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_uint16(pctx, r->ppropid + i)) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_tpropval_array(PULL_CTX *pctx, TPROPVAL_ARRAY *r)
{
	int i;
	
	if (!ext_pack_pull_uint16(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->ppropval = NULL;
		return 1;
	}
	r->ppropval = emalloc(sizeof(TAGGED_PROPVAL)*r->count);
	if (NULL == r->ppropval) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_tagged_propval(pctx, r->ppropval + i)) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_tarray_set(PULL_CTX *pctx, TARRAY_SET *r)
{
	int i;
	
	if (!ext_pack_pull_uint32(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->pparray = NULL;
		return 1;
	}
	r->pparray = emalloc(sizeof(TPROPVAL_ARRAY*)*r->count);
	if (NULL == r->pparray) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		r->pparray[i] = emalloc(sizeof(TPROPVAL_ARRAY));
		if (NULL == r->pparray[i]) {
			return 0;
		}
		if (!ext_pack_pull_tpropval_array(pctx, r->pparray[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_sort_order(PULL_CTX *pctx, SORT_ORDER *r)
{	
	if (!ext_pack_pull_uint16(pctx, &r->type)) {
		return 0;
	}
	if (r->type & 0x1000 && 0 == (r->type & 0x2000)) {
		return 0;
	}
	if (!ext_pack_pull_uint16(pctx, &r->propid)) {
		return 0;
	}
	return ext_pack_pull_uint8(pctx, &r->table_sort);
}

zend_bool ext_pack_pull_sortorder_set(PULL_CTX *pctx, SORTORDER_SET *r)
{
	int i;
	
	if (!ext_pack_pull_uint16(pctx, &r->count)) {
		return 0;
	}
	if (!ext_pack_pull_uint16(pctx, &r->ccategories)) {
		return 0;
	}
	if (!ext_pack_pull_uint16(pctx, &r->cexpanded)) {
		return 0;
	}
	if (0 == r->count || r->ccategories > r->count ||
		r->cexpanded > r->ccategories) {
		return 0;
	}
	r->psort = emalloc(sizeof(SORT_ORDER)*r->count);
	if (NULL == r->psort) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_sort_order(pctx, r->psort + i)) {
			return 0;
		}
	}
	return 1;
}

static zend_bool ext_pack_pull_permission_row(
	PULL_CTX *pctx, PERMISSION_ROW *r)
{
	if (!ext_pack_pull_uint32(pctx, &r->flags)) {
		return 0;
	}
	if (!ext_pack_pull_binary(pctx, &r->entryid)) {
		return 0;
	}
	return ext_pack_pull_uint32(pctx, &r->member_rights);
}

zend_bool ext_pack_pull_permission_set(PULL_CTX *pctx, PERMISSION_SET *r)
{
	int i;
	
	if (!ext_pack_pull_uint16(pctx, &r->count)) {
		return 0;
	}
	r->prows = emalloc(sizeof(PERMISSION_ROW)*r->count);
	if (NULL == r->prows) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_permission_row(pctx, &r->prows[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_rule_data(PULL_CTX *pctx, RULE_DATA *r)
{
	if (!ext_pack_pull_uint8(pctx, &r->flags)) {
		return 0;
	}
	return ext_pack_pull_tpropval_array(pctx, &r->propvals);
}

zend_bool ext_pack_pull_rule_list(PULL_CTX *pctx, RULE_LIST *r)
{
	int i;
	
	if (!ext_pack_pull_uint16(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->prule = NULL;
		return 1;
	}
	r->prule = emalloc(sizeof(RULE_DATA)*r->count);
	if (NULL == r->prule) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_rule_data(pctx, &r->prule[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_pull_oneoff_entryid(PULL_CTX *pctx, ONEOFF_ENTRYID *r)
{
	if (!ext_pack_pull_uint32(pctx, &r->flags)) {
		return 0;
	}
	if (!ext_pack_pull_bytes(pctx, r->provider_uid, 16)) {
		return 0;
	}
	if (!ext_pack_pull_uint16(pctx, &r->version)) {
		return 0;
	}
	if (!ext_pack_pull_uint16(pctx, &r->ctrl_flags)) {
		return 0;
	}
	if (r->ctrl_flags & CTRL_FLAG_UNICODE) {
		if (!ext_pack_pull_wstring(pctx, &r->pdisplay_name)) {
			return 0;
		}
		if (!ext_pack_pull_wstring(pctx, &r->paddress_type)) {
			return 0;
		}
		return ext_pack_pull_wstring(pctx, &r->pmail_address);
	} else {
		if (!ext_pack_pull_string(pctx, &r->pdisplay_name)) {
			return 0;
		}
		if (!ext_pack_pull_string(pctx, &r->paddress_type)) {
			return 0;
		}
		return ext_pack_pull_string(pctx, &r->pmail_address);
	}
}

static zend_bool ext_pack_pull_message_state(PULL_CTX *pctx, MESSAGE_STATE *r)
{
	if (!ext_pack_pull_binary(pctx, &r->source_key)) {
		return 0;
	}
	return ext_pack_pull_uint32(pctx, &r->message_flags);
}

zend_bool ext_pack_pull_state_array(PULL_CTX *pctx, STATE_ARRAY *r)
{
	int i;
	
	if (!ext_pack_pull_uint32(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->pstate = NULL;
		return 1;
	}
	r->pstate = emalloc(sizeof(MESSAGE_STATE)*r->count);
	if (NULL == r->pstate) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_pull_message_state(pctx, &r->pstate[i])) {
			return 0;
		}
	}
	return 1;
}

static zend_bool ext_pack_pull_newmail_znotification(
	PULL_CTX *pctx, NEWMAIL_ZNOTIFICATION *r)
{
	if (!ext_pack_pull_binary(pctx, &r->entryid)) {
		return 0;
	}
	if (!ext_pack_pull_binary(pctx, &r->parentid)) {
		return 0;
	}
	if (!ext_pack_pull_uint32(pctx, &r->flags)) {
		return 0;
	}
	if (!ext_pack_pull_string(pctx, &r->message_class)) {
		return 0;
	}
	return ext_pack_pull_uint32(pctx, &r->message_flags);
}

static zend_bool ext_pack_pull_object_znotification(
	PULL_CTX *pctx, OBJECT_ZNOTIFICATION *r)
{
	uint8_t tmp_byte;
	
	if (!ext_pack_pull_uint32(pctx, &r->object_type)) {
		return 0;
	}
	if (!ext_pack_pull_uint8(pctx, &tmp_byte)) {
		return 0;
	}
	if (0 == tmp_byte) {
		r->pentryid = NULL;
	} else {
		r->pentryid = emalloc(sizeof(BINARY));
		if (NULL == r->pentryid) {
			return 0;
		}
		if (!ext_pack_pull_binary(pctx, r->pentryid)) {
			return 0;
		}
	}
	if (!ext_pack_pull_uint8(pctx, &tmp_byte)) {
		return 0;
	}
	if (0 == tmp_byte) {
		r->pparentid = NULL;
	} else {
		r->pparentid = emalloc(sizeof(BINARY));
		if (NULL == r->pparentid) {
			return 0;
		}
		if (!ext_pack_pull_binary(pctx, r->pparentid)) {
			return 0;
		}
	}
	if (!ext_pack_pull_uint8(pctx, &tmp_byte)) {
		return 0;
	}
	if (0 == tmp_byte) {
		r->pold_entryid = NULL;
	} else {
		r->pold_entryid = emalloc(sizeof(BINARY));
		if (NULL == r->pold_entryid) {
			return 0;
		}
		if (!ext_pack_pull_binary(pctx, r->pold_entryid)) {
			return 0;
		}
	}
	if (!ext_pack_pull_uint8(pctx, &tmp_byte)) {
		return 0;
	}
	if (0 == tmp_byte) {
		r->pold_parentid = NULL;
	} else {
		r->pold_parentid = emalloc(sizeof(BINARY));
		if (NULL == r->pold_parentid) {
			return 0;
		}
		if (!ext_pack_pull_binary(pctx, r->pold_parentid)) {
			return 0;
		}
	}
	if (!ext_pack_pull_uint8(pctx, &tmp_byte)) {
		return 0;
	}
	if (0 == tmp_byte) {
		r->pproptags = NULL;
		return 1;
	} else {
		r->pproptags = emalloc(sizeof(PROPTAG_ARRAY));
		if (NULL == r->pproptags) {
			return 0;
		}
		return ext_pack_pull_proptag_array(pctx, r->pproptags);
	}
}

static zend_bool ext_pack_pull_znotification(
	PULL_CTX *pctx, ZNOTIFICATION *r)
{
	if (!ext_pack_pull_uint32(pctx, &r->event_type)) {
		return 0;
	}
	switch (r->event_type) {
	case EVENT_TYPE_NEWMAIL:
		r->pnotification_data = emalloc(sizeof(NEWMAIL_ZNOTIFICATION));
		if (NULL == r->pnotification_data) {
			return 0;
		}
		return ext_pack_pull_newmail_znotification(
					pctx, r->pnotification_data);
	case EVENT_TYPE_OBJECTCREATED:
	case EVENT_TYPE_OBJECTDELETED:
	case EVENT_TYPE_OBJECTMODIFIED:
	case EVENT_TYPE_OBJECTMOVED:
	case EVENT_TYPE_OBJECTCOPIED:
	case EVENT_TYPE_SEARCHCOMPLETE:
		r->pnotification_data = emalloc(sizeof(OBJECT_ZNOTIFICATION));
		if (NULL == r->pnotification_data) {
			return 0;
		}
		return ext_pack_pull_object_znotification(
					pctx, r->pnotification_data);
	default:
		r->pnotification_data = NULL;
		return 1;
	}
}

zend_bool ext_pack_pull_znotification_array(
	PULL_CTX *pctx, ZNOTIFICATION_ARRAY *r)
{
	int i;
	
	if (!ext_pack_pull_uint16(pctx, &r->count)) {
		return 0;
	}
	if (0 == r->count) {
		r->ppnotification = NULL;
		return 1;
	}
	r->ppnotification = emalloc(sizeof(ZNOTIFICATION*)*r->count);
	if (NULL == r->ppnotification) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		r->ppnotification[i] = emalloc(sizeof(ZNOTIFICATION));
		if (NULL == r->ppnotification[i]) {
			return 0;
		}
		if (!ext_pack_pull_znotification(
			pctx, r->ppnotification[i])) {
			return 0;
		}
	}
	return 1;
}

/*---------------------------------------------------------------------------*/

zend_bool ext_pack_push_init(PUSH_CTX *pctx)
{	
	pctx->alloc_size = GROWING_BLOCK_SIZE;
	pctx->data = emalloc(GROWING_BLOCK_SIZE);
	if (NULL == pctx->data) {
		return 0;
	}
	pctx->offset = 0;
	return 1;
}

void ext_pack_push_free(PUSH_CTX *pctx)
{
	efree(pctx->data);
}

static zend_bool ext_pack_push_check_overflow(PUSH_CTX *pctx, uint32_t extra_size)
{
	uint32_t size;
	uint8_t *pdata;
	uint32_t alloc_size;
	
	size = extra_size + pctx->offset;
	if (pctx->alloc_size >= size) {
		return 1;
	}
	for (alloc_size=pctx->alloc_size; alloc_size<size;
		alloc_size+=GROWING_BLOCK_SIZE);
	pdata = erealloc(pctx->data, alloc_size);
	if (NULL == pdata) {
		return 0;
	}
	pctx->data = pdata;
	pctx->alloc_size = alloc_size;
	return 1;
}

zend_bool ext_pack_push_advance(PUSH_CTX *pctx, uint32_t size)
{
	if (!ext_pack_push_check_overflow(pctx, size)) {
		return 0;
	}
	pctx->offset += size;
	return 1;
}

zend_bool ext_pack_push_bytes(PUSH_CTX *pctx, const uint8_t *pdata, uint32_t n)
{
	if (!ext_pack_push_check_overflow(pctx, n)) {
		return 0;
	}
	memcpy(pctx->data + pctx->offset, pdata, n);
	pctx->offset += n;
	return 1;
}

zend_bool ext_pack_push_uint8(PUSH_CTX *pctx, uint8_t v)
{
	if (!ext_pack_push_check_overflow(pctx, sizeof(uint8_t))) {
		return 0;
	}
	SCVAL(pctx->data, pctx->offset, v);
	pctx->offset += sizeof(uint8_t);
	return 1;
}

zend_bool ext_pack_push_uint16(PUSH_CTX *pctx, uint16_t v)
{
	if (!ext_pack_push_check_overflow(pctx, sizeof(uint16_t))) {
		return 0;
	}
	SSVAL(pctx->data, pctx->offset, v);
	pctx->offset += sizeof(uint16_t);
	return 1;
}

zend_bool ext_pack_push_uint32(PUSH_CTX *pctx, uint32_t v)
{
	if (!ext_pack_push_check_overflow(pctx, sizeof(uint32_t))) {
		return 0;
	}
	SIVAL(pctx->data, pctx->offset, v);
	pctx->offset += sizeof(uint32_t);
	return 1;
}

zend_bool ext_pack_push_int32(PUSH_CTX *pctx, int32_t v)
{
	if (!ext_pack_push_check_overflow(pctx, sizeof(int32_t))) {
		return 0;
	}
	SIVALS(pctx->data, pctx->offset, v);
	pctx->offset += sizeof(int32_t);
	return 1;
}

zend_bool ext_pack_push_uint64(PUSH_CTX *pctx, uint64_t v)
{
	if (!ext_pack_push_check_overflow(pctx, sizeof(uint64_t))) {
		return 0;
	}
	SIVAL(pctx->data, pctx->offset, (v & 0xFFFFFFFF));
	SIVAL(pctx->data, pctx->offset+4, (v>>32));
	pctx->offset += sizeof(uint64_t);
	return 1;
}

zend_bool ext_pack_push_float(PUSH_CTX *pctx, float v)
{
	if (!ext_pack_push_check_overflow(pctx, sizeof(float))) {
		return 0;
	}
	memcpy(pctx->data + pctx->offset, &v, 4);
	pctx->offset += sizeof(float);
	return 1;
}

zend_bool ext_pack_push_double(PUSH_CTX *pctx, double v)
{
	if (!ext_pack_push_check_overflow(pctx, sizeof(double))) {
		return 0;
	}
	memcpy(pctx->data + pctx->offset, &v, 8);
	pctx->offset += sizeof(double);
	return 1;
}

zend_bool ext_pack_push_binary(PUSH_CTX *pctx, const BINARY *r)
{
	if (!ext_pack_push_uint32(pctx, r->cb)) {
		return 0;
	}
	if (0 == r->cb) {
		return 1;
	}
	return ext_pack_push_bytes(pctx, r->pb, r->cb);
}

zend_bool ext_pack_push_guid(PUSH_CTX *pctx, const GUID *r)
{
	if (!ext_pack_push_uint32(pctx, r->time_low)) {
		return 0;
	}
	if (!ext_pack_push_uint16(pctx, r->time_mid)) {
		return 0;
	}
	if (!ext_pack_push_uint16(pctx, r->time_hi_and_version)) {
		return 0;
	}
	if (!ext_pack_push_bytes(pctx, r->clock_seq, 2)) {
		return 0;
	}
	return ext_pack_push_bytes(pctx, r->node, 6);
}

zend_bool ext_pack_push_string(PUSH_CTX *pctx, const char *pstr)
{
	return ext_pack_push_bytes(pctx, pstr, strlen(pstr) + 1);
}

zend_bool ext_pack_push_wstring(PUSH_CTX *pctx, const char *pstr)
{
	int len;
	char *pbuff;
	
	len = 2*strlen(pstr) + 2;
	pbuff = malloc(len);
	if (0 == pbuff) {
		return 0;
	}
	len = utf8_to_utf16le(pstr, pbuff, len);
	if (len < 2) {
		pbuff[0] = '\0';
		pbuff[1] = '\0';
		len = 2;
	}
	if (!ext_pack_push_bytes(pctx, pbuff, len)) {
		free(pbuff);
		return 0;
	}
	free(pbuff);
	return 1;
}

zend_bool ext_pack_push_short_array(PUSH_CTX *pctx, const SHORT_ARRAY *r)
{
	int i;
	
	if (!ext_pack_push_uint32(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_uint16(pctx, r->ps[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_long_array(PUSH_CTX *pctx, const LONG_ARRAY *r)
{
	int i;
	
	if (!ext_pack_push_uint32(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_uint32(pctx, r->pl[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_longlong_array(PUSH_CTX *pctx, const LONGLONG_ARRAY *r)
{
	int i;
	
	if (!ext_pack_push_uint32(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_uint64(pctx, r->pll[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_binary_array(PUSH_CTX *pctx, const BINARY_ARRAY *r)
{
	int i;
	
	if (!ext_pack_push_uint32(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_binary(pctx, &r->pbin[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_string_array(PUSH_CTX *pctx, const STRING_ARRAY *r)
{
	int i;
	
	if (!ext_pack_push_uint32(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_string(pctx, r->ppstr[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_wstring_array(
	PUSH_CTX *pctx, const STRING_ARRAY *r)
{
	int i;
	
	if (!ext_pack_push_uint32(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_wstring(pctx, r->ppstr[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_guid_array(PUSH_CTX *pctx, const GUID_ARRAY *r)
{
	int i;
	
	if (!ext_pack_push_uint32(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_guid(pctx, &r->pguid[i])) {
			return 0;
		}
	}
	return 1;
}

static zend_bool ext_pack_push_restriction_and_or(
	PUSH_CTX *pctx, const RESTRICTION_AND_OR *r)
{
	int i;
	
	if (!ext_pack_push_uint32(pctx, r->count)) {
		return 0;	
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_restriction(pctx, &r->pres[i])) {
			return 0;
		}
	}
	return 1;
}

static zend_bool ext_pack_push_restriction_not(
	PUSH_CTX *pctx, const RESTRICTION_NOT *r)
{
	return ext_pack_push_restriction(pctx, &r->res);
}

static zend_bool ext_pack_push_restriction_content(
	PUSH_CTX *pctx, const RESTRICTION_CONTENT *r)
{
	if (!ext_pack_push_uint32(pctx, r->fuzzy_level)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, r->proptag)) {
		return 0;
	}
	return ext_pack_push_tagged_propval(pctx, &r->propval);
}

static zend_bool ext_pack_push_restriction_property(
	PUSH_CTX *pctx, const RESTRICTION_PROPERTY *r)
{
	if (!ext_pack_push_uint8(pctx, r->relop)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, r->proptag)) {
		return 0;
	}
	return ext_pack_push_tagged_propval(pctx, &r->propval);
}

static zend_bool ext_pack_push_restriction_propcompare(
	PUSH_CTX *pctx, const RESTRICTION_PROPCOMPARE *r)
{
	if (!ext_pack_push_uint8(pctx, r->relop)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, r->proptag1)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, r->proptag2);
}

static zend_bool ext_pack_push_restriction_bitmask(
	PUSH_CTX *pctx, const RESTRICTION_BITMASK *r)
{
	if (!ext_pack_push_uint8(pctx, r->bitmask_relop)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, r->proptag)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, r->mask);
}

static zend_bool ext_pack_push_restriction_size(
	PUSH_CTX *pctx, const RESTRICTION_SIZE *r)
{
	if (!ext_pack_push_uint8(pctx, r->relop)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, r->proptag)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, r->size);
}

static zend_bool ext_pack_push_restriction_exist(
	PUSH_CTX *pctx, const RESTRICTION_EXIST *r)
{
	return ext_pack_push_uint32(pctx, r->proptag);
}

static zend_bool ext_pack_push_restriction_subobj(
	PUSH_CTX *pctx, const RESTRICTION_SUBOBJ *r)
{
	if (!ext_pack_push_uint32(pctx, r->subobject)) {
		return 0;
	}
	return ext_pack_push_restriction(pctx, &r->res);
}

static zend_bool ext_pack_push_restriction_comment(
	PUSH_CTX *pctx, const RESTRICTION_COMMENT *r)
{
	int i;
	
	if (0 == r->count) {
		return 0;
	}
	if (!ext_pack_push_uint8(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_tagged_propval(pctx, &r->ppropval[i])) {
			return 0;
		}
	}
	if (NULL != r->pres) {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		return ext_pack_push_restriction(pctx, r->pres);
	}
	return ext_pack_push_uint8(pctx, 0);
}

static zend_bool ext_pack_push_restriction_count(
	PUSH_CTX *pctx, const RESTRICTION_COUNT *r)
{
	if (!ext_pack_push_uint32(pctx, r->count)) {
		return 0;
	}
	return ext_pack_push_restriction(pctx, &r->sub_res);
}

zend_bool ext_pack_push_restriction(PUSH_CTX *pctx, const RESTRICTION *r)
{
	if (!ext_pack_push_uint8(pctx, r->rt)) {
		return 0;
	}
	switch (r->rt) {
	case RESTRICTION_TYPE_AND:
	case RESTRICTION_TYPE_OR:
		return ext_pack_push_restriction_and_or(pctx, r->pres);
	case RESTRICTION_TYPE_NOT:
		return ext_pack_push_restriction_not(pctx, r->pres);
	case RESTRICTION_TYPE_CONTENT:
		return ext_pack_push_restriction_content(pctx, r->pres);
	case RESTRICTION_TYPE_PROPERTY:
		return ext_pack_push_restriction_property(pctx, r->pres);
	case RESTRICTION_TYPE_PROPCOMPARE:
		return ext_pack_push_restriction_propcompare(pctx, r->pres);
	case RESTRICTION_TYPE_BITMASK:
		return ext_pack_push_restriction_bitmask(pctx, r->pres);
	case RESTRICTION_TYPE_SIZE:
		return ext_pack_push_restriction_size(pctx, r->pres);
	case RESTRICTION_TYPE_EXIST:
		return ext_pack_push_restriction_exist(pctx, r->pres);
	case RESTRICTION_TYPE_SUBOBJ:
		return ext_pack_push_restriction_subobj(pctx, r->pres);
	case RESTRICTION_TYPE_COMMENT:
		return ext_pack_push_restriction_comment(pctx, r->pres);
	case RESTRICTION_TYPE_COUNT:
		return ext_pack_push_restriction_count(pctx, r->pres);
	case RESTRICTION_TYPE_NULL:
		return 1;
	}
	return 0;
}

zend_bool ext_pack_push_movecopy_action(
	PUSH_CTX *pctx, const MOVECOPY_ACTION *r)
{
	if (!ext_pack_push_binary(pctx, &r->store_eid)) {
		return 0;
	}
	return ext_pack_push_binary(pctx, &r->folder_eid);
}

static zend_bool ext_pack_push_reply_action(
	PUSH_CTX *pctx, const REPLY_ACTION *r)
{	
	if (!ext_pack_push_binary(pctx, &r->message_eid)) {
		return 0;
	}
	return ext_pack_push_guid(pctx, &r->template_guid);
}

static zend_bool ext_pack_push_recipient_block(
	PUSH_CTX *pctx, const RECIPIENT_BLOCK *r)
{
	int i;
	
	if (0 == r->count) {
		return 0;
	}
	if (!ext_pack_push_uint8(pctx, r->reserved)) {
		return 0;
	}
	if (!ext_pack_push_uint16(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_tagged_propval(pctx, &r->ppropval[i])) {
			return 0;
		}
	}
	return 1;
}

static zend_bool ext_pack_push_forwarddelegate_action(
	PUSH_CTX *pctx, const FORWARDDELEGATE_ACTION *r)
{
	int i;
	
	if (0 == r->count) {
		return 0;
	}
	if (!ext_pack_push_uint16(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_recipient_block(pctx, &r->pblock[i])) {
			return 0;
		}
	}
	return 1;
}

static zend_bool ext_pack_push_action_block(
	PUSH_CTX *pctx, const ACTION_BLOCK *r)
{
	uint32_t offset;
	uint32_t offset1;
	uint16_t tmp_len;
	
	offset = pctx->offset;
	if (!ext_pack_push_advance(pctx, sizeof(uint16_t))) {
		return 0;
	}
	if (!ext_pack_push_uint8(pctx, r->type)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, r->flavor)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, r->flags)) {
		return 0;
	}
	switch (r->type) {
	case ACTION_TYPE_OP_MOVE:
	case ACTION_TYPE_OP_COPY:
		if (!ext_pack_push_movecopy_action(pctx, r->pdata)) {
			return 0;
		}
		break;
	case ACTION_TYPE_OP_REPLY:
	case ACTION_TYPE_OP_OOF_REPLY:
		if (!ext_pack_push_reply_action(pctx, r->pdata)) {
			return 0;
		}
		break;
	case ACTION_TYPE_OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - 2*sizeof(uint32_t);
		if (!ext_pack_push_bytes(pctx, r->pdata, tmp_len)) {
			return 0;
		}
		break;
	case ACTION_TYPE_OP_BOUNCE:
		if (!ext_pack_push_uint32(pctx, *(uint32_t*)r->pdata)) {
			return 0;
		}
		break;
	case ACTION_TYPE_OP_FORWARD:
	case ACTION_TYPE_OP_DELEGATE:
		if (!ext_pack_push_forwarddelegate_action(pctx, r->pdata)) {
			return 0;
		}
		break;
	case ACTION_TYPE_OP_TAG:
		if (!ext_pack_push_tagged_propval(pctx, r->pdata)) {
			return 0;
		}
	case ACTION_TYPE_OP_DELETE:
	case ACTION_TYPE_OP_MARK_AS_READ:
		break;
	default:
		return 0;
	}
	tmp_len = pctx->offset - (offset + sizeof(uint16_t));
	offset1 = pctx->offset;
	pctx->offset = offset;
	if (!ext_pack_push_uint16(pctx, tmp_len)) {
		return 0;
	}
	pctx->offset = offset1;
	return 1;
}

zend_bool ext_pack_push_rule_actions(
	PUSH_CTX *pctx, const RULE_ACTIONS *r)
{
	int i;
	
	if (0 == r->count) {
		return 0;
	}
	if (!ext_pack_push_uint16(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_action_block(pctx, &r->pblock[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_propval(PUSH_CTX *pctx,
	uint16_t type, const void *pval)
{
	/* convert multi-value instance into single value */
	if (0x3000 == (type & 0x3000)) {
		type &= ~0x3000;
	}
	switch (type) {
	case PROPVAL_TYPE_SHORT:
		return ext_pack_push_uint16(pctx, *(uint16_t*)pval);
	case PROPVAL_TYPE_LONG:
	case PROPVAL_TYPE_ERROR:
		return ext_pack_push_uint32(pctx, *(uint32_t*)pval);
	case PROPVAL_TYPE_FLOAT:
		return ext_pack_push_float(pctx, *(float*)pval);
	case PROPVAL_TYPE_DOUBLE:
	case PROPVAL_TYPE_FLOATINGTIME:
		return ext_pack_push_double(pctx, *(double*)pval);
	case PROPVAL_TYPE_BYTE:
		return ext_pack_push_uint8(pctx, *(uint8_t*)pval);
	case PROPVAL_TYPE_LONGLONG:
	case PROPVAL_TYPE_FILETIME:
		return ext_pack_push_uint64(pctx, *(uint64_t*)pval);
	case PROPVAL_TYPE_STRING:
	case PROPVAL_TYPE_WSTRING:
		return ext_pack_push_string(pctx, pval);
	case PROPVAL_TYPE_GUID:
		return ext_pack_push_guid(pctx, pval);
	case PROPVAL_TYPE_RESTRICTION:
		return ext_pack_push_restriction(pctx, pval);
	case PROPVAL_TYPE_RULE:
		return ext_pack_push_rule_actions(pctx, pval);
	case PROPVAL_TYPE_BINARY:
		return ext_pack_push_binary(pctx, pval);
	case PROPVAL_TYPE_SHORT_ARRAY:
		return ext_pack_push_short_array(pctx, pval);
	case PROPVAL_TYPE_LONG_ARRAY:
		return ext_pack_push_long_array(pctx, pval);
	case PROPVAL_TYPE_LONGLONG_ARRAY:
		return ext_pack_push_longlong_array(pctx, pval);
	case PROPVAL_TYPE_STRING_ARRAY:
	case PROPVAL_TYPE_WSTRING_ARRAY:
		return ext_pack_push_string_array(pctx, pval);
	case PROPVAL_TYPE_GUID_ARRAY:
		return ext_pack_push_guid_array(pctx, pval);
	case PROPVAL_TYPE_BINARY_ARRAY:
		return ext_pack_push_binary_array(pctx, pval);
	default:
		return 0;
	}
}

zend_bool ext_pack_push_tagged_propval(
	PUSH_CTX *pctx, const TAGGED_PROPVAL *r)
{
	if (!ext_pack_push_uint32(pctx, r->proptag)) {
		return 0;
	}
	return ext_pack_push_propval(pctx, r->proptag&0xFFFF, r->pvalue);
}

zend_bool ext_pack_push_proptag_array(
	PUSH_CTX *pctx, const PROPTAG_ARRAY *r)
{
	int i;
	
	if (!ext_pack_push_uint16(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_uint32(pctx, r->pproptag[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_property_name(
	PUSH_CTX *pctx, const PROPERTY_NAME *r)
{
	uint32_t offset;
	uint32_t offset1;
	uint8_t name_size;
	
	if (!ext_pack_push_uint8(pctx, r->kind)) {
		return 0;
	}
	if (!ext_pack_push_guid(pctx, &r->guid)) {
		return 0;
	}
	if (KIND_LID == r->kind) {
		if (!ext_pack_push_uint32(pctx, *r->plid)) {
			return 0;
		}
	} else if (KIND_NAME == r->kind) {
		offset = pctx->offset;
		if (!ext_pack_push_advance(pctx, sizeof(uint8_t))) {
			return 0;
		}
		if (!ext_pack_push_string(pctx, r->pname)) {
			return 0;
		}
		name_size = pctx->offset - (offset + sizeof(uint8_t));
		offset1 = pctx->offset;
		pctx->offset = offset;
		if (!ext_pack_push_uint8(pctx, name_size)) {
			return 0;
		}
		pctx->offset = offset1;
	}
	return 1;
}

zend_bool ext_pack_push_propname_array(
	PUSH_CTX *pctx, const PROPNAME_ARRAY *r)
{
	int i;
	
	if (!ext_pack_push_uint16(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_property_name(pctx, r->ppropname + i)) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_propid_array(
	PUSH_CTX *pctx, const PROPID_ARRAY *r)
{
	int i;
	
	if (!ext_pack_push_uint16(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_uint16(pctx, r->ppropid[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_tpropval_array(
	PUSH_CTX *pctx, const TPROPVAL_ARRAY *r)
{
	int i;
	
	if (!ext_pack_push_uint16(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_tagged_propval(pctx, r->ppropval + i)) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_tarray_set(PUSH_CTX *pctx, const TARRAY_SET *r)
{
	int i;
	
	if (!ext_pack_push_uint32(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_tpropval_array(pctx, r->pparray[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_sort_order(PUSH_CTX *pctx, const SORT_ORDER *r)
{
	if (r->type & 0x1000 && 0 == (r->type & 0x2000)) {
		return 0;
	}
	if (!ext_pack_push_uint16(pctx, r->type)) {
		return 0;
	}
	if (!ext_pack_push_uint16(pctx, r->propid)) {
		return 0;
	}
	return ext_pack_push_uint8(pctx, r->table_sort);
}

zend_bool ext_pack_push_sortorder_set(
	PUSH_CTX *pctx, const SORTORDER_SET *r)
{
	int i;
	
	if (0 == r->count || r->ccategories > r->count ||
		r->cexpanded > r->ccategories) {
		return 0;
	}
	if (!ext_pack_push_uint16(pctx, r->count)) {
		return 0;
	}
	if (!ext_pack_push_uint16(pctx, r->ccategories)) {
		return 0;
	}
	if (!ext_pack_push_uint16(pctx, r->cexpanded)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_sort_order(pctx, r->psort + i)) {
			return 0;
		}
	}
	return 1;
}

static zend_bool ext_pack_push_permission_row(
	PUSH_CTX *pctx, const PERMISSION_ROW *r)
{
	if (!ext_pack_push_uint32(pctx, r->flags)) {
		return 0;
	}
	if (!ext_pack_push_binary(pctx, &r->entryid)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, r->member_rights);
}

zend_bool ext_pack_push_permission_set(
	PUSH_CTX *pctx, const PERMISSION_SET *r)
{
	int i;
	
	if (!ext_pack_push_uint16(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_permission_row(pctx, &r->prows[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_rule_data(
	PUSH_CTX *pctx, const RULE_DATA *r)
{
	if (!ext_pack_push_uint8(pctx, r->flags)) {
		return 0;
	}
	return ext_pack_push_tpropval_array(pctx, &r->propvals);
}

zend_bool ext_pack_push_rule_list(
	PUSH_CTX *pctx, const RULE_LIST *r)
{
	int i;
	
	if (!ext_pack_push_uint16(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_rule_data(pctx, &r->prule[i])) {
			return 0;
		}
	}
	return 1;
}

zend_bool ext_pack_push_oneoff_entryid(PUSH_CTX *pctx,
	const ONEOFF_ENTRYID *r)
{
	if (!ext_pack_push_uint32(pctx, r->flags)) {
		return 0;
	}
	if (!ext_pack_push_bytes(pctx, r->provider_uid, 16)) {
		return 0;
	}
	if (!ext_pack_push_uint16(pctx, r->version)) {
		return 0;
	}
	if (!ext_pack_push_uint16(pctx, r->ctrl_flags)) {
		return 0;
	}
	if (r->ctrl_flags & CTRL_FLAG_UNICODE) {
		if (!ext_pack_push_wstring(pctx, r->pdisplay_name)) {
			return 0;
		}
		if (!ext_pack_push_wstring(pctx, r->paddress_type)) {
			return 0;
		}
		return ext_pack_push_wstring(pctx, r->pmail_address);
	} else {
		if (!ext_pack_push_string(pctx, r->pdisplay_name)) {
			return 0;
		}
		if (!ext_pack_push_string(pctx, r->paddress_type)) {
			return 0;
		}
		return ext_pack_push_string(pctx, r->pmail_address);
	}
}

static zend_bool ext_pack_push_message_state(
	PUSH_CTX *pctx, const MESSAGE_STATE *r)
{
	if (!ext_pack_push_binary(pctx, &r->source_key)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, r->message_flags);
}

zend_bool ext_pack_push_state_array(
	PUSH_CTX *pctx, const STATE_ARRAY *r)
{
	int i;
	
	if (!ext_pack_push_uint32(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_message_state(pctx, &r->pstate[i])) {
			return 0;
		}
	}
	return 1;
}

static zend_bool ext_pack_push_newmail_znotification(
	PUSH_CTX *pctx, const NEWMAIL_ZNOTIFICATION *r)
{
	if (!ext_pack_push_binary(pctx, &r->entryid)) {
		return 0;
	}
	if (!ext_pack_push_binary(pctx, &r->parentid)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, r->flags)) {
		return 0;
	}
	if (!ext_pack_push_string(pctx, r->message_class)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, r->message_flags);
}

static zend_bool ext_pack_push_object_znotification(
	PUSH_CTX *pctx, const OBJECT_ZNOTIFICATION *r)
{	
	if (!ext_pack_push_uint32(pctx, r->object_type)) {
		return 0;
	}
	if (NULL == r->pentryid) {
		if (!ext_pack_push_uint8(pctx, 0)) {
			return 0;
		}
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		if (!ext_pack_push_binary(pctx, r->pentryid)) {
			return 0;
		}
	}
	if (NULL == r->pparentid) {
		if (!ext_pack_push_uint8(pctx, 0)) {
			return 0;
		}
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		if (!ext_pack_push_binary(pctx, r->pparentid)) {
			return 0;
		}
	}
	if (NULL == r->pold_entryid) {
		if (!ext_pack_push_uint8(pctx, 0)) {
			return 0;
		}
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		if (!ext_pack_push_binary(pctx, r->pold_entryid)) {
			return 0;
		}
	}
	if (NULL == r->pold_parentid) {
		if (!ext_pack_push_uint8(pctx, 0)) {
			return 0;
		}
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		if (!ext_pack_push_binary(pctx, r->pold_parentid)) {
			return 0;
		}
	}
	if (NULL == r->pproptags) {
		return ext_pack_push_uint8(pctx, 0);
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		return ext_pack_push_proptag_array(pctx, r->pproptags);
	}
}

static zend_bool ext_pack_push_znotification(
	PUSH_CTX *pctx, const ZNOTIFICATION *r)
{
	if (!ext_pack_push_uint32(pctx, r->event_type)) {
		return 0;
	}
	switch (r->event_type) {
	case EVENT_TYPE_NEWMAIL:
		return ext_pack_push_newmail_znotification(
					pctx, r->pnotification_data);
	case EVENT_TYPE_OBJECTCREATED:
	case EVENT_TYPE_OBJECTDELETED:
	case EVENT_TYPE_OBJECTMODIFIED:
	case EVENT_TYPE_OBJECTMOVED:
	case EVENT_TYPE_OBJECTCOPIED:
	case EVENT_TYPE_SEARCHCOMPLETE:
		return ext_pack_push_object_znotification(
					pctx, r->pnotification_data);
	default:
		return 1;
	}
}

zend_bool ext_pack_push_znotification_array(
	PUSH_CTX *pctx, const ZNOTIFICATION_ARRAY *r)
{
	int i;
	
	if (!ext_pack_push_uint16(pctx, r->count)) {
		return 0;
	}
	for (i=0; i<r->count; i++) {
		if (!ext_pack_push_znotification(
			pctx, r->ppnotification[i])) {
			return 0;
		}
	}
	return 1;
}
