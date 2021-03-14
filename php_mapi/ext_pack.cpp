// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/mapidefs.h>
#include "ext_pack.h"
#include <climits>
#include <cstdlib>
#include <cstring>
#include <iconv.h>
#include <cstdint>
#include <gromox/defs.h>
#include "ext.hpp"
#define BTRY(expr) do { if (!(expr)) return 0; } while (false)
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
	if (iconv(conv_id, &pin, &in_len, &pout, &len) == static_cast<size_t>(-1)) {
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
	if (iconv(conv_id, &pin, &src_len, &pout, &len) == static_cast<size_t>(-1)) {
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
	*v = pctx->udata[pctx->offset];
	pctx->offset += sizeof(uint8_t);
	return 1;
}

zend_bool ext_pack_pull_uint16(PULL_CTX *pctx, uint16_t *v)
{
	if (pctx->data_size < sizeof(uint16_t) ||
		pctx->offset + sizeof(uint16_t) > pctx->data_size) {
		return 0;
	}
	memcpy(v, &pctx->udata[pctx->offset], sizeof(*v));
	*v = le16_to_cpu(*v);
	pctx->offset += sizeof(uint16_t);
	return 1;
}

zend_bool ext_pack_pull_uint32(PULL_CTX *pctx, uint32_t *v)
{
	if (pctx->data_size < sizeof(uint32_t) ||
		pctx->offset + sizeof(uint32_t) > pctx->data_size) {
		return 0;
	}
	memcpy(v, &pctx->udata[pctx->offset], sizeof(*v));
	*v = le32_to_cpu(*v);
	pctx->offset += sizeof(uint32_t);
	return 1;
}

zend_bool ext_pack_pull_uint64(PULL_CTX *pctx, uint64_t *v)
{
	if (pctx->data_size < sizeof(uint64_t) ||
		pctx->offset + sizeof(uint64_t) > pctx->data_size) {
		return 0;
	}
	memcpy(v, &pctx->udata[pctx->offset], sizeof(*v));
	*v = le64_to_cpu(*v);
	pctx->offset += sizeof(uint64_t);
	return 1;
}

zend_bool ext_pack_pull_float(PULL_CTX *pctx, float *v)
{
	if (pctx->data_size < sizeof(float) ||
		pctx->offset + sizeof(float) > pctx->data_size) {
		return 0;
	}
	memcpy(v, &pctx->udata[pctx->offset], sizeof(*v));
	pctx->offset += sizeof(float);
	return 1;
}

zend_bool ext_pack_pull_double(PULL_CTX *pctx, double *v)
{
	if (pctx->data_size < sizeof(double) ||
		pctx->offset + sizeof(double) > pctx->data_size) {
		return 0;
	}
	memcpy(v, &pctx->udata[pctx->offset], sizeof(*v));
	pctx->offset += sizeof(double);
	return 1;
}

zend_bool ext_pack_pull_bytes(PULL_CTX *pctx, uint8_t *data, uint32_t n)
{
	if (pctx->data_size < n || pctx->offset + n > pctx->data_size) {
		return 0;
	}
	memcpy(data, &pctx->udata[pctx->offset], n);
	pctx->offset += n;
	return 1;
}

zend_bool ext_pack_pull_guid(PULL_CTX *pctx, GUID *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->time_low));
	BTRY(ext_pack_pull_uint16(pctx, &r->time_mid));
	BTRY(ext_pack_pull_uint16(pctx, &r->time_hi_and_version));
	BTRY(ext_pack_pull_bytes(pctx, r->clock_seq, 2));
	return ext_pack_pull_bytes(pctx, r->node, 6);
}

zend_bool ext_pack_pull_string(PULL_CTX *pctx, char **ppstr)
{
	if (pctx->offset >= pctx->data_size) {
		return 0;
	}
	auto len = strnlen(&pctx->sdata[pctx->offset], pctx->data_size - pctx->offset);
	if (len + 1 > pctx->data_size - pctx->offset) {
		return 0;
	}
	len ++;
	*ppstr = sta_malloc<char>(len);
	if (NULL == *ppstr) {
		return 0;
	}
	memcpy(*ppstr, &pctx->sdata[pctx->offset], len);
	return ext_pack_pull_advance(pctx, len);
}

zend_bool ext_pack_pull_wstring(PULL_CTX *pctx, char **ppstr)
{
	int i;
	int len, max_len;
	
	if (pctx->offset >= pctx->data_size) {
		return 0;
	}
	max_len = pctx->data_size - pctx->offset;
	for (i=0; i<max_len-1; i+=2) {
		if (pctx->sdata[pctx->offset+i] == '\0' &&
		    pctx->sdata[pctx->offset+i+1] == '\0')
			break;
	}
	if (i >= max_len - 1) {
		return 0;
	}
	len = i + 2;
	*ppstr = sta_malloc<char>(2 * len);
	if (NULL == *ppstr) {
		return 0;
	}
	auto pbuff = static_cast<char *>(malloc(len));
	if (pbuff == nullptr)
		return 0;
	memcpy(pbuff, &pctx->sdata[pctx->offset], len);
	if (0 == utf16le_to_utf8(pbuff, len, *ppstr, 2*len)) {
		free(pbuff);
		return 0;
	}
	free(pbuff);
	return ext_pack_pull_advance(pctx, len);
}

zend_bool ext_pack_pull_binary(PULL_CTX *pctx, BINARY *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->cb));
	if (0 == r->cb) {
		r->pb = NULL;
		return 1;
	}
	r->pv = emalloc(r->cb);
	if (r->pv == nullptr) {
		r->cb = 0;
		return 0;
	}
	return ext_pack_pull_bytes(pctx, r->pb, r->cb);
}

zend_bool ext_pack_pull_short_array(PULL_CTX *pctx, SHORT_ARRAY *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->count));
	if (0 == r->count) {
		r->ps = NULL;
		return 1;
	}
	r->ps = sta_malloc<uint16_t>(r->count);
	if (NULL == r->ps) {
		r->count = 0;
		return 0;
	}
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_pull_uint16(pctx, &r->ps[i]));
	return 1;
}

zend_bool ext_pack_pull_long_array(PULL_CTX *pctx, LONG_ARRAY *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->count));
	if (0 == r->count) {
		r->pl = NULL;
		return 1;
	}
	r->pl = sta_malloc<uint32_t>(r->count);
	if (NULL == r->pl) {
		r->count = 0;
		return 0;
	}
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_pull_uint32(pctx, &r->pl[i]));
	return 1;
}

zend_bool ext_pack_pull_longlong_array(PULL_CTX *pctx, LONGLONG_ARRAY *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->count));
	if (0 == r->count) {
		r->pll = NULL;
		return 1;
	}
	r->pll = sta_malloc<uint64_t>(r->count);
	if (NULL == r->pll) {
		r->count = 0;
		return 0;
	}
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_pull_uint64(pctx, &r->pll[i]));
	return 1;
}

zend_bool ext_pack_pull_binary_array(PULL_CTX *pctx, BINARY_ARRAY *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->count));
	if (0 == r->count) {
		r->pbin = NULL;
		return 1;
	}
	r->pbin = sta_malloc<BINARY>(r->count);
	if (NULL == r->pbin) {
		r->count = 0;
		return 0;
	}
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_pull_binary(pctx, &r->pbin[i]));
	return 1;
}

zend_bool ext_pack_pull_string_array(PULL_CTX *pctx, STRING_ARRAY *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->count));
	if (0 == r->count) {
		r->ppstr = NULL;
		return 1;
	}
	r->ppstr = sta_malloc<char *>(r->count);
	if (NULL == r->ppstr) {
		r->count = 0;
		return 0;
	}
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_pull_string(pctx, &r->ppstr[i]));
	return 1;
}

zend_bool ext_pack_pull_guid_array(PULL_CTX *pctx, GUID_ARRAY *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->count));
	if (0 == r->count) {
		r->pguid = NULL;
		return 1;
	}
	r->pguid = sta_malloc<GUID>(r->count);
	if (NULL == r->pguid) {
		r->count = 0;
		return 0;
	}
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_pull_guid(pctx, &r->pguid[i]));
	return 1;
}

static zend_bool ext_pack_pull_restriction_and_or(
	PULL_CTX *pctx, RESTRICTION_AND_OR *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->count));
	if (0 == r->count) {
		r->pres = NULL;
		return 1;
	}
	r->pres = sta_malloc<RESTRICTION>(r->count);
	if (NULL == r->pres) {
		r->count = 0;
		return 0;
	}
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_pull_restriction(pctx, &r->pres[i]));
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
	BTRY(ext_pack_pull_uint32(pctx, &r->fuzzy_level));
	BTRY(ext_pack_pull_uint32(pctx, &r->proptag));
	return ext_pack_pull_tagged_propval(pctx, &r->propval);
}

static zend_bool ext_pack_pull_restriction_property(
	PULL_CTX *pctx, RESTRICTION_PROPERTY *r)
{
	uint8_t relop;
	BTRY(ext_pack_pull_uint8(pctx, &relop));
	r->relop = static_cast<enum relop>(relop);
	BTRY(ext_pack_pull_uint32(pctx, &r->proptag));
	return ext_pack_pull_tagged_propval(pctx, &r->propval);
}

static zend_bool ext_pack_pull_restriction_propcompare(
	PULL_CTX *pctx, RESTRICTION_PROPCOMPARE *r)
{
	uint8_t relop;
	BTRY(ext_pack_pull_uint8(pctx, &relop));
	r->relop = static_cast<enum relop>(relop);
	BTRY(ext_pack_pull_uint32(pctx, &r->proptag1));
	return ext_pack_pull_uint32(pctx, &r->proptag2);
}

static zend_bool ext_pack_pull_restriction_bitmask(
	PULL_CTX *pctx, RESTRICTION_BITMASK *r)
{
	uint8_t relop;
	BTRY(ext_pack_pull_uint8(pctx, &relop));
	r->bitmask_relop = static_cast<enum bm_relop>(relop);
	BTRY(ext_pack_pull_uint32(pctx, &r->proptag));
	return ext_pack_pull_uint32(pctx, &r->mask);
}

static zend_bool ext_pack_pull_restriction_size(
	PULL_CTX *pctx, RESTRICTION_SIZE *r)
{
	uint8_t relop;
	BTRY(ext_pack_pull_uint8(pctx, &relop));
	r->relop = static_cast<enum relop>(relop);
	BTRY(ext_pack_pull_uint32(pctx, &r->proptag));
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
	BTRY(ext_pack_pull_uint32(pctx, &r->subobject));
	return ext_pack_pull_restriction(pctx, &r->res);
}

static zend_bool ext_pack_pull_restriction_comment(
	PULL_CTX *pctx, RESTRICTION_COMMENT *r)
{
	int i;
	uint8_t res_present;
	
	BTRY(ext_pack_pull_uint8(pctx, &r->count));
	if (0 == r->count) {
		return 0;
	}
	r->ppropval = sta_malloc<TAGGED_PROPVAL>(r->count);
	if (NULL == r->ppropval) {
		r->count = 0;
		return 0;
	}
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_pull_tagged_propval(pctx, &r->ppropval[i]));
	}
	BTRY(ext_pack_pull_uint8(pctx, &res_present));
	if (0 != res_present) {
		r->pres = st_malloc<RESTRICTION>();
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
	BTRY(ext_pack_pull_uint32(pctx, &r->count));
	return ext_pack_pull_restriction(pctx, &r->sub_res);
}

zend_bool ext_pack_pull_restriction(PULL_CTX *pctx, RESTRICTION *r)
{
	uint8_t rt;
	BTRY(ext_pack_pull_uint8(pctx, &rt));
	r->rt = static_cast<enum res_type>(rt);
	switch (r->rt) {
	case RES_AND:
	case RES_OR:
		r->pres = emalloc(sizeof(RESTRICTION_AND_OR));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_and_or(pctx, r->andor);
	case RES_NOT:
		r->pres = emalloc(sizeof(RESTRICTION_NOT));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_not(pctx, r->xnot);
	case RES_CONTENT:
		r->pres = emalloc(sizeof(RESTRICTION_CONTENT));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_content(pctx, r->cont);
	case RES_PROPERTY:
		r->pres = emalloc(sizeof(RESTRICTION_PROPERTY));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_property(pctx, r->prop);
	case RES_PROPCOMPARE:
		r->pres = emalloc(sizeof(RESTRICTION_PROPCOMPARE));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_propcompare(pctx, r->pcmp);
	case RES_BITMASK:
		r->pres = emalloc(sizeof(RESTRICTION_BITMASK));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_bitmask(pctx, r->bm);
	case RES_SIZE:
		r->pres = emalloc(sizeof(RESTRICTION_SIZE));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_size(pctx, r->size);
	case RES_EXIST:
		r->pres = emalloc(sizeof(RESTRICTION_EXIST));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_exist(pctx, r->exist);
	case RES_SUBRESTRICTION:
		r->pres = emalloc(sizeof(RESTRICTION_SUBOBJ));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_subobj(pctx, r->sub);
	case RES_COMMENT:
		r->pres = emalloc(sizeof(RESTRICTION_COMMENT));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_comment(pctx, r->comment);
	case RES_COUNT:
		r->pres = emalloc(sizeof(RESTRICTION_COUNT));
		if (NULL == r->pres) {
			return 0;
		}
		return ext_pack_pull_restriction_count(pctx, r->count);
	case RES_NULL:
		r->pres = NULL;
		return 1;
	default:
		return 0;
	}
}

static zend_bool ext_pack_pull_movecopy_action(PULL_CTX *pctx, MOVECOPY_ACTION *r)
{
	BTRY(ext_pack_pull_binary(pctx, &r->store_eid));
	return ext_pack_pull_binary(pctx, &r->folder_eid);
}

static zend_bool ext_pack_pull_reply_action(PULL_CTX *pctx, REPLY_ACTION *r)
{
	BTRY(ext_pack_pull_binary(pctx, &r->message_eid));
	return ext_pack_pull_guid(pctx, &r->template_guid);
}

static zend_bool ext_pack_pull_recipient_block(PULL_CTX *pctx, RECIPIENT_BLOCK *r)
{
	int i;
	
	BTRY(ext_pack_pull_uint8(pctx, &r->reserved));
	BTRY(ext_pack_pull_uint16(pctx, &r->count));
	if (0 == r->count) {
		return 0;
	}
	r->ppropval = sta_malloc<TAGGED_PROPVAL>(r->count);
	if (NULL == r->ppropval) {
		r->count = 0;
		return 0;
	}
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_pull_tagged_propval(pctx, &r->ppropval[i]));
	}
	return 1;
}

static zend_bool ext_pack_pull_forwarddelegate_action(
	PULL_CTX *pctx, FORWARDDELEGATE_ACTION *r)
{
	int i;
	
	BTRY(ext_pack_pull_uint16(pctx, &r->count));
	if (0 == r->count) {
		return 0;
	}
	r->pblock = sta_malloc<RECIPIENT_BLOCK>(r->count);
	if (NULL == r->pblock) {
		r->count = 0;
		return 0;
	}
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_pull_recipient_block(pctx, &r->pblock[i]));
	}
	return 1;
}

static zend_bool ext_pack_pull_action_block(PULL_CTX *pctx, ACTION_BLOCK *r)
{
	uint16_t tmp_len;
	
	BTRY(ext_pack_pull_uint16(pctx, &r->length));
	BTRY(ext_pack_pull_uint8(pctx, &r->type));
	BTRY(ext_pack_pull_uint32(pctx, &r->flavor));
	BTRY(ext_pack_pull_uint32(pctx, &r->flags));
	switch (r->type) {
	case OP_MOVE:
	case OP_COPY:
		r->pdata = emalloc(sizeof(MOVECOPY_ACTION));
		if (NULL == r->pdata) {
			return 0;
		}
		return ext_pack_pull_movecopy_action(pctx, static_cast<MOVECOPY_ACTION *>(r->pdata));
	case OP_REPLY:
	case OP_OOF_REPLY:
		r->pdata = emalloc(sizeof(REPLY_ACTION));
		if (NULL == r->pdata) {
			return 0;
		}
		return ext_pack_pull_reply_action(pctx,
		       static_cast<REPLY_ACTION *>(r->pdata));
	case OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - 2*sizeof(uint32_t);
		r->pdata = emalloc(tmp_len);
		if (NULL == r->pdata) {
			return 0;
		}
		return ext_pack_pull_bytes(pctx,
		       static_cast<uint8_t *>(r->pdata), tmp_len);
	case OP_BOUNCE:
		r->pdata = emalloc(sizeof(uint32_t));
		if (NULL == r->pdata) {
			return 0;
		}
		return ext_pack_pull_uint32(pctx,
		       static_cast<uint32_t *>(r->pdata));
	case OP_FORWARD:
	case OP_DELEGATE:
		r->pdata = emalloc(sizeof(FORWARDDELEGATE_ACTION));
		if (NULL == r->pdata) {
			return 0;
		}
		return ext_pack_pull_forwarddelegate_action(pctx,
		       static_cast<FORWARDDELEGATE_ACTION *>(r->pdata));
	case OP_TAG:
		r->pdata = emalloc(sizeof(TAGGED_PROPVAL));
		if (NULL == r->pdata) {
			return 0;
		}
		return ext_pack_pull_tagged_propval(pctx,
		       static_cast<TAGGED_PROPVAL *>(r->pdata));
	case OP_DELETE:
	case OP_MARK_AS_READ:
		r->pdata = NULL;
		return 1;
	default:
		return 0;
	}
}

zend_bool ext_pack_pull_rule_actions(PULL_CTX *pctx, RULE_ACTIONS *r)
{
	int i;
	
	BTRY(ext_pack_pull_uint16(pctx, &r->count));
	if (0 == r->count) {
		return 0;
	}
	r->pblock = sta_malloc<ACTION_BLOCK>(r->count);
	if (NULL == r->pblock) {
		r->count = 0;
		return 0;
	}
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_pull_action_block(pctx, &r->pblock[i]));
	}
	return 1;
}

zend_bool ext_pack_pull_propval(PULL_CTX *pctx, uint16_t type, void **ppval)
{
	/* convert multi-value instance into single value */
	if ((type & MVI_FLAG) == MVI_FLAG)
		type &= ~MVI_FLAG;
	switch (type) {
	case PT_SHORT:
		*ppval = emalloc(sizeof(uint16_t));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_uint16(pctx, static_cast<uint16_t *>(*ppval));
	case PT_LONG:
	case PT_ERROR:
		*ppval = emalloc(sizeof(uint32_t));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_uint32(pctx, static_cast<uint32_t *>(*ppval));
	case PT_FLOAT:
		*ppval = emalloc(sizeof(float));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_float(pctx, static_cast<float *>(*ppval));
	case PT_DOUBLE:
	case PT_APPTIME:
		*ppval = emalloc(sizeof(double));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_double(pctx, static_cast<double *>(*ppval));
	case PT_BOOLEAN:
		*ppval = emalloc(sizeof(uint8_t));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_uint8(pctx, static_cast<uint8_t *>(*ppval));
	case PT_I8:
	case PT_SYSTIME:
		*ppval = emalloc(sizeof(uint64_t));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_uint64(pctx, static_cast<uint64_t *>(*ppval));
	case PT_STRING8:
	case PT_UNICODE:
		return ext_pack_pull_string(pctx, (char**)ppval);
	case PT_CLSID:
		*ppval = emalloc(sizeof(GUID));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_guid(pctx, static_cast<GUID *>(*ppval));
	case PT_SRESTRICT:
		*ppval = emalloc(sizeof(RESTRICTION));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_restriction(pctx, static_cast<RESTRICTION *>(*ppval));
	case PT_ACTIONS:
		*ppval = emalloc(sizeof(RULE_ACTIONS));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_rule_actions(pctx, static_cast<RULE_ACTIONS *>(*ppval));
	case PT_BINARY:
		*ppval = emalloc(sizeof(BINARY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_binary(pctx, static_cast<BINARY *>(*ppval));
	case PT_MV_SHORT:
		*ppval = emalloc(sizeof(SHORT_ARRAY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_short_array(pctx, static_cast<SHORT_ARRAY *>(*ppval));
	case PT_MV_LONG:
		*ppval = emalloc(sizeof(LONG_ARRAY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_long_array(pctx, static_cast<LONG_ARRAY *>(*ppval));
	case PT_MV_I8:
		*ppval = emalloc(sizeof(LONGLONG_ARRAY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_longlong_array(pctx, static_cast<LONGLONG_ARRAY *>(*ppval));
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		*ppval = emalloc(sizeof(STRING_ARRAY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_string_array(pctx, static_cast<STRING_ARRAY *>(*ppval));
	case PT_MV_CLSID:
		*ppval = emalloc(sizeof(GUID_ARRAY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_guid_array(pctx, static_cast<GUID_ARRAY *>(*ppval));
	case PT_MV_BINARY:
		*ppval = emalloc(sizeof(BINARY_ARRAY));
		if (NULL == *ppval) {
			return 0;
		}
		return ext_pack_pull_binary_array(pctx, static_cast<BINARY_ARRAY *>(*ppval));
	default:
		return 0;
	}
}

zend_bool ext_pack_pull_tagged_propval(PULL_CTX *pctx, TAGGED_PROPVAL *r)
{	
	BTRY(ext_pack_pull_uint32(pctx, &r->proptag));
	return ext_pack_pull_propval(pctx, PROP_TYPE(r->proptag), &r->pvalue);
}

zend_bool ext_pack_pull_proptag_array(PULL_CTX *pctx, PROPTAG_ARRAY *r)
{
	int i;
	
	BTRY(ext_pack_pull_uint16(pctx, &r->count));
	if (0 == r->count) {
		r->pproptag = NULL;
		return 1;
	}
	r->pproptag = sta_malloc<uint32_t>(r->count);
	if (NULL == r->pproptag) {
		r->count = 0;
		return 0;
	}
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_pull_uint32(pctx, &r->pproptag[i]));
	}
	return 1;
}

zend_bool ext_pack_pull_property_name(PULL_CTX *pctx, PROPERTY_NAME *r)
{
	uint32_t offset;
	uint8_t name_size;
	
	BTRY(ext_pack_pull_uint8(pctx, &r->kind));
	BTRY(ext_pack_pull_guid(pctx, &r->guid));
	r->plid = NULL;
	r->pname = NULL;
	if (r->kind == MNID_ID) {
		r->plid = st_malloc<uint32_t>();
		if (NULL == r->plid) {
			return 0;
		}
		BTRY(ext_pack_pull_uint32(pctx, r->plid));
	} else if (r->kind == MNID_STRING) {
		BTRY(ext_pack_pull_uint8(pctx, &name_size));
		if (name_size < 2) {
			return 0;
		}
		offset = pctx->offset + name_size;
		BTRY(ext_pack_pull_string(pctx, &r->pname));
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
	
	BTRY(ext_pack_pull_uint16(pctx, &r->count));
	if (0 == r->count) {
		r->ppropname = NULL;
		return 1;
	}
	r->ppropname = sta_malloc<PROPERTY_NAME>(r->count);
	if (NULL == r->ppropname) {
		r->count = 0;
		return 0;
	}
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_pull_property_name(pctx, r->ppropname + i));
	}
	return 1;
}

zend_bool ext_pack_pull_propid_array(PULL_CTX *pctx, PROPID_ARRAY *r)
{
	int i;
	
	BTRY(ext_pack_pull_uint16(pctx, &r->count));
	if (0 == r->count) {
		r->ppropid = NULL;
		return 1;
	}
	r->ppropid = sta_malloc<uint16_t>(r->count);
	if (NULL == r->ppropid) {
		r->count = 0;
		return 0;
	}
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_pull_uint16(pctx, r->ppropid + i));
	}
	return 1;
}

zend_bool ext_pack_pull_tpropval_array(PULL_CTX *pctx, TPROPVAL_ARRAY *r)
{
	int i;
	
	BTRY(ext_pack_pull_uint16(pctx, &r->count));
	if (0 == r->count) {
		r->ppropval = NULL;
		return 1;
	}
	r->ppropval = sta_malloc<TAGGED_PROPVAL>(r->count);
	if (NULL == r->ppropval) {
		r->count = 0;
		return 0;
	}
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_pull_tagged_propval(pctx, r->ppropval + i));
	}
	return 1;
}

zend_bool ext_pack_pull_tarray_set(PULL_CTX *pctx, TARRAY_SET *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->count));
	if (0 == r->count) {
		r->pparray = NULL;
		return 1;
	}
	r->pparray = sta_malloc<TPROPVAL_ARRAY *>(r->count);
	if (NULL == r->pparray) {
		r->count = 0;
		return 0;
	}
	for (size_t i = 0; i < r->count; ++i) {
		r->pparray[i] = st_malloc<TPROPVAL_ARRAY>();
		if (NULL == r->pparray[i]) {
			return 0;
		}
		BTRY(ext_pack_pull_tpropval_array(pctx, r->pparray[i]));
	}
	return 1;
}

static zend_bool ext_pack_pull_permission_row(
	PULL_CTX *pctx, PERMISSION_ROW *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->flags));
	BTRY(ext_pack_pull_binary(pctx, &r->entryid));
	return ext_pack_pull_uint32(pctx, &r->member_rights);
}

zend_bool ext_pack_pull_permission_set(PULL_CTX *pctx, PERMISSION_SET *r)
{
	int i;
	
	BTRY(ext_pack_pull_uint16(pctx, &r->count));
	r->prows = sta_malloc<PERMISSION_ROW>(r->count);
	if (NULL == r->prows) {
		r->count = 0;
		return 0;
	}
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_pull_permission_row(pctx, &r->prows[i]));
	}
	return 1;
}

zend_bool ext_pack_pull_oneoff_entryid(PULL_CTX *pctx, ONEOFF_ENTRYID *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->flags));
	BTRY(ext_pack_pull_bytes(pctx, r->provider_uid, 16));
	BTRY(ext_pack_pull_uint16(pctx, &r->version));
	BTRY(ext_pack_pull_uint16(pctx, &r->ctrl_flags));
	if (r->ctrl_flags & CTRL_FLAG_UNICODE) {
		BTRY(ext_pack_pull_wstring(pctx, &r->pdisplay_name));
		BTRY(ext_pack_pull_wstring(pctx, &r->paddress_type));
		return ext_pack_pull_wstring(pctx, &r->pmail_address);
	} else {
		BTRY(ext_pack_pull_string(pctx, &r->pdisplay_name));
		BTRY(ext_pack_pull_string(pctx, &r->paddress_type));
		return ext_pack_pull_string(pctx, &r->pmail_address);
	}
}

static zend_bool ext_pack_pull_message_state(PULL_CTX *pctx, MESSAGE_STATE *r)
{
	BTRY(ext_pack_pull_binary(pctx, &r->source_key));
	return ext_pack_pull_uint32(pctx, &r->message_flags);
}

zend_bool ext_pack_pull_state_array(PULL_CTX *pctx, STATE_ARRAY *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->count));
	if (0 == r->count) {
		r->pstate = NULL;
		return 1;
	}
	r->pstate = sta_malloc<MESSAGE_STATE>(r->count);
	if (NULL == r->pstate) {
		r->count = 0;
		return 0;
	}
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_pull_message_state(pctx, &r->pstate[i]));
	return 1;
}

static zend_bool ext_pack_pull_newmail_znotification(
	PULL_CTX *pctx, NEWMAIL_ZNOTIFICATION *r)
{
	BTRY(ext_pack_pull_binary(pctx, &r->entryid));
	BTRY(ext_pack_pull_binary(pctx, &r->parentid));
	BTRY(ext_pack_pull_uint32(pctx, &r->flags));
	BTRY(ext_pack_pull_string(pctx, &r->message_class));
	return ext_pack_pull_uint32(pctx, &r->message_flags);
}

static zend_bool ext_pack_pull_object_znotification(
	PULL_CTX *pctx, OBJECT_ZNOTIFICATION *r)
{
	uint8_t tmp_byte;
	
	BTRY(ext_pack_pull_uint32(pctx, &r->object_type));
	BTRY(ext_pack_pull_uint8(pctx, &tmp_byte));
	if (0 == tmp_byte) {
		r->pentryid = NULL;
	} else {
		r->pentryid = st_malloc<BINARY>();
		if (NULL == r->pentryid) {
			return 0;
		}
		BTRY(ext_pack_pull_binary(pctx, r->pentryid));
	}
	BTRY(ext_pack_pull_uint8(pctx, &tmp_byte));
	if (0 == tmp_byte) {
		r->pparentid = NULL;
	} else {
		r->pparentid = st_malloc<BINARY>();
		if (NULL == r->pparentid) {
			return 0;
		}
		BTRY(ext_pack_pull_binary(pctx, r->pparentid));
	}
	BTRY(ext_pack_pull_uint8(pctx, &tmp_byte));
	if (0 == tmp_byte) {
		r->pold_entryid = NULL;
	} else {
		r->pold_entryid = st_malloc<BINARY>();
		if (NULL == r->pold_entryid) {
			return 0;
		}
		BTRY(ext_pack_pull_binary(pctx, r->pold_entryid));
	}
	BTRY(ext_pack_pull_uint8(pctx, &tmp_byte));
	if (0 == tmp_byte) {
		r->pold_parentid = NULL;
	} else {
		r->pold_parentid = st_malloc<BINARY>();
		if (NULL == r->pold_parentid) {
			return 0;
		}
		BTRY(ext_pack_pull_binary(pctx, r->pold_parentid));
	}
	BTRY(ext_pack_pull_uint8(pctx, &tmp_byte));
	if (0 == tmp_byte) {
		r->pproptags = NULL;
		return 1;
	} else {
		r->pproptags = st_malloc<PROPTAG_ARRAY>();
		if (NULL == r->pproptags) {
			return 0;
		}
		return ext_pack_pull_proptag_array(pctx, r->pproptags);
	}
}

static zend_bool ext_pack_pull_znotification(
	PULL_CTX *pctx, ZNOTIFICATION *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->event_type));
	switch (r->event_type) {
	case EVENT_TYPE_NEWMAIL:
		r->pnotification_data = emalloc(sizeof(NEWMAIL_ZNOTIFICATION));
		if (NULL == r->pnotification_data) {
			return 0;
		}
		return ext_pack_pull_newmail_znotification(pctx,
		       static_cast<NEWMAIL_ZNOTIFICATION *>(r->pnotification_data));
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
		return ext_pack_pull_object_znotification(pctx,
		       static_cast<OBJECT_ZNOTIFICATION *>(r->pnotification_data));
	default:
		r->pnotification_data = NULL;
		return 1;
	}
}

zend_bool ext_pack_pull_znotification_array(
	PULL_CTX *pctx, ZNOTIFICATION_ARRAY *r)
{
	int i;
	
	BTRY(ext_pack_pull_uint16(pctx, &r->count));
	if (0 == r->count) {
		r->ppnotification = NULL;
		return 1;
	}
	r->ppnotification = sta_malloc<ZNOTIFICATION *>(r->count);
	if (NULL == r->ppnotification) {
		r->count = 0;
		return 0;
	}
	for (i=0; i<r->count; i++) {
		r->ppnotification[i] = st_malloc<ZNOTIFICATION>();
		if (NULL == r->ppnotification[i]) {
			return 0;
		}
		BTRY(ext_pack_pull_znotification(pctx, r->ppnotification[i]));
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
	uint32_t alloc_size;
	
	size = extra_size + pctx->offset;
	if (pctx->alloc_size >= size) {
		return 1;
	}
	for (alloc_size=pctx->alloc_size; alloc_size<size;
		alloc_size+=GROWING_BLOCK_SIZE);
	auto pdata = static_cast<uint8_t *>(erealloc(pctx->data, alloc_size));
	if (NULL == pdata) {
		return 0;
	}
	pctx->data = pdata;
	pctx->alloc_size = alloc_size;
	return 1;
}

zend_bool ext_pack_push_advance(PUSH_CTX *pctx, uint32_t size)
{
	BTRY(ext_pack_push_check_overflow(pctx, size));
	pctx->offset += size;
	return 1;
}

zend_bool ext_pack_push_bytes(PUSH_CTX *pctx, const void *pdata, uint32_t n)
{
	BTRY(ext_pack_push_check_overflow(pctx, n));
	memcpy(&pctx->udata[pctx->offset], pdata, n);
	pctx->offset += n;
	return 1;
}

zend_bool ext_pack_push_uint8(PUSH_CTX *pctx, uint8_t v)
{
	BTRY(ext_pack_push_check_overflow(pctx, sizeof(v)));
	pctx->udata[pctx->offset] = v;
	pctx->offset += sizeof(uint8_t);
	return 1;
}

zend_bool ext_pack_push_uint16(PUSH_CTX *pctx, uint16_t v)
{
	BTRY(ext_pack_push_check_overflow(pctx, sizeof(v)));
	v = cpu_to_le16(v);
	memcpy(&pctx->udata[pctx->offset], &v, sizeof(v));
	pctx->offset += sizeof(uint16_t);
	return 1;
}

zend_bool ext_pack_push_uint32(PUSH_CTX *pctx, uint32_t v)
{
	BTRY(ext_pack_push_check_overflow(pctx, sizeof(v)));
	v = cpu_to_le32(v);
	memcpy(&pctx->udata[pctx->offset], &v, sizeof(v));
	pctx->offset += sizeof(uint32_t);
	return 1;
}

zend_bool ext_pack_push_uint64(PUSH_CTX *pctx, uint64_t v)
{
	BTRY(ext_pack_push_check_overflow(pctx, sizeof(v)));
	v = cpu_to_le64(v);
	memcpy(&pctx->udata[pctx->offset], &v, sizeof(v));
	pctx->offset += sizeof(uint64_t);
	return 1;
}

zend_bool ext_pack_push_float(PUSH_CTX *pctx, float v)
{
	static_assert(sizeof(v) == 4 && CHAR_BIT == 8, "");
	BTRY(ext_pack_push_check_overflow(pctx, sizeof(v)));
	memcpy(&pctx->udata[pctx->offset], &v, sizeof(v));
	pctx->offset += sizeof(float);
	return 1;
}

zend_bool ext_pack_push_double(PUSH_CTX *pctx, double v)
{
	static_assert(sizeof(v) == 8 && CHAR_BIT == 8, "");
	BTRY(ext_pack_push_check_overflow(pctx, sizeof(v)));
	memcpy(&pctx->udata[pctx->offset], &v, sizeof(v));
	pctx->offset += sizeof(double);
	return 1;
}

zend_bool ext_pack_push_binary(PUSH_CTX *pctx, const BINARY *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->cb));
	if (0 == r->cb) {
		return 1;
	}
	return ext_pack_push_bytes(pctx, r->pb, r->cb);
}

zend_bool ext_pack_push_guid(PUSH_CTX *pctx, const GUID *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->time_low));
	BTRY(ext_pack_push_uint16(pctx, r->time_mid));
	BTRY(ext_pack_push_uint16(pctx, r->time_hi_and_version));
	BTRY(ext_pack_push_bytes(pctx, r->clock_seq, 2));
	return ext_pack_push_bytes(pctx, r->node, 6);
}

zend_bool ext_pack_push_string(PUSH_CTX *pctx, const char *pstr)
{
	return ext_pack_push_bytes(pctx, pstr, strlen(pstr) + 1);
}

zend_bool ext_pack_push_wstring(PUSH_CTX *pctx, const char *pstr)
{
	int len;
	
	len = 2*strlen(pstr) + 2;
	auto pbuff = static_cast<char *>(malloc(len));
	if (pbuff == nullptr)
		return 0;
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
	BTRY(ext_pack_push_uint32(pctx, r->count));
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_push_uint16(pctx, r->ps[i]));
	return 1;
}

zend_bool ext_pack_push_long_array(PUSH_CTX *pctx, const LONG_ARRAY *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->count));
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_push_uint32(pctx, r->pl[i]));
	return 1;
}

zend_bool ext_pack_push_longlong_array(PUSH_CTX *pctx, const LONGLONG_ARRAY *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->count));
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_push_uint64(pctx, r->pll[i]));
	return 1;
}

zend_bool ext_pack_push_binary_array(PUSH_CTX *pctx, const BINARY_ARRAY *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->count));
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_push_binary(pctx, &r->pbin[i]));
	return 1;
}

zend_bool ext_pack_push_string_array(PUSH_CTX *pctx, const STRING_ARRAY *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->count));
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_push_string(pctx, r->ppstr[i]));
	return 1;
}

zend_bool ext_pack_push_guid_array(PUSH_CTX *pctx, const GUID_ARRAY *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->count));
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_push_guid(pctx, &r->pguid[i]));
	return 1;
}

static zend_bool ext_pack_push_restriction_and_or(
	PUSH_CTX *pctx, const RESTRICTION_AND_OR *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->count));
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_push_restriction(pctx, &r->pres[i]));
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
	BTRY(ext_pack_push_uint32(pctx, r->fuzzy_level));
	BTRY(ext_pack_push_uint32(pctx, r->proptag));
	return ext_pack_push_tagged_propval(pctx, &r->propval);
}

static zend_bool ext_pack_push_restriction_property(
	PUSH_CTX *pctx, const RESTRICTION_PROPERTY *r)
{
	BTRY(ext_pack_push_uint8(pctx, r->relop));
	BTRY(ext_pack_push_uint32(pctx, r->proptag));
	return ext_pack_push_tagged_propval(pctx, &r->propval);
}

static zend_bool ext_pack_push_restriction_propcompare(
	PUSH_CTX *pctx, const RESTRICTION_PROPCOMPARE *r)
{
	BTRY(ext_pack_push_uint8(pctx, r->relop));
	BTRY(ext_pack_push_uint32(pctx, r->proptag1));
	return ext_pack_push_uint32(pctx, r->proptag2);
}

static zend_bool ext_pack_push_restriction_bitmask(
	PUSH_CTX *pctx, const RESTRICTION_BITMASK *r)
{
	BTRY(ext_pack_push_uint8(pctx, r->bitmask_relop));
	BTRY(ext_pack_push_uint32(pctx, r->proptag));
	return ext_pack_push_uint32(pctx, r->mask);
}

static zend_bool ext_pack_push_restriction_size(
	PUSH_CTX *pctx, const RESTRICTION_SIZE *r)
{
	BTRY(ext_pack_push_uint8(pctx, r->relop));
	BTRY(ext_pack_push_uint32(pctx, r->proptag));
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
	BTRY(ext_pack_push_uint32(pctx, r->subobject));
	return ext_pack_push_restriction(pctx, &r->res);
}

static zend_bool ext_pack_push_restriction_comment(
	PUSH_CTX *pctx, const RESTRICTION_COMMENT *r)
{
	int i;
	
	if (0 == r->count) {
		return 0;
	}
	BTRY(ext_pack_push_uint8(pctx, r->count));
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_push_tagged_propval(pctx, &r->ppropval[i]));
	}
	if (NULL != r->pres) {
		BTRY(ext_pack_push_uint8(pctx, 1));
		return ext_pack_push_restriction(pctx, r->pres);
	}
	return ext_pack_push_uint8(pctx, 0);
}

static zend_bool ext_pack_push_restriction_count(
	PUSH_CTX *pctx, const RESTRICTION_COUNT *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->count));
	return ext_pack_push_restriction(pctx, &r->sub_res);
}

zend_bool ext_pack_push_restriction(PUSH_CTX *pctx, const RESTRICTION *r)
{
	BTRY(ext_pack_push_uint8(pctx, r->rt));
	switch (r->rt) {
	case RES_AND:
	case RES_OR:
		return ext_pack_push_restriction_and_or(pctx, r->andor);
	case RES_NOT:
		return ext_pack_push_restriction_not(pctx, r->xnot);
	case RES_CONTENT:
		return ext_pack_push_restriction_content(pctx, r->cont);
	case RES_PROPERTY:
		return ext_pack_push_restriction_property(pctx, r->prop);
	case RES_PROPCOMPARE:
		return ext_pack_push_restriction_propcompare(pctx, r->pcmp);
	case RES_BITMASK:
		return ext_pack_push_restriction_bitmask(pctx, r->bm);
	case RES_SIZE:
		return ext_pack_push_restriction_size(pctx, r->size);
	case RES_EXIST:
		return ext_pack_push_restriction_exist(pctx, r->exist);
	case RES_SUBRESTRICTION:
		return ext_pack_push_restriction_subobj(pctx, r->sub);
	case RES_COMMENT:
		return ext_pack_push_restriction_comment(pctx, r->comment);
	case RES_COUNT:
		return ext_pack_push_restriction_count(pctx, r->count);
	case RES_NULL:
		return 1;
	}
	return 0;
}

static zend_bool ext_pack_push_movecopy_action(PUSH_CTX *pctx,
    const MOVECOPY_ACTION *r)
{
	BTRY(ext_pack_push_binary(pctx, &r->store_eid));
	return ext_pack_push_binary(pctx, &r->folder_eid);
}

static zend_bool ext_pack_push_reply_action(
	PUSH_CTX *pctx, const REPLY_ACTION *r)
{	
	BTRY(ext_pack_push_binary(pctx, &r->message_eid));
	return ext_pack_push_guid(pctx, &r->template_guid);
}

static zend_bool ext_pack_push_recipient_block(
	PUSH_CTX *pctx, const RECIPIENT_BLOCK *r)
{
	int i;
	
	if (0 == r->count) {
		return 0;
	}
	BTRY(ext_pack_push_uint8(pctx, r->reserved));
	BTRY(ext_pack_push_uint16(pctx, r->count));
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_push_tagged_propval(pctx, &r->ppropval[i]));
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
	BTRY(ext_pack_push_uint16(pctx, r->count));
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_push_recipient_block(pctx, &r->pblock[i]));
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
	BTRY(ext_pack_push_advance(pctx, sizeof(uint16_t)));
	BTRY(ext_pack_push_uint8(pctx, r->type));
	BTRY(ext_pack_push_uint32(pctx, r->flavor));
	BTRY(ext_pack_push_uint32(pctx, r->flags));
	switch (r->type) {
	case OP_MOVE:
	case OP_COPY:
		BTRY(ext_pack_push_movecopy_action(pctx, static_cast<MOVECOPY_ACTION *>(r->pdata)));
		break;
	case OP_REPLY:
	case OP_OOF_REPLY:
		BTRY(ext_pack_push_reply_action(pctx, static_cast<REPLY_ACTION *>(r->pdata)));
		break;
	case OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - 2*sizeof(uint32_t);
		BTRY(ext_pack_push_bytes(pctx, r->pdata, tmp_len));
		break;
	case OP_BOUNCE:
		BTRY(ext_pack_push_uint32(pctx, *static_cast<uint32_t *>(r->pdata)));
		break;
	case OP_FORWARD:
	case OP_DELEGATE:
		BTRY(ext_pack_push_forwarddelegate_action(pctx, static_cast<FORWARDDELEGATE_ACTION *>(r->pdata)));
		break;
	case OP_TAG:
		BTRY(ext_pack_push_tagged_propval(pctx, static_cast<TAGGED_PROPVAL *>(r->pdata)));
	case OP_DELETE:
	case OP_MARK_AS_READ:
		break;
	default:
		return 0;
	}
	tmp_len = pctx->offset - (offset + sizeof(uint16_t));
	offset1 = pctx->offset;
	pctx->offset = offset;
	BTRY(ext_pack_push_uint16(pctx, tmp_len));
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
	BTRY(ext_pack_push_uint16(pctx, r->count));
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_push_action_block(pctx, &r->pblock[i]));
	}
	return 1;
}

static zend_bool ext_pack_push_propval(PUSH_CTX *pctx, uint16_t type,
    const void *pval)
{
	/* convert multi-value instance into single value */
	if ((type & MVI_FLAG) == MVI_FLAG)
		type &= ~MVI_FLAG;
	switch (type) {
	case PT_SHORT:
		return ext_pack_push_uint16(pctx, *(uint16_t*)pval);
	case PT_LONG:
	case PT_ERROR:
		return ext_pack_push_uint32(pctx, *(uint32_t*)pval);
	case PT_FLOAT:
		return ext_pack_push_float(pctx, *(float*)pval);
	case PT_DOUBLE:
	case PT_APPTIME:
		return ext_pack_push_double(pctx, *(double*)pval);
	case PT_BOOLEAN:
		return ext_pack_push_uint8(pctx, *(uint8_t*)pval);
	case PT_I8:
	case PT_SYSTIME:
		return ext_pack_push_uint64(pctx, *(uint64_t*)pval);
	case PT_STRING8:
	case PT_UNICODE:
		return ext_pack_push_string(pctx,
		       static_cast<const char *>(pval));
	case PT_CLSID:
		return ext_pack_push_guid(pctx,
		       static_cast<const GUID *>(pval));
	case PT_SRESTRICT:
		return ext_pack_push_restriction(pctx,
		       static_cast<const RESTRICTION *>(pval));
	case PT_ACTIONS:
		return ext_pack_push_rule_actions(pctx,
		       static_cast<const RULE_ACTIONS *>(pval));
	case PT_BINARY:
		return ext_pack_push_binary(pctx,
		       static_cast<const BINARY *>(pval));
	case PT_MV_SHORT:
		return ext_pack_push_short_array(pctx,
		       static_cast<const SHORT_ARRAY *>(pval));
	case PT_MV_LONG:
		return ext_pack_push_long_array(pctx,
		       static_cast<const LONG_ARRAY *>(pval));
	case PT_MV_I8:
		return ext_pack_push_longlong_array(pctx,
		       static_cast<const LONGLONG_ARRAY *>(pval));
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		return ext_pack_push_string_array(pctx,
		       static_cast<const STRING_ARRAY *>(pval));
	case PT_MV_CLSID:
		return ext_pack_push_guid_array(pctx,
		       static_cast<const GUID_ARRAY *>(pval));
	case PT_MV_BINARY:
		return ext_pack_push_binary_array(pctx,
		       static_cast<const BINARY_ARRAY *>(pval));
	default:
		return 0;
	}
}

zend_bool ext_pack_push_tagged_propval(
	PUSH_CTX *pctx, const TAGGED_PROPVAL *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->proptag));
	return ext_pack_push_propval(pctx, PROP_TYPE(r->proptag), r->pvalue);
}

zend_bool ext_pack_push_proptag_array(
	PUSH_CTX *pctx, const PROPTAG_ARRAY *r)
{
	int i;
	
	BTRY(ext_pack_push_uint16(pctx, r->count));
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_push_uint32(pctx, r->pproptag[i]));
	}
	return 1;
}

zend_bool ext_pack_push_property_name(
	PUSH_CTX *pctx, const PROPERTY_NAME *r)
{
	uint32_t offset;
	uint32_t offset1;
	uint8_t name_size;
	
	BTRY(ext_pack_push_uint8(pctx, r->kind));
	BTRY(ext_pack_push_guid(pctx, &r->guid));
	if (r->kind == MNID_ID) {
		BTRY(ext_pack_push_uint32(pctx, *r->plid));
	} else if (r->kind == MNID_STRING) {
		offset = pctx->offset;
		BTRY(ext_pack_push_advance(pctx, sizeof(uint8_t)));
		BTRY(ext_pack_push_string(pctx, r->pname));
		name_size = pctx->offset - (offset + sizeof(uint8_t));
		offset1 = pctx->offset;
		pctx->offset = offset;
		BTRY(ext_pack_push_uint8(pctx, name_size));
		pctx->offset = offset1;
	}
	return 1;
}

zend_bool ext_pack_push_propname_array(
	PUSH_CTX *pctx, const PROPNAME_ARRAY *r)
{
	int i;
	
	BTRY(ext_pack_push_uint16(pctx, r->count));
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_push_property_name(pctx, r->ppropname + i));
	}
	return 1;
}

zend_bool ext_pack_push_propid_array(
	PUSH_CTX *pctx, const PROPID_ARRAY *r)
{
	int i;
	
	BTRY(ext_pack_push_uint16(pctx, r->count));
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_push_uint16(pctx, r->ppropid[i]));
	}
	return 1;
}

zend_bool ext_pack_push_tpropval_array(
	PUSH_CTX *pctx, const TPROPVAL_ARRAY *r)
{
	int i;
	
	BTRY(ext_pack_push_uint16(pctx, r->count));
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_push_tagged_propval(pctx, r->ppropval + i));
	}
	return 1;
}

zend_bool ext_pack_push_tarray_set(PUSH_CTX *pctx, const TARRAY_SET *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->count));
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_push_tpropval_array(pctx, r->pparray[i]));
	return 1;
}

zend_bool ext_pack_push_sort_order(PUSH_CTX *pctx, const SORT_ORDER *r)
{
	if ((r->type & MVI_FLAG) == MV_FLAG)
		/* MV_FLAG set without MV_INSTANCE */
		return 0;
	BTRY(ext_pack_push_uint16(pctx, r->type));
	BTRY(ext_pack_push_uint16(pctx, r->propid));
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
	BTRY(ext_pack_push_uint16(pctx, r->count));
	BTRY(ext_pack_push_uint16(pctx, r->ccategories));
	BTRY(ext_pack_push_uint16(pctx, r->cexpanded));
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_push_sort_order(pctx, r->psort + i));
	}
	return 1;
}

static zend_bool ext_pack_push_permission_row(
	PUSH_CTX *pctx, const PERMISSION_ROW *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->flags));
	BTRY(ext_pack_push_binary(pctx, &r->entryid));
	return ext_pack_push_uint32(pctx, r->member_rights);
}

zend_bool ext_pack_push_permission_set(
	PUSH_CTX *pctx, const PERMISSION_SET *r)
{
	int i;
	
	BTRY(ext_pack_push_uint16(pctx, r->count));
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_push_permission_row(pctx, &r->prows[i]));
	}
	return 1;
}

zend_bool ext_pack_push_rule_data(
	PUSH_CTX *pctx, const RULE_DATA *r)
{
	BTRY(ext_pack_push_uint8(pctx, r->flags));
	return ext_pack_push_tpropval_array(pctx, &r->propvals);
}

zend_bool ext_pack_push_rule_list(
	PUSH_CTX *pctx, const RULE_LIST *r)
{
	int i;
	
	BTRY(ext_pack_push_uint16(pctx, r->count));
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_push_rule_data(pctx, &r->prule[i]));
	}
	return 1;
}

zend_bool ext_pack_push_oneoff_entryid(PUSH_CTX *pctx,
	const ONEOFF_ENTRYID *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->flags));
	BTRY(ext_pack_push_bytes(pctx, r->provider_uid, 16));
	BTRY(ext_pack_push_uint16(pctx, r->version));
	BTRY(ext_pack_push_uint16(pctx, r->ctrl_flags));
	if (r->ctrl_flags & CTRL_FLAG_UNICODE) {
		BTRY(ext_pack_push_wstring(pctx, r->pdisplay_name));
		BTRY(ext_pack_push_wstring(pctx, r->paddress_type));
		return ext_pack_push_wstring(pctx, r->pmail_address);
	} else {
		BTRY(ext_pack_push_string(pctx, r->pdisplay_name));
		BTRY(ext_pack_push_string(pctx, r->paddress_type));
		return ext_pack_push_string(pctx, r->pmail_address);
	}
}

static zend_bool ext_pack_push_message_state(
	PUSH_CTX *pctx, const MESSAGE_STATE *r)
{
	BTRY(ext_pack_push_binary(pctx, &r->source_key));
	return ext_pack_push_uint32(pctx, r->message_flags);
}

zend_bool ext_pack_push_state_array(
	PUSH_CTX *pctx, const STATE_ARRAY *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->count));
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_push_message_state(pctx, &r->pstate[i]));
	return 1;
}
