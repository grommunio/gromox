// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/mapidefs.h>
#include <gromox/propval.hpp>
#include <gromox/restriction.hpp>
#include <gromox/rule_actions.hpp>
#include <gromox/util.hpp>

using namespace gromox;

void *propval_dup(uint16_t type, const void *pvi)
{
	if (pvi == nullptr) {
		debug_info("[propval]: cannot duplicate NULL propval");
		return NULL;
	}
	switch (type) {
	case PT_UNSPECIFIED: {
		auto preturn = me_alloc<TYPED_PROPVAL>();
		auto psrc = static_cast<const TYPED_PROPVAL *>(pvi);
		if (preturn == nullptr)
			return NULL;
		preturn->type = psrc->type;
		preturn->pvalue = propval_dup(psrc->type, psrc->pvalue);
		if (preturn->pvalue == nullptr) {
			free(preturn);
			return NULL;
		}
		return preturn;
	}
	case PT_SHORT: {
		auto preturn = me_alloc<uint16_t>();
		if (preturn == nullptr)
			return NULL;
		*preturn = *static_cast<const uint16_t *>(pvi);
		return preturn;
	}
	case PT_ERROR:
	case PT_LONG: {
		auto preturn = me_alloc<uint32_t>();
		if (preturn == nullptr)
			return NULL;
		*preturn = *static_cast<const uint32_t *>(pvi);
		return preturn;
	}
	case PT_FLOAT: {
		auto preturn = me_alloc<float>();
		if (preturn == nullptr)
			return NULL;
		*preturn = *static_cast<const float *>(pvi);
		return preturn;
	}
	case PT_DOUBLE:
	case PT_APPTIME: {
		auto preturn = me_alloc<double>();
		if (preturn == nullptr)
			return NULL;
		*preturn = *static_cast<const double *>(pvi);
		return preturn;
	}
	case PT_BOOLEAN: {
		auto preturn = me_alloc<uint8_t>();
		if (preturn == nullptr)
			return NULL;
		*preturn = *static_cast<const uint8_t *>(pvi);
		return preturn;
	}
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME: {
		auto preturn = me_alloc<uint64_t>();
		if (preturn == nullptr)
			return NULL;
		*preturn = *static_cast<const uint64_t *>(pvi);
		return preturn;
	}
	case PT_STRING8:
	case PT_UNICODE:
		return strdup(static_cast<const char *>(pvi));
	case PT_CLSID: {
		auto preturn = me_alloc<GUID>();
		if (preturn == nullptr)
			return NULL;
		memcpy(preturn, pvi, sizeof(GUID));
		return preturn;
	}
	case PT_SVREID: {
		auto preturn = me_alloc<SVREID>();
		auto psrc = static_cast<const SVREID *>(pvi);
		if (preturn == nullptr)
			return NULL;
		if (psrc->pbin == nullptr) {
			memcpy(preturn, pvi, sizeof(SVREID));
			return preturn;
		}
		preturn->pbin = me_alloc<BINARY>();
		if (preturn->pbin == nullptr) {
			free(preturn);
			return NULL;
		}
		preturn->pbin->cb = psrc->pbin->cb;
		if (psrc->pbin->cb == 0) {
			preturn->pbin->pv = nullptr;
			return preturn;
		}
		preturn->pbin->pv = malloc(psrc->pbin->cb);
		if (preturn->pbin->pv == nullptr) {
			free(preturn->pbin);
			free(preturn);
			return NULL;
		}
		memcpy(preturn->pbin->pv, psrc->pbin->pv, psrc->pbin->cb);
		return preturn;
	}
	case PT_SRESTRICTION:
		return restriction_dup(static_cast<const RESTRICTION *>(pvi));
	case PT_ACTIONS:
		return rule_actions_dup(static_cast<const RULE_ACTIONS *>(pvi));
	case PT_BINARY:
	case PT_OBJECT: {
		auto preturn = me_alloc<BINARY>();
		auto psrc = static_cast<const BINARY *>(pvi);
		if (preturn == nullptr)
			return NULL;
		preturn->cb = psrc->cb;
		if (psrc->cb == 0) {
			preturn->pv = NULL;
			return preturn;
		}
		preturn->pv = malloc(psrc->cb);
		if (preturn->pv == nullptr) {
			free(preturn);
			return NULL;
		}
		memcpy(preturn->pv, psrc->pv, psrc->cb);
		return preturn;
	}
	case PT_MV_SHORT: {
		auto preturn = me_alloc<SHORT_ARRAY>();
		auto psrc = static_cast<const SHORT_ARRAY *>(pvi);
		if (preturn == nullptr)
			return NULL;
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->ps = nullptr;
			return preturn;
		}
		preturn->ps = me_alloc<uint16_t>(psrc->count);
		if (preturn->ps == nullptr) {
			free(preturn);
			return NULL;
		}
		memcpy(preturn->ps, psrc->ps, sizeof(uint16_t) * psrc->count);
		return preturn;
	}
	case PT_MV_LONG: {
		auto preturn = me_alloc<LONG_ARRAY>();
		auto psrc = static_cast<const LONG_ARRAY *>(pvi);
		if (preturn == nullptr)
			return NULL;
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->pl = NULL;
			return preturn;
		}
		preturn->pl = me_alloc<uint32_t>(psrc->count);
		if (preturn->pl == nullptr) {
			free(preturn);
			return NULL;
		}
		memcpy(preturn->pl, psrc->pl, sizeof(uint32_t) * psrc->count);
		return preturn;
	}
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME: {
		auto preturn = me_alloc<LONGLONG_ARRAY>();
		auto psrc = static_cast<const LONGLONG_ARRAY *>(pvi);
		if (preturn == nullptr)
			return NULL;
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->pll = nullptr;
			return preturn;
		}
		preturn->pll = me_alloc<uint64_t>(psrc->count);
		if (preturn->pll == nullptr) {
			free(preturn);
			return NULL;
		}
		memcpy(preturn->pll, psrc->pll, sizeof(uint64_t) * psrc->count);
		return preturn;
	}
	case PT_MV_FLOAT: {
		auto preturn = me_alloc<FLOAT_ARRAY>();
		auto psrc = static_cast<const FLOAT_ARRAY *>(pvi);
		if (preturn == nullptr)
			return NULL;
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->mval = nullptr;
			return preturn;
		}
		preturn->mval = me_alloc<float>(psrc->count);
		if (preturn->mval == nullptr) {
			free(preturn);
			return NULL;
		}
		memcpy(preturn->mval, psrc->mval, sizeof(float) * psrc->count);
		return preturn;
	}
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME: {
		auto preturn = me_alloc<DOUBLE_ARRAY>();
		auto psrc = static_cast<const DOUBLE_ARRAY *>(pvi);
		if (preturn == nullptr)
			return NULL;
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->mval = nullptr;
			return preturn;
		}
		preturn->mval = me_alloc<double>(psrc->count);
		if (preturn->mval == nullptr) {
			free(preturn);
			return NULL;
		}
		memcpy(preturn->mval, psrc->mval, sizeof(double) * psrc->count);
		return preturn;
	}
	case PT_MV_STRING8:
	case PT_MV_UNICODE: {
		auto preturn = me_alloc<STRING_ARRAY>();
		auto psrc = static_cast<const STRING_ARRAY *>(pvi);
		if (preturn == nullptr)
			return NULL;
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->ppstr = nullptr;
			return preturn;
		}
		preturn->ppstr = me_alloc<char *>(psrc->count);
		if (preturn->ppstr == nullptr) {
			free(preturn);
			return NULL;
		}
		for (size_t i = 0; i < psrc->count; ++i) {
			preturn->ppstr[i] = strdup(psrc->ppstr[i]);
			if (preturn->ppstr[i] != nullptr)
				continue;
			while (i-- > 0)
				free(preturn->ppstr[i]);
			free(preturn->ppstr);
			free(preturn);
			return NULL;
		}
		return preturn;
	}
	case PT_MV_CLSID: {
		auto preturn = me_alloc<GUID_ARRAY>();
		auto psrc = static_cast<const GUID_ARRAY *>(pvi);
		if (preturn == nullptr)
			return NULL;
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->pguid = nullptr;
			return preturn;
		}
		preturn->pguid = me_alloc<GUID>(psrc->count);
		if (preturn->pguid == nullptr) {
			free(preturn);
			return NULL;
		}
		memcpy(preturn->pguid, psrc->pguid, sizeof(GUID) * psrc->count);
		return preturn;
	}
	case PT_MV_BINARY: {
		auto preturn = me_alloc<BINARY_ARRAY>();
		auto psrc = static_cast<const BINARY_ARRAY *>(pvi);
		if (preturn == nullptr)
			return NULL;
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->pbin = nullptr;
			return preturn;
		}
		preturn->pbin = me_alloc<BINARY>(psrc->count);
		if (preturn->pbin == nullptr) {
			free(preturn);
			return NULL;
		}
		for (size_t i = 0; i < psrc->count; ++i) {
			preturn->pbin[i].cb = psrc->pbin[i].cb;
			if (psrc->pbin[i].cb == 0) {
				preturn->pbin[i].pb = NULL;
				continue;
			}
			preturn->pbin[i].pv = malloc(psrc->pbin[i].cb);
			if (preturn->pbin[i].pv == nullptr) {
				while (i > 0)
					free(preturn->pbin[--i].pv);
				free(preturn->pbin);
				free(preturn);
				return NULL;
			}
			memcpy(preturn->pbin[i].pv, psrc->pbin[i].pv, psrc->pbin[i].cb);
		}
		return preturn;
	}
	}
	return NULL;
}

void propval_free(uint16_t type, void *pvalue)
{
	if (NULL == pvalue) {
		debug_info("[propval] cannot free NULL propval");
		return;
	}
	switch (type) {
	case PT_UNSPECIFIED:
		propval_free(((TYPED_PROPVAL*)pvalue)->type,
					((TYPED_PROPVAL*)pvalue)->pvalue);
		break;
	case PT_SHORT:
	case PT_LONG:
	case PT_FLOAT:
	case PT_DOUBLE:
	case PT_CURRENCY:
	case PT_APPTIME:
	case PT_ERROR:
	case PT_BOOLEAN:
	case PT_I8:
	case PT_STRING8:
	case PT_UNICODE:
	case PT_SYSTIME:
	case PT_CLSID:
		break;
	case PT_SRESTRICTION:
		restriction_free(static_cast<RESTRICTION *>(pvalue));
		return;
	case PT_ACTIONS:
		rule_actions_free(static_cast<RULE_ACTIONS *>(pvalue));
		return;
	case PT_SVREID:
		if (NULL != ((SVREID*)pvalue)->pbin) {
			free(((SVREID*)pvalue)->pbin->pb);
			free(((SVREID*)pvalue)->pbin);
		}
		break;
	case PT_BINARY:
	case PT_OBJECT:
		free(static_cast<BINARY *>(pvalue)->pb);
		break;
	case PT_MV_SHORT:
		free(((SHORT_ARRAY*)pvalue)->ps);
		break;
	case PT_MV_LONG:
		free(((LONG_ARRAY*)pvalue)->pl);
		break;
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME:
		free(((LONGLONG_ARRAY*)pvalue)->pll);
		break;
	case PT_MV_FLOAT:
		free(static_cast<FLOAT_ARRAY *>(pvalue)->mval);
		break;
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME:
		free(static_cast<DOUBLE_ARRAY *>(pvalue)->mval);
		break;
	case PT_MV_STRING8:
	case PT_MV_UNICODE: {
		auto sa = static_cast<STRING_ARRAY *>(pvalue);
		for (size_t i = 0; i < sa->count; ++i)
			free(sa->ppstr[i]);
		free(sa->ppstr);
		break;
	}
	case PT_MV_CLSID:
		free(((GUID_ARRAY*)pvalue)->pguid);
		break;
	case PT_MV_BINARY: {
		auto ba = static_cast<BINARY_ARRAY *>(pvalue);
		for (size_t i = 0; i < ba->count; ++i)
			free(ba->pbin[i].pb);
		free(ba->pbin);
		break;
	}
	}
	free(pvalue);
}

/**
 * Returns the octet count for the UTF-16 representation of the string.
 */
static uint32_t propval_utf16_len(const char *putf8_string)
{
	size_t len;
	if (!utf16_count_codepoints(putf8_string, &len))
		return 0;
	return 2 * len;
}

uint32_t propval_size(uint16_t type, void *pvalue)
{
	uint32_t length;
	
	switch (type) {
	case PT_UNSPECIFIED:
		return propval_size(((TYPED_PROPVAL*)pvalue)->type,
						((TYPED_PROPVAL*)pvalue)->pvalue);
	case PT_SHORT:
		return sizeof(uint16_t);
	case PT_ERROR:
	case PT_LONG:
		return sizeof(uint32_t);
	case PT_FLOAT:
		return sizeof(float);
	case PT_DOUBLE:
	case PT_APPTIME:
		return sizeof(double);
	case PT_BOOLEAN:
		return sizeof(uint8_t);
	case PT_OBJECT:
	case PT_BINARY:
		return static_cast<BINARY *>(pvalue)->cb;
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		return sizeof(uint64_t);
	case PT_STRING8:
		return strlen(static_cast<char *>(pvalue)) + 1;
	case PT_UNICODE:
		return propval_utf16_len(static_cast<char *>(pvalue));
	case PT_CLSID:
		return 16;
	case PT_SVREID:
		if (static_cast<SVREID *>(pvalue)->pbin != nullptr)
			return ((SVREID*)pvalue)->pbin->cb + 1;
		return 21;
	case PT_SRESTRICTION:
		return restriction_size(static_cast<RESTRICTION *>(pvalue));
	case PT_ACTIONS:
		return rule_actions_size(static_cast<RULE_ACTIONS *>(pvalue));
	case PT_MV_SHORT:
		return sizeof(uint16_t)*((SHORT_ARRAY*)pvalue)->count;
	case PT_MV_LONG:
		return sizeof(uint32_t)*((LONG_ARRAY*)pvalue)->count;
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME:
		return sizeof(uint64_t)*((LONGLONG_ARRAY*)pvalue)->count;
	case PT_MV_FLOAT:
		return sizeof(float) * static_cast<FLOAT_ARRAY *>(pvalue)->count;
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME:
		return sizeof(double) * static_cast<DOUBLE_ARRAY *>(pvalue)->count;
	case PT_MV_STRING8: {
		length = 0;
		auto sa = static_cast<STRING_ARRAY *>(pvalue);
		for (size_t i = 0; i < sa->count; ++i)
			length += strlen(sa->ppstr[i]) + 1;
		return length;
	}
	case PT_MV_UNICODE: {
		length = 0;
		auto sa = static_cast<STRING_ARRAY *>(pvalue);
		for (size_t i = 0; i < sa->count; ++i)
			length += propval_utf16_len(sa->ppstr[i]);
		return length;
	}
	case PT_MV_CLSID:
		return 16*((GUID_ARRAY*)pvalue)->count;
	case PT_MV_BINARY: {
		length = 0;
		auto ba = static_cast<BINARY_ARRAY *>(pvalue);
		for (size_t i = 0; i < ba->count; ++i)
			length += ba->pbin[i].cb;
		return length;
	}
	}
	return 0;
}

int BINARY::compare(const BINARY &o) const
{
	/*
	 * The sorting by length could be explained by BINARY's encoding on the wire
	 * (length prefixes the byte block). It could also just be convention.
	 */
	if (cb < o.cb)
		return -1;
	if (cb > o.cb)
		return 1;
	return memcmp(pv, o.pv, cb);
}

int SVREID::compare(const SVREID &o) const
{
	/*
	 * This performs a FLATUID/bytewise comparison similar to BINARY properties.
	 * Still need to validate if Exchange actually does the same.
	 */
	uint16_t len = cpu_to_le16(pbin != nullptr ? pbin->cb + 1 : 21);
	uint16_t o_len = cpu_to_le16(o.pbin != nullptr ? o.pbin->cb + 1 : 21);
	uint8_t flag = pbin == nullptr;
	uint8_t o_flag = o.pbin == nullptr;
	auto ret = memcmp(&len, &o_len, sizeof(uint16_t));
	if (ret != 0)
		return ret;
	ret = memcmp(&flag, &o_flag, sizeof(uint8_t));
	if (ret != 0)
		return ret;
	uint8_t buf[20], o_buf[20];
	BINARY bin{20, buf}, o_bin{20, o_buf};
	if (flag) {
		cpu_to_le64p(&buf[0], folder_id);
		cpu_to_le64p(&buf[8], message_id);
		cpu_to_le32p(&buf[16], instance);
	}
	if (o_flag) {
		cpu_to_le64p(&o_buf[0], o.folder_id);
		cpu_to_le64p(&o_buf[8], o.message_id);
		cpu_to_le32p(&o_buf[16], o.instance);
	}
	if (flag)
		return bin.compare(o_flag ? o_bin : *o.pbin);
	else
		return pbin->compare(o_flag ? o_bin : *o.pbin);
}

int SVREID_compare(const SVREID *a, const SVREID *b)
{
	if (a == nullptr)
		return b == nullptr ? 0 : -1;
	if (b == nullptr)
		return 1;
	return a->compare(*b);
}

bool propval_compare_relop(enum relop relop, uint16_t proptype,
    const void *pvalue1, const void *pvalue2)
{
#define MVCOMPARE(field) do { \
		cmp = three_way_compare(a->count, b->count); \
		if (cmp == 0) \
			cmp = memcmp(a->field, b->field, sizeof(a->field[0]) * a->count); \
	} while (false)

	int cmp = -2;
	switch (relop) {
	case RELOP_LT:
	case RELOP_LE:
	case RELOP_GT:
	case RELOP_GE:
	case RELOP_EQ:
	case RELOP_NE:
		break;
	default: /* RE, DL - not implemented */
		return false;
	}
	switch (proptype) {
	case PT_SHORT:
		cmp = three_way_compare(*static_cast<const uint16_t *>(pvalue1),
		      *static_cast<const uint16_t *>(pvalue2));
		break;
	case PT_LONG:
	case PT_ERROR:
		cmp = three_way_compare(*static_cast<const uint32_t *>(pvalue1),
		      *static_cast<const uint32_t *>(pvalue2));
		break;
	case PT_BOOLEAN:
		cmp = three_way_compare(*static_cast<const uint8_t *>(pvalue1),
		      *static_cast<const uint8_t *>(pvalue2));
		break;
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		cmp = three_way_compare(*static_cast<const uint64_t *>(pvalue1),
		      *static_cast<const uint64_t *>(pvalue2));
		break;
	case PT_FLOAT:
		cmp = three_way_compare(*static_cast<const float *>(pvalue1),
		      *static_cast<const float *>(pvalue2));
		break;
	case PT_DOUBLE:
	case PT_APPTIME:
		cmp = three_way_compare(*static_cast<const double *>(pvalue1),
		      *static_cast<const double *>(pvalue2));
		break;
	case PT_STRING8:
	case PT_UNICODE:
		cmp = strcasecmp(static_cast<const char *>(pvalue1),
		      static_cast<const char *>(pvalue2));
		break;
	case PT_CLSID:
		cmp = static_cast<const GUID *>(pvalue1)->compare(*static_cast<const GUID *>(pvalue2));
		break;
	case PT_BINARY:
		cmp = static_cast<const BINARY *>(pvalue1)->compare(*static_cast<const BINARY *>(pvalue2));
		break;
	case PT_SVREID:
		cmp = static_cast<const SVREID *>(pvalue1)->compare(*static_cast<const SVREID *>(pvalue2));
		break;
	case PT_MV_SHORT: {
		auto a = static_cast<const SHORT_ARRAY *>(pvalue1);
		auto b = static_cast<const SHORT_ARRAY *>(pvalue2);
		MVCOMPARE(ps);
		break;
	}
	case PT_MV_LONG: {
		auto a = static_cast<const LONG_ARRAY *>(pvalue1);
		auto b = static_cast<const LONG_ARRAY *>(pvalue2);
		MVCOMPARE(pl);
		break;
	}
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME: {
		auto a = static_cast<const LONGLONG_ARRAY *>(pvalue1);
		auto b = static_cast<const LONGLONG_ARRAY *>(pvalue2);
		MVCOMPARE(pll);
		break;
	}
	case PT_MV_FLOAT: {
		auto a = static_cast<const FLOAT_ARRAY *>(pvalue1);
		auto b = static_cast<const FLOAT_ARRAY *>(pvalue2);
		MVCOMPARE(mval);
		break;
	}
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME: {
		auto a = static_cast<const DOUBLE_ARRAY *>(pvalue1);
		auto b = static_cast<const DOUBLE_ARRAY *>(pvalue2);
		MVCOMPARE(mval);
		break;
	}
	case PT_MV_STRING8:
	case PT_MV_UNICODE: {
		auto sa1 = static_cast<const STRING_ARRAY *>(pvalue1);
		auto sa2 = static_cast<const STRING_ARRAY *>(pvalue2);
		cmp = three_way_compare(sa1->count, sa2->count);
		if (cmp != 0)
			break;
		for (size_t i = 0; i < sa1->count; ++i) {
			cmp = strcasecmp(sa1->ppstr[i], sa2->ppstr[i]);
			if (cmp != 0)
				break;
		}
		break;
	}
	case PT_MV_CLSID: {
		auto bv1 = static_cast<const GUID_ARRAY *>(pvalue1);
		auto bv2 = static_cast<const GUID_ARRAY *>(pvalue2);
		cmp = three_way_compare(bv1->count, bv2->count);
		if (cmp != 0)
			break;
		for (size_t i = 0; i < bv1->count; ++i) {
			cmp = bv1->pguid[i].compare(bv2->pguid[i]);
			if (cmp != 0)
				break;
		}
		break;
	}
	case PT_MV_BINARY: {
		auto bv1 = static_cast<const BINARY_ARRAY *>(pvalue1);
		auto bv2 = static_cast<const BINARY_ARRAY *>(pvalue2);
		cmp = three_way_compare(bv1->count, bv2->count);
		if (cmp != 0)
			break;
		for (size_t i = 0; i < bv1->count; ++i) {
			cmp = bv1->pbin[i].compare(bv2->pbin[i]);
			if (cmp != 0)
				break;
		}
		break;
	}
	}
	return three_way_evaluate(cmp, relop);
#undef MVCOMPARE
}

namespace gromox {

bool propval_compare_relop_nullok(enum relop relop, uint16_t proptype,
    const void *a, const void *b)
{
	/*
	 * EXC2019-compatible behavior: absent values sort before anything
	 * else, and compare equal to another absent property.
	 */
	if (a == nullptr)
		return three_way_evaluate(b == nullptr ? 0 : -1, relop);
	return b == nullptr ? three_way_evaluate(1, relop) :
	       propval_compare_relop(relop, proptype, a, b);
}

bool three_way_evaluate(int order, enum relop r)
{
	switch (r) {
	case RELOP_LT: return order < 0;
	case RELOP_LE: return order <= 0;
	case RELOP_GT: return order > 0;
	case RELOP_GE: return order >= 0;
	case RELOP_EQ: return order == 0;
	case RELOP_NE: return order != 0;
	default: return false;
	}
}

}
