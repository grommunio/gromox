// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2025 grommunio GmbH
// This file is part of Gromox.
#include <cmath>
#include <compare>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <libHX/endian.h>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/propval.hpp>
#include <gromox/restriction.hpp>
#include <gromox/rule_actions.hpp>
#include <gromox/util.hpp>

using namespace gromox;

void *propval_dup(uint16_t type, const void *pvi)
{
	if (pvi == nullptr) {
		mlog(LV_DEBUG, "propval: cannot duplicate NULL propval");
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
	case PT_GXI_STRING:
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
		return static_cast<const SRestriction *>(pvi)->dup();
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
		if (psrc->cb > 0 && preturn->pv == nullptr) {
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
		mlog(LV_DEBUG, "propval: cannot free NULL propval");
		return;
	}
	switch (type) {
	case PT_UNSPECIFIED: {
		auto &tp = *static_cast<TYPED_PROPVAL *>(pvalue);
		propval_free(tp.type, tp.pvalue);
		break;
	}
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
	case PT_GXI_STRING:
	case PT_SYSTIME:
	case PT_CLSID:
		break;
	case PT_SRESTRICTION:
		restriction_free(static_cast<RESTRICTION *>(pvalue));
		return;
	case PT_ACTIONS:
		rule_actions_free(static_cast<RULE_ACTIONS *>(pvalue));
		return;
	case PT_SVREID: {
		auto &e = *static_cast<SVREID *>(pvalue);
		if (e.pbin == nullptr)
			break;
		free(e.pbin->pb);
		free(e.pbin);
		break;
	}
	case PT_BINARY:
	case PT_OBJECT:
		free(static_cast<BINARY *>(pvalue)->pb);
		break;
	case PT_MV_SHORT:
		free(static_cast<SHORT_ARRAY *>(pvalue)->ps);
		break;
	case PT_MV_LONG:
		free(static_cast<LONG_ARRAY *>(pvalue)->pl);
		break;
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME:
		free(static_cast<LONGLONG_ARRAY *>(pvalue)->pll);
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
		free(static_cast<GUID_ARRAY *>(pvalue)->pguid);
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

uint32_t propval_size(uint16_t type, const void *pvalue)
{
	uint32_t length;
	
	switch (type) {
	case PT_UNSPECIFIED: {
		auto &tp = *static_cast<const TYPED_PROPVAL *>(pvalue);
		return propval_size(tp.type, tp.pvalue);
	}
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
		return static_cast<const BINARY *>(pvalue)->cb;
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		return sizeof(uint64_t);
	case PT_STRING8:
	case PT_UNICODE:
	case PT_GXI_STRING:
		return strlen(static_cast<const char *>(pvalue));
	case PT_CLSID:
		return 16;
	case PT_SVREID: {
		auto &e = *static_cast<const SVREID *>(pvalue);
		return e.pbin != nullptr ? e.pbin->cb + 1 : 21;
	}
	case PT_SRESTRICTION:
		return restriction_size(static_cast<const RESTRICTION *>(pvalue));
	case PT_ACTIONS:
		return rule_actions_size(static_cast<const RULE_ACTIONS *>(pvalue));
	case PT_MV_SHORT:
		return sizeof(uint16_t) * static_cast<const SHORT_ARRAY *>(pvalue)->count;
	case PT_MV_LONG:
		return sizeof(uint32_t) * static_cast<const LONG_ARRAY *>(pvalue)->count;
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME:
		return sizeof(uint64_t) * static_cast<const LONGLONG_ARRAY *>(pvalue)->count;
	case PT_MV_FLOAT:
		return sizeof(float) * static_cast<const FLOAT_ARRAY *>(pvalue)->count;
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME:
		return sizeof(double) * static_cast<const DOUBLE_ARRAY *>(pvalue)->count;
	case PT_MV_STRING8:
	case PT_MV_UNICODE: {
		length = 0;
		auto sa = static_cast<const STRING_ARRAY *>(pvalue);
		for (size_t i = 0; i < sa->count; ++i)
			length += strlen(sa->ppstr[i]);
		return length;
	}
	case PT_MV_CLSID:
		return 16 * static_cast<const GUID_ARRAY *>(pvalue)->count;
	case PT_MV_BINARY: {
		length = 0;
		auto ba = static_cast<const BINARY_ARRAY *>(pvalue);
		for (size_t i = 0; i < ba->count; ++i)
			length += ba->pbin[i].cb;
		return length;
	}
	}
	return 0;
}

std::strong_ordering BINARY::operator<=>(const BINARY &o) const
{
	/*
	 * The sorting by length could be explained by BINARY's encoding on the wire
	 * (length prefixes the byte block). It could also just be convention.
	 * Either way, this is what EXC2019 does.
	 */
	if (cb == o.cb)
		return memcmp(pv, o.pv, cb) <=> 0;
	return cb < o.cb ? std::strong_ordering::less : std::strong_ordering::greater;
}

std::strong_ordering SVREID::operator<=>(const SVREID &o) const
{
	/*
	 * This performs a FLATUID/bytewise comparison similar to BINARY properties.
	 * Still need to validate if Exchange actually does the same.
	 */
	uint16_t len = cpu_to_le16(pbin != nullptr ? pbin->cb + 1 : 21);
	uint16_t o_len = cpu_to_le16(o.pbin != nullptr ? o.pbin->cb + 1 : 21);
	uint8_t flag = pbin == nullptr;
	uint8_t o_flag = o.pbin == nullptr;
	auto ret = memcmp(&len, &o_len, sizeof(uint16_t)) <=> 0;
	if (ret != 0)
		return ret;
	ret = memcmp(&flag, &o_flag, sizeof(uint8_t)) <=> 0;
	if (ret != 0)
		return ret;
	uint8_t buf[20], o_buf[20];
	BINARY bin{20, {buf}}, o_bin{20, {o_buf}};
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
	return (flag ? bin : *pbin) <=> (o_flag ? o_bin : *o.pbin);
}

std::strong_ordering SVREID_compare(const SVREID *a, const SVREID *b)
{
	if (a == nullptr)
		return b == nullptr ? std::strong_ordering::equal : std::strong_ordering::less;
	if (b == nullptr)
		return std::strong_ordering::greater;
	return *a <=> *b;
}

template<typename T> static std::strong_ordering fpcompare(T x, T y)
{
	auto z = x <=> y;
	if (z == std::partial_ordering::equivalent)
		return std::strong_ordering::equivalent;
	else if (z == std::partial_ordering::less)
		return std::strong_ordering::less;
	else if (z == std::partial_ordering::greater)
		return std::strong_ordering::greater;
	else if (std::isnan(x))
		/* Mimic what EXC2019 seems to be doing (similar to nullptr handling) */
		return std::isnan(y) ? std::strong_ordering::equivalent : std::strong_ordering::less;
	else
		return std::isnan(y) ? std::strong_ordering::greater : std::strong_ordering::equivalent;
}

/**
 * This supports only comparisons between same-typed values.
 *
 * However, for RELOP_EQ and RELOP_NE, comparisons between PT_MV_x
 * and PT_x should be added [GXL-361].
 */
std::strong_ordering propval_compare(const void *pvalue1, const void *pvalue2,
    proptype_t proptype)
{
#define MVCOMPARE2(field, retype) do { \
		cmp = a->count <=> b->count; \
		if (cmp != 0) \
			break; \
		for (size_t jj = 0; jj < a->count; ++jj) { \
			cmp = static_cast<retype>((a->field)[jj]) <=> \
			      static_cast<retype>((b->field)[jj]); \
			if (cmp != 0) \
				break; \
		} \
	} while (false)

	auto cmp = std::strong_ordering::equivalent;
	switch (proptype) {
	case PT_SHORT:
		return *static_cast<const uint16_t *>(pvalue1) <=>
		       *static_cast<const uint16_t *>(pvalue2);
	case PT_LONG:
	case PT_ERROR:
		return *static_cast<const uint32_t *>(pvalue1) <=>
		       *static_cast<const uint32_t *>(pvalue2);
	case PT_BOOLEAN:
		return !!*static_cast<const uint8_t *>(pvalue1) <=>
		       !!*static_cast<const uint8_t *>(pvalue2);
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		return *static_cast<const uint64_t *>(pvalue1) <=>
		       *static_cast<const uint64_t *>(pvalue2);
	case PT_FLOAT:
		return fpcompare(*static_cast<const float *>(pvalue1),
		       *static_cast<const float *>(pvalue2));
	case PT_DOUBLE:
	case PT_APPTIME:
		return fpcompare(*static_cast<const double *>(pvalue1),
		       *static_cast<const double *>(pvalue2));
	case PT_STRING8:
	case PT_UNICODE:
	case PT_GXI_STRING:
		return strcasecmp(static_cast<const char *>(pvalue1),
		       static_cast<const char *>(pvalue2)) <=> 0;
	case PT_CLSID:
		return *static_cast<const GUID *>(pvalue1) <=>
		       *static_cast<const GUID *>(pvalue2);
	case PT_BINARY:
		return *static_cast<const BINARY *>(pvalue1) <=>
		       *static_cast<const BINARY *>(pvalue2);
	case PT_SVREID:
		return *static_cast<const SVREID *>(pvalue1) <=>
		       *static_cast<const SVREID *>(pvalue2);
	case PT_MV_SHORT: {
		auto a = static_cast<const SHORT_ARRAY *>(pvalue1);
		auto b = static_cast<const SHORT_ARRAY *>(pvalue2);
		MVCOMPARE2(ps, int16_t);
		break;
	}
	case PT_MV_LONG: {
		auto a = static_cast<const LONG_ARRAY *>(pvalue1);
		auto b = static_cast<const LONG_ARRAY *>(pvalue2);
		MVCOMPARE2(pl, int32_t);
		break;
	}
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME: {
		auto a = static_cast<const LONGLONG_ARRAY *>(pvalue1);
		auto b = static_cast<const LONGLONG_ARRAY *>(pvalue2);
		MVCOMPARE2(pll, int64_t);
		break;
	}
	case PT_MV_FLOAT: {
		auto a = static_cast<const FLOAT_ARRAY *>(pvalue1);
		auto b = static_cast<const FLOAT_ARRAY *>(pvalue2);
		cmp = a->count <=> b->count;
		if (cmp != 0)
			break;
		for (size_t i = 0; i < a->count; ++i) {
			cmp = fpcompare(a->mval[i], b->mval[i]);
			if (cmp != 0)
				break;
		}
		break;
	}
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME: {
		auto a = static_cast<const DOUBLE_ARRAY *>(pvalue1);
		auto b = static_cast<const DOUBLE_ARRAY *>(pvalue2);
		cmp = a->count <=> b->count;
		if (cmp != 0)
			break;
		for (size_t i = 0; i < a->count; ++i) {
			cmp = fpcompare(a->mval[i], b->mval[i]);
			if (cmp != 0)
				break;
		}
		break;
	}
	case PT_MV_STRING8:
	case PT_MV_UNICODE: {
		auto sa1 = static_cast<const STRING_ARRAY *>(pvalue1);
		auto sa2 = static_cast<const STRING_ARRAY *>(pvalue2);
		cmp = sa1->count <=> sa2->count;
		if (cmp != 0)
			break;
		for (size_t i = 0; i < sa1->count; ++i) {
			cmp = strcasecmp(sa1->ppstr[i], sa2->ppstr[i]) <=> 0;
			if (cmp != 0)
				break;
		}
		break;
	}
	case PT_MV_CLSID: {
		auto bv1 = static_cast<const GUID_ARRAY *>(pvalue1);
		auto bv2 = static_cast<const GUID_ARRAY *>(pvalue2);
		cmp = bv1->count <=> bv2->count;
		if (cmp != 0)
			break;
		for (size_t i = 0; i < bv1->count; ++i) {
			cmp = bv1->pguid[i] <=> bv2->pguid[i];
			if (cmp != 0)
				break;
		}
		break;
	}
	case PT_MV_BINARY: {
		auto bv1 = static_cast<const BINARY_ARRAY *>(pvalue1);
		auto bv2 = static_cast<const BINARY_ARRAY *>(pvalue2);
		cmp = bv1->count <=> bv2->count;
		if (cmp != 0)
			break;
		for (size_t i = 0; i < bv1->count; ++i) {
			cmp = bv1->pbin[i] <=> bv2->pbin[i];
			if (cmp != 0)
				break;
		}
		break;
	}
	}
	return cmp;
#undef MVCOMPARE2
}

bool propval_compare_relop(enum relop relop, proptype_t proptype,
    const void *pvalue1, const void *pvalue2)
{
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
	return three_way_eval(relop, propval_compare(pvalue1, pvalue2, proptype));
}

namespace gromox {

bool propval_compare_relop_nullok(enum relop relop, proptype_t proptype,
    const void *a, const void *b)
{
	/*
	 * EXC2019-compatible behavior: absent values sort before anything
	 * else, and compare equal to another absent property.
	 * (See also: db_engine_compare_propval)
	 */
	if (a == nullptr)
		return three_way_eval(relop, b == nullptr ?
		       std::strong_ordering::equal : std::strong_ordering::less);
	return b == nullptr ? three_way_eval(relop, std::strong_ordering::greater) :
	       propval_compare_relop(relop, proptype, a, b);
}

bool three_way_eval(relop r, std::strong_ordering order)
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
