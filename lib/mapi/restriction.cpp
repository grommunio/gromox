// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <string>
#include <utility>
#include <gromox/mapidefs.h>
#include <gromox/propval.hpp>
#include <gromox/restriction.hpp>

using namespace gromox;

static void *restriction_dup_by_type(mapi_rtype, const void *rst);
static void restriction_free_by_type(mapi_rtype, void *rst);

restriction_list *restriction_list::dup() const
{
	auto n = me_alloc<RESTRICTION_AND_OR>();
	if (n == nullptr)
		return NULL;
	auto prestriction = this;
	n->count = prestriction->count;
	n->pres = me_alloc<RESTRICTION>(n->count);
	if (n->pres == nullptr) {
		free(n);
		return NULL;
	}
	for (size_t i = 0; i < prestriction->count; ++i) {
		n->pres[i].rt = prestriction->pres[i].rt;
		n->pres[i].pres = restriction_dup_by_type(
			prestriction->pres[i].rt, prestriction->pres[i].pres);
		if (n->pres[i].pres == nullptr) {
			while (i-- > 0)
				restriction_free_by_type(n->pres[i].rt, n->pres[i].pres);
			free(n->pres);
			free(n);
			return NULL;
		}
	}
	return n;
}

static void restriction_free_and_or(RESTRICTION_AND_OR *prestriction)
{
	for (size_t i = 0; i < prestriction->count; ++i)
		restriction_free_by_type(prestriction->pres[i].rt,
								prestriction->pres[i].pres);
	if (prestriction->pres != nullptr)
		free(prestriction->pres);
	free(prestriction);
}

SNotRestriction *SNotRestriction::dup() const
{
	auto pres = me_alloc<RESTRICTION_NOT>();
	if (pres == nullptr)
		return NULL;
	auto prestriction = this;
	pres->res.rt = prestriction->res.rt;
	pres->res.pres = restriction_dup_by_type(
		prestriction->res.rt, prestriction->res.pres);
	if (NULL == pres->res.pres) {
		free(pres);
		return NULL;
	}
	return pres;
}

static void restriction_free_not(
	RESTRICTION_NOT *prestriction)
{
	restriction_free_by_type(prestriction->res.rt, prestriction->res.pres);
	free(prestriction);
}

SContentRestriction *SContentRestriction::dup() const
{
	auto pres = me_alloc<RESTRICTION_CONTENT>();
	if (pres == nullptr)
		return NULL;
	auto prestriction = this;
	pres->fuzzy_level = prestriction->fuzzy_level;
	pres->proptag = prestriction->proptag;
	pres->propval.proptag = prestriction->propval.proptag;
	pres->propval.pvalue = propval_dup(PROP_TYPE(prestriction->propval.proptag),
						prestriction->propval.pvalue);
	if (NULL == pres->propval.pvalue) {
		free(pres);
		return NULL;
	}
	return pres;
}

static void restriction_free_content(RESTRICTION_CONTENT *prestriction)
{
	propval_free(PROP_TYPE(prestriction->propval.proptag), prestriction->propval.pvalue);
	free(prestriction);
}

SPropertyRestriction *SPropertyRestriction::dup() const
{
	auto pres = me_alloc<RESTRICTION_PROPERTY>();
	if (pres == nullptr)
		return NULL;
	auto prestriction = this;
	pres->relop = prestriction->relop;
	pres->proptag = prestriction->proptag;
	pres->propval.proptag = prestriction->propval.proptag;
	pres->propval.pvalue = propval_dup(PROP_TYPE(prestriction->propval.proptag),
						prestriction->propval.pvalue);
	if (NULL == pres->propval.pvalue) {
		free(pres);
		return NULL;
	}
	return pres;
}

static void restriction_free_property(
	RESTRICTION_PROPERTY *prestriction)
{
	propval_free(PROP_TYPE(prestriction->propval.proptag),
		prestriction->propval.pvalue);
	free(prestriction);
}

SComparePropsRestriction *SComparePropsRestriction::dup() const
{
	auto pres = me_alloc<RESTRICTION_PROPCOMPARE>();
	if (pres == nullptr)
		return NULL;
	auto prestriction = this;
	pres->relop = prestriction->relop;
	pres->proptag1 = prestriction->proptag1;
	pres->proptag2 = prestriction->proptag2;
	return pres;
}

static void restriction_free_propcompare(
	RESTRICTION_PROPCOMPARE *prestriction)
{
	free(prestriction);
}

SBitMaskRestriction *SBitMaskRestriction::dup() const
{
	auto pres = me_alloc<RESTRICTION_BITMASK>();
	if (pres == nullptr)
		return NULL;
	auto prestriction = this;
	pres->bitmask_relop = prestriction->bitmask_relop;
	pres->proptag = prestriction->proptag;
	pres->mask = prestriction->mask;
	return pres;
}

static void restriction_free_bitmask(
	RESTRICTION_BITMASK *prestriction)
{
	free(prestriction);
}

SSizeRestriction *SSizeRestriction::dup() const
{
	auto pres = me_alloc<RESTRICTION_SIZE>();
	if (pres == nullptr)
		return NULL;
	auto prestriction = this;
	pres->relop = prestriction->relop;
	pres->proptag = prestriction->proptag;
	pres->size = prestriction->size;
	return pres;
}

static void restriction_free_size(
	RESTRICTION_SIZE *prestriction)
{
	free(prestriction);
}

SExistRestriction *SExistRestriction::dup() const
{
	auto pres = me_alloc<RESTRICTION_EXIST>();
	if (pres == nullptr)
		return NULL;
	auto prestriction = this;
	pres->proptag = prestriction->proptag;
	return pres;
}

static void restriction_free_exist(RESTRICTION_EXIST *prestriction)
{
	free(prestriction);
}

SSubRestriction *SSubRestriction::dup() const
{
	auto pres = me_alloc<RESTRICTION_SUBOBJ>();
	if (pres == nullptr)
		return NULL;
	auto prestriction = this;
	pres->subobject = prestriction->subobject;
	pres->res.rt = prestriction->res.rt;
	pres->res.pres = restriction_dup_by_type(
		prestriction->res.rt, prestriction->res.pres);
	if (NULL == pres->res.pres) {
		free(pres);
		return NULL;
	}
	return pres;
}

static void restriction_free_subobj(
	RESTRICTION_SUBOBJ *prestriction)
{
	restriction_free_by_type(prestriction->res.rt, prestriction->res.pres);
	free(prestriction);
}

SCommentRestriction *SCommentRestriction::dup() const
{
	int i;
	auto n = me_alloc<RESTRICTION_COMMENT>();
	if (n == nullptr)
		return NULL;
	auto prestriction = this;
	n->count = prestriction->count;
	n->ppropval = me_alloc<TAGGED_PROPVAL>(n->count);
	if (n->ppropval == nullptr) {
		free(n);
		return NULL;
	}
	for (i=0; i<prestriction->count; i++) {
		n->ppropval[i].proptag = prestriction->ppropval[i].proptag;
		n->ppropval[i].pvalue = propval_dup(PROP_TYPE(prestriction->ppropval[i].proptag),
				prestriction->ppropval[i].pvalue);
		if (n->ppropval[i].pvalue == nullptr) {
			for (i -= 1; i >= 0; i--)
				propval_free(PROP_TYPE(n->ppropval[i].proptag), n->ppropval[i].pvalue);
			free(n->ppropval);
			free(n);
			return NULL;
		}
	}
	if (NULL != prestriction->pres) {
		n->pres = prestriction->pres->dup();
		if (n->pres == nullptr) {
			for (i = 0; i < n->count; ++i)
				propval_free(PROP_TYPE(n->ppropval[i].proptag), n->ppropval[i].pvalue);
			free(n->ppropval);
			free(n);
			return NULL;
		}
	} else {
		n->pres = NULL;
	}
	return n;
}

static void restriction_free_comment(
	RESTRICTION_COMMENT *prestriction)
{
	for (unsigned int i = 0 ; i < prestriction->count; ++i)
		propval_free(PROP_TYPE(prestriction->ppropval[i].proptag),
							prestriction->ppropval[i].pvalue);
	free(prestriction->ppropval);
	if (prestriction->pres != nullptr)
		restriction_free(prestriction->pres);
	free(prestriction);
}

SCountRestriction *SCountRestriction::dup() const
{
	auto pres = me_alloc<RESTRICTION_COUNT>();
	if (pres == nullptr)
		return NULL;
	auto prestriction = this;
	pres->count = prestriction->count;
	pres->sub_res.rt = prestriction->sub_res.rt;
	pres->sub_res.pres = restriction_dup_by_type(
		prestriction->sub_res.rt, prestriction->sub_res.pres);
	if (NULL == pres->sub_res.pres) {
		free(pres);
		return NULL;
	}
	return pres;
}

static void restriction_free_count(RESTRICTION_COUNT *prestriction)
{
	restriction_free_by_type(prestriction->sub_res.rt, prestriction->sub_res.pres);
	free(prestriction);
}

static void *restriction_dup_by_type(mapi_rtype rt, const void *prestriction)
{
	switch (rt) {
	case RES_AND:
	case RES_OR:
		return static_cast<const restriction_list *>(prestriction)->dup();
	case RES_NOT:
		return static_cast<const SNotRestriction *>(prestriction)->dup();
	case RES_CONTENT:
		return static_cast<const SContentRestriction *>(prestriction)->dup();
	case RES_PROPERTY:
		return static_cast<const SPropertyRestriction *>(prestriction)->dup();
	case RES_PROPCOMPARE:
		return static_cast<const SComparePropsRestriction *>(prestriction)->dup();
	case RES_BITMASK:
		return static_cast<const SBitMaskRestriction *>(prestriction)->dup();
	case RES_SIZE:
		return static_cast<const SSizeRestriction *>(prestriction)->dup();
	case RES_EXIST:
		return static_cast<const SExistRestriction *>(prestriction)->dup();
	case RES_SUBRESTRICTION:
		return static_cast<const SSubRestriction *>(prestriction)->dup();
	case RES_COMMENT:
	case RES_ANNOTATION:
		return static_cast<const SCommentRestriction *>(prestriction)->dup();
	case RES_COUNT:
		return static_cast<const SCountRestriction *>(prestriction)->dup();
	default:
		return NULL;
	}
	return nullptr;
}

static void restriction_free_by_type(mapi_rtype rt, void *prestriction)
{
	switch (rt) {
	case RES_AND:
	case RES_OR:
		return restriction_free_and_or(static_cast<RESTRICTION_AND_OR *>(prestriction));
	case RES_NOT:
		return restriction_free_not(static_cast<RESTRICTION_NOT *>(prestriction));
	case RES_CONTENT:
		return restriction_free_content(static_cast<RESTRICTION_CONTENT *>(prestriction));
	case RES_PROPERTY:
		return restriction_free_property(static_cast<RESTRICTION_PROPERTY *>(prestriction));
	case RES_PROPCOMPARE:
		return restriction_free_propcompare(static_cast<RESTRICTION_PROPCOMPARE *>(prestriction));
	case RES_BITMASK:
		return restriction_free_bitmask(static_cast<RESTRICTION_BITMASK *>(prestriction));
	case RES_SIZE:
		return restriction_free_size(static_cast<RESTRICTION_SIZE *>(prestriction));
	case RES_EXIST:
		return restriction_free_exist(static_cast<RESTRICTION_EXIST *>(prestriction));
	case RES_SUBRESTRICTION:
		return restriction_free_subobj(static_cast<RESTRICTION_SUBOBJ *>(prestriction));
	case RES_COMMENT:
	case RES_ANNOTATION:
		return restriction_free_comment(static_cast<RESTRICTION_COMMENT *>(prestriction));
	case RES_COUNT:
		return restriction_free_count(static_cast<RESTRICTION_COUNT *>(prestriction));
	default:
		return;
	}
}

SRestriction *SRestriction::dup() const
{
	auto n = me_alloc<RESTRICTION>();
	if (n == nullptr)
		return NULL;
	auto prestriction = this;
	n->rt = prestriction->rt;
	n->pres = restriction_dup_by_type(prestriction->rt, prestriction->pres);
	if (n->pres == nullptr) {
		free(n);
		return NULL;
	}
	return n;
}

void restriction_free(RESTRICTION *prestriction)
{
	restriction_free_by_type(prestriction->rt, prestriction->pres);
	free(prestriction);
}

static uint32_t restriction_and_or_size(const RESTRICTION_AND_OR *r)
{
	uint32_t size;
	
	size = sizeof(uint16_t);
	for (size_t i = 0; i < r->count; ++i)
		size += restriction_size(r->pres + i);
	return size;
}

static uint32_t restriction_not_size(const RESTRICTION_NOT *r)
{
	return restriction_size(&r->res);
}

static uint32_t restriction_content_size(
	const RESTRICTION_CONTENT *r)
{
	return propval_size(PROP_TYPE(r->propval.proptag),
			r->propval.pvalue) + sizeof(uint32_t) +
			sizeof(uint32_t) + sizeof(uint32_t);
}

static uint32_t restriction_property_size(
	const RESTRICTION_PROPERTY *r)
{
	return sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t) +
	       propval_size(PROP_TYPE(r->propval.proptag), r->propval.pvalue);
}

static uint32_t restriction_propcompare_size(
	const RESTRICTION_PROPCOMPARE *r)
{
	return sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t);
}

static uint32_t restriction_bitmask_size(
	const RESTRICTION_BITMASK *r)
{
	return sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t);
}

static uint32_t restriction_size_size(
	const RESTRICTION_SIZE *r)
{
	return sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t);
}

static uint32_t restriction_exist_size(
	const RESTRICTION_EXIST *r)
{
	return sizeof(uint32_t);
}

static uint32_t restriction_size_subobj(
	const RESTRICTION_SUBOBJ *r)
{
	return restriction_size(&r->res) + sizeof(uint32_t);
}

static uint32_t restriction_comment_size(
	const RESTRICTION_COMMENT *r)
{
	uint32_t size;
	
	size = sizeof(uint8_t);
	for (unsigned int i = 0; i < r->count; ++i)
		size += propval_size(PROP_TYPE(r->ppropval[i].proptag),
					r->ppropval[i].pvalue) + sizeof(uint32_t);
	size ++;
	if (r->pres != nullptr)
		size += restriction_size(r->pres);
	return size;
}

static uint32_t restriction_count_size(const RESTRICTION_COUNT *r)
{
	return restriction_size(&r->sub_res) + sizeof(uint32_t);
}

uint32_t restriction_size(const RESTRICTION *r)
{
	switch (r->rt) {
	case RES_AND:
	case RES_OR:
		return restriction_and_or_size(r->andor) + sizeof(uint8_t);
	case RES_NOT:
		return restriction_not_size(r->xnot) + sizeof(uint8_t);
	case RES_CONTENT:
		return restriction_content_size(r->cont) + sizeof(uint8_t);
	case RES_PROPERTY:
		return restriction_property_size(r->prop) + sizeof(uint8_t);
	case RES_PROPCOMPARE:
		return restriction_propcompare_size(r->pcmp) + sizeof(uint8_t);
	case RES_BITMASK:
		return restriction_bitmask_size(r->bm) + sizeof(uint8_t);
	case RES_SIZE:
		return restriction_size_size(r->size) + sizeof(uint8_t);
	case RES_EXIST:
		return restriction_exist_size(r->exist) + sizeof(uint8_t);
	case RES_SUBRESTRICTION:
		return restriction_size_subobj(r->sub) + sizeof(uint8_t);
	case RES_COMMENT:
	case RES_ANNOTATION:
		return restriction_comment_size(r->comment) + sizeof(uint8_t);
	case RES_COUNT:
		return restriction_count_size(r->count) + sizeof(uint8_t);
	default:
		return 0;
	}
	return 0;
}
