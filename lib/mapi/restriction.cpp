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

static RESTRICTION_AND_OR* restriction_dup_and_or(
	const RESTRICTION_AND_OR *prestriction)
{
	auto pres = me_alloc<RESTRICTION_AND_OR>();
	if (NULL == pres) {
		return NULL;
	}
	pres->count = prestriction->count;
	pres->pres = me_alloc<RESTRICTION>(pres->count);
	if (NULL == pres->pres) {
		free(pres);
		return NULL;
	}
	for (size_t i = 0; i < prestriction->count; ++i) {
		pres->pres[i].rt = prestriction->pres[i].rt;
		pres->pres[i].pres = restriction_dup_by_type(
			prestriction->pres[i].rt, prestriction->pres[i].pres);
		if (NULL == pres->pres[i].pres) {
			while (i-- > 0)
				restriction_free_by_type(
					pres->pres[i].rt, pres->pres[i].pres);
			free(pres->pres);
			free(pres);
			return NULL;
		}
	}
	return pres;
}

static void restriction_free_and_or(RESTRICTION_AND_OR *prestriction)
{
	for (size_t i = 0; i < prestriction->count; ++i)
		restriction_free_by_type(prestriction->pres[i].rt,
								prestriction->pres[i].pres);
	if (NULL != prestriction->pres) {
		free(prestriction->pres);
	}
	free(prestriction);
}

static RESTRICTION_NOT* restriction_dup_not(
	const RESTRICTION_NOT *prestriction)
{
	auto pres = me_alloc<RESTRICTION_NOT>();
	if (NULL == pres) {
		return NULL;
	}
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
	restriction_free_by_type(prestriction->res.rt,
							prestriction->res.pres);
	free(prestriction);
}

static RESTRICTION_CONTENT* restriction_dup_content(
	const RESTRICTION_CONTENT *prestriction)
{
	auto pres = me_alloc<RESTRICTION_CONTENT>();
	if (NULL == pres) {
		return NULL;
	}
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
	propval_free(PROP_TYPE(prestriction->propval.proptag),
							prestriction->propval.pvalue);
	free(prestriction);
}

static RESTRICTION_PROPERTY* restriction_dup_property(
	const RESTRICTION_PROPERTY *prestriction)
{
	auto pres = me_alloc<RESTRICTION_PROPERTY>();
	if (NULL == pres) {
		return NULL;
	}
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

static RESTRICTION_PROPCOMPARE* restriction_dup_propcompare(
	const RESTRICTION_PROPCOMPARE *prestriction)
{
	auto pres = me_alloc<RESTRICTION_PROPCOMPARE>();
	if (NULL == pres) {
		return NULL;
	}
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

static RESTRICTION_BITMASK* restriction_dup_bitmask(
	const RESTRICTION_BITMASK *prestriction)
{
	auto pres = me_alloc<RESTRICTION_BITMASK>();
	if (NULL == pres) {
		return NULL;
	}
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

static RESTRICTION_SIZE* restriction_dup_size(
	const RESTRICTION_SIZE *prestriction)
{
	auto pres = me_alloc<RESTRICTION_SIZE>();
	if (NULL == pres) {
		return NULL;
	}
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

static RESTRICTION_EXIST* restriction_dup_exist(
	const RESTRICTION_EXIST *prestriction)
{
	auto pres = me_alloc<RESTRICTION_EXIST>();
	if (NULL == pres) {
		return NULL;
	}
	pres->proptag = prestriction->proptag;
	return pres;
}

static void restriction_free_exist(RESTRICTION_EXIST *prestriction)
{
	free(prestriction);
}

static RESTRICTION_SUBOBJ* restriction_dup_subobj(
	const RESTRICTION_SUBOBJ *prestriction)
{
	auto pres = me_alloc<RESTRICTION_SUBOBJ>();
	if (NULL == pres) {
		return NULL;
	}
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
	restriction_free_by_type(prestriction->res.rt,
							prestriction->res.pres);
	free(prestriction);
}

static RESTRICTION_COMMENT* restriction_dup_comment(
	const RESTRICTION_COMMENT *prestriction)
{
	int i;
	auto pres = me_alloc<RESTRICTION_COMMENT>();
	if (NULL == pres) {
		return NULL;
	}
	pres->count = prestriction->count;
	pres->ppropval = me_alloc<TAGGED_PROPVAL>(pres->count);
	if (NULL == pres->ppropval) {
		free(pres);
		return NULL;
	}
	for (i=0; i<prestriction->count; i++) {
		pres->ppropval[i].proptag = prestriction->ppropval[i].proptag;
		pres->ppropval[i].pvalue = propval_dup(PROP_TYPE(prestriction->ppropval[i].proptag),
				prestriction->ppropval[i].pvalue);
		if (NULL == pres->ppropval[i].pvalue) {
			for (i-=1; i>=0; i--) {
				propval_free(PROP_TYPE(pres->ppropval[i].proptag),
									pres->ppropval[i].pvalue);
			}
			free(pres->ppropval);
			free(pres);
			return NULL;
		}
	}
	if (NULL != prestriction->pres) {
		pres->pres = restriction_dup(prestriction->pres);
		if (NULL == pres->pres) {
			for (i=0; i<pres->count; i++) {
				propval_free(PROP_TYPE(pres->ppropval[i].proptag),
									pres->ppropval[i].pvalue);
			}
			free(pres->ppropval);
			free(pres);
			return NULL;
		}
	} else {
		pres->pres = NULL;
	}
	return pres;
}

static void restriction_free_comment(
	RESTRICTION_COMMENT *prestriction)
{
	int i;
	
	for (i=0; i<prestriction->count; i++) {
		propval_free(PROP_TYPE(prestriction->ppropval[i].proptag),
							prestriction->ppropval[i].pvalue);
	}
	free(prestriction->ppropval);
	if (NULL != prestriction->pres) {
		restriction_free(prestriction->pres);
	}
	free(prestriction);
}

static RESTRICTION_COUNT* restriction_dup_count(
	const RESTRICTION_COUNT *prestriction)
{
	auto pres = me_alloc<RESTRICTION_COUNT>();
	if (NULL == pres) {
		return NULL;
	}
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

static void restriction_free_count(
	RESTRICTION_COUNT *prestriction)
{
	restriction_free_by_type(prestriction->sub_res.rt,
							prestriction->sub_res.pres);
	free(prestriction);
}

static void *restriction_dup_by_type(mapi_rtype rt, const void *prestriction)
{
	switch (rt) {
	case RES_AND:
	case RES_OR:
		return restriction_dup_and_or(static_cast<const RESTRICTION_AND_OR *>(prestriction));
	case RES_NOT:
		return restriction_dup_not(static_cast<const RESTRICTION_NOT *>(prestriction));
	case RES_CONTENT:
		return restriction_dup_content(static_cast<const RESTRICTION_CONTENT *>(prestriction));
	case RES_PROPERTY:
		return restriction_dup_property(static_cast<const RESTRICTION_PROPERTY *>(prestriction));
	case RES_PROPCOMPARE:
		return restriction_dup_propcompare(static_cast<const RESTRICTION_PROPCOMPARE *>(prestriction));
	case RES_BITMASK:
		return restriction_dup_bitmask(static_cast<const RESTRICTION_BITMASK *>(prestriction));
	case RES_SIZE:
		return restriction_dup_size(static_cast<const RESTRICTION_SIZE *>(prestriction));
	case RES_EXIST:
		return restriction_dup_exist(static_cast<const RESTRICTION_EXIST *>(prestriction));
	case RES_SUBRESTRICTION:
		return restriction_dup_subobj(static_cast<const RESTRICTION_SUBOBJ *>(prestriction));
	case RES_COMMENT:
	case RES_ANNOTATION:
		return restriction_dup_comment(static_cast<const RESTRICTION_COMMENT *>(prestriction));
	case RES_COUNT:
		return restriction_dup_count(static_cast<const RESTRICTION_COUNT *>(prestriction));
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

RESTRICTION* restriction_dup(const RESTRICTION *prestriction)
{
	auto pres = me_alloc<RESTRICTION>();
	if (NULL == pres) {
		return NULL;
	}
	pres->rt = prestriction->rt;
	pres->pres = restriction_dup_by_type(prestriction->rt,
										prestriction->pres);
	if (NULL == pres->pres) {
		free(pres);
		return NULL;
	}
	return pres;
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
	int i;
	uint32_t size;
	
	size = sizeof(uint8_t);
	for (i=0; i<r->count; i++) {
		size += propval_size(PROP_TYPE(r->ppropval[i].proptag),
					r->ppropval[i].pvalue) + sizeof(uint32_t);
	}
	size ++;
	if (NULL != r->pres) {
		size += restriction_size(r->pres);
	}
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
