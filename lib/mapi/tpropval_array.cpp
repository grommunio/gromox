// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <gromox/mapidefs.h>
#include <gromox/propval.hpp>
#include <gromox/util.hpp>

static bool tpropval_array_append(TPROPVAL_ARRAY *parray, uint32_t proptag,
    const void *xpropval)
{
	if (xpropval == nullptr) {
		debug_info("[tpropval_array]: pvalue is"
			" NULL in tpropval_array_append");
		return true;
	}
	if (parray->count == 0 && parray->ppropval == nullptr &&
	    !tpropval_array_init_internal(parray))
		return false;
	auto count = strange_roundup(parray->count, SR_GROW_TAGGED_PROPVAL);
	if (parray->count + 1U >= count) {
		count += SR_GROW_TAGGED_PROPVAL;
		auto ppropvals = gromox::re_alloc<TAGGED_PROPVAL>(parray->ppropval, count);
		if (NULL == ppropvals) {
			return false;
		}
		parray->ppropval = ppropvals;
	}
	parray->ppropval[parray->count].proptag = proptag;
	parray->ppropval[parray->count].pvalue = propval_dup(PROP_TYPE(proptag), xpropval);
	if (NULL == parray->ppropval[parray->count].pvalue) {
		return false;
	}
	parray->count ++;
	return true;
}

int TPROPVAL_ARRAY::set(uint32_t tag, const void *xpropval)
{
	auto parray = this;
	void *pvalue;
	
	for (size_t i = 0; i < count; ++i) {
		if (parray->ppropval[i].proptag != tag)
			continue;
		pvalue = parray->ppropval[i].pvalue;
		parray->ppropval[i].pvalue = propval_dup(
			PROP_TYPE(tag), xpropval);
		if (NULL == parray->ppropval[i].pvalue) {
			parray->ppropval[i].pvalue = pvalue;
			return -ENOMEM;
		}
		propval_free(PROP_TYPE(tag), pvalue);
		return 0;
	}
	return tpropval_array_append(parray, tag, xpropval) ? 0 : -ENOMEM;
}

void TPROPVAL_ARRAY::erase(uint32_t proptag)
{
	auto parray = this;
	
	for (size_t i = 0; i < count; ++i) {
		if (proptag != parray->ppropval[i].proptag)
			continue;
		propval_free(PROP_TYPE(proptag), parray->ppropval[i].pvalue);
		parray->count--;
		if (i < parray->count) {
			memmove(parray->ppropval + i, parray->ppropval + i + 1,
				(parray->count - i) * sizeof(TAGGED_PROPVAL));
		}
		return;
	}
}

bool tpropval_array_init_internal(TPROPVAL_ARRAY *parray)
{
	parray->count = 0;
	auto count = strange_roundup(parray->count, SR_GROW_TAGGED_PROPVAL);
	parray->ppropval = gromox::me_alloc<TAGGED_PROPVAL>(count);
	return parray->ppropval != nullptr;
}

TPROPVAL_ARRAY* tpropval_array_init()
{
	auto parray = gromox::me_alloc<TPROPVAL_ARRAY>();
	if (NULL == parray) {
		return NULL;
	}
	if (!tpropval_array_init_internal(parray)) {
		free(parray);
		return NULL;
	}
	return parray;
}

void tpropval_array_free_internal(TPROPVAL_ARRAY *parray)
{
	for (size_t i = 0; i < parray->count; ++i)
		propval_free(PROP_TYPE(parray->ppropval[i].proptag),
			parray->ppropval[i].pvalue);
	free(parray->ppropval);
}

void tpropval_array_free(TPROPVAL_ARRAY *parray)
{
	tpropval_array_free_internal(parray);
	free(parray);
}

TPROPVAL_ARRAY *TPROPVAL_ARRAY::dup() const
{
	auto parray = this;
	auto parray1 = tpropval_array_init();
	if (NULL == parray1) {
		return NULL;
	}
	for (size_t i = 0; i < count; ++i) {
		if (!tpropval_array_append(parray1, parray->ppropval[i].proptag,
		    parray->ppropval[i].pvalue)) {
			tpropval_array_free(parray1);
			return NULL;
		}
	}
	return parray1;
}
