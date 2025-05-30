// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <gromox/mapidefs.h>
#include <gromox/propval.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static bool tpropval_array_append(TPROPVAL_ARRAY *parray, proptag_t proptag,
    const void *xpropval)
{
	if (xpropval == nullptr) {
		mlog(LV_DEBUG, "pvalue is NULL in %s", __PRETTY_FUNCTION__);
		return true;
	}
	if (parray->count == 0 && parray->ppropval == nullptr &&
	    !tpropval_array_init_internal(parray))
		return false;
	auto count = strange_roundup(parray->count, SR_GROW_TAGGED_PROPVAL);
	if (parray->count + 1U >= count) {
		count += SR_GROW_TAGGED_PROPVAL;
		auto ppropvals = gromox::re_alloc<TAGGED_PROPVAL>(parray->ppropval, count);
		if (ppropvals == nullptr)
			return false;
		parray->ppropval = ppropvals;
	}
	auto v = propval_dup(PROP_TYPE(proptag), xpropval);
	if (v == nullptr)
		return false;
	parray->emplace_back(proptag, v);
	return true;
}

ec_error_t TPROPVAL_ARRAY::set(uint32_t tag, const void *xpropval)
{
	for (size_t i = 0; i < count; ++i) {
		if (ppropval[i].proptag != tag)
			continue;
		auto pvalue = ppropval[i].pvalue;
		ppropval[i].pvalue = propval_dup(PROP_TYPE(tag), xpropval);
		if (ppropval[i].pvalue == nullptr) {
			ppropval[i].pvalue = pvalue;
			return ecServerOOM;
		}
		propval_free(PROP_TYPE(tag), pvalue);
		return ecSuccess;
	}
	/*
	 * XXX: _dup could bail out because of unrecognized type, so
	 * ENOMEM is not correct all the time.
	 */
	return tpropval_array_append(this, tag, xpropval) ? ecSuccess : ecServerOOM;
}

void TPROPVAL_ARRAY::erase(proptag_t proptag)
{
	static_assert(std::is_trivially_copyable_v<TAGGED_PROPVAL>);
	for (size_t i = 0; i < count; ++i) {
		if (ppropval[i].proptag != proptag)
			continue;
		propval_free(PROP_TYPE(proptag), ppropval[i].pvalue);
		--count;
		if (i < count)
			memmove(&ppropval[i], &ppropval[i+1], (count - i) * sizeof(TAGGED_PROPVAL));
		return;
	}
}

size_t TPROPVAL_ARRAY::erase_if(bool (*pred)(const TAGGED_PROPVAL &tp))
{
	static_assert(std::is_trivially_copyable_v<TAGGED_PROPVAL>);
	size_t o = 0;
	for (size_t i = 0; i < count; ++i) {
		auto &p = ppropval[i];
		if (pred(p))
			propval_free(PROP_TYPE(p.proptag), p.pvalue);
		else if (i != o)
			memcpy(&ppropval[o++], &ppropval[i], sizeof(TAGGED_PROPVAL));
		else
			++o;
	}
	auto removed = count - o;
	count = o;
	return removed;
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
	if (parray == nullptr)
		return NULL;
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
	auto parray1 = tpropval_array_init();
	if (parray1 == nullptr)
		return NULL;
	for (size_t i = 0; i < count; ++i) {
		if (!tpropval_array_append(parray1, ppropval[i].proptag,
		    ppropval[i].pvalue)) {
			tpropval_array_free(parray1);
			return NULL;
		}
	}
	return parray1;
}
